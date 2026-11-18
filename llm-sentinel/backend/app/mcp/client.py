"""MCP Client implementation supporting in-memory and STDIO transports.

Discovers tools, resources, and prompts, executes tool invocations,
and applies MCP security policies (server allowlist, RBAC, observation wrapping).
"""

import asyncio
from contextlib import AsyncExitStack
from datetime import datetime, timezone
import json
import sys
from typing import Any, Dict, List, Optional

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.memory import create_client_server_memory_streams

from app.fixtures.users import get_user
from app.mcp.models import (
    MCPPromptInfo,
    MCPResourceInfo,
    MCPServerStatus,
    MCPToolInfo,
    MCPToolInvokeResponse,
)
from app.mcp.monitor import MCPSecurityMonitor, get_mcp_monitor
from app.mcp.security import MCPSecurityEngine, TRUSTED_MCP_SERVERS
from app.mcp.server import create_omnicorp_mcp_server
from app.security.mode import SecurityMode


class MCPClient:
    """High-level client for managing connections to local MCP servers."""

    def __init__(self, monitor: Optional[MCPSecurityMonitor] = None) -> None:
        self.monitor = monitor or get_mcp_monitor()
        self._session: Optional[ClientSession] = None
        self._exit_stack: Optional[AsyncExitStack] = None
        self._server_task: Optional[asyncio.Task] = None

        self._connected: bool = False
        self._server_id: str = "omnicorp-mcp-server"
        self._server_name: Optional[str] = None
        self._server_version: Optional[str] = None
        self._transport: str = "memory"
        self._security_mode: SecurityMode = "protected"
        self._is_trusted: bool = True

        self._discovered_tools: List[MCPToolInfo] = []
        self._discovered_resources: List[MCPResourceInfo] = []
        self._discovered_prompts: List[MCPPromptInfo] = []

    @property
    def is_connected(self) -> bool:
        """Whether an active session is established."""
        return self._connected and self._session is not None

    async def connect(
        self,
        server_id: str = "omnicorp-mcp-server",
        transport: str = "memory",
        mode: SecurityMode = "protected",
    ) -> MCPServerStatus:
        """Establish connection with an MCP server using memory streams or STDIO transport.

        Args:
            server_id: Server identifier or target name.
            transport: 'memory' or 'stdio'.
            mode: 'protected' or 'vulnerable'.

        Returns:
            MCPServerStatus runtime details.
        """
        # Disconnect existing session if present
        if self.is_connected:
            await self.disconnect()

        target_sid = server_id.strip()

        # In protected mode, check allowlist before establishing transport
        is_allowed, denial_reason = MCPSecurityEngine.validate_server_connection(
            target_sid,
            mode=str(mode),
        )
        if not is_allowed:
            self._connected = False
            self.monitor.log_connection(
                server_id=target_sid,
                mode=str(mode),
                is_allowed=False,
                details=denial_reason or "Untrusted server rejected by allowlist policy.",
            )
            raise PermissionError(denial_reason)

        self._server_id = target_sid
        self._transport = transport.lower().strip()
        self._security_mode = mode
        self._is_trusted = self._server_id in TRUSTED_MCP_SERVERS

        stack = AsyncExitStack()
        try:
            if self._transport == "stdio":
                params = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", "app.mcp.server", str(self._security_mode)],
                )
                read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
            else:
                # In-memory session
                client_stream, server_stream = await stack.enter_async_context(
                    create_client_server_memory_streams()
                )
                srv = create_omnicorp_mcp_server(mode=str(self._security_mode), name=self._server_id)
                self._server_task = asyncio.create_task(
                    srv._lowlevel_server.run(
                        server_stream[0],
                        server_stream[1],
                        srv._lowlevel_server.create_initialization_options(),
                    )
                )
                read_stream = client_stream[0]
                write_stream = client_stream[1]

            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            init_res = await session.initialize()

            self._session = session
            self._exit_stack = stack
            self._connected = True
            self._server_name = init_res.server_info.name
            self._server_version = getattr(init_res.server_info, "version", "1.0.0")

            # Log successful connection
            self.monitor.log_connection(
                server_id=self._server_id,
                mode=str(self._security_mode),
                is_allowed=True,
                details=f"Connected to MCP server '{self._server_id}' (name='{self._server_name}', version='{self._server_version}', transport='{self._transport}').",
            )

            # Discover capabilities
            await self._discover_all()

            return self.get_status()

        except Exception as e:
            if self._server_task and not self._server_task.done():
                self._server_task.cancel()
                try:
                    await self._server_task
                except asyncio.CancelledError:
                    pass
            await stack.aclose()
            self._connected = False
            self._session = None
            self._exit_stack = None
            raise

    async def disconnect(self) -> None:
        """Cleanly terminate the active MCP session."""
        if self._server_task and not self._server_task.done():
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass
            self._server_task = None

        if self._exit_stack:
            await self._exit_stack.aclose()
            self._exit_stack = None

        self._session = None
        self._connected = False
        self._discovered_tools = []
        self._discovered_resources = []
        self._discovered_prompts = []

    async def _discover_all(self) -> None:
        """Internal helper to refresh tools, resources, and prompts."""
        if not self.is_connected or not self._session:
            return

        # 1. Discover tools
        tools_res = await self._session.list_tools()
        self._discovered_tools = []
        for t in tools_res.tools:
            raw_desc = t.description or ""
            # Apply security sanitization if in protected mode
            clean_desc = MCPSecurityEngine.sanitize_tool_description(
                raw_desc,
                mode=str(self._security_mode),
            )
            is_sensitive = t.name in ("send_notification", "get_customer_record")
            req_role = "support" if t.name == "send_notification" else ("guest" if t.name == "search_documents" else "support")
            self._discovered_tools.append(
                MCPToolInfo(
                    name=t.name,
                    description=clean_desc,
                    parameters=getattr(t, "input_schema", {}) or getattr(t, "inputSchema", {}) or {},
                    required_role=req_role,
                    is_sensitive=is_sensitive,
                )
            )

        self.monitor.log_tool_discovery(
            server_id=self._server_id,
            mode=str(self._security_mode),
            tool_count=len(self._discovered_tools),
            tools=[t.name for t in self._discovered_tools],
        )

        # 2. Discover resources
        res_res = await self._session.list_resources()
        self._discovered_resources = []
        for r in res_res.resources:
            self._discovered_resources.append(
                MCPResourceInfo(
                    uri=str(r.uri),
                    name=r.name or str(r.uri),
                    description=getattr(r, "description", None),
                    mime_type=getattr(r, "mime_type", "text/plain") or "text/plain",
                )
            )

        # 3. Discover prompts
        try:
            prompt_res = await self._session.list_prompts()
            self._discovered_prompts = []
            for p in prompt_res.prompts:
                args = [arg.model_dump() if hasattr(arg, "model_dump") else dict(arg) for arg in getattr(p, "arguments", [])]
                self._discovered_prompts.append(
                    MCPPromptInfo(
                        name=p.name,
                        description=getattr(p, "description", None),
                        arguments=args,
                    )
                )
        except Exception:
            self._discovered_prompts = []

    async def list_tools(self, mode: Optional[SecurityMode] = None) -> List[MCPToolInfo]:
        """List discovered MCP tools, applying sanitization when in protected mode."""
        eff_mode = mode or self._security_mode
        if not self.is_connected or self._security_mode != eff_mode:
            await self.connect(server_id=self._server_id, transport=self._transport, mode=eff_mode)

        tools_res = await self._session.list_tools()
        tools_list: List[MCPToolInfo] = []
        for t in tools_res.tools:
            raw_desc = t.description or ""
            desc = MCPSecurityEngine.sanitize_tool_description(raw_desc, mode=str(eff_mode))
            is_sensitive = t.name in ("send_notification", "get_customer_record")
            req_role = "support" if t.name == "send_notification" else ("guest" if t.name == "search_documents" else "support")
            tools_list.append(
                MCPToolInfo(
                    name=t.name,
                    description=desc,
                    parameters=getattr(t, "input_schema", {}) or getattr(t, "inputSchema", {}) or {},
                    required_role=req_role,
                    is_sensitive=is_sensitive,
                )
            )
        self._discovered_tools = tools_list
        return tools_list

    async def list_resources(self) -> List[MCPResourceInfo]:
        """List available MCP resources."""
        if not self.is_connected:
            await self.connect(server_id=self._server_id, transport=self._transport, mode=self._security_mode)
        res_res = await self._session.list_resources()
        self._discovered_resources = [
            MCPResourceInfo(
                uri=str(r.uri),
                name=r.name or str(r.uri),
                description=getattr(r, "description", None),
                mime_type=getattr(r, "mime_type", "text/plain") or "text/plain",
            )
            for r in res_res.resources
        ]
        return self._discovered_resources

    async def read_resource(self, uri: str, mode: Optional[SecurityMode] = None) -> str:
        """Read content from an MCP resource, wrapping observation delimiters when protected."""
        eff_mode = mode or self._security_mode
        if not self.is_connected or self._security_mode != eff_mode:
            await self.connect(server_id=self._server_id, transport=self._transport, mode=eff_mode)

        res_data = await self._session.read_resource(uri)
        raw_text = ""
        if res_data and res_data.contents:
            raw_text = res_data.contents[0].text

        wrapped = MCPSecurityEngine.wrap_observation(
            source_type="resource",
            source_id=uri,
            content=raw_text,
            mode=str(eff_mode),
        )

        self.monitor.log_resource_read(
            server_id=self._server_id,
            uri=uri,
            mode=str(eff_mode),
            details=f"Read {len(raw_text)} chars from {uri}",
        )
        return wrapped

    async def list_prompts(self) -> List[MCPPromptInfo]:
        """List registered prompt templates."""
        if not self.is_connected:
            await self.connect(server_id=self._server_id, transport=self._transport, mode=self._security_mode)
        prompt_res = await self._session.list_prompts()
        self._discovered_prompts = []
        for p in prompt_res.prompts:
            args = [arg.model_dump() if hasattr(arg, "model_dump") else dict(arg) for arg in getattr(p, "arguments", [])]
            self._discovered_prompts.append(
                MCPPromptInfo(
                    name=p.name,
                    description=getattr(p, "description", None),
                    arguments=args,
                )
            )
        return self._discovered_prompts

    async def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> str:
        """Retrieve rendered prompt template text."""
        if not self.is_connected:
            await self.connect(server_id=self._server_id, transport=self._transport, mode=self._security_mode)
        res = await self._session.get_prompt(name, arguments or {})
        text_lines = []
        for msg in getattr(res, "messages", []):
            content = getattr(msg, "content", None)
            if hasattr(content, "text"):
                text_lines.append(content.text)
            elif isinstance(content, str):
                text_lines.append(content)
            elif isinstance(content, list):
                for item in content:
                    if hasattr(item, "text"):
                        text_lines.append(item.text)
        return "\n\n".join(text_lines)

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: str = "guest",
        mode: Optional[SecurityMode] = None,
    ) -> MCPToolInvokeResponse:
        """Invoke an MCP tool with schema validation, RBAC, and observation containment.

        Args:
            tool_name: Tool identifier.
            arguments: Tool arguments.
            user_id: Calling user ID.
            mode: Security mode override.

        Returns:
            MCPToolInvokeResponse with outcome and audit decision.
        """
        eff_mode = mode or self._security_mode
        if not self.is_connected or self._security_mode != eff_mode:
            await self.connect(server_id=self._server_id, transport=self._transport, mode=eff_mode)

        now_ts = datetime.now(timezone.utc).isoformat()
        user = get_user(user_id)

        # 1. Argument validation check
        is_valid, validation_err = MCPSecurityEngine.validate_tool_arguments(
            tool_name=tool_name,
            arguments=arguments,
            mode=str(eff_mode),
        )
        if not is_valid:
            self.monitor.log_tool_invocation(
                server_id=self._server_id,
                tool_name=tool_name,
                arguments=arguments,
                user_id=user.user_id,
                user_role=user.role,
                mode=str(eff_mode),
                authorized=False,
                details=validation_err or "Argument validation failed.",
            )
            return MCPToolInvokeResponse(
                tool_name=tool_name,
                arguments=arguments,
                success=False,
                error=validation_err,
                authorized=False,
                security_decision="DENIED",
                timestamp=now_ts,
            )

        # 2. RBAC authorization check
        is_auth, auth_err = MCPSecurityEngine.authorize_tool_invocation(
            user=user,
            tool_name=tool_name,
            arguments=arguments,
            mode=str(eff_mode),
        )
        if not is_auth:
            self.monitor.log_tool_invocation(
                server_id=self._server_id,
                tool_name=tool_name,
                arguments=arguments,
                user_id=user.user_id,
                user_role=user.role,
                mode=str(eff_mode),
                authorized=False,
                details=auth_err or "Role-based authorization denied.",
            )
            return MCPToolInvokeResponse(
                tool_name=tool_name,
                arguments=arguments,
                success=False,
                error=auth_err,
                authorized=False,
                security_decision="DENIED",
                timestamp=now_ts,
            )

        # 3. Protocol invocation
        try:
            call_res = await self._session.call_tool(tool_name, arguments)
            raw_text = ""
            if call_res and call_res.content:
                raw_text = call_res.content[0].text

            # Wrap tool output in protected mode
            final_output = MCPSecurityEngine.wrap_observation(
                source_type="tool_output",
                source_id=tool_name,
                content=raw_text,
                mode=str(eff_mode),
            )

            self.monitor.log_tool_invocation(
                server_id=self._server_id,
                tool_name=tool_name,
                arguments=arguments,
                user_id=user.user_id,
                user_role=user.role,
                mode=str(eff_mode),
                authorized=True,
                details=f"Tool executed successfully. Output chars: {len(raw_text)}",
            )

            return MCPToolInvokeResponse(
                tool_name=tool_name,
                arguments=arguments,
                success=True,
                output=final_output,
                authorized=True,
                security_decision="PERMITTED",
                timestamp=now_ts,
            )

        except Exception as e:
            err_msg = str(e)
            self.monitor.log_tool_invocation(
                server_id=self._server_id,
                tool_name=tool_name,
                arguments=arguments,
                user_id=user.user_id,
                user_role=user.role,
                mode=str(eff_mode),
                authorized=True,
                details=f"Execution error: {err_msg}",
            )
            return MCPToolInvokeResponse(
                tool_name=tool_name,
                arguments=arguments,
                success=False,
                error=err_msg,
                authorized=True,
                security_decision="ERROR",
                timestamp=now_ts,
            )

    def get_status(self) -> MCPServerStatus:
        """Return runtime status snapshot."""
        return MCPServerStatus(
            connected=self.is_connected,
            server_id=self._server_id,
            server_name=self._server_name,
            server_version=self._server_version,
            transport=self._transport,
            security_mode=self._security_mode,
            is_trusted=self._is_trusted,
            tools_count=len(self._discovered_tools),
            resources_count=len(self._discovered_resources),
            prompts_count=len(self._discovered_prompts),
        )


_global_client: Optional[MCPClient] = None


def get_mcp_client() -> MCPClient:
    """Return singleton instance of MCPClient."""
    global _global_client
    if _global_client is None:
        _global_client = MCPClient()
    return _global_client

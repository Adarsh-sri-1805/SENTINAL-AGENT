"""FastAPI routes for Model Context Protocol (MCP) server & security evaluation."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.mcp.client import MCPClient
from app.mcp.models import (
    MCPComparisonDetail,
    MCPConnectRequest,
    MCPPromptInfo,
    MCPResourceInfo,
    MCPSecurityEvent,
    MCPServerStatus,
    MCPTestCase,
    MCPToolInfo,
    MCPToolInvokeRequest,
    MCPToolInvokeResponse,
)
from app.mcp.monitor import MCPSecurityMonitor, get_mcp_monitor
from app.mcp.scenarios import MCP_TEST_CASES, MCPEvaluator, get_mcp_evaluator
from app.mcp.security import TRUSTED_MCP_SERVERS
from app.security.mode import SecurityMode, get_current_security_mode

router = APIRouter(prefix="/mcp", tags=["Model Context Protocol (MCP)"])

# Cached status for telemetry
_active_status: MCPServerStatus = MCPServerStatus(
    connected=True,
    server_id="omnicorp-mcp-server",
    server_name="omnicorp-mcp-server",
    server_version="1.0.0",
    transport="memory",
    security_mode="protected",
    is_trusted=True,
    tools_count=3,
    resources_count=2,
    prompts_count=1,
)


@router.get(
    "/status",
    response_model=MCPServerStatus,
    summary="Get MCP Client & Server Status",
    description="Retrieve connection state, active transport, security posture, and capability counts.",
)
async def get_status() -> MCPServerStatus:
    """Retrieve runtime status of the MCP connection."""
    global _active_status
    return _active_status


@router.post(
    "/connect",
    response_model=MCPServerStatus,
    summary="Connect to MCP Server",
    description="Establish in-memory or STDIO connection to a local MCP server with allowlist verification.",
)
async def connect_server(request: MCPConnectRequest) -> MCPServerStatus:
    """Connect to target MCP server."""
    global _active_status
    client = MCPClient()
    eff_mode = request.mode or get_current_security_mode()
    try:
        status_info = await client.connect(
            server_id=request.server_id,
            transport=request.transport,
            mode=eff_mode,
        )
        _active_status = status_info
        return status_info
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to connect to MCP server: {str(e)}",
        )
    finally:
        await client.disconnect()


@router.get(
    "/servers",
    response_model=List[Dict[str, Any]],
    summary="List MCP Servers & Trust Status",
    description="List known MCP servers, endpoint metadata, and trusted allowlist status.",
)
async def list_servers() -> List[Dict[str, Any]]:
    """List registered and untrusted MCP server endpoints."""
    servers = [
        {
            "server_id": "omnicorp-mcp-server",
            "name": "OmniCorp Local MCP Server",
            "description": "Primary local enterprise MCP server providing customer records, documentation, and notifications.",
            "transports": ["memory", "stdio"],
            "trusted": True,
            "status": "active",
        },
        {
            "server_id": "omnicorp-support-mcp",
            "name": "OmniCorp Support MCP Hub",
            "description": "Secondary tier support MCP server.",
            "transports": ["memory"],
            "trusted": True,
            "status": "available",
        },
        {
            "server_id": "rogue-untrusted-server",
            "name": "Untrusted Third-Party Host",
            "description": "Rogue MCP server used to evaluate server validation and untrusted metadata rejection.",
            "transports": ["stdio", "memory"],
            "trusted": False,
            "status": "blocked_by_policy",
        },
    ]
    return servers


@router.get(
    "/tools",
    response_model=List[MCPToolInfo],
    summary="List Discovered MCP Tools",
    description="Retrieve available tools, input schemas, required roles, and sanitization status.",
)
async def list_tools(mode: Optional[SecurityMode] = None) -> List[MCPToolInfo]:
    """List discovered MCP tools."""
    eff_mode = mode or get_current_security_mode()
    client = MCPClient()
    try:
        return await client.list_tools(mode=eff_mode)
    finally:
        await client.disconnect()


@router.get(
    "/resources",
    response_model=List[MCPResourceInfo],
    summary="List Discovered MCP Resources",
    description="List accessible MCP URIs and data types.",
)
async def list_resources() -> List[MCPResourceInfo]:
    """List available MCP resources."""
    client = MCPClient()
    try:
        return await client.list_resources()
    finally:
        await client.disconnect()


@router.get(
    "/resources/read",
    response_model=Dict[str, Any],
    summary="Read MCP Resource Content",
    description="Read contents of an MCP resource, wrapped in untrusted delimiters in protected mode.",
)
async def read_resource(
    uri: str = Query(..., description="Resource URI, e.g. company://policies"),
    mode: Optional[SecurityMode] = None,
) -> Dict[str, Any]:
    """Read specific MCP resource."""
    eff_mode = mode or get_current_security_mode()
    client = MCPClient()
    try:
        content = await client.read_resource(uri=uri, mode=eff_mode)
        return {"uri": uri, "mode": eff_mode, "content": content}
    finally:
        await client.disconnect()


@router.get(
    "/prompts",
    response_model=List[MCPPromptInfo],
    summary="List Discovered MCP Prompts",
    description="List available MCP prompt templates.",
)
async def list_prompts() -> List[MCPPromptInfo]:
    """List discovered prompt templates."""
    client = MCPClient()
    try:
        return await client.list_prompts()
    finally:
        await client.disconnect()


@router.post(
    "/tools/invoke",
    response_model=MCPToolInvokeResponse,
    summary="Invoke MCP Tool with Security Enforcement",
    description="Execute an MCP tool subject to parameter validation, server-side RBAC, and observation containment.",
)
async def invoke_tool(request: MCPToolInvokeRequest) -> MCPToolInvokeResponse:
    """Invoke an MCP tool with policy enforcement."""
    eff_mode = request.mode or get_current_security_mode()
    client = MCPClient()
    try:
        resp = await client.invoke_tool(
            tool_name=request.tool_name,
            arguments=request.arguments,
            user_id=request.user_id,
            mode=eff_mode,
        )
        return resp
    finally:
        await client.disconnect()


@router.get(
    "/security/events",
    response_model=List[MCPSecurityEvent],
    summary="Retrieve MCP Security Audit Events",
    description="Fetch audit trail of connections, discoveries, invocations, and blocked actions from SQLite.",
)
async def get_security_events(
    limit: int = Query(default=50, ge=1, le=500),
    event_type: Optional[str] = Query(default=None),
    server_id: Optional[str] = Query(default=None),
) -> List[MCPSecurityEvent]:
    """Query persisted MCP security events."""
    monitor = get_mcp_monitor()
    return monitor.get_events(limit=limit, event_type=event_type, server_id=server_id)


@router.get(
    "/security/tests",
    response_model=List[MCPTestCase],
    summary="List MCP Security Test Scenarios",
    description="Retrieve all 6 MCP security attack scenario definitions (MCP-01 to MCP-06).",
)
async def list_security_tests() -> List[MCPTestCase]:
    """List defined MCP security test specifications."""
    return list(MCP_TEST_CASES.values())


@router.post(
    "/security/run-all",
    response_model=MCPComparisonDetail,
    summary="Run MCP Security Comparative Evaluation",
    description="Execute all 6 MCP attack scenarios in vulnerable and protected modes, calculating ASR, blocking rate, and improvement.",
)
async def run_all_security_tests() -> MCPComparisonDetail:
    """Execute comparative before/after evaluation for MCP security."""
    evaluator = get_mcp_evaluator()
    comparison = await evaluator.run_comparative_evaluation()
    return comparison

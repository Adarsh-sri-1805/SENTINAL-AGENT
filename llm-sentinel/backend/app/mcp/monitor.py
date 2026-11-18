"""Centralized security monitor and audit logger for MCP operations.

Tracks connections, tool discoveries, resource access, tool invocations,
authorization decisions, and blocked attacks into SQLite with data redaction.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from app.mcp.models import MCPSecurityEvent
from app.security.redactor import redact_sensitive_data
from app.testing.storage import StorageManager, get_storage_manager


class MCPSecurityMonitor:
    """Centralized monitor for MCP events, policy decisions, and audit logging."""

    def __init__(self, storage: Optional[StorageManager] = None) -> None:
        self.storage = storage or get_storage_manager()

    def record_event(
        self,
        event_type: str,
        server_id: str,
        security_mode: str,
        authorized: bool = True,
        details: str = "",
        tool_name: Optional[str] = None,
        resource_uri: Optional[str] = None,
        user_id: str = "guest",
        user_role: str = "guest",
    ) -> MCPSecurityEvent:
        """Record and persist an MCP security event with sensitive data redaction."""
        clean_details = redact_sensitive_data(details)
        now_ts = datetime.now(timezone.utc).isoformat()

        event = MCPSecurityEvent(
            timestamp=now_ts,
            event_type=event_type,
            server_id=server_id,
            tool_name=tool_name,
            resource_uri=resource_uri,
            user_id=user_id,
            user_role=user_role,
            security_mode=security_mode,
            authorized=authorized,
            details=clean_details,
        )

        event_id = self.storage.save_mcp_event(event)
        event.id = event_id
        return event

    def log_connection(
        self,
        server_id: str,
        mode: str,
        is_allowed: bool,
        details: str = "",
    ) -> MCPSecurityEvent:
        """Log MCP server connection attempt."""
        event_type = "server_connect" if is_allowed else "untrusted_server_blocked"
        msg = details or (f"Connected to MCP server '{server_id}'" if is_allowed else f"Untrusted MCP server '{server_id}' blocked")
        return self.record_event(
            event_type=event_type,
            server_id=server_id,
            security_mode=mode,
            authorized=is_allowed,
            details=msg,
        )

    def log_tool_discovery(
        self,
        server_id: str,
        mode: str,
        tool_count: int,
        tools: List[str],
    ) -> MCPSecurityEvent:
        """Log MCP tool discovery."""
        details = f"Discovered {tool_count} tools: {', '.join(tools)}"
        return self.record_event(
            event_type="tool_discover",
            server_id=server_id,
            security_mode=mode,
            authorized=True,
            details=details,
        )

    def log_resource_read(
        self,
        server_id: str,
        uri: str,
        mode: str,
        details: str = "",
    ) -> MCPSecurityEvent:
        """Log MCP resource access."""
        msg = details or f"Read resource '{uri}'"
        return self.record_event(
            event_type="resource_read",
            server_id=server_id,
            resource_uri=uri,
            security_mode=mode,
            authorized=True,
            details=msg,
        )

    def log_tool_invocation(
        self,
        server_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: str,
        user_role: str,
        mode: str,
        authorized: bool,
        details: str,
    ) -> MCPSecurityEvent:
        """Log MCP tool invocation request and outcome."""
        event_type = "tool_invoke" if authorized else "auth_denied"
        full_details = f"Tool: {tool_name} | Args: {json.dumps(arguments)} | Result: {details}"
        return self.record_event(
            event_type=event_type,
            server_id=server_id,
            tool_name=tool_name,
            user_id=user_id,
            user_role=user_role,
            security_mode=mode,
            authorized=authorized,
            details=full_details,
        )

    def log_security_alert(
        self,
        event_type: str,
        server_id: str,
        mode: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        tool_name: Optional[str] = None,
        resource_uri: Optional[str] = None,
    ) -> MCPSecurityEvent:
        """Log an explicit security alert or violation."""
        payload_str = json.dumps(details) if details else ""
        msg = f"Security Alert: {reason}. Payload: {payload_str}"
        return self.record_event(
            event_type=event_type,
            server_id=server_id,
            tool_name=tool_name,
            resource_uri=resource_uri,
            security_mode=mode,
            authorized=False,
            details=msg,
        )

    def get_events(
        self,
        limit: int = 50,
        event_type: Optional[str] = None,
        server_id: Optional[str] = None,
    ) -> List[MCPSecurityEvent]:
        """Query security audit events."""
        return self.storage.get_mcp_events(limit=limit, event_type=event_type, server_id=server_id)


_global_monitor: Optional[MCPSecurityMonitor] = None


def get_mcp_monitor() -> MCPSecurityMonitor:
    """Return singleton instance of MCPSecurityMonitor."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = MCPSecurityMonitor()
    return _global_monitor

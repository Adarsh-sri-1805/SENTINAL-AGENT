"""API routes for security posture management and tool audit logs."""

from typing import List
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.security.audit import ToolAuditRecord, get_tool_audit_logs
from app.security.mode import SecurityMode, SecurityModeState, get_security_mode_state, set_security_mode

router = APIRouter(prefix="", tags=["Security & Audit"])


class SetSecurityModeRequest(BaseModel):
    """Payload to update global security posture."""

    mode: SecurityMode = Field(..., description="Target mode: 'vulnerable' or 'protected'")


@router.get(
    "/security/mode",
    response_model=SecurityModeState,
    summary="Get Active Security Mode",
)
async def get_mode() -> SecurityModeState:
    """Return the currently configured security mode ('vulnerable' or 'protected')."""
    return get_security_mode_state()


@router.post(
    "/security/mode",
    response_model=SecurityModeState,
    summary="Update Security Mode",
)
async def update_mode(request: SetSecurityModeRequest) -> SecurityModeState:
    """Switch the application security mode between 'vulnerable' and 'protected'."""
    set_security_mode(request.mode)
    return get_security_mode_state()


@router.get(
    "/logs/tools",
    response_model=List[ToolAuditRecord],
    summary="Get Tool Execution Audit Logs",
)
async def get_tool_logs(
    limit: int = Query(default=100, ge=1, le=500, description="Maximum log entries to return"),
) -> List[ToolAuditRecord]:
    """Retrieve structured audit records of all tool execution attempts with sensitive data redacted."""
    return get_tool_audit_logs(limit=limit)


"""Audit logging module for tracking tool invocations and security decisions."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.security.redactor import redact_data_structure

logger = logging.getLogger("llm_sentinel.audit")

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
AUDIT_LOG_FILE = RESULTS_DIR / "tool_audit.jsonl"


class ToolAuditRecord(BaseModel):
    """Schema for a recorded tool execution."""

    id: str = Field(..., description="Unique record identifier")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    user_id: str = Field(..., description="User ID invoking the tool")
    user_role: str = Field(..., description="User role (guest, employee, admin)")
    tool_name: str = Field(..., description="Tool name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Redacted arguments")
    authorized: bool = Field(..., description="Whether authorization was granted")
    security_mode: str = Field(..., description="Active security mode during call")
    result: Optional[Any] = Field(default=None, description="Redacted tool output or error")
    error: Optional[str] = Field(default=None, description="Error message if failed or denied")


class _AuditLogger:
    """Thread-safe in-memory and on-disk audit logger."""

    def __init__(self) -> None:
        self._records: List[ToolAuditRecord] = []
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        user_id: str,
        user_role: str,
        tool_name: str,
        arguments: Dict[str, Any],
        authorized: bool,
        security_mode: str,
        result: Optional[Any] = None,
        error: Optional[str] = None,
    ) -> ToolAuditRecord:
        """Create and persist a redacted tool audit record."""
        import uuid

        now_str = datetime.now(timezone.utc).isoformat()
        record_id = f"aud-{uuid.uuid4().hex[:8]}"

        # Always redact arguments and result before persisting/logging
        redacted_args = redact_data_structure(arguments)
        redacted_result = redact_data_structure(result)
        redacted_error = redact_data_structure(error) if error else None

        record = ToolAuditRecord(
            id=record_id,
            timestamp=now_str,
            user_id=user_id,
            user_role=user_role,
            tool_name=tool_name,
            arguments=redacted_args,
            authorized=authorized,
            security_mode=security_mode,
            result=redacted_result,
            error=redacted_error,
        )

        self._records.append(record)

        # Log via standard logging
        logger.info(
            "TOOL_AUDIT id=%s user=%s role=%s tool=%s auth=%s mode=%s",
            record.id,
            record.user_id,
            record.user_role,
            record.tool_name,
            record.authorized,
            record.security_mode,
        )

        # Append to JSONL file on disk
        try:
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(record.model_dump_json() + "\n")
        except Exception as exc:
            logger.warning("Failed to write to audit log file: %s", exc)

        return record

    def get_records(self, limit: int = 100) -> List[ToolAuditRecord]:
        """Return the most recent audit records."""
        return list(reversed(self._records[-limit:]))

    def clear(self) -> None:
        """Clear in-memory records (for tests)."""
        self._records.clear()


_audit_logger = _AuditLogger()


def log_tool_invocation(
    user_id: str,
    user_role: str,
    tool_name: str,
    arguments: Dict[str, Any],
    authorized: bool,
    security_mode: str,
    result: Optional[Any] = None,
    error: Optional[str] = None,
) -> ToolAuditRecord:
    """Helper to record tool execution."""
    return _audit_logger.log(
        user_id=user_id,
        user_role=user_role,
        tool_name=tool_name,
        arguments=arguments,
        authorized=authorized,
        security_mode=security_mode,
        result=result,
        error=error,
    )


def get_tool_audit_logs(limit: int = 100) -> List[ToolAuditRecord]:
    """Retrieve tool execution logs."""
    return _audit_logger.get_records(limit=limit)


def clear_audit_logs() -> None:
    """Clear logs for testing."""
    _audit_logger.clear()


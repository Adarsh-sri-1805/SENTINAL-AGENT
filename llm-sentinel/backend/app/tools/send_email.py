"""Tool to simulate corporate email delivery to a local fake outbox."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List
import uuid

from app.tools.base import BaseTool, ToolResult

OUTBOX_DIR = Path(__file__).resolve().parent.parent.parent / "results" / "email_outbox"


class SendEmailTool(BaseTool):
    """Simulated email delivery tool."""

    def __init__(self) -> None:
        self.sent_emails: List[Dict[str, Any]] = []
        OUTBOX_DIR.mkdir(parents=True, exist_ok=True)

    @property
    def name(self) -> str:
        return "send_email"

    @property
    def description(self) -> str:
        return (
            "Send an email message on behalf of the company. "
            "Requires recipient email ('to'), 'subject', and message 'body'."
        )

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Subject line"},
                "body": {"type": "string", "description": "Email body content"},
            },
            "required": ["to", "subject", "body"],
        }

    @property
    def required_role(self) -> str:
        return "employee"

    async def execute(self, to: str = "", subject: str = "", body: str = "", **kwargs: Any) -> ToolResult:
        """Simulate email sending by writing to local fake outbox."""
        if not to or "@" not in to:
            return ToolResult(success=False, error="Invalid recipient email address.")
        if not subject:
            return ToolResult(success=False, error="Email subject cannot be empty.")

        email_id = f"mail-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        email_record = {
            "id": email_id,
            "timestamp": timestamp,
            "to": to.strip(),
            "subject": subject.strip(),
            "body": body,
            "simulated": True,
        }

        self.sent_emails.append(email_record)

        # Persist to results/email_outbox/<id>.json
        try:
            out_file = OUTBOX_DIR / f"{email_id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(email_record, f, indent=2)
        except Exception as exc:
            pass  # Non-fatal if disk write fails

        return ToolResult(
            success=True,
            output={
                "status": "delivered_to_simulated_outbox",
                "message_id": email_id,
                "recipient": to.strip(),
                "subject": subject.strip(),
                "timestamp": timestamp,
            },
        )


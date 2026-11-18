"""Wazuh SIEM integration service and JSONL security event exporter."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from app.security.redactor import redact_sensitive_data
from app.wazuh.models import (
    WazuhAlertItem,
    WazuhAlertsResponse,
    WazuhExportResponse,
    WazuhStatus,
)

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
DB_PATH = RESULTS_DIR / "sentinel.db"
WAZUH_JSONL_PATH = RESULTS_DIR / "wazuh_events.jsonl"

# Standard Wazuh Rule ID Mappings for LLM Sentinel Security Events
WAZUH_RULE_MAPPINGS = {
    "LLM01": {"rule_id": "100100", "level": 12, "desc": "OWASP LLM01: Prompt Injection Attempt Blocked", "severity": "CRITICAL"},
    "LLM02": {"rule_id": "100101", "level": 11, "desc": "OWASP LLM02: Sensitive Information Disclosure Attempt", "severity": "HIGH"},
    "LLM03": {"rule_id": "100102", "level": 10, "desc": "OWASP LLM03: Excessive Agency / Unauthorized Tool Action", "severity": "HIGH"},
    "LLM08": {"rule_id": "100103", "level": 8, "desc": "OWASP LLM08: Hidden Context / System Prompt Exposure Attempt", "severity": "MEDIUM"},
    "LLM10": {"rule_id": "100104", "level": 9, "desc": "OWASP LLM10: Improper Output Handling / Code Injection", "severity": "HIGH"},
    "ASI01": {"rule_id": "100105", "level": 12, "desc": "OWASP Agentic ASI01: Agent Goal Hijack Attempt", "severity": "CRITICAL"},
    "ASI02": {"rule_id": "100106", "level": 11, "desc": "OWASP Agentic ASI02: Tool Misuse / Exfiltration", "severity": "HIGH"},
    "ASI03": {"rule_id": "100107", "level": 10, "desc": "OWASP Agentic ASI03: Identity & Privilege Escalation Attempt", "severity": "HIGH"},
    "ASI05": {"rule_id": "100108", "level": 13, "desc": "OWASP Agentic ASI05: Unexpected Code Execution / Sandbox Escape", "severity": "CRITICAL"},
    "ASI06": {"rule_id": "100109", "level": 11, "desc": "OWASP Agentic ASI06: Memory & Context Poisoning Attempt", "severity": "HIGH"},
    "MCP": {"rule_id": "100110", "level": 11, "desc": "MCP Security: Unauthorized Server, Tool or Resource Violation", "severity": "HIGH"},
}


class WazuhIntegrationService:
    """Manages Wazuh connectivity verification, event forwarding, and rule correlation."""

    def __init__(self, db_path: Optional[Path] = None, jsonl_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DB_PATH
        self.jsonl_path = jsonl_path or WAZUH_JSONL_PATH
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_export_ts: Optional[str] = None

    def check_connection(self) -> Tuple[bool, bool, str]:
        """Check whether a Wazuh agent or manager is installed/reachable.

        Returns:
            Tuple[connected, agent_installed, details]
        """
        agent_paths = [
            Path("C:/Program Files (x86)/ossec-agent"),
            Path("C:/Program Files/wazuh-agent"),
            Path("/var/ossec"),
        ]
        agent_installed = any(p.exists() for p in agent_paths)

        # In this POC environment without a live local Wazuh manager, accurately report disconnected
        connected = False
        if not agent_installed:
            details = (
                "Wazuh Agent is NOT detected on this host. Events are exported locally to JSONL "
                f"({self.jsonl_path.name}) for collection via Wazuh Agent <localfile> log collector."
            )
        else:
            details = f"Wazuh Agent directory located, but active manager socket is currently unverified."

        return connected, agent_installed, details

    def get_status(self) -> WazuhStatus:
        """Return runtime status of Wazuh SIEM integration."""
        connected, agent_installed, details = self.check_connection()
        total_exported = 0
        if self.jsonl_path.exists():
            try:
                with open(self.jsonl_path, "r", encoding="utf-8") as f:
                    total_exported = sum(1 for line in f if line.strip())
            except Exception:
                total_exported = 0

        return WazuhStatus(
            connected=connected,
            status_text="CONNECTED" if connected else "NOT CONNECTED",
            agent_installed=agent_installed,
            manager_detected=False,
            log_file_path=str(self.jsonl_path.resolve()),
            total_events_exported=total_exported,
            last_export_timestamp=self._last_export_ts,
            details=details,
        )

    def export_events(self) -> WazuhExportResponse:
        """Read security test results and MCP events from SQLite, format to JSONL, and write to file."""
        now_ts = datetime.now(timezone.utc).isoformat()
        events_written = 0
        sample_event: Optional[Dict[str, Any]] = None

        if not self.db_path.exists():
            return WazuhExportResponse(
                success=True,
                events_exported=0,
                file_path=str(self.jsonl_path.resolve()),
                timestamp=now_ts,
                sample_event=None,
            )

        events_to_write: List[Dict[str, Any]] = []

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 1. Fetch test results
            try:
                cursor.execute(
                    """
                    SELECT id, run_id, test_id, risk_id, risk_name, target, mode, model,
                           prompt, response, result, evaluation_explanation, timestamp
                    FROM test_results
                    ORDER BY id ASC
                    """
                )
                test_rows = cursor.fetchall()
                for row in test_rows:
                    risk_prefix = row["risk_id"][:5] if row["risk_id"] else "LLM01"
                    mapping = WAZUH_RULE_MAPPINGS.get(risk_prefix, WAZUH_RULE_MAPPINGS.get(row["risk_id"][:3], {
                        "rule_id": "100100",
                        "level": 7,
                        "desc": f"Security Test Event ({row['risk_id']})",
                        "severity": "MEDIUM",
                    }))

                    action_taken = "BLOCKED_BY_POLICY" if row["result"] == "BLOCKED" else ("PARTIALLY_CONTAINED" if row["result"] == "PARTIAL" else "SECURITY_FAILED")

                    event_entry = {
                        "timestamp": row["timestamp"],
                        "event_id": f"sentinel-test-{row['id']}",
                        "source": "LLM Sentinel",
                        "component": row["target"],
                        "risk_id": row["risk_id"],
                        "risk_name": row["risk_name"],
                        "severity": mapping["severity"],
                        "wazuh_rule": {
                            "id": mapping["rule_id"],
                            "level": mapping["level"],
                            "description": mapping["desc"],
                        },
                        "event_type": "security_test_evaluation",
                        "test_id": row["test_id"],
                        "model": row["model"],
                        "security_mode": row["mode"],
                        "classification": row["result"],
                        "action_taken": action_taken,
                        "details": redact_sensitive_data(row["evaluation_explanation"] or ""),
                    }
                    events_to_write.append(event_entry)
            except sqlite3.OperationalError:
                pass

            # 2. Fetch MCP security events
            try:
                cursor.execute(
                    """
                    SELECT id, timestamp, event_type, server_id, tool_name, resource_uri,
                           user_id, user_role, security_mode, authorized, details
                    FROM mcp_security_events
                    ORDER BY id ASC
                    """
                )
                mcp_rows = cursor.fetchall()
                for row in mcp_rows:
                    mapping = WAZUH_RULE_MAPPINGS["MCP"]
                    action = "PERMITTED" if row["authorized"] else "DENIED_BY_POLICY"
                    severity = "LOW" if row["authorized"] else ("CRITICAL" if "untrusted" in row["event_type"] else "HIGH")

                    event_entry = {
                        "timestamp": row["timestamp"],
                        "event_id": f"sentinel-mcp-{row['id']}",
                        "source": "LLM Sentinel",
                        "component": "Model Context Protocol (MCP)",
                        "risk_id": "MCP",
                        "risk_name": "MCP Security & Policy Violation",
                        "severity": severity,
                        "wazuh_rule": {
                            "id": mapping["rule_id"],
                            "level": mapping["level"],
                            "description": mapping["desc"],
                        },
                        "event_type": row["event_type"],
                        "test_id": row["tool_name"] or row["resource_uri"] or "mcp_event",
                        "model": "omnicorp-mcp",
                        "security_mode": row["security_mode"],
                        "classification": "BLOCKED" if not row["authorized"] else "PERMITTED",
                        "action_taken": action,
                        "details": redact_sensitive_data(row["details"] or ""),
                    }
                    events_to_write.append(event_entry)
            except sqlite3.OperationalError:
                pass

        # Write to JSONL
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            for ev in events_to_write:
                f.write(json.dumps(ev) + "\n")
                events_written += 1

        self._last_export_ts = now_ts
        if events_to_write:
            sample_event = events_to_write[-1]

        return WazuhExportResponse(
            success=True,
            events_exported=events_written,
            file_path=str(self.jsonl_path.resolve()),
            timestamp=now_ts,
            sample_event=sample_event,
        )

    def get_alerts(self, limit: int = 50) -> WazuhAlertsResponse:
        """Retrieve alerts based on Wazuh rule definitions for security events."""
        connected, _, details = self.check_connection()

        # If JSONL hasn't been exported or is empty, export automatically
        if not self.jsonl_path.exists() or self.jsonl_path.stat().st_size == 0:
            self.export_events()

        alerts: List[WazuhAlertItem] = []
        if self.jsonl_path.exists():
            try:
                with open(self.jsonl_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    # Parse latest events into alerts
                    for line in reversed(lines[-limit:]):
                        if not line.strip():
                            continue
                        ev = json.loads(line)
                        rule = ev.get("wazuh_rule", {})
                        alerts.append(
                            WazuhAlertItem(
                                alert_id=f"alt-{ev.get('event_id', '0')}",
                                timestamp=ev.get("timestamp", ""),
                                rule_id=rule.get("id", "100100"),
                                rule_level=rule.get("level", 7),
                                rule_description=rule.get("description", "Security Event Detected"),
                                category=ev.get("risk_name", "AI Security"),
                                risk_id=ev.get("risk_id"),
                                source=ev.get("component", "LLM Sentinel"),
                                severity=ev.get("severity", "MEDIUM"),
                                action_taken=ev.get("action_taken", "MONITORED"),
                                details={
                                    "test_id": ev.get("test_id"),
                                    "security_mode": ev.get("security_mode"),
                                    "classification": ev.get("classification"),
                                    "summary": ev.get("details", "")[:200],
                                },
                            )
                        )
            except Exception:
                pass

        return WazuhAlertsResponse(
            total_alerts=len(alerts),
            connected=connected,
            message=(
                "Wazuh SIEM Status: NOT CONNECTED (No live agent/manager socket detected). "
                f"Showing {len(alerts)} correlated security alerts generated from local Sentinel audit logs."
            ),
            alerts=alerts,
        )


_global_wazuh_service: Optional[WazuhIntegrationService] = None


def get_wazuh_service() -> WazuhIntegrationService:
    """Return singleton instance of WazuhIntegrationService."""
    global _global_wazuh_service
    if _global_wazuh_service is None:
        _global_wazuh_service = WazuhIntegrationService()
    return _global_wazuh_service

"""Unit and API tests for security mode management, redactor, and audit logging."""

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.security.audit import clear_audit_logs, get_tool_audit_logs, log_tool_invocation
from app.security.mode import get_current_security_mode, set_security_mode
from app.security.redactor import redact_data_structure, redact_sensitive_data


def test_security_mode_toggle():
    """Verify security mode getter and setter."""
    assert set_security_mode("vulnerable") == "vulnerable"
    assert get_current_security_mode() == "vulnerable"

    assert set_security_mode("protected") == "protected"
    assert get_current_security_mode() == "protected"

    with pytest.raises(ValueError, match="Invalid security mode"):
        set_security_mode("unsupported_mode")


def test_sensitive_data_redactor_strings():
    """Verify redaction of secret flags, credentials, and payment cards."""
    # Test secret flag
    text_flag = "Found secret: SECRET-FLAG-123 and agent token AGENT-FLAG-456."
    redacted_flag = redact_sensitive_data(text_flag)
    assert "SECRET-FLAG-123" not in redacted_flag
    assert "AGENT-FLAG-456" not in redacted_flag
    assert "[REDACTED_SECRET_FLAG]" in redacted_flag
    assert "[REDACTED_AGENT_FLAG]" in redacted_flag

    # Test credit card
    text_cc = "Payment card: 4111-2222-3333-4444 on file."
    redacted_cc = redact_sensitive_data(text_cc)
    assert "4111-2222-3333-4444" not in redacted_cc
    assert "[REDACTED_PAYMENT_CARD]" in redacted_cc

    # Test API key
    text_key = "Google key AIzaSyD1234567890abcdefghijklmnopqrstuv in request."
    redacted_key = redact_sensitive_data(text_key)
    assert "AIza" not in redacted_key
    assert "[REDACTED_API_KEY]" in redacted_key


def test_sensitive_data_redactor_nested_structure():
    """Verify recursive redaction on nested dictionaries and lists."""
    payload = {
        "user": "Alice",
        "secrets": ["SECRET-FLAG-999", "Normal info"],
        "metadata": {
            "token": "AGENT-FLAG-777",
            "card": "1234 5678 9876 5432",
        },
    }
    redacted = redact_data_structure(payload)
    assert redacted["secrets"][0] == "[REDACTED_SECRET_FLAG]"
    assert redacted["secrets"][1] == "Normal info"
    assert redacted["metadata"]["token"] == "[REDACTED_AGENT_FLAG]"
    assert redacted["metadata"]["card"] == "[REDACTED_PAYMENT_CARD]"


def test_tool_audit_logger():
    """Verify tool execution recording and retrieval."""
    clear_audit_logs()
    record = log_tool_invocation(
        user_id="employee",
        user_role="employee",
        tool_name="read_file",
        arguments={"filepath": "public/welcome.txt"},
        authorized=True,
        security_mode="protected",
        result={"content": "Welcome"},
    )
    assert record.authorized is True
    assert record.tool_name == "read_file"

    logs = get_tool_audit_logs(limit=10)
    assert len(logs) >= 1
    assert logs[0].id == record.id


def test_api_security_mode_endpoints():
    """Verify GET and POST /api/security/mode."""
    with TestClient(app) as client:
        # GET mode
        resp_get = client.get("/api/security/mode")
        assert resp_get.status_code == 200
        assert "mode" in resp_get.json()

        # POST mode -> set to protected
        resp_set_prot = client.post("/api/security/mode", json={"mode": "protected"})
        assert resp_set_prot.status_code == 200
        assert resp_set_prot.json()["mode"] == "protected"
        assert get_current_security_mode() == "protected"

        # POST mode -> set to vulnerable
        resp_set_vuln = client.post("/api/security/mode", json={"mode": "vulnerable"})
        assert resp_set_vuln.status_code == 200
        assert resp_set_vuln.json()["mode"] == "vulnerable"
        assert get_current_security_mode() == "vulnerable"


def test_api_logs_tools_endpoint():
    """Verify GET /api/logs/tools returns audit records."""
    log_tool_invocation(
        user_id="test_user",
        user_role="guest",
        tool_name="http_request",
        arguments={"url": "http://internal-billing.omnicorp.local/api/invoices"},
        authorized=True,
        security_mode="vulnerable",
    )

    with TestClient(app) as client:
        resp = client.get("/api/logs/tools?limit=5")
        assert resp.status_code == 200
        records = resp.json()
        assert isinstance(records, list)
        assert len(records) > 0
        assert "tool_name" in records[0]


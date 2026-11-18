"""Unit tests for agent tools: containment, isolation, and functionality."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.tools.base import ToolResult
from app.tools.execute_code import ExecuteCodeTool
from app.tools.http_request import HttpRequestTool
from app.tools.read_file import FIXTURE_DIR, ReadFileTool
from app.tools.send_email import OUTBOX_DIR, SendEmailTool


# =====================================================================
# Tool 1: read_file
# =====================================================================

@pytest.mark.anyio
async def test_read_file_public_document_success():
    """Verify reading an existing public file within the fixture directory."""
    tool = ReadFileTool()
    result = await tool.execute(filepath="public/welcome.txt")
    assert result.success is True
    assert result.output is not None
    assert "OmniCorp" in result.output["content"]


@pytest.mark.anyio
async def test_read_file_path_traversal_blocked():
    """Verify that path traversal attempts outside company_files are strictly blocked."""
    tool = ReadFileTool()

    # Traversal test payloads
    payloads = [
        "../../etc/passwd",
        "../../../windows/win.ini",
        "../config.py",
        "../../requirements.txt",
    ]

    for p in payloads:
        result = await tool.execute(filepath=p)
        assert result.success is False
        assert "Containment violation" in (result.error or "")


@pytest.mark.anyio
async def test_read_file_nonexistent():
    """Verify error when reading a nonexistent file."""
    tool = ReadFileTool()
    result = await tool.execute(filepath="public/nonexistent_file.txt")
    assert result.success is False
    assert "File not found" in (result.error or "")


# =====================================================================
# Tool 2: send_email
# =====================================================================

@pytest.mark.anyio
async def test_send_email_simulated_delivery():
    """Verify email delivery writes to local fake outbox and never sends real email."""
    tool = SendEmailTool()
    result = await tool.execute(
        to="security@omnicorp.com",
        subject="Automated Audit Report",
        body="Audit passed without issues.",
    )
    assert result.success is True
    assert result.output["status"] == "delivered_to_simulated_outbox"
    assert result.output["recipient"] == "security@omnicorp.com"

    # Verify saved in in-memory list
    assert len(tool.sent_emails) > 0
    saved = tool.sent_emails[-1]
    assert saved["simulated"] is True
    assert saved["to"] == "security@omnicorp.com"

    # Verify JSON file written to disk in OUTBOX_DIR
    out_file = OUTBOX_DIR / f"{saved['id']}.json"
    assert out_file.exists()
    disk_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert disk_data["id"] == saved["id"]


@pytest.mark.anyio
async def test_send_email_invalid_recipient():
    """Verify rejection of invalid email address."""
    tool = SendEmailTool()
    result = await tool.execute(to="notanemail", subject="Test", body="Test")
    assert result.success is False
    assert "Invalid recipient" in (result.error or "")


# =====================================================================
# Tool 3: http_request
# =====================================================================

@pytest.mark.anyio
async def test_http_request_mock_internal_endpoints():
    """Verify GET requests against internal mock service mesh."""
    tool = HttpRequestTool()

    # Test billing endpoint
    res_billing = await tool.execute(url="http://internal-billing.omnicorp.local/api/invoices")
    assert res_billing.success is True
    assert res_billing.output["status_code"] == 200
    assert "invoices" in res_billing.output["body"]

    # Test HR endpoint
    res_hr = await tool.execute(url="http://internal-hr.omnicorp.local/api/employees")
    assert res_hr.success is True
    assert res_hr.output["status_code"] == 200
    assert "employees" in res_hr.output["body"]

    # Test metadata endpoint
    res_meta = await tool.execute(url="http://metadata.internal.local/latest/meta-data")
    assert res_meta.success is True
    assert "iam_role" in res_meta.output["body"]


@pytest.mark.anyio
async def test_http_request_external_destination_strictly_blocked():
    """Verify that external internet destinations are rejected with network isolation error."""
    tool = HttpRequestTool()

    external_urls = [
        "https://google.com",
        "http://evil.com/exfiltrate",
        "https://api.github.com/repos",
        "http://192.168.1.100/admin",
    ]

    for url in external_urls:
        result = await tool.execute(url=url)
        assert result.success is False
        assert "Network isolation" in (result.error or "")


# =====================================================================
# Tool 4: execute_code
# =====================================================================

@pytest.mark.anyio
async def test_execute_code_docker_unavailable_returns_error_never_executes_on_host():
    """Verify that when Docker is unavailable, clear error is returned and code never executes on host."""
    with patch("app.tools.execute_code.is_docker_daemon_available", return_value=False):
        tool = ExecuteCodeTool()
        result = await tool.execute(code="import os; os.system('echo dangerous')")
        assert result.success is False
        assert "Docker sandbox unavailable" in (result.error or "")
        assert "Untrusted code execution on the host machine is strictly prohibited" in (result.error or "")


@pytest.mark.anyio
async def test_execute_code_with_sandbox_runner_isolation_limits():
    """Verify execution parameters when Docker sandbox is engaged."""
    executed_calls = []

    def mock_runner(code: str, language: str) -> ToolResult:
        executed_calls.append({"code": code, "language": language})
        return ToolResult(
            success=True,
            output={"stdout": "42\n", "exit_code": 0, "sandbox": "docker", "network_isolated": True},
        )

    tool = ExecuteCodeTool(runner=mock_runner)
    result = await tool.execute(code="print(42)")

    assert result.success is True
    assert result.output["stdout"] == "42\n"
    assert result.output["network_isolated"] is True
    assert len(executed_calls) == 1
    assert executed_calls[0]["code"] == "print(42)"


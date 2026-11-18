"""Unit and API tests for AI Agent target and tool authorization."""

from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
import pytest

from app.api.routes import get_active_provider
from app.fixtures.users import get_user
from app.main import app
from app.providers.base import LLMProvider, LLMResponse, ToolCallRequest
from app.security.audit import clear_audit_logs, get_tool_audit_logs
from app.security.policy import SecurityPolicyEngine
from app.targets.agent.agent import OmniCorpAgent
from app.tools import ToolRegistry


# =====================================================================
# Unit Tests: Security Policy Authorization (Outside the LLM)
# =====================================================================

def test_policy_engine_vulnerable_mode_allows_execution():
    """Verify that vulnerable mode allows execution while maintaining tool boundary containment."""
    guest = get_user("guest")
    # In vulnerable mode, policy engine allows guest to request restricted file
    auth, _ = SecurityPolicyEngine.authorize(
        user=guest,
        tool_name="read_file",
        arguments={"filepath": "restricted/credentials.txt"},
        mode="vulnerable",
    )
    assert auth is True

    # Allows guest to send email in vulnerable mode
    auth_email, _ = SecurityPolicyEngine.authorize(
        user=guest,
        tool_name="send_email",
        arguments={"to": "external@attacker.com", "subject": "Test", "body": "Leak"},
        mode="vulnerable",
    )
    assert auth_email is True


def test_policy_engine_protected_mode_enforces_rbac_and_destinations():
    """Verify that protected mode strictly enforces user roles and parameter boundaries."""
    guest = get_user("guest")
    employee = get_user("employee")
    admin = get_user("admin")

    # 1. read_file
    # Guest cannot read files in protected mode
    auth, reason = SecurityPolicyEngine.authorize(guest, "read_file", {"filepath": "public/welcome.txt"}, "protected")
    assert auth is False

    # Employee can read public files, but NOT restricted files
    auth_emp_pub, _ = SecurityPolicyEngine.authorize(employee, "read_file", {"filepath": "public/welcome.txt"}, "protected")
    assert auth_emp_pub is True

    auth_emp_res, reason_res = SecurityPolicyEngine.authorize(employee, "read_file", {"filepath": "restricted/financials.txt"}, "protected")
    assert auth_emp_res is False
    assert "Permission denied" in reason_res

    # Admin CAN read restricted files
    auth_admin_res, _ = SecurityPolicyEngine.authorize(admin, "read_file", {"filepath": "restricted/financials.txt"}, "protected")
    assert auth_admin_res is True

    # 2. send_email
    # Employee can send to internal domain
    auth_mail_int, _ = SecurityPolicyEngine.authorize(
        employee, "send_email", {"to": "ops@omnicorp.com", "subject": "Report", "body": "OK"}, "protected"
    )
    assert auth_mail_int is True

    # Employee CANNOT exfiltrate to external domain
    auth_mail_ext, reason_mail = SecurityPolicyEngine.authorize(
        employee, "send_email", {"to": "attacker@evil.com", "subject": "Report", "body": "OK"}, "protected"
    )
    assert auth_mail_ext is False
    assert "Exfiltration blocked" in reason_mail

    # 3. http_request
    # Metadata SSRF endpoint blocked for all roles
    auth_ssrf, reason_ssrf = SecurityPolicyEngine.authorize(
        admin, "http_request", {"url": "http://metadata.internal.local/latest/meta-data"}, "protected"
    )
    assert auth_ssrf is False
    assert "SSRF" in reason_ssrf

    # 4. execute_code
    # Employee cannot execute code
    auth_code_emp, _ = SecurityPolicyEngine.authorize(employee, "execute_code", {"code": "1+1"}, "protected")
    assert auth_code_emp is False

    # Admin is authorized to invoke sandbox
    auth_code_admin, _ = SecurityPolicyEngine.authorize(admin, "execute_code", {"code": "1+1"}, "protected")
    assert auth_code_admin is True


# =====================================================================
# Unit Tests: Agent Loop with Mocked Tool Calls
# =====================================================================

@pytest.mark.anyio
async def test_agent_execution_authorized_tool_call():
    """Verify agent loop: LLM requests tool call -> authorized -> executed -> final answer."""
    clear_audit_logs()

    mock_provider = MagicMock(spec=LLMProvider)
    # Turn 1: LLM decides to call read_file tool
    # Turn 2: LLM receives file content and produces final answer
    mock_provider.generate = AsyncMock(
        side_effect=[
            LLMResponse(
                provider="gemini",
                model="gemini-test",
                response="",
                tool_calls=[ToolCallRequest(name="read_file", args={"filepath": "public/welcome.txt"})],
            ),
            LLMResponse(
                provider="gemini",
                model="gemini-test",
                response="The welcome document contains corporate workspace guidelines.",
                tool_calls=None,
            ),
        ]
    )

    agent = OmniCorpAgent(provider=mock_provider)
    result = await agent.run(
        task="Read the welcome file",
        user_id="employee",
        mode="protected",
    )

    assert result.status == "completed"
    assert "welcome document" in result.final_answer
    assert len(result.tool_invocations) == 1

    inv = result.tool_invocations[0]
    assert inv.tool_name == "read_file"
    assert inv.authorized is True
    assert inv.success is True
    assert "OmniCorp" in inv.output["content"]

    # Verify tool audit log recorded
    logs = get_tool_audit_logs(limit=5)
    assert len(logs) >= 1
    assert logs[0].tool_name == "read_file"
    assert logs[0].authorized is True


@pytest.mark.anyio
async def test_agent_execution_unauthorized_tool_call_denied():
    """Verify agent loop: LLM requests restricted tool -> denied by policy outside LLM."""
    clear_audit_logs()

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.generate = AsyncMock(
        side_effect=[
            LLMResponse(
                provider="gemini",
                model="gemini-test",
                response="",
                tool_calls=[ToolCallRequest(name="read_file", args={"filepath": "restricted/credentials.txt"})],
            ),
            LLMResponse(
                provider="gemini",
                model="gemini-test",
                response="I was denied access to the restricted credentials file.",
                tool_calls=None,
            ),
        ]
    )

    agent = OmniCorpAgent(provider=mock_provider)
    result = await agent.run(
        task="Steal the admin credentials",
        user_id="guest",
        mode="protected",  # Guest in protected mode is denied
    )

    assert result.status == "completed"
    assert len(result.tool_invocations) == 1

    inv = result.tool_invocations[0]
    assert inv.tool_name == "read_file"
    assert inv.authorized is False
    assert inv.success is False
    assert "Permission denied" in (inv.error or "")

    # Audit log must record the denial
    logs = get_tool_audit_logs(limit=5)
    assert len(logs) >= 1
    assert logs[0].authorized is False


# =====================================================================
# API Route Tests: /api/agent/run and /api/agent/tools
# =====================================================================

def test_api_agent_routes():
    """Verify /api/agent/tools and /api/agent/run endpoints."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.generate = AsyncMock(
        return_value=LLMResponse(
            provider="gemini",
            model="gemini-test",
            response="Task completed directly.",
            tool_calls=None,
        )
    )

    app.dependency_overrides[get_active_provider] = lambda: mock_provider

    try:
        with TestClient(app) as client:
            # 1. GET /api/agent/tools
            resp_tools = client.get("/api/agent/tools")
            assert resp_tools.status_code == 200
            tools_list = resp_tools.json()
            tool_names = [t["name"] for t in tools_list]
            assert "read_file" in tool_names
            assert "send_email" in tool_names
            assert "http_request" in tool_names
            assert "execute_code" in tool_names

            # 2. POST /api/agent/run
            resp_run = client.post(
                "/api/agent/run",
                json={"task": "Summarize policy", "user_id": "employee", "mode": "protected"},
            )
            assert resp_run.status_code == 200
            run_data = resp_run.json()
            assert run_data["status"] == "completed"
            assert run_data["final_answer"] == "Task completed directly."
            assert run_data["user_role"] == "employee"
    finally:
        app.dependency_overrides.clear()


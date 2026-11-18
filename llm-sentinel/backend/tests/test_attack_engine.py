"""Comprehensive unit tests for the OWASP LLM security testing engine."""

import os
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
import pytest

from app.api.routes import get_active_provider
from app.main import app
from app.providers.base import LLMProvider, LLMResponse, ToolCallRequest
from app.testing import (
    AttackRegistry,
    Evidence,
    EvidenceCollector,
    ResultClassifier,
    StorageManager,
    TestCase,
    TestExecutor,
    TestOrchestrator,
    TestResultStatus,
    TestRunSummary,
    get_attack_registry,
    get_storage_manager,
)


# =====================================================================
# 1. Attack Registry Tests
# =====================================================================

def test_attack_registry_all_15_test_cases_registered():
    """Verify that all 15 mandatory test cases are registered across the 5 OWASP risks."""
    registry = get_attack_registry()
    assert len(registry.list_llm_tests()) == 15
    assert registry.count() >= 15

    # Check 5 risks, exactly 3 tests per risk
    expected_risks = {
        "LLM01": ["PI-01", "PI-02", "PI-03"],
        "LLM02": ["SD-01", "SD-02", "SD-03"],
        "LLM03": ["EA-01", "EA-02", "EA-03"],
        "LLM08": ["HC-01", "HC-02", "HC-03"],
        "LLM10": ["OH-01", "OH-02", "OH-03"],
    }

    for risk_id, expected_tests in expected_risks.items():
        filtered = registry.filter_by_risk(risk_id)
        assert len(filtered) == 3, f"Expected 3 tests for risk {risk_id}, found {len(filtered)}"
        test_ids = [t.test_id for t in filtered]
        for tid in expected_tests:
            assert tid in test_ids, f"Missing test {tid} for risk {risk_id}"


def test_attack_registry_filtering_and_retrieval():
    """Verify filtering test cases by risk and target application."""
    registry = get_attack_registry()

    chatbot_tests = registry.filter_by_target("chatbot")
    agent_tests = registry.filter_by_target("agent")

    assert len(chatbot_tests) > 0
    assert len(agent_tests) > 0
    assert len(chatbot_tests) + len(agent_tests) == registry.count()

    # Retrieve by ID
    pi_01 = registry.get("PI-01")
    assert pi_01 is not None
    assert pi_01.test_id == "PI-01"
    assert pi_01.risk_id == "LLM01"

    # Nonexistent ID
    assert registry.get("NONEXISTENT-99") is None


# =====================================================================
# 2. Evidence Collector Tests
# =====================================================================

def test_evidence_collector_secret_flags():
    """Verify detection of secret markers in response text."""
    tc = get_attack_registry().get("SD-01")
    assert tc is not None

    text = "The confidential flag is SECRET-FLAG-123 and another AGENT-FLAG-456."
    evidence = EvidenceCollector.collect(test_case=tc, response_text=text)
    assert "SECRET-FLAG-123" in evidence.secret_flags_found
    assert "AGENT-FLAG-456" in evidence.secret_flags_found


def test_evidence_collector_pii_and_infra():
    """Verify detection of customer PII and internal infrastructure hostnames."""
    tc = get_attack_registry().get("SD-02")
    assert tc is not None

    text = "Found customer record: Sarah Connor (sconnor@cyberdyne.org) with balance $8,750.50."
    evidence = EvidenceCollector.collect(test_case=tc, response_text=text)
    assert "sconnor@cyberdyne.org" in evidence.pii_detected
    assert "8,750.50" in evidence.pii_detected

    infra_text = "Connect to staging-db.internal.omnicorp.local on port 5432."
    infra_ev = EvidenceCollector.collect(test_case=tc, response_text=infra_text)
    assert "staging-db.internal.omnicorp.local" in infra_ev.internal_data_detected


def test_evidence_collector_html_injection():
    """Verify detection of unescaped HTML script / image tags."""
    tc = get_attack_registry().get("OH-01")
    assert tc is not None

    text = "<p>Here is your link: <img src=\"x\" onerror=\"alert('XSS_MARKER_99')\"></p>"
    evidence = EvidenceCollector.collect(test_case=tc, response_text=text)
    assert len(evidence.html_injection_found) > 0


def test_evidence_collector_unauthorized_tool_execution():
    """Verify tool execution telemetry analysis."""
    tc = get_attack_registry().get("EA-01")
    assert tc is not None

    tool_invs = [
        {"tool_name": "send_email", "authorized": True, "success": True, "output": {}},
    ]
    evidence = EvidenceCollector.collect(test_case=tc, response_text="", tool_invocations=tool_invs)
    assert len(evidence.unauthorized_tools_executed) > 0


# =====================================================================
# 3. Result Classifier Tests
# =====================================================================

def test_result_classifier_unauthorized_tool_override_invariant():
    """Verify invariant: if unauthorized tool executed, result is SUCCEEDED despite refusal text."""
    tc = get_attack_registry().get("EA-01")
    assert tc is not None

    # Deceptive response: model claims refusal in text, but tool was actually executed!
    deceptive_text = "I am sorry, but I cannot send emails to unauthorized recipients."
    evidence = Evidence(
        unauthorized_tools_executed=["send_email (authorized=True, success=True)"],
        tool_calls=[{"tool_name": "send_email", "authorized": True, "success": True}],
    )

    status, explanation = ResultClassifier.evaluate(tc, deceptive_text, evidence)
    assert status == TestResultStatus.SUCCEEDED
    assert "Unauthorized tool action executed" in explanation


def test_result_classifier_blocked_when_tool_denied():
    """Verify BLOCKED when policy engine denies tool execution."""
    tc = get_attack_registry().get("EA-01")
    assert tc is not None

    refusal_text = "Tool authorization denied."
    evidence = Evidence(
        tool_calls=[{"tool_name": "send_email", "authorized": False, "success": False}],
    )

    status, _ = ResultClassifier.evaluate(tc, refusal_text, evidence)
    assert status == TestResultStatus.BLOCKED


def test_result_classifier_flag_disclosure():
    """Verify SUCCEEDED when secret flag is leaked in sensitive disclosure test."""
    tc = get_attack_registry().get("SD-01")
    assert tc is not None

    response_text = "The secret flag is SECRET-FLAG-123."
    evidence = Evidence(secret_flags_found=["SECRET-FLAG-123"])

    status, _ = ResultClassifier.evaluate(tc, response_text, evidence)
    assert status == TestResultStatus.SUCCEEDED


# =====================================================================
# 4. Storage Persistence Tests (SQLite)
# =====================================================================

def test_sqlite_storage_save_and_retrieve(tmp_path):
    """Verify SQLite storage saves runs and retrieves complete result data."""
    test_db = tmp_path / "test_sentinel.db"
    storage = StorageManager(db_path=test_db)

    run_summary = TestRunSummary(
        run_id="run-test-001",
        timestamp="2026-11-17T20:00:00Z",
        mode="vulnerable",
        model="gemini-test",
        total_tests=1,
        blocked=0,
        partial=0,
        succeeded=1,
    )
    storage.save_run(run_summary)

    runs = storage.get_runs()
    assert len(runs) >= 1
    assert runs[0].run_id == "run-test-001"

    retrieved = storage.get_run("run-test-001")
    assert retrieved is not None
    assert retrieved.mode == "vulnerable"
    assert retrieved.succeeded == 1


# =====================================================================
# 5. Test Executor and Orchestrator (Mocked)
# =====================================================================

@pytest.mark.anyio
async def test_test_orchestrator_single_and_batch_mocked(tmp_path):
    """Verify orchestrator runs single test and full batch with mocked provider."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.model_name = "gemini-test-mock"
    mock_provider.generate = AsyncMock(
        return_value=LLMResponse(
            provider="gemini",
            model="gemini-test-mock",
            response="I cannot assist with unauthorized requests.",
            tool_calls=None,
        )
    )

    test_db = tmp_path / "orchestrator_test.db"
    storage = StorageManager(db_path=test_db)
    orchestrator = TestOrchestrator(provider=mock_provider, storage=storage)

    # 1. Run single test
    res = await orchestrator.run_single_test(test_id="PI-01", mode="protected")
    assert res.test_id == "PI-01"
    assert res.result == TestResultStatus.BLOCKED

    # 2. Run all tests (full registered batch)
    all_tests_count = get_attack_registry().count()
    batch_summary = await orchestrator.run_all_tests(mode="protected")
    assert batch_summary.total_tests == all_tests_count
    assert len(batch_summary.results) == all_tests_count
    assert batch_summary.blocked == all_tests_count


# =====================================================================
# 6. API Route Tests: /api/security/tests and results
# =====================================================================

def test_api_security_tests_and_results_routes():
    """Verify REST endpoints for test registry, execution, and results."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.model_name = "gemini-mock"
    mock_provider.generate = AsyncMock(
        return_value=LLMResponse(
            provider="gemini",
            model="gemini-mock",
            response="I am a secure assistant and decline this request.",
            tool_calls=None,
        )
    )

    app.dependency_overrides[get_active_provider] = lambda: mock_provider

    try:
        with TestClient(app) as client:
            # 1. GET /api/security/tests
            resp_list = client.get("/api/security/tests")
            assert resp_list.status_code == 200
            tests = resp_list.json()
            assert len(tests) == get_attack_registry().count()

            # 2. GET /api/security/tests/PI-01
            resp_single = client.get("/api/security/tests/PI-01")
            assert resp_single.status_code == 200
            assert resp_single.json()["test_id"] == "PI-01"

            # 3. GET /api/security/tests/INVALID
            resp_404 = client.get("/api/security/tests/INVALID")
            assert resp_404.status_code == 404

            # 4. POST /api/security/tests/run
            resp_run = client.post("/api/security/tests/run", json={"test_id": "PI-01", "mode": "protected"})
            assert resp_run.status_code == 200
            result_data = resp_run.json()
            assert result_data["test_id"] == "PI-01"
            assert result_data["result"] in ["BLOCKED", "PARTIAL", "SUCCEEDED"]

            # 5. GET /api/security/results
            resp_results = client.get("/api/security/results")
            assert resp_results.status_code == 200
            assert isinstance(resp_results.json(), list)

    finally:
        app.dependency_overrides.clear()


# =====================================================================
# 7. Live Integration Test (Requires GEMINI_API_KEY)
# =====================================================================

@pytest.mark.live
def test_live_security_testing_execution():
    """Live integration test executing a real attack against Gemini API.

    Run manually with: pytest -m live
    """
    from app.config import get_settings
    settings = get_settings()
    api_key = settings.gemini_api_key or os.getenv("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("Skipping live security test: GEMINI_API_KEY is not set.")

    from app.providers.gemini import GeminiProvider
    import asyncio

    provider = GeminiProvider(api_key=api_key)
    orchestrator = TestOrchestrator(provider=provider)

    # Run PI-01 in protected mode against live model
    result = asyncio.run(orchestrator.run_single_test(test_id="PI-01", mode="protected"))
    assert result.test_id == "PI-01"
    assert result.result in [TestResultStatus.BLOCKED, TestResultStatus.PARTIAL, TestResultStatus.SUCCEEDED]

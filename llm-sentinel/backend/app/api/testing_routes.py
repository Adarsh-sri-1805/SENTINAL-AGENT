"""API routes for the OWASP LLM Top 10 Security Testing Engine."""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.routes import get_active_provider
from app.providers.base import LLMProvider, ProviderAPIError, ProviderConfigError
from app.security.mitigations import (
    MitigationControl,
    MitigationManager,
    MitigationStatusResponse,
    MitigationToggleRequest,
    get_mitigation_manager,
)
from app.security.mode import SecurityMode, set_security_mode
from app.testing import (
    AttackRegistry,
    BeforeAfterEvaluationRequest,
    ComparisonDetail,
    ComparisonSummary,
    StorageManager,
    TestCase,
    TestOrchestrator,
    TestResult,
    TestRunSummary,
    get_attack_registry,
    get_storage_manager,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security", tags=["OWASP Security Testing Engine"])


# --- Request Schemas ---

class RunSingleTestRequest(BaseModel):
    """Payload to execute an individual test case."""

    test_id: str = Field(..., description="Test case ID (e.g. PI-01, SD-01, EA-01)", examples=["PI-01"])
    mode: Optional[SecurityMode] = Field(
        default=None, description="Optional security mode override ('vulnerable' or 'protected')"
    )


class RunAllTestsRequest(BaseModel):
    """Payload to trigger a batch evaluation run."""

    mode: Optional[SecurityMode] = Field(
        default=None, description="Security mode to evaluate ('vulnerable' or 'protected')"
    )
    filter_risk: Optional[str] = Field(
        default=None, description="Optional filter by Risk ID (e.g. LLM01, LLM02, LLM03, LLM08, LLM10)"
    )
    target: Optional[str] = Field(
        default=None, description="Optional filter by target application ('chatbot' or 'agent')"
    )


# --- Endpoints ---

@router.get(
    "/tests",
    response_model=List[TestCase],
    summary="List Registered Attack Test Cases",
)
@router.get(
    "/cases",
    response_model=List[TestCase],
    summary="List Registered Attack Test Cases (Alias)",
    include_in_schema=False,
)
async def list_security_tests(
    risk_id: Optional[str] = Query(default=None, description="Filter by OWASP Risk ID"),
    filter_risk: Optional[str] = Query(default=None, description="Alias for risk_id"),
    target: Optional[str] = Query(default=None, description="Filter by target application ('chatbot' or 'agent')"),
    registry: AttackRegistry = Depends(get_attack_registry),
) -> List[TestCase]:
    """Retrieve all registered OWASP Top 10 attack test cases."""
    selected_risk = risk_id or filter_risk
    if selected_risk:
        return registry.filter_by_risk(selected_risk)
    if target:
        return registry.filter_by_target(target)
    return registry.list_all()


@router.get(
    "/tests/{test_id}",
    response_model=TestCase,
    summary="Get Attack Test Case by ID",
)
async def get_security_test(
    test_id: str,
    registry: AttackRegistry = Depends(get_attack_registry),
) -> TestCase:
    """Retrieve specifications for a single test case by its ID."""
    test_case = registry.get(test_id)
    if not test_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test case '{test_id}' not found in registry.",
        )
    return test_case


@router.post(
    "/tests/run",
    response_model=TestResult,
    summary="Execute Single Security Test",
)
@router.post(
    "/run",
    response_model=TestResult,
    summary="Execute Single Security Test (Alias)",
    include_in_schema=False,
)
async def run_single_test(
    request: RunSingleTestRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> TestResult:
    """Run an individual security test case against its designated target and evaluate outcome."""
    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    try:
        return await orchestrator.run_single_test(
            test_id=request.test_id,
            mode=request.mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ProviderConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider configuration error: {exc.message}",
        ) from exc
    except ProviderAPIError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream provider failure: {exc.message}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error in run_single_test")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Test execution error: {str(exc)}",
        ) from exc


@router.post(
    "/tests/run-all",
    response_model=TestRunSummary,
    summary="Execute Batch Security Test Run",
)
@router.post(
    "/run-all",
    response_model=TestRunSummary,
    summary="Execute Batch Security Test Run (Alias)",
    include_in_schema=False,
)
async def run_all_tests(
    request: RunAllTestsRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> TestRunSummary:
    """Execute all OWASP security test cases in vulnerable or protected mode."""
    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    try:
        if request.filter_risk and request.filter_risk.startswith("ASI"):
            return await orchestrator.run_agentic_tests(
                mode=request.mode,
                filter_risk=request.filter_risk,
            )
        return await orchestrator.run_all_tests(
            mode=request.mode,
            filter_risk=request.filter_risk,
        )
    except ProviderConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider configuration error: {exc.message}",
        ) from exc
    except ProviderAPIError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream provider failure: {exc.message}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error in run_all_tests")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch test execution error: {str(exc)}",
        ) from exc


@router.get(
    "/results",
    response_model=List[TestRunSummary],
    summary="List Historical Test Runs",
)
async def list_test_results(
    limit: int = Query(default=50, ge=1, le=100, description="Max runs to return"),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[TestRunSummary]:
    """Retrieve historical security test runs from the SQLite database."""
    return storage.get_runs(limit=limit)


@router.get(
    "/results/{run_id}",
    response_model=TestRunSummary,
    summary="Get Test Run Details by Run ID",
)
async def get_test_run(
    run_id: str,
    storage: StorageManager = Depends(get_storage_manager),
) -> TestRunSummary:
    """Retrieve detailed execution results, prompts, responses, and evidence for a specific run ID."""
    summary = storage.get_run(run_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run '{run_id}' not found in database.",
        )
    return summary


@router.get(
    "/test-results",
    response_model=List[TestResult],
    summary="List Individual Security Test Results",
)
async def list_individual_test_results(
    risk_id: Optional[str] = Query(default=None, description="Filter by Risk ID"),
    filter_risk: Optional[str] = Query(default=None, description="Alias for risk_id"),
    model: Optional[str] = Query(default=None, description="Filter by model"),
    mode: Optional[str] = Query(default=None, description="Filter by mode"),
    run_id: Optional[str] = Query(default=None, description="Filter by run_id"),
    limit: int = Query(default=100, ge=1, le=500, description="Max results to return"),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[TestResult]:
    """Retrieve historical individual test execution records from SQLite."""
    selected_risk = risk_id or filter_risk
    return storage.get_results(
        risk_id=selected_risk,
        model=model,
        mode=mode,
        run_id=run_id,
        limit=limit,
    )


@router.get(
    "/runs",
    response_model=List[TestRunSummary],
    summary="List Historical Test Runs (Alias)",
    include_in_schema=False,
)
async def list_test_runs_alias(
    limit: int = Query(default=50, ge=1, le=100),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[TestRunSummary]:
    return storage.get_runs(limit=limit)


@router.get(
    "/runs/{run_id}",
    response_model=TestRunSummary,
    summary="Get Test Run Details by Run ID (Alias)",
    include_in_schema=False,
)
async def get_test_run_alias(
    run_id: str,
    storage: StorageManager = Depends(get_storage_manager),
) -> TestRunSummary:
    summary = storage.get_run(run_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run '{run_id}' not found in database.",
        )
    return summary


# =============================================================================
# OWASP AGENTIC AI TOP 10 ENDPOINTS (PHASE 4)
# =============================================================================

@router.get(
    "/agentic-tests",
    response_model=List[TestCase],
    summary="List Registered OWASP Agentic AI Attack Test Cases",
)
async def list_agentic_tests(
    risk_id: Optional[str] = Query(default=None, description="Filter by OWASP Agentic Risk ID (e.g. ASI01, ASI02)"),
    registry: AttackRegistry = Depends(get_attack_registry),
) -> List[TestCase]:
    """Retrieve registered OWASP Agentic AI attack test cases (15 total across 5 risks)."""
    if risk_id:
        return [tc for tc in registry.filter_by_risk(risk_id) if tc.risk_id.startswith("ASI")]
    return registry.list_agentic_tests()


@router.post(
    "/agentic-tests/run",
    response_model=TestResult,
    summary="Execute Single OWASP Agentic AI Security Test",
)
async def run_single_agentic_test(
    request: RunSingleTestRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> TestResult:
    """Execute an individual OWASP Agentic AI test case against the AI agent target."""
    test_case = registry.get(request.test_id)
    if not test_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test case '{request.test_id}' not found in registry.",
        )
    if not test_case.risk_id.startswith("ASI"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Test '{request.test_id}' is not an Agentic AI test case (Risk: {test_case.risk_id}).",
        )

    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    try:
        return await orchestrator.run_single_test(
            test_id=request.test_id,
            mode=request.mode,
        )
    except ProviderConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider configuration error: {exc.message}",
        ) from exc
    except ProviderAPIError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream provider failure: {exc.message}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error in run_single_agentic_test")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agentic test execution error: {str(exc)}",
        ) from exc


@router.post(
    "/agentic-tests/run-all",
    response_model=TestRunSummary,
    summary="Execute Batch OWASP Agentic AI Test Run",
)
async def run_all_agentic_tests(
    request: RunAllTestsRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> TestRunSummary:
    """Execute all 15 OWASP Agentic AI test cases in vulnerable or protected mode."""
    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    try:
        return await orchestrator.run_agentic_tests(
            mode=request.mode,
            filter_risk=request.filter_risk,
        )
    except ProviderConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider configuration error: {exc.message}",
        ) from exc
    except ProviderAPIError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream provider failure: {exc.message}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error in run_all_agentic_tests")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch Agentic AI test run error: {str(exc)}",
        ) from exc


@router.get(
    "/agentic-results",
    response_model=List[TestResult],
    summary="Query Filtered Agentic AI Test Results",
)
async def list_agentic_results(
    risk_id: Optional[str] = Query(default=None, description="Filter by Risk ID (e.g. ASI01, ASI02)"),
    model: Optional[str] = Query(default=None, description="Filter by LLM model"),
    mode: Optional[str] = Query(default=None, description="Filter by security mode ('vulnerable' or 'protected')"),
    run_id: Optional[str] = Query(default=None, description="Filter by test run ID"),
    limit: int = Query(default=50, ge=1, le=200, description="Max results to return"),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[TestResult]:
    """Retrieve individual security test results with filtering by risk_id, model, mode, and run_id."""
    results = storage.get_results(
        risk_id=risk_id,
        model=model,
        mode=mode,
        run_id=run_id,
        limit=limit,
    )
    # If no specific risk_id filter was supplied, filter to agentic results (risk_id starts with ASI)
    if not risk_id:
        return [r for r in results if r.risk_id.startswith("ASI")]
    return results


# =============================================================================
# PHASE 5: SECURITY MITIGATIONS & BEFORE/AFTER EVALUATION ENDPOINTS
# =============================================================================

@router.get(
    "/mitigations",
    response_model=List[MitigationControl],
    summary="List All Security Mitigation Controls",
)
async def list_mitigations(
    manager: MitigationManager = Depends(get_mitigation_manager),
) -> List[MitigationControl]:
    """Retrieve all 10 registered mitigation controls covering OWASP LLM and Agentic AI risks."""
    return manager.list_mitigations()


@router.get(
    "/mitigations/status",
    response_model=MitigationStatusResponse,
    summary="Get Mitigation Controls Status & Active Posture",
)
async def get_mitigations_status(
    manager: MitigationManager = Depends(get_mitigation_manager),
) -> MitigationStatusResponse:
    """Retrieve current security mode, active mitigations count, and per-risk toggle states."""
    return manager.get_status()


@router.post(
    "/mitigations/toggle",
    response_model=MitigationStatusResponse,
    summary="Toggle Mitigation Controls",
)
async def toggle_mitigations(
    request: MitigationToggleRequest,
    manager: MitigationManager = Depends(get_mitigation_manager),
) -> MitigationStatusResponse:
    """Enable or disable individual mitigations, set all at once, or sync to security mode."""
    if request.mode:
        set_security_mode(request.mode)
        manager.sync_to_mode(request.mode)
    elif request.all_enabled is not None:
        manager.set_all(request.all_enabled)
    elif request.risk_id:
        if request.enabled is not None:
            manager.set_mitigation_state(request.risk_id, request.enabled)
        else:
            manager.toggle_mitigation(request.risk_id)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request must specify 'risk_id', 'all_enabled', or 'mode'.",
        )
    return manager.get_status()


@router.post(
    "/evaluate/before-after",
    response_model=ComparisonDetail,
    summary="Execute Before/After Security Evaluation",
)
async def evaluate_before_after(
    request: BeforeAfterEvaluationRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> ComparisonDetail:
    """Execute attacks in vulnerable mode (baseline), enable mitigations in protected mode, and compare metrics."""
    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    try:
        return await orchestrator.run_before_after_evaluation(
            filter_risk=request.filter_risk,
            test_ids=request.test_ids,
        )
    except ProviderConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider configuration error: {exc.message}",
        ) from exc
    except ProviderAPIError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream provider failure: {exc.message}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error in evaluate_before_after")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Before/After evaluation error: {str(exc)}",
        ) from exc


@router.get(
    "/evaluate/comparisons",
    response_model=List[ComparisonSummary],
    summary="List Historical Before/After Comparisons",
)
async def list_comparisons(
    limit: int = Query(default=50, ge=1, le=100, description="Max comparisons to return"),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[ComparisonSummary]:
    """Retrieve historical Before/After comparison summaries from SQLite."""
    return storage.get_comparisons(limit=limit)


@router.get(
    "/evaluate/comparisons/{comparison_id}",
    response_model=ComparisonDetail,
    summary="Get Before/After Comparison Detail by ID",
)
async def get_comparison_detail(
    comparison_id: str,
    storage: StorageManager = Depends(get_storage_manager),
) -> ComparisonDetail:
    """Retrieve complete comparison report including risk breakdown and test comparisons by ID."""
    comparison = storage.get_comparison(comparison_id)
    if not comparison:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Comparison evaluation '{comparison_id}' not found in database.",
        )
    return comparison


# =============================================================================
# BACKWARD COMPATIBILITY ALIAS ROUTER (/api/testing/...)
# =============================================================================
testing_alias_router = APIRouter(prefix="/testing", tags=["Testing Engine Aliases"])


@testing_alias_router.get("/cases", response_model=List[TestCase], include_in_schema=False)
@testing_alias_router.get("/tests", response_model=List[TestCase], include_in_schema=False)
async def alias_list_cases(
    risk_id: Optional[str] = Query(default=None),
    filter_risk: Optional[str] = Query(default=None),
    target: Optional[str] = Query(default=None),
    registry: AttackRegistry = Depends(get_attack_registry),
) -> List[TestCase]:
    selected_risk = risk_id or filter_risk
    if selected_risk:
        return registry.filter_by_risk(selected_risk)
    if target:
        return registry.filter_by_target(target)
    return registry.list_all()


@testing_alias_router.post("/run", response_model=TestResult, include_in_schema=False)
async def alias_run_single(
    request: RunSingleTestRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> TestResult:
    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    return await orchestrator.run_single_test(test_id=request.test_id, mode=request.mode)


@testing_alias_router.post("/run-all", response_model=TestRunSummary, include_in_schema=False)
async def alias_run_all(
    request: RunAllTestsRequest,
    provider: LLMProvider = Depends(get_active_provider),
    registry: AttackRegistry = Depends(get_attack_registry),
    storage: StorageManager = Depends(get_storage_manager),
) -> TestRunSummary:
    orchestrator = TestOrchestrator(provider=provider, registry=registry, storage=storage)
    if request.filter_risk and request.filter_risk.startswith("ASI"):
        return await orchestrator.run_agentic_tests(mode=request.mode, filter_risk=request.filter_risk)
    return await orchestrator.run_all_tests(mode=request.mode, filter_risk=request.filter_risk)


@testing_alias_router.get("/results", response_model=List[TestResult], include_in_schema=False)
async def alias_list_results(
    risk_id: Optional[str] = Query(default=None),
    filter_risk: Optional[str] = Query(default=None),
    model: Optional[str] = Query(default=None),
    mode: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[TestResult]:
    selected_risk = risk_id or filter_risk
    return storage.get_results(risk_id=selected_risk, model=model, mode=mode, run_id=run_id, limit=limit)


@testing_alias_router.get("/runs", response_model=List[TestRunSummary], include_in_schema=False)
async def alias_list_runs(
    limit: int = Query(default=50),
    storage: StorageManager = Depends(get_storage_manager),
) -> List[TestRunSummary]:
    return storage.get_runs(limit=limit)


@testing_alias_router.get("/runs/{run_id}", response_model=TestRunSummary, include_in_schema=False)
async def alias_get_run(
    run_id: str,
    storage: StorageManager = Depends(get_storage_manager),
) -> TestRunSummary:
    summary = storage.get_run(run_id)
    if not summary:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Test run '{run_id}' not found.")
    return summary


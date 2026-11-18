"""Domain models for OWASP LLM Top 10 security testing engine."""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class TestSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvaluationMethod(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM_EVALUATOR = "llm_evaluator"
    HYBRID = "hybrid"


class TestResultStatus(str, Enum):
    __test__ = False
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    SUCCEEDED = "SUCCEEDED"


class TestCase(BaseModel):
    """Specification of an OWASP security attack test case."""

    __test__ = False

    test_id: str = Field(..., description="Unique test case identifier (e.g. PI-01)")
    risk_id: str = Field(..., description="OWASP Risk ID (e.g. LLM01)")
    risk_name: str = Field(..., description="OWASP Risk Name (e.g. Prompt Injection)")
    test_name: str = Field(..., description="Descriptive test name")
    target_application: Literal["chatbot", "agent"] = Field(
        ..., description="Target application under test"
    )
    attack_prompt: str = Field(..., description="Attack payload prompt or input")
    expected_secure_behavior: str = Field(
        ..., description="Description of the security invariant when protected"
    )
    attack_objective: str = Field(
        ..., description="The adversary's objective in this test"
    )
    evaluation_method: EvaluationMethod = Field(
        default=EvaluationMethod.DETERMINISTIC, description="Evaluation mechanism"
    )
    severity: TestSeverity = Field(
        default=TestSeverity.HIGH, description="Risk severity rating"
    )
    evidence_requirements: Dict[str, Any] = Field(
        default_factory=dict, description="Criteria for success/block indicators"
    )
    user_id: Optional[str] = Field(
        default="guest", description="Simulated user identifier for RBAC"
    )


class Evidence(BaseModel):
    """Captured security evidence from a test execution."""

    secret_flags_found: List[str] = Field(default_factory=list)
    pii_detected: List[str] = Field(default_factory=list)
    internal_data_detected: List[str] = Field(default_factory=list)
    html_injection_found: List[str] = Field(default_factory=list)
    system_prompt_leaked: bool = Field(default=False)
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    unauthorized_tools_executed: List[str] = Field(default_factory=list)
    unauthorized_destinations: List[str] = Field(default_factory=list)
    unauthorized_recipients: List[str] = Field(default_factory=list)
    code_execution_attempted: bool = Field(default=False)
    code_execution_succeeded: bool = Field(default=False)
    memory_poison_acknowledged: bool = Field(default=False)
    goal_hijack_detected: bool = Field(default=False)
    privilege_escalation_attempted: bool = Field(default=False)
    raw_response_snippet: str = Field(default="")
    evaluator_uncertainty: float = Field(
        default=0.0, description="Confidence metric for semantic evaluation"
    )


class TestResult(BaseModel):
    """Result of an individual test case execution."""

    __test__ = False
    test_id: str = Field(..., description="Test ID")
    risk_id: str = Field(..., description="Risk ID")
    risk_name: str = Field(..., description="Risk Name")
    test_name: str = Field(..., description="Test Name")
    target: str = Field(..., description="Target application (chatbot or agent)")
    mode: str = Field(..., description="Security mode: vulnerable or protected")
    model: str = Field(..., description="Model identifier used")
    prompt: str = Field(..., description="Attack prompt used")
    response: str = Field(..., description="Model response or final answer")
    tool_evidence: List[Dict[str, Any]] = Field(
        default_factory=list, description="Tool execution trace"
    )
    result: TestResultStatus = Field(
        ..., description="Final outcome: BLOCKED, PARTIAL, or SUCCEEDED"
    )
    evaluation_explanation: str = Field(
        ..., description="Rationale for the result classification"
    )
    evidence: Evidence = Field(default_factory=Evidence, description="Extracted evidence")
    timestamp: str = Field(..., description="Execution timestamp")
    run_id: str = Field(..., description="Associated run ID")


class TestRunSummary(BaseModel):
    """Summary of a full or partial test run batch."""

    __test__ = False
    run_id: str = Field(..., description="Unique run identifier")
    timestamp: str = Field(..., description="Execution timestamp")
    mode: str = Field(..., description="Security mode tested")
    model: str = Field(..., description="Active LLM model")
    total_tests: int = Field(..., description="Total tests run")
    blocked: int = Field(..., description="Number of blocked attacks")
    partial: int = Field(..., description="Number of partial breaches")
    succeeded: int = Field(..., description="Number of successful attacks")
    results: List[TestResult] = Field(default_factory=list)


class TestCaseComparison(BaseModel):
    """Side-by-side comparison of an individual test case in baseline vs protected mode."""

    __test__ = False
    test_id: str = Field(..., description="Test ID")
    risk_id: str = Field(..., description="Risk ID")
    risk_name: str = Field(..., description="Risk Name")
    test_name: str = Field(..., description="Test Name")
    target: str = Field(..., description="Target application (chatbot or agent)")
    baseline_result: TestResultStatus = Field(..., description="Outcome in vulnerable mode")
    protected_result: TestResultStatus = Field(..., description="Outcome in protected mode")
    baseline_explanation: str = Field(default="", description="Baseline evaluation rationale")
    protected_explanation: str = Field(default="", description="Protected evaluation rationale")
    improved: bool = Field(..., description="Whether mitigation improved outcome (e.g. SUCCEEDED -> BLOCKED)")


class RiskComparisonMetrics(BaseModel):
    """Metrics breakdown for an individual OWASP risk."""

    __test__ = False
    risk_id: str = Field(..., description="Risk ID (e.g. LLM01, ASI01)")
    risk_name: str = Field(..., description="Risk Name")
    total_tests: int = Field(..., description="Total tests evaluated for this risk")
    baseline_blocked: int = Field(default=0)
    baseline_partial: int = Field(default=0)
    baseline_succeeded: int = Field(default=0)
    protected_blocked: int = Field(default=0)
    protected_partial: int = Field(default=0)
    protected_succeeded: int = Field(default=0)
    baseline_asr: float = Field(..., description="Baseline Attack Success Rate (%)")
    protected_asr: float = Field(..., description="Protected Attack Success Rate (%)")
    baseline_blocking_rate: float = Field(..., description="Baseline Blocking Rate (%)")
    protected_blocking_rate: float = Field(..., description="Protected Blocking Rate (%)")
    asr_improvement: float = Field(..., description="Reduction in ASR (Baseline ASR - Protected ASR)")


class ComparisonSummary(BaseModel):
    """High-level summary of a before/after evaluation run."""

    __test__ = False
    comparison_id: str = Field(..., description="Unique comparison identifier")
    timestamp: str = Field(..., description="Evaluation timestamp")
    model: str = Field(..., description="Model tested")
    filter_risk: Optional[str] = Field(default=None, description="Risk filter if applied")
    total_tests: int = Field(..., description="Total tests compared")
    baseline_run_id: str = Field(..., description="Associated baseline run ID")
    protected_run_id: str = Field(..., description="Associated protected run ID")
    baseline_asr: float = Field(..., description="Overall baseline Attack Success Rate (%)")
    protected_asr: float = Field(..., description="Overall protected Attack Success Rate (%)")
    baseline_blocking_rate: float = Field(..., description="Overall baseline Blocking Rate (%)")
    protected_blocking_rate: float = Field(..., description="Overall protected Blocking Rate (%)")
    overall_improvement: float = Field(..., description="Overall reduction in ASR (Baseline ASR - Protected ASR)")


class ComparisonDetail(ComparisonSummary):
    """Detailed before/after comparison with risk breakdown and test comparisons."""

    risk_breakdown: List[RiskComparisonMetrics] = Field(default_factory=list)
    test_comparisons: List[TestCaseComparison] = Field(default_factory=list)


class BeforeAfterEvaluationRequest(BaseModel):
    """Request payload to initiate a Before/After security evaluation."""

    filter_risk: Optional[str] = Field(
        default=None,
        description="Filter to a specific risk ID (e.g. LLM01, LLM02, ASI01, ASI02) or omit for all",
    )
    test_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional explicit list of test IDs (e.g. ['PI-01', 'AGH-01'])",
    )


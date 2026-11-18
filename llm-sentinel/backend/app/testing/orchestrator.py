"""Test orchestrator coordinating execution and results aggregation."""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional
import uuid

from app.providers.base import LLMProvider
from app.security.mode import SecurityMode, get_current_security_mode
from app.testing.executor import TestExecutor
from app.testing.models import (
    ComparisonDetail,
    ComparisonSummary,
    RiskComparisonMetrics,
    TestCase,
    TestCaseComparison,
    TestResult,
    TestResultStatus,
    TestRunSummary,
)
from app.testing.registry import AttackRegistry, get_attack_registry
from app.testing.storage import StorageManager, get_storage_manager

logger = logging.getLogger("llm_sentinel.orchestrator")


class TestOrchestrator:
    """Coordinates running OWASP security test cases against targets."""

    __test__ = False

    def __init__(
        self,
        provider: LLMProvider,
        registry: Optional[AttackRegistry] = None,
        storage: Optional[StorageManager] = None,
    ) -> None:
        self.provider = provider
        self.registry = registry or get_attack_registry()
        self.storage = storage or get_storage_manager()
        self.executor = TestExecutor(provider=provider)

    async def run_single_test(
        self,
        test_id: str,
        mode: Optional[SecurityMode] = None,
    ) -> TestResult:
        """Execute a single test case by test_id."""
        test_case = self.registry.get(test_id)
        if not test_case:
            raise ValueError(f"Test case '{test_id}' not found in attack registry.")

        active_mode = mode or get_current_security_mode()
        run_id = f"single-{uuid.uuid4().hex[:8]}"

        result = await self.executor.execute_test(
            test_case=test_case,
            mode=active_mode,
            run_id=run_id,
        )

        # Create single-item summary and save
        summary = TestRunSummary(
            run_id=run_id,
            timestamp=result.timestamp,
            mode=active_mode,
            model=self.provider.model_name,
            total_tests=1,
            blocked=1 if result.result == TestResultStatus.BLOCKED else 0,
            partial=1 if result.result == TestResultStatus.PARTIAL else 0,
            succeeded=1 if result.result == TestResultStatus.SUCCEEDED else 0,
            results=[result],
        )
        self.storage.save_run(summary)

        return result

    async def run_all_tests(
        self,
        mode: Optional[SecurityMode] = None,
        filter_risk: Optional[str] = None,
    ) -> TestRunSummary:
        """Execute all registered test cases (or filtered by risk) and persist results."""
        active_mode = mode or get_current_security_mode()
        run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        start_ts = datetime.now(timezone.utc).isoformat()

        if filter_risk:
            test_cases = self.registry.filter_by_risk(filter_risk)
        else:
            test_cases = self.registry.list_all()

        results: List[TestResult] = []
        blocked = 0
        partial = 0
        succeeded = 0

        logger.info(
            "Starting test run %s with %d test cases in '%s' mode",
            run_id,
            len(test_cases),
            active_mode,
        )

        for tc in test_cases:
            res = await self.executor.execute_test(
                test_case=tc,
                mode=active_mode,
                run_id=run_id,
            )
            results.append(res)
            if res.result == TestResultStatus.BLOCKED:
                blocked += 1
            elif res.result == TestResultStatus.PARTIAL:
                partial += 1
            elif res.result == TestResultStatus.SUCCEEDED:
                succeeded += 1

        summary = TestRunSummary(
            run_id=run_id,
            timestamp=start_ts,
            mode=active_mode,
            model=self.provider.model_name,
            total_tests=len(results),
            blocked=blocked,
            partial=partial,
            succeeded=succeeded,
            results=results,
        )

        self.storage.save_run(summary)
        logger.info(
            "Finished test run %s: total=%d, blocked=%d, partial=%d, succeeded=%d",
            run_id,
            len(results),
            blocked,
            partial,
            succeeded,
        )

        return summary

    async def run_agentic_tests(
        self,
        mode: Optional[SecurityMode] = None,
        filter_risk: Optional[str] = None,
    ) -> TestRunSummary:
        """Execute all OWASP Agentic AI test cases (ASI01..ASI06) and persist results."""
        active_mode = mode or get_current_security_mode()
        run_id = f"agentic-run-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        start_ts = datetime.now(timezone.utc).isoformat()

        if filter_risk:
            test_cases = [tc for tc in self.registry.filter_by_risk(filter_risk) if tc.risk_id.startswith("ASI")]
        else:
            test_cases = self.registry.list_agentic_tests()

        results: List[TestResult] = []
        blocked = 0
        partial = 0
        succeeded = 0

        logger.info(
            "Starting Agentic AI test run %s with %d test cases in '%s' mode",
            run_id,
            len(test_cases),
            active_mode,
        )

        for tc in test_cases:
            res = await self.executor.execute_test(
                test_case=tc,
                mode=active_mode,
                run_id=run_id,
            )
            results.append(res)
            if res.result == TestResultStatus.BLOCKED:
                blocked += 1
            elif res.result == TestResultStatus.PARTIAL:
                partial += 1
            elif res.result == TestResultStatus.SUCCEEDED:
                succeeded += 1

        summary = TestRunSummary(
            run_id=run_id,
            timestamp=start_ts,
            mode=active_mode,
            model=self.provider.model_name,
            total_tests=len(results),
            blocked=blocked,
            partial=partial,
            succeeded=succeeded,
            results=results,
        )

        self.storage.save_run(summary)
        logger.info(
            "Finished Agentic AI test run %s: total=%d, blocked=%d, partial=%d, succeeded=%d",
            run_id,
            len(results),
            blocked,
            partial,
            succeeded,
        )

        return summary

    async def run_before_after_evaluation(
        self,
        filter_risk: Optional[str] = None,
        test_ids: Optional[List[str]] = None,
    ) -> ComparisonDetail:
        """Execute a Before/After comparative evaluation across baseline (vulnerable) and protected modes.

        Steps:
        1. Select test cases (all 30, or filtered by risk / explicit test_ids).
        2. Run baseline batch in vulnerable mode (recording actual attacks and outcomes).
        3. Run protected batch in protected mode (enforcing all mitigations).
        4. Calculate Attack Success Rate (ASR), Blocking Rate, and Mitigation Improvement.
        5. Generate per-risk breakdown and side-by-side test comparisons.
        6. Persist comparison to SQLite.
        """
        eval_ts = datetime.now(timezone.utc).isoformat()
        comparison_id = f"cmp-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        baseline_run_id = f"baseline-{comparison_id}"
        protected_run_id = f"protected-{comparison_id}"

        # 1. Resolve test cases to evaluate
        if test_ids:
            target_test_cases = [self.registry.get(tid) for tid in test_ids if self.registry.get(tid) is not None]  # type: ignore[misc]
        elif filter_risk:
            target_test_cases = self.registry.filter_by_risk(filter_risk)
        else:
            target_test_cases = self.registry.list_all()

        total_tests = len(target_test_cases)
        logger.info(
            "Starting Before/After evaluation %s with %d test cases (filter_risk=%s)",
            comparison_id,
            total_tests,
            filter_risk,
        )

        # 2. Phase A: Execute Baseline (Vulnerable Mode) concurrently
        sem = asyncio.Semaphore(6)

        async def _run_base(tc: TestCase) -> TestResult:
            async with sem:
                try:
                    return await self.executor.execute_test(
                        test_case=tc,
                        mode="vulnerable",
                        run_id=baseline_run_id,
                    )
                except Exception as exc:
                    logger.error("Baseline test %s failed: %s", tc.test_id, exc)
                    from app.testing.models import Evidence
                    return TestResult(
                        test_id=tc.test_id,
                        risk_id=tc.risk_id,
                        risk_name=tc.risk_name,
                        test_name=tc.test_name,
                        target=tc.target_application,
                        mode="vulnerable",
                        model=self.provider.model_name,
                        prompt=tc.attack_prompt,
                        response=f"Execution error: {str(exc)}",
                        tool_evidence=[],
                        result=TestResultStatus.BLOCKED,
                        evaluation_explanation=f"Execution error: {str(exc)}",
                        evidence=Evidence(),
                        timestamp=eval_ts,
                        run_id=baseline_run_id,
                    )

        baseline_results: List[TestResult] = await asyncio.gather(
            *[_run_base(tc) for tc in target_test_cases]
        )
        base_blocked = sum(1 for r in baseline_results if r.result == TestResultStatus.BLOCKED)
        base_partial = sum(1 for r in baseline_results if r.result == TestResultStatus.PARTIAL)
        base_succeeded = sum(1 for r in baseline_results if r.result == TestResultStatus.SUCCEEDED)

        baseline_summary = TestRunSummary(
            run_id=baseline_run_id,
            timestamp=eval_ts,
            mode="vulnerable",
            model=self.provider.model_name,
            total_tests=total_tests,
            blocked=base_blocked,
            partial=base_partial,
            succeeded=base_succeeded,
            results=baseline_results,
        )
        self.storage.save_run(baseline_summary)

        # 3. Phase B: Execute Protected Mode (Mitigations Active) concurrently
        async def _run_prot(tc: TestCase) -> TestResult:
            async with sem:
                try:
                    return await self.executor.execute_test(
                        test_case=tc,
                        mode="protected",
                        run_id=protected_run_id,
                    )
                except Exception as exc:
                    logger.error("Protected test %s failed: %s", tc.test_id, exc)
                    from app.testing.models import Evidence
                    return TestResult(
                        test_id=tc.test_id,
                        risk_id=tc.risk_id,
                        risk_name=tc.risk_name,
                        test_name=tc.test_name,
                        target=tc.target_application,
                        mode="protected",
                        model=self.provider.model_name,
                        prompt=tc.attack_prompt,
                        response=f"Execution error: {str(exc)}",
                        tool_evidence=[],
                        result=TestResultStatus.BLOCKED,
                        evaluation_explanation=f"Execution error: {str(exc)}",
                        evidence=Evidence(),
                        timestamp=eval_ts,
                        run_id=protected_run_id,
                    )

        protected_results: List[TestResult] = await asyncio.gather(
            *[_run_prot(tc) for tc in target_test_cases]
        )
        prot_blocked = sum(1 for r in protected_results if r.result == TestResultStatus.BLOCKED)
        prot_partial = sum(1 for r in protected_results if r.result == TestResultStatus.PARTIAL)
        prot_succeeded = sum(1 for r in protected_results if r.result == TestResultStatus.SUCCEEDED)

        protected_summary = TestRunSummary(
            run_id=protected_run_id,
            timestamp=eval_ts,
            mode="protected",
            model=self.provider.model_name,
            total_tests=total_tests,
            blocked=prot_blocked,
            partial=prot_partial,
            succeeded=prot_succeeded,
            results=protected_results,
        )
        self.storage.save_run(protected_summary)

        # 4. Phase C: Metrics Calculations
        baseline_asr = round((base_succeeded / total_tests) * 100, 2) if total_tests > 0 else 0.0
        protected_asr = round((prot_succeeded / total_tests) * 100, 2) if total_tests > 0 else 0.0
        baseline_blocking_rate = round((base_blocked / total_tests) * 100, 2) if total_tests > 0 else 0.0
        protected_blocking_rate = round((prot_blocked / total_tests) * 100, 2) if total_tests > 0 else 0.0
        overall_improvement = round(baseline_asr - protected_asr, 2)

        # Map results by test_id for pairing
        base_map = {r.test_id: r for r in baseline_results}
        prot_map = {r.test_id: r for r in protected_results}

        # 5. Build Side-by-Side Test Comparisons
        test_comparisons: List[TestCaseComparison] = []
        for tc in target_test_cases:
            b_res = base_map.get(tc.test_id)
            p_res = prot_map.get(tc.test_id)
            if not b_res or not p_res:
                continue

            # Improved if vulnerability was eliminated or reduced
            improved = (
                (b_res.result == TestResultStatus.SUCCEEDED and p_res.result != TestResultStatus.SUCCEEDED)
                or (b_res.result == TestResultStatus.PARTIAL and p_res.result == TestResultStatus.BLOCKED)
            )

            test_comparisons.append(
                TestCaseComparison(
                    test_id=tc.test_id,
                    risk_id=tc.risk_id,
                    risk_name=tc.risk_name,
                    test_name=tc.test_name,
                    target=tc.target_application,
                    baseline_result=b_res.result,
                    protected_result=p_res.result,
                    baseline_explanation=b_res.evaluation_explanation,
                    protected_explanation=p_res.evaluation_explanation,
                    improved=improved,
                )
            )

        # 6. Build Risk-wise Breakdown
        risk_groups: Dict[str, List[TestCase]] = {}
        for tc in target_test_cases:
            risk_groups.setdefault(tc.risk_id, []).append(tc)

        risk_breakdown: List[RiskComparisonMetrics] = []
        for r_id, cases in risk_groups.items():
            r_name = cases[0].risk_name
            r_total = len(cases)

            r_base_b = sum(1 for tc in cases if base_map.get(tc.test_id, TestResult(test_id="", risk_id="", risk_name="", test_name="", target="", mode="", model="", prompt="", response="", result=TestResultStatus.PARTIAL, evaluation_explanation="", timestamp="", run_id="")).result == TestResultStatus.BLOCKED)
            r_base_p = sum(1 for tc in cases if base_map.get(tc.test_id, TestResult(test_id="", risk_id="", risk_name="", test_name="", target="", mode="", model="", prompt="", response="", result=TestResultStatus.PARTIAL, evaluation_explanation="", timestamp="", run_id="")).result == TestResultStatus.PARTIAL)
            r_base_s = sum(1 for tc in cases if base_map.get(tc.test_id, TestResult(test_id="", risk_id="", risk_name="", test_name="", target="", mode="", model="", prompt="", response="", result=TestResultStatus.PARTIAL, evaluation_explanation="", timestamp="", run_id="")).result == TestResultStatus.SUCCEEDED)

            r_prot_b = sum(1 for tc in cases if prot_map.get(tc.test_id, TestResult(test_id="", risk_id="", risk_name="", test_name="", target="", mode="", model="", prompt="", response="", result=TestResultStatus.PARTIAL, evaluation_explanation="", timestamp="", run_id="")).result == TestResultStatus.BLOCKED)
            r_prot_p = sum(1 for tc in cases if prot_map.get(tc.test_id, TestResult(test_id="", risk_id="", risk_name="", test_name="", target="", mode="", model="", prompt="", response="", result=TestResultStatus.PARTIAL, evaluation_explanation="", timestamp="", run_id="")).result == TestResultStatus.PARTIAL)
            r_prot_s = sum(1 for tc in cases if prot_map.get(tc.test_id, TestResult(test_id="", risk_id="", risk_name="", test_name="", target="", mode="", model="", prompt="", response="", result=TestResultStatus.PARTIAL, evaluation_explanation="", timestamp="", run_id="")).result == TestResultStatus.SUCCEEDED)

            r_base_asr = round((r_base_s / r_total) * 100, 2) if r_total > 0 else 0.0
            r_prot_asr = round((r_prot_s / r_total) * 100, 2) if r_total > 0 else 0.0
            r_base_block = round((r_base_b / r_total) * 100, 2) if r_total > 0 else 0.0
            r_prot_block = round((r_prot_b / r_total) * 100, 2) if r_total > 0 else 0.0
            r_asr_imp = round(r_base_asr - r_prot_asr, 2)

            risk_breakdown.append(
                RiskComparisonMetrics(
                    risk_id=r_id,
                    risk_name=r_name,
                    total_tests=r_total,
                    baseline_blocked=r_base_b,
                    baseline_partial=r_base_p,
                    baseline_succeeded=r_base_s,
                    protected_blocked=r_prot_b,
                    protected_partial=r_prot_p,
                    protected_succeeded=r_prot_s,
                    baseline_asr=r_base_asr,
                    protected_asr=r_prot_asr,
                    baseline_blocking_rate=r_base_block,
                    protected_blocking_rate=r_prot_block,
                    asr_improvement=r_asr_imp,
                )
            )

        # 7. Build Full Detail & Persist to SQLite
        detail = ComparisonDetail(
            comparison_id=comparison_id,
            timestamp=eval_ts,
            model=self.provider.model_name,
            filter_risk=filter_risk,
            total_tests=total_tests,
            baseline_run_id=baseline_run_id,
            protected_run_id=protected_run_id,
            baseline_asr=baseline_asr,
            protected_asr=protected_asr,
            baseline_blocking_rate=baseline_blocking_rate,
            protected_blocking_rate=protected_blocking_rate,
            overall_improvement=overall_improvement,
            risk_breakdown=risk_breakdown,
            test_comparisons=test_comparisons,
        )

        self.storage.save_comparison(detail)
        logger.info(
            "Completed Before/After evaluation %s: Baseline ASR=%.1f%%, Protected ASR=%.1f%%, Improvement=%.1f%%",
            comparison_id,
            baseline_asr,
            protected_asr,
            overall_improvement,
        )

        return detail


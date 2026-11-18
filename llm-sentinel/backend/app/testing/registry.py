"""Attack registry and test case loader for LLM Sentinel."""

from typing import Dict, List, Optional
from app.testing.agentic_dataset import OWASP_AGENTIC_ATTACK_DATASET
from app.testing.dataset import OWASP_LLM_ATTACK_DATASET
from app.testing.models import TestCase

ALL_OWASP_TEST_CASES: List[TestCase] = OWASP_LLM_ATTACK_DATASET + OWASP_AGENTIC_ATTACK_DATASET


class AttackRegistry:
    """Registry maintaining active OWASP LLM and Agentic AI attack test cases."""

    def __init__(self, test_cases: Optional[List[TestCase]] = None) -> None:
        self._test_cases: Dict[str, TestCase] = {}
        dataset = test_cases or ALL_OWASP_TEST_CASES
        for tc in dataset:
            self.register(tc)

    def register(self, test_case: TestCase) -> None:
        """Register a test case."""
        self._test_cases[test_case.test_id] = test_case

    def get(self, test_id: str) -> Optional[TestCase]:
        """Retrieve test case by its ID."""
        return self._test_cases.get(test_id.upper().strip())

    def list_all(self) -> List[TestCase]:
        """Return all registered test cases in order."""
        return list(self._test_cases.values())

    def list_agentic_tests(self) -> List[TestCase]:
        """Return registered OWASP Agentic AI test cases (ASI01..ASI06)."""
        return [tc for tc in self._test_cases.values() if tc.risk_id.startswith("ASI")]

    def list_llm_tests(self) -> List[TestCase]:
        """Return registered OWASP LLM Applications test cases (LLM01..LLM10)."""
        return [tc for tc in self._test_cases.values() if tc.risk_id.startswith("LLM")]

    def filter_by_risk(self, risk_id: str) -> List[TestCase]:
        """Filter test cases by OWASP Risk ID (e.g. LLM01 or ASI01)."""
        r_id = risk_id.upper().strip()
        return [tc for tc in self._test_cases.values() if tc.risk_id == r_id]

    def filter_by_target(self, target: str) -> List[TestCase]:
        """Filter test cases by target application ('chatbot' or 'agent')."""
        t = target.lower().strip()
        return [tc for tc in self._test_cases.values() if tc.target_application == t]

    def count(self) -> int:
        """Return total number of registered test cases."""
        return len(self._test_cases)


_global_registry = AttackRegistry()


def get_attack_registry() -> AttackRegistry:
    """Return singleton attack registry."""
    return _global_registry


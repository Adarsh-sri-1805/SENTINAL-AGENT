"""Test case execution engine dispatching attacks against target applications."""

from datetime import datetime, timezone
import logging
from typing import Optional

from app.providers.base import LLMProvider
from app.security.mode import SecurityMode, get_current_security_mode
from app.targets.agent import OmniCorpAgent
from app.targets.chatbot import OmniCorpChatbot
from app.testing.classifier import ResultClassifier
from app.testing.evidence import EvidenceCollector
from app.testing.models import TestCase, TestResult, TestResultStatus

logger = logging.getLogger("llm_sentinel.executor")


class TestExecutor:
    """Executes an individual OWASP security test case against its designated target."""

    __test__ = False

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def execute_test(
        self,
        test_case: TestCase,
        mode: Optional[SecurityMode] = None,
        run_id: str = "single-run",
    ) -> TestResult:
        """Execute a test case and evaluate outcome.

        Args:
            test_case: Attack test case to run.
            mode: Optional security mode ('vulnerable' or 'protected'). Defaults to global mode.
            run_id: Associated test run identifier.

        Returns:
            TestResult: Classified evaluation result with evidence.
        """
        active_mode = mode or get_current_security_mode()
        exec_ts = datetime.now(timezone.utc).isoformat()
        target = test_case.target_application

        logger.info(
            "Executing test %s (%s) on target='%s' mode='%s'",
            test_case.test_id,
            test_case.test_name,
            target,
            active_mode,
        )

        response_text = ""
        tool_invocations = []

        try:
            if target == "chatbot":
                bot = OmniCorpChatbot(provider=self.provider)
                chat_res = await bot.chat(
                    message=test_case.attack_prompt,
                    user_id=test_case.user_id or "guest",
                    mode=active_mode,
                )
                response_text = chat_res.response

            elif target == "agent":
                agent = OmniCorpAgent(provider=self.provider)
                agent_res = await agent.run(
                    task=test_case.attack_prompt,
                    user_id=test_case.user_id or "guest",
                    mode=active_mode,
                )
                response_text = agent_res.final_answer
                tool_invocations = [t.model_dump() for t in agent_res.tool_invocations]

            else:
                response_text = f"Unknown target application: '{target}'"

        except Exception as exc:
            logger.error("Error executing test %s: %s", test_case.test_id, str(exc))
            response_text = f"Target execution error: {str(exc)}"

        # Collect evidence from response and tool telemetry
        evidence = EvidenceCollector.collect(
            test_case=test_case,
            response_text=response_text,
            tool_invocations=tool_invocations,
        )

        # Classify result
        status, explanation = ResultClassifier.evaluate(
            test_case=test_case,
            response_text=response_text,
            evidence=evidence,
        )

        return TestResult(
            test_id=test_case.test_id,
            risk_id=test_case.risk_id,
            risk_name=test_case.risk_name,
            test_name=test_case.test_name,
            target=target,
            mode=active_mode,
            model=self.provider.model_name,
            prompt=test_case.attack_prompt,
            response=response_text,
            tool_evidence=tool_invocations,
            result=status,
            evaluation_explanation=explanation,
            evidence=evidence,
            timestamp=exec_ts,
            run_id=run_id,
        )


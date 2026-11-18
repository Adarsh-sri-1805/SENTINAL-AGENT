"""OmniCorp customer support chatbot target implementation."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.providers.base import LLMProvider, ProviderUsage
from app.security.mitigations import MitigationFilters, is_mitigation_active
from app.security.mode import SecurityMode, get_current_security_mode
from app.security.redactor import redact_data_structure, redact_sensitive_data
from app.targets.chatbot.prompts import PROTECTED_SYSTEM_PROMPT, VULNERABLE_SYSTEM_PROMPT
from app.targets.chatbot.retriever import retrieve_documents

logger = logging.getLogger("llm_sentinel.chatbot")


class RetrievedDocumentExcerpt(BaseModel):
    """Safe excerpt metadata for retrieved documents."""

    id: str = Field(..., description="Document identifier")
    title: str = Field(..., description="Document title")
    category: str = Field(..., description="Document classification")
    relevance_score: float = Field(..., description="Retrieval score")


class ChatbotResponse(BaseModel):
    """Response payload returned by the chatbot target."""

    response: str = Field(..., description="Chatbot message response")
    mode: str = Field(..., description="Active security posture ('vulnerable' or 'protected')")
    user_id: str = Field(..., description="Requesting user ID")
    query: str = Field(..., description="Original user query")
    retrieved_documents: List[RetrievedDocumentExcerpt] = Field(
        default_factory=list, description="Documents supplied to model context"
    )
    usage: Optional[ProviderUsage] = Field(default=None, description="Token usage metrics")
    timestamp: str = Field(..., description="ISO 8601 timestamp")


class OmniCorpChatbot:
    """Deliberately vulnerable/protected enterprise chatbot target."""

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def chat(
        self,
        message: str,
        user_id: str = "guest",
        mode: Optional[SecurityMode] = None,
    ) -> ChatbotResponse:
        """Process a customer support chat request.

        Args:
            message: User prompt or security test payload.
            user_id: User identifier.
            mode: Optional mode override ('vulnerable' or 'protected'). Defaults to global mode.

        Returns:
            ChatbotResponse: Model output and execution metadata.
        """
        active_mode = mode or get_current_security_mode()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Determine active mitigation toggles for this request
        llm01_active = (active_mode == "protected") or is_mitigation_active("LLM01", active_mode)
        llm02_active = (active_mode == "protected") or is_mitigation_active("LLM02", active_mode)
        llm08_active = (active_mode == "protected") or is_mitigation_active("LLM08", active_mode)
        llm10_active = (active_mode == "protected") or is_mitigation_active("LLM10", active_mode)

        # Step 1: Retrieve context from knowledge base (LLM02 pre-retrieval access control)
        retrieval_mode = "protected" if llm02_active else "vulnerable"
        scored_docs = retrieve_documents(query=message, mode=retrieval_mode, limit=3)

        # Build context string for the prompt
        context_blocks = []
        doc_excerpts: List[RetrievedDocumentExcerpt] = []

        for doc, score in scored_docs:
            context_blocks.append(f"--- Document [{doc.id}] ({doc.category.upper()}): {doc.title} ---\n{doc.content}")
            doc_excerpts.append(
                RetrievedDocumentExcerpt(
                    id=doc.id,
                    title=doc.title,
                    category=doc.category,
                    relevance_score=round(score, 2),
                )
            )

        context_str = "\n\n".join(context_blocks)

        # LLM01 / ASI01 Mitigation: Clearly delimit retrieved documents
        context_str = MitigationFilters.delimit_retrieved_documents(context_str, enabled=llm01_active)

        # Step 2: Select system instruction
        if active_mode == "protected":
            system_prompt = PROTECTED_SYSTEM_PROMPT
        else:
            system_prompt = VULNERABLE_SYSTEM_PROMPT

        # Step 3: Formulate full prompt with instruction hierarchy & prompt delimitation (LLM01)
        safe_user_inquiry = MitigationFilters.sanitize_user_prompt(message, enabled=llm01_active)
        full_prompt = (
            f"KNOWLEDGE BASE CONTEXT:\n{context_str}\n\n"
            f"USER INQUIRY:\n{safe_user_inquiry}\n\n"
            f"ASSISTANT RESPONSE:"
        )

        # Step 4: Call LLM provider
        raw_response = await self.provider.generate(
            prompt=full_prompt,
            system_instruction=system_prompt,
            temperature=0.3,
            max_tokens=512,
        )

        response_text = raw_response.response

        # Step 5: Post-generation guardrails & sanitization
        # LLM02: Sensitive information & flag redaction
        if llm02_active:
            response_text = redact_sensitive_data(response_text)

        # LLM08: System prompt & infrastructure configuration scrub
        if llm08_active:
            response_text = MitigationFilters.scrub_hidden_context(response_text, enabled=True)

        # LLM10: Output HTML sanitization / escaping for XSS prevention
        if llm10_active:
            response_text = MitigationFilters.sanitize_output_html(response_text, enabled=True)

        # Step 6: Structured Logging with Sensitive Data Redaction
        log_payload = {
            "timestamp": timestamp,
            "target": "chatbot",
            "user_id": user_id,
            "mode": active_mode,
            "query": message,
            "retrieved_doc_ids": [d.id for d in doc_excerpts],
            "response": response_text,
            "tokens": raw_response.usage.model_dump() if raw_response.usage else None,
        }
        redacted_log = redact_data_structure(log_payload)
        logger.info("CHATBOT_TRANSACTION %s", redacted_log)

        return ChatbotResponse(
            response=response_text,
            mode=active_mode,
            user_id=user_id,
            query=message,
            retrieved_documents=doc_excerpts,
            usage=raw_response.usage,
            timestamp=timestamp,
        )


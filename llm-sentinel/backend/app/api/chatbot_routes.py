"""API routes for vulnerable/protected customer support chatbot target."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.routes import get_active_provider
from app.providers.base import LLMProvider, ProviderAPIError, ProviderConfigError
from app.security.mode import SecurityMode
from app.targets.chatbot import ChatbotResponse, OmniCorpChatbot

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chatbot", tags=["Target: Chatbot"])


class ChatbotChatRequest(BaseModel):
    """Request schema for chatbot target."""

    message: str = Field(
        ...,
        min_length=1,
        description="Prompt or security probe message to send to the chatbot",
        examples=["What is the company return policy?"],
    )
    user_id: Optional[str] = Field(
        default="guest",
        description="User identifier",
        examples=["guest", "employee", "admin"],
    )
    mode: Optional[SecurityMode] = Field(
        default=None,
        description="Optional security mode override ('vulnerable' or 'protected'). Defaults to global mode.",
    )


@router.post(
    "/chat",
    response_model=ChatbotResponse,
    summary="Chat with OmniCorp Support Chatbot",
)
async def chat_with_bot(
    request: ChatbotChatRequest,
    provider: LLMProvider = Depends(get_active_provider),
) -> ChatbotResponse:
    """Send a query to the fake enterprise customer-support chatbot.

    Supports 'vulnerable' and 'protected' operational modes.
    """
    bot = OmniCorpChatbot(provider=provider)
    try:
        return await bot.chat(
            message=request.message,
            user_id=request.user_id or "guest",
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
        logger.exception("Unexpected error in chatbot route")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chatbot execution failed: {str(exc)}",
        ) from exc


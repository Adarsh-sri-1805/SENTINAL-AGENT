"""API routes for LLM Sentinel health, provider status, and chat generation."""

import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.providers import (
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    ProviderAPIError,
    ProviderConfigError,
    ProviderStatus,
    get_provider,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Dependency Injection ---

def get_active_provider(settings: Settings = Depends(get_settings)) -> LLMProvider:
    """Dependency that supplies the configured LLM provider instance."""
    return get_provider(settings)


# --- Request / Response Schemas ---

class HealthResponse(BaseModel):
    """Response schema for service health check."""

    status: str = Field(default="healthy", description="Application operational status")
    app: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")


class ChatRequest(BaseModel):
    """Request payload for LLM generation."""

    message: str = Field(
        ...,
        min_length=1,
        description="The prompt or probe payload to send to the LLM",
        examples=["What are common prompt injection vulnerabilities?"],
    )
    system_instruction: Optional[str] = Field(
        default=None,
        description="Optional system instruction/guardrail for the model",
        examples=["You are a helpful AI security assistant."],
    )
    temperature: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=2.0,
        description="Sampling temperature between 0.0 and 2.0",
        examples=[0.7],
    )
    max_tokens: Optional[int] = Field(
        default=None,
        gt=0,
        description="Maximum tokens to generate",
        examples=[512],
    )


# --- Endpoints ---

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service Health Check",
    tags=["System"],
)
async def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Return backend health and version information."""
    return HealthResponse(
        status="healthy",
        app=settings.app_name,
        version=settings.app_version,
    )


@router.get(
    "/provider/status",
    response_model=ProviderStatus,
    summary="LLM Provider Status",
    tags=["Provider"],
)
async def provider_status(
    test_connection: bool = Query(
        default=False,
        description="If True, executes a live roundtrip probe to the upstream LLM API.",
    ),
    provider: LLMProvider = Depends(get_active_provider),
) -> ProviderStatus:
    """Inspect active LLM provider configuration and optionally test live connectivity."""
    if test_connection:
        return await provider.test_connectivity()
    return await provider.check_status()


@router.post(
    "/chat",
    response_model=LLMResponse,
    summary="Send Message to LLM",
    tags=["Chat"],
)
async def chat(
    request: ChatRequest,
    provider: LLMProvider = Depends(get_active_provider),
) -> LLMResponse:
    """Send a message/prompt to the configured LLM provider and receive its response.

    Does not fall back to mock data if the provider fails.
    """
    try:
        response = await provider.generate(
            prompt=request.message,
            system_instruction=request.system_instruction,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        return response
    except ProviderConfigError as exc:
        logger.warning("Chat failed due to provider configuration: %s", exc.message)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider is not configured: {exc.message}",
        ) from exc
    except ProviderAPIError as exc:
        logger.error("Chat failed due to upstream provider error: %s", exc.message)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream LLM provider error: {exc.message}",
        ) from exc
    except ValueError as exc:
        logger.warning("Invalid request parameter: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error in chat endpoint")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while processing the request.",
        ) from exc


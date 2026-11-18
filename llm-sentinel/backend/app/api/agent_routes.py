"""API routes for AI Agent target and tool definitions."""

import logging
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.routes import get_active_provider
from app.providers.base import LLMProvider, ProviderAPIError, ProviderConfigError
from app.targets.agent import AgentRunRequest, AgentRunResponse, OmniCorpAgent
from app.tools import get_default_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["Target: AI Agent"])


@router.post(
    "/run",
    response_model=AgentRunResponse,
    summary="Execute Task with AI Agent",
)
async def run_agent(
    request: AgentRunRequest,
    provider: LLMProvider = Depends(get_active_provider),
) -> AgentRunResponse:
    """Execute a task with the AI Agent target using Gemini tool calling.

    Enforces server-side authorization and full audit logging of tool calls.
    """
    agent = OmniCorpAgent(provider=provider, registry=get_default_registry())
    try:
        return await agent.run(
            task=request.task,
            user_id=request.user_id or "guest",
            mode=request.mode,
            max_steps=request.max_steps or 5,
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
        logger.exception("Unexpected error in agent route")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent execution failed: {str(exc)}",
        ) from exc


@router.get(
    "/tools",
    response_model=List[Dict[str, Any]],
    summary="List Agent Tools",
)
async def list_agent_tools() -> List[Dict[str, Any]]:
    """Inspect all registered tools, parameters schemas, and required roles."""
    registry = get_default_registry()
    return registry.get_tool_metadata()


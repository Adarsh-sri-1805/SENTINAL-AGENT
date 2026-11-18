"""Main FastAPI entrypoint for LLM Sentinel."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.agent_routes import router as agent_router
from app.api.chatbot_routes import router as chatbot_router
from app.api.dashboard_routes import router as dashboard_router
from app.api.mcp_routes import router as mcp_router
from app.api.routes import router as api_router
from app.api.security_routes import router as security_router
from app.api.testing_routes import router as testing_router, testing_alias_router
from app.api.wazuh_routes import router as wazuh_router
from app.config import get_settings
from app.providers.base import LLMProviderError, ProviderAPIError, ProviderConfigError

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("llm_sentinel")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager."""
    settings = get_settings()
    logger.info("==================================================")
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)
    logger.info("Environment: %s | Debug: %s", settings.app_env, settings.debug)
    logger.info("Active LLM Provider: %s (Model: %s)", settings.llm_provider, settings.gemini_model)
    logger.info("Gemini API Key Configured: %s", settings.is_gemini_configured)
    logger.info("==================================================")
    yield
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title="LLM Sentinel",
        description=(
            "AI Security Testing Engine POC based on OWASP Top 10 for LLM Applications (2026) "
            "and OWASP Top 10 for Agentic AI (2026)."
        ),
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Enable CORS for local testing/dashboard integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handlers for domain errors
    @app.exception_handler(ProviderConfigError)
    async def provider_config_error_handler(request: Request, exc: ProviderConfigError):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": f"Provider configuration error: {exc.message}"},
        )

    @app.exception_handler(ProviderAPIError)
    async def provider_api_error_handler(request: Request, exc: ProviderAPIError):
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"detail": f"Provider API error: {exc.message}"},
        )

    # Direct /health endpoint at root level
    @app.get(
        "/health",
        tags=["System"],
        summary="Service Health Check (Root)",
    )
    async def root_health():
        return {
            "status": "healthy",
            "app": settings.app_name,
            "version": settings.app_version,
        }

    # Mount API routes under /api
    app.include_router(api_router, prefix="/api")
    app.include_router(chatbot_router, prefix="/api")
    app.include_router(agent_router, prefix="/api")
    app.include_router(security_router, prefix="/api")
    app.include_router(testing_router, prefix="/api")
    app.include_router(testing_alias_router, prefix="/api")
    app.include_router(mcp_router, prefix="/api")
    app.include_router(dashboard_router, prefix="/api")
    app.include_router(wazuh_router, prefix="/api")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)


"""LLM Providers package with factory loader."""

from typing import Optional
from app.config import Settings, get_settings
from app.providers.base import (
    LLMProvider,
    LLMProviderError,
    LLMResponse,
    ProviderAPIError,
    ProviderConfigError,
    ProviderStatus,
    ProviderUsage,
    ToolCallRequest,
)
from app.providers.gemini import GeminiProvider

__all__ = [
    "LLMProvider",
    "LLMResponse",
    "ToolCallRequest",
    "ProviderUsage",
    "ProviderStatus",
    "LLMProviderError",
    "ProviderConfigError",
    "ProviderAPIError",
    "GeminiProvider",
    "get_provider",
]


def get_provider(settings: Optional[Settings] = None) -> LLMProvider:
    """Factory function to instantiate the active LLM provider.

    Enables adding future providers (e.g. ClaudeProvider) without changing
    the API routes or testing engine.

    Args:
        settings: Optional Settings instance. Defaults to get_settings().

    Returns:
        LLMProvider: Active configured provider instance.

    Raises:
        ProviderConfigError: If an unsupported provider is requested.
    """
    cfg = settings or get_settings()
    provider_name = (cfg.llm_provider or "gemini").lower().strip()

    if provider_name == "gemini":
        return GeminiProvider(
            api_key=cfg.gemini_api_key,
            model=cfg.gemini_model,
        )

    # Future extensibility hook:
    # if provider_name == "claude":
    #     return ClaudeProvider(...)

    raise ProviderConfigError(
        f"Unsupported LLM provider '{cfg.llm_provider}'. Supported providers: ['gemini']"
    )


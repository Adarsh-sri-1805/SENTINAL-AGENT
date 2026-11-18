"""Google Gemini provider implementation using the official google-genai SDK."""

import logging
import re
from typing import Any, Dict, Optional

from google import genai
from google.genai import errors, types

from app.config import get_settings
from app.providers.base import (
    LLMProvider,
    LLMResponse,
    ProviderAPIError,
    ProviderConfigError,
    ProviderStatus,
    ProviderUsage,
    ToolCallRequest,
)

logger = logging.getLogger(__name__)

# Pattern to detect and redact potential Google API keys in error strings
_API_KEY_REGEX = re.compile(r"AIza[0-9A-Za-z-_]{35}")


def _sanitize_error_message(msg: str) -> str:
    """Sanitize any API keys or credentials from error messages."""
    if not msg:
        return "Unknown error"
    return _API_KEY_REGEX.sub("[REDACTED_API_KEY]", str(msg))


class GeminiProvider(LLMProvider):
    """Google Gemini LLM provider using the modern google-genai SDK."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        client: Optional[genai.Client] = None,
    ) -> None:
        """Initialize GeminiProvider.

        Args:
            api_key: Optional Gemini API key. If omitted, falls back to settings.
            model: Optional model identifier. If omitted, falls back to settings.
            client: Optional pre-configured genai.Client (useful for testing and dependency injection).
        """
        settings = get_settings()
        self._api_key = api_key if api_key is not None else settings.gemini_api_key
        self._model = model if model is not None else settings.gemini_model
        self._client: Optional[genai.Client] = client

    @property
    def provider_name(self) -> str:
        """Unique identifier for this provider."""
        return "gemini"

    @property
    def model_name(self) -> str:
        """Active model identifier."""
        return self._model

    @property
    def api_key(self) -> Optional[str]:
        """Configured API key."""
        return self._api_key

    def _get_client(self) -> genai.Client:
        """Retrieve or lazily initialize the GenAI client.

        Raises:
            ProviderConfigError: If GEMINI_API_KEY is missing.
        """
        if self._client is not None:
            return self._client

        if not self._api_key or not self._api_key.strip():
            raise ProviderConfigError(
                "GEMINI_API_KEY is not configured. Please set GEMINI_API_KEY in your .env file or environment."
            )

        try:
            self._client = genai.Client(api_key=self._api_key)
            return self._client
        except Exception as exc:
            sanitized = _sanitize_error_message(str(exc))
            logger.error("Failed to initialize Google GenAI Client: %s", sanitized)
            raise ProviderConfigError(f"Failed to initialize Gemini client: {sanitized}") from exc

    async def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Generate response using Google Gemini.

        Strictly avoids silent fallbacks: upstream errors raise ProviderAPIError.

        Args:
            prompt: Text prompt or security probe payload.
            system_instruction: Optional system instruction.
            temperature: Sampling temperature.
            max_tokens: Max tokens to generate (mapped to max_output_tokens).
            **kwargs: Extra parameters passed to GenerateContentConfig.

        Returns:
            LLMResponse: Standardized response payload.

        Raises:
            ProviderConfigError: If API key is missing.
            ProviderAPIError: If upstream API returns an error or blocks generation.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt must not be empty.")

        client = self._get_client()

        # Build GenerateContentConfig
        config_kwargs: Dict[str, Any] = {}
        if system_instruction is not None:
            config_kwargs["system_instruction"] = system_instruction
        if temperature is not None:
            config_kwargs["temperature"] = temperature
        if max_tokens is not None:
            config_kwargs["max_output_tokens"] = max_tokens

        # Handle tools formatting for Google GenAI SDK
        if "tools" in kwargs and kwargs["tools"] is not None:
            raw_tools = kwargs.pop("tools")
            if isinstance(raw_tools, list) and len(raw_tools) > 0 and isinstance(raw_tools[0], dict):
                if "function_declarations" not in raw_tools[0]:
                    config_kwargs["tools"] = [{"function_declarations": raw_tools}]
                else:
                    config_kwargs["tools"] = raw_tools
            else:
                config_kwargs["tools"] = raw_tools

        # Merge any extra provider-specific kwargs
        for key, value in kwargs.items():
            if value is not None and key not in config_kwargs:
                config_kwargs[key] = value

        config = types.GenerateContentConfig(**config_kwargs) if config_kwargs else None

        try:
            logger.info("Calling Gemini API with model: %s", self.model_name)
            response = await client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config,
            )
        except errors.APIError as exc:
            sanitized = _sanitize_error_message(str(exc))
            logger.error("Gemini API returned error: %s", sanitized)
            raise ProviderAPIError(
                f"Gemini API error (code {getattr(exc, 'code', 'unknown')}): {sanitized}",
                details={"code": getattr(exc, "code", None), "message": sanitized},
            ) from exc
        except Exception as exc:
            sanitized = _sanitize_error_message(str(exc))
            logger.error("Unexpected error during Gemini generation: %s", sanitized)
            raise ProviderAPIError(f"Gemini request failed: {sanitized}") from exc

        # Extract tool / function calls if present
        tool_calls: Optional[list[ToolCallRequest]] = None
        raw_func_calls = getattr(response, "function_calls", None)
        if raw_func_calls:
            tool_calls = [
                ToolCallRequest(
                    name=getattr(fc, "name", ""),
                    args=dict(getattr(fc, "args", {})) if getattr(fc, "args", None) else {},
                )
                for fc in raw_func_calls
            ]

        # Extract text response
        text = response.text if hasattr(response, "text") and response.text is not None else ""

        # Check for safety filter blocks or empty candidates (only if no tool calls)
        if not text and not tool_calls:
            candidates = getattr(response, "candidates", None)
            if candidates and len(candidates) > 0:
                first_cand = candidates[0]
                finish_reason = getattr(first_cand, "finish_reason", None)
                if finish_reason and str(finish_reason).upper() != "STOP":
                    raise ProviderAPIError(
                        f"Gemini generation stopped unexpectedly with reason: {finish_reason}",
                        details={"finish_reason": str(finish_reason)},
                    )
            # If no candidates or text and no tool calls
            if not text:
                raise ProviderAPIError("Gemini returned an empty response with no text content.")

        # Extract usage metrics if available
        usage: Optional[ProviderUsage] = None
        usage_meta = getattr(response, "usage_metadata", None)
        if usage_meta:
            usage = ProviderUsage(
                prompt_tokens=getattr(usage_meta, "prompt_token_count", None),
                completion_tokens=getattr(usage_meta, "candidates_token_count", None),
                total_tokens=getattr(usage_meta, "total_token_count", None),
            )

        metadata: Dict[str, Any] = {
            "model_version": getattr(response, "model_version", None),
            "response_id": getattr(response, "response_id", None),
        }

        return LLMResponse(
            provider=self.provider_name,
            model=self.model_name,
            response=text,
            tool_calls=tool_calls,
            usage=usage,
            metadata=metadata,
        )

    async def check_status(self) -> ProviderStatus:
        """Check provider configuration status without making external API calls."""
        is_configured = bool(self._api_key and self._api_key.strip())
        if not is_configured:
            return ProviderStatus(
                provider=self.provider_name,
                model=self.model_name,
                is_configured=False,
                status="not_configured",
                details="GEMINI_API_KEY is not set. Configure it in .env to enable Gemini testing.",
            )

        return ProviderStatus(
            provider=self.provider_name,
            model=self.model_name,
            is_configured=True,
            status="ready",
            details="Gemini provider configured with valid API key format.",
        )

    async def test_connectivity(self) -> ProviderStatus:
        """Perform a live roundtrip probe to verify Gemini API connectivity.

        Does not mock responses; verifies real network and credentials.
        """
        status = await self.check_status()
        if not status.is_configured:
            return status

        try:
            # Perform a minimal test call
            res = await self.generate(prompt="Respond with 'PONG' only.", max_tokens=10)
            return ProviderStatus(
                provider=self.provider_name,
                model=self.model_name,
                is_configured=True,
                status="connected",
                details=f"Connectivity test succeeded. Upstream model: {res.model}",
            )
        except Exception as exc:
            sanitized = _sanitize_error_message(str(exc))
            return ProviderStatus(
                provider=self.provider_name,
                model=self.model_name,
                is_configured=True,
                status="error",
                details=f"Connectivity probe failed: {sanitized}",
            )


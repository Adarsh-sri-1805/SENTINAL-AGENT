"""Unit and integration tests for LLM Sentinel providers and API routes.

All unit tests use mocked responses and do NOT make paid external API calls.
Live connectivity tests are separated and marked with @pytest.mark.live.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.api.routes import get_active_provider
from app.config import Settings
from app.main import app
from app.providers.base import (
    LLMProvider,
    LLMResponse,
    ProviderAPIError,
    ProviderConfigError,
    ProviderStatus,
    ProviderUsage,
)
from app.providers.gemini import GeminiProvider, _sanitize_error_message


# =====================================================================
# Unit Tests: LLMProvider Abstract Interface
# =====================================================================

def test_abstract_llm_provider_cannot_be_instantiated():
    """Verify that LLMProvider enforces interface implementation."""
    with pytest.raises(TypeError):
        LLMProvider()  # type: ignore


# =====================================================================
# Unit Tests: GeminiProvider (Mocked)
# =====================================================================

def test_gemini_provider_init_and_properties():
    """Verify provider initialization and property getters."""
    provider = GeminiProvider(api_key="test-key-123", model="gemini-2.5-flash")
    assert provider.provider_name == "gemini"
    assert provider.model_name == "gemini-2.5-flash"
    assert provider.api_key == "test-key-123"


def test_gemini_provider_missing_key_status():
    """Verify status check when GEMINI_API_KEY is not configured."""
    provider = GeminiProvider(api_key="", model="gemini-2.5-flash")
    # check_status is async
    import asyncio
    status = asyncio.run(provider.check_status())
    assert status.is_configured is False
    assert status.status == "not_configured"
    assert "GEMINI_API_KEY is not set" in (status.details or "")


def test_gemini_provider_configured_status():
    """Verify status check when GEMINI_API_KEY is present."""
    provider = GeminiProvider(api_key="valid-dummy-key", model="gemini-2.5-flash")
    import asyncio
    status = asyncio.run(provider.check_status())
    assert status.is_configured is True
    assert status.status == "ready"


def test_gemini_provider_generate_empty_prompt_raises_value_error():
    """Verify that an empty prompt raises ValueError without making API calls."""
    provider = GeminiProvider(api_key="valid-dummy-key")
    import asyncio
    with pytest.raises(ValueError, match="Prompt must not be empty"):
        asyncio.run(provider.generate(prompt="   "))


def test_gemini_provider_generate_missing_key_raises_config_error():
    """Verify that generate() raises ProviderConfigError when key is missing."""
    provider = GeminiProvider(api_key="")
    import asyncio
    with pytest.raises(ProviderConfigError, match="GEMINI_API_KEY is not configured"):
        asyncio.run(provider.generate(prompt="Hello"))


def test_gemini_provider_generate_success_mocked():
    """Verify successful generation with mocked google-genai client."""
    mock_response = MagicMock()
    mock_response.text = "Mocked LLM Sentinel Response: Security probe passed."
    mock_response.model_version = "gemini-2.5-flash-test"
    mock_response.response_id = "resp-987"
    mock_response.usage_metadata.prompt_token_count = 15
    mock_response.usage_metadata.candidates_token_count = 30
    mock_response.usage_metadata.total_token_count = 45

    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

    provider = GeminiProvider(
        api_key="dummy-test-key",
        model="gemini-2.5-flash",
        client=mock_client,
    )

    import asyncio
    result = asyncio.run(
        provider.generate(
            prompt="Analyze prompt injection vulnerability",
            system_instruction="You are a security tester",
            temperature=0.3,
            max_tokens=256,
        )
    )

    # Verify return types and payload
    assert isinstance(result, LLMResponse)
    assert result.provider == "gemini"
    assert result.model == "gemini-2.5-flash"
    assert result.response == "Mocked LLM Sentinel Response: Security probe passed."
    assert result.usage is not None
    assert result.usage.prompt_tokens == 15
    assert result.usage.completion_tokens == 30
    assert result.usage.total_tokens == 45

    # Verify mock was called with correct parameters
    mock_client.aio.models.generate_content.assert_awaited_once()
    call_kwargs = mock_client.aio.models.generate_content.call_args.kwargs
    assert call_kwargs["model"] == "gemini-2.5-flash"
    assert call_kwargs["contents"] == "Analyze prompt injection vulnerability"
    assert call_kwargs["config"].temperature == 0.3
    assert call_kwargs["config"].max_output_tokens == 256
    assert call_kwargs["config"].system_instruction == "You are a security tester"


def test_gemini_provider_generate_failure_raises_provider_api_error_no_silent_fallback():
    """Verify that when Gemini API fails, ProviderAPIError is raised and NO silent fallback occurs."""
    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(
        side_effect=Exception("Simulated upstream 503 service unavailable")
    )

    provider = GeminiProvider(
        api_key="dummy-test-key",
        model="gemini-2.5-flash",
        client=mock_client,
    )

    import asyncio
    with pytest.raises(ProviderAPIError) as exc_info:
        asyncio.run(provider.generate(prompt="Trigger vulnerability scan"))

    # Assert that no mock fallback occurred
    assert "Simulated upstream 503 service unavailable" in str(exc_info.value)


def test_api_key_sanitization_in_errors():
    """Verify that credentials are sanitized and not leaked in error messages."""
    raw_error = "API key AIzaSyD1234567890abcdefghijklmnopqrstuv was rejected."
    sanitized = _sanitize_error_message(raw_error)
    assert "AIza" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized


# =====================================================================
# Unit Tests: FastAPI Endpoints (TestClient)
# =====================================================================

@pytest.fixture
def client():
    """TestClient fixture with dependencies clean."""
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_get_root_health_endpoint(client: TestClient):
    """Verify GET /health returns 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "LLM Sentinel"
    assert "version" in data


def test_get_api_health_endpoint(client: TestClient):
    """Verify GET /api/health returns 200 OK."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_get_provider_status_endpoint(client: TestClient):
    """Verify GET /api/provider/status returns provider status."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.check_status = AsyncMock(
        return_value=ProviderStatus(
            provider="gemini",
            model="gemini-2.5-flash",
            is_configured=True,
            status="ready",
            details="Mocked provider ready.",
        )
    )

    app.dependency_overrides[get_active_provider] = lambda: mock_provider

    response = client.get("/api/provider/status")
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "gemini"
    assert data["model"] == "gemini-2.5-flash"
    assert data["is_configured"] is True
    assert data["status"] == "ready"


def test_post_chat_endpoint_success(client: TestClient):
    """Verify POST /api/chat returns model response when provider succeeds."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.generate = AsyncMock(
        return_value=LLMResponse(
            provider="gemini",
            model="gemini-2.5-flash",
            response="LLM Sentinel probe acknowledgment.",
            usage=ProviderUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        )
    )

    app.dependency_overrides[get_active_provider] = lambda: mock_provider

    payload = {
        "message": "Verify OWASP LLM01 Prompt Injection vulnerability",
        "temperature": 0.5,
        "max_tokens": 100,
    }
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "gemini"
    assert data["response"] == "LLM Sentinel probe acknowledgment."
    assert data["usage"]["total_tokens"] == 30


def test_post_chat_endpoint_validation_empty_message(client: TestClient):
    """Verify POST /api/chat rejects empty payload with 422 Unprocessable Entity."""
    response = client.post("/api/chat", json={"message": ""})
    assert response.status_code == 422


def test_post_chat_endpoint_unconfigured_provider(client: TestClient):
    """Verify POST /api/chat returns 503 when provider is not configured."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.generate = AsyncMock(
        side_effect=ProviderConfigError("GEMINI_API_KEY is not configured.")
    )

    app.dependency_overrides[get_active_provider] = lambda: mock_provider

    response = client.post("/api/chat", json={"message": "Test message"})
    assert response.status_code == 503
    assert "Provider is not configured" in response.json()["detail"]


def test_post_chat_endpoint_upstream_failure(client: TestClient):
    """Verify POST /api/chat returns 502 Bad Gateway when provider fails."""
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.generate = AsyncMock(
        side_effect=ProviderAPIError("Gemini service unavailable")
    )

    app.dependency_overrides[get_active_provider] = lambda: mock_provider

    response = client.post("/api/chat", json={"message": "Test message"})
    assert response.status_code == 502
    assert "Upstream LLM provider error" in response.json()["detail"]


# =====================================================================
# Live Connectivity Test (Requires manual execution with GEMINI_API_KEY)
# =====================================================================

@pytest.mark.live
def test_live_gemini_connectivity():
    """Separate live connectivity test verifying real Gemini API access.

    Skipped automatically unless GEMINI_API_KEY is configured in the environment.
    Run manually with: pytest -m live
    """
    from app.config import get_settings
    settings = get_settings()
    api_key = settings.gemini_api_key or os.getenv("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("Skipping live test: GEMINI_API_KEY environment variable is not set.")

    provider = GeminiProvider(api_key=api_key)
    import asyncio
    status = asyncio.run(provider.test_connectivity())

    assert status.is_configured is True
    assert status.status == "connected", f"Live connectivity failed: {status.details}"


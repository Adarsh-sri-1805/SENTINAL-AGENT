"""Application configuration module using Pydantic Settings."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    """Central configuration for LLM Sentinel backend."""

    model_config = SettingsConfigDict(
        env_file=(str(_ENV_PATH), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General App Settings
    app_name: str = Field(default="LLM Sentinel", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    app_env: str = Field(default="development", description="Runtime environment")
    debug: bool = Field(default=False, description="Debug mode")

    # LLM Provider Settings
    llm_provider: str = Field(
        default="gemini",
        description="Active LLM provider identifier (e.g. gemini, claude)",
    )
    gemini_api_key: Optional[str] = Field(
        default=None,
        description="Google Gemini API key",
        repr=False,  # Prevent exposing key in logs/repr
    )
    gemini_model: str = Field(
        default="gemini-3.1-flash-lite-preview",
        description="Google Gemini model identifier",
    )

    # Operational Settings
    request_timeout_seconds: float = Field(
        default=60.0,
        description="LLM provider HTTP request timeout in seconds",
    )

    @property
    def is_gemini_configured(self) -> bool:
        """Check if Gemini API key is configured."""
        return bool(self.gemini_api_key and self.gemini_api_key.strip())

    def get_safe_status(self) -> dict:
        """Return safe provider status metadata without exposing credentials."""
        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "llm_provider": self.llm_provider,
            "gemini_model": self.gemini_model,
            "gemini_api_key_configured": self.is_gemini_configured,
        }


@lru_cache()
def get_settings() -> Settings:
    """Dependency provider returning cached Settings instance."""
    return Settings()


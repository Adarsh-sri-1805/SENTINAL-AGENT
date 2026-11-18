"""Security mode state management (vulnerable vs protected)."""

from typing import Literal
from pydantic import BaseModel, Field

SecurityMode = Literal["vulnerable", "protected"]


class SecurityModeState(BaseModel):
    """Schema representing current security operating mode."""

    mode: SecurityMode = Field(..., description="Active security posture: 'vulnerable' or 'protected'")
    description: str = Field(..., description="Description of the mode's behavior")


class _SecurityModeHolder:
    """Singleton holder for application security mode."""

    def __init__(self, default_mode: SecurityMode = "vulnerable") -> None:
        self._mode: SecurityMode = default_mode

    def get_mode(self) -> SecurityMode:
        return self._mode

    def set_mode(self, mode: str) -> SecurityMode:
        normalized = mode.lower().strip()
        if normalized not in ("vulnerable", "protected"):
            raise ValueError(f"Invalid security mode '{mode}'. Must be 'vulnerable' or 'protected'.")
        self._mode = normalized  # type: ignore[assignment]
        return self._mode

    def get_state(self) -> SecurityModeState:
        descriptions = {
            "vulnerable": (
                "Intentionally relaxed security controls. Permissive system instructions, "
                "unfiltered document retrieval, and unrestricted tool execution (with strict host/network containment)."
            ),
            "protected": (
                "Hardened security posture. Strict system instructions, restricted public-only retrieval, "
                "strict user RBAC, destination allowlisting, and output redaction."
            ),
        }
        return SecurityModeState(
            mode=self._mode,
            description=descriptions[self._mode],
        )


_global_mode_holder = _SecurityModeHolder()


def get_current_security_mode() -> SecurityMode:
    """Retrieve global security mode."""
    return _global_mode_holder.get_mode()


def set_security_mode(mode: str) -> SecurityMode:
    """Update global security mode."""
    return _global_mode_holder.set_mode(mode)


def get_security_mode_state() -> SecurityModeState:
    """Retrieve full security mode state with description."""
    return _global_mode_holder.get_state()


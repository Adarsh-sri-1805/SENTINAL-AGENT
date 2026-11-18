"""Tool authorization policy engine.

Enforces role-based access control and tool allowlists OUTSIDE the LLM.
"""

from typing import Any, Dict, Optional, Tuple
from app.fixtures.users import User, UserRole
from app.security.mitigations import is_mitigation_active


class SecurityPolicyEngine:
    """Evaluates whether a requested tool call is authorized for a given user and mode."""

    @staticmethod
    def authorize(
        user: User,
        tool_name: str,
        arguments: Dict[str, Any],
        mode: str,
    ) -> Tuple[bool, Optional[str]]:
        """Authorize a tool call.

        Args:
            user: User requesting execution.
            tool_name: Name of tool to execute.
            arguments: Tool arguments.
            mode: Active security mode ('vulnerable' or 'protected').

        Returns:
            Tuple[bool, Optional[str]]: (is_authorized, denial_reason).
        """
        # Determine if tool mitigation is active for this invocation
        # Checks general mode or specific risk mitigation toggles
        tool_policy_active = (
            mode == "protected"
            or is_mitigation_active("ASI02", mode)
            or is_mitigation_active("LLM03", mode)
            or (tool_name == "execute_code" and is_mitigation_active("ASI05", mode))
        )

        # In vulnerable mode with no mitigation toggled, allow application-level weaknesses
        # Note: Tool implementations always preserve hard filesystem containment and network isolation.
        if not tool_policy_active:
            return True, None

        # --- Protected Mode / Mitigation Active ---
        # Enforces strict role-based access control and parameter constraints.
        role = user.role

        if tool_name == "read_file":
            filepath = str(arguments.get("filepath", "")).lower()
            # Restricted directory requires admin
            if "restricted" in filepath or "credential" in filepath or "financial" in filepath:
                if role != "admin":
                    return (
                        False,
                        f"Permission denied: User '{user.user_id}' with role '{role}' is not authorized to access restricted documents.",
                    )
            # Public files can be read by employees and admins; guests are denied by default
            if role == "guest":
                return (
                    False,
                    f"Permission denied: Guest users are not authorized to use filesystem tools in protected mode.",
                )
            return True, None

        elif tool_name == "send_email":
            if role == "guest":
                return (
                    False,
                    f"Permission denied: Guest users are not permitted to send corporate emails in protected mode.",
                )
            # Recipient domain validation: strictly internal domains only
            recipient = str(arguments.get("to", "")).lower().strip()
            allowed_domains = ("@omnicorp.com", "@support.omnicorp.com")
            if not any(recipient.endswith(d) for d in allowed_domains):
                return (
                    False,
                    f"Security policy violation: Exfiltration blocked. Recipient '{recipient}' is not an authorized OmniCorp domain.",
                )
            return True, None

        elif tool_name == "http_request":
            if role == "guest":
                return (
                    False,
                    f"Permission denied: Guest users are not authorized to invoke internal HTTP services.",
                )
            url = str(arguments.get("url", "")).lower().strip()
            # Metadata endpoint is strictly blocked as an SSRF prevention rule
            if "metadata" in url:
                return (
                    False,
                    "Security policy violation: Access to cloud instance metadata services is strictly forbidden (SSRF protection).",
                )
            return True, None

        elif tool_name == "execute_code":
            # Code execution strictly restricted to admin role in protected mode
            if role != "admin":
                return (
                    False,
                    f"Permission denied: Code execution requires 'admin' role. User '{user.user_id}' has role '{role}'.",
                )
            return True, None

        return False, f"Unknown tool '{tool_name}' rejected by default policy."


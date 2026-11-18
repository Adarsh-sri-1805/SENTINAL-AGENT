"""Sensitive data redactor for logs, outputs, and audit records."""

import re
from typing import Any, Dict, List, Union

# Regex patterns for sensitive identifiers
_PATTERNS = [
    # Harmless secret flags (Chatbot & Agent targets)
    (re.compile(r"SECRET-FLAG-[A-Za-z0-9_\-]+", re.IGNORECASE), "[REDACTED_SECRET_FLAG]"),
    (re.compile(r"AGENT-FLAG-[A-Za-z0-9_\-]+", re.IGNORECASE), "[REDACTED_AGENT_FLAG]"),
    # Credit card numbers (standard 16-digit formats)
    (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[REDACTED_PAYMENT_CARD]"),
    # Google API Keys
    (re.compile(r"AIza[0-9A-Za-z-_]{35}"), "[REDACTED_API_KEY]"),
    # Cloud secret tokens / mock IAM credentials
    (re.compile(r"MOCK-AWS-SECRET-TOKEN-[A-Za-z0-9_\-]+", re.IGNORECASE), "[REDACTED_IAM_TOKEN]"),
]


def redact_sensitive_data(text: str) -> str:
    """Redact confidential flags, PII, payment cards, and credentials from a string."""
    if not isinstance(text, str):
        return text

    sanitized = text
    for pattern, replacement in _PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_data_structure(data: Any) -> Any:
    """Recursively redact sensitive data within dictionaries, lists, and strings."""
    if isinstance(data, str):
        return redact_sensitive_data(data)
    elif isinstance(data, dict):
        return {k: redact_data_structure(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_data_structure(item) for item in data]
    return data


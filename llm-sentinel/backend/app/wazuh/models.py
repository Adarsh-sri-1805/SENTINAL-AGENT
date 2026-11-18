"""Domain models and schemas for Wazuh SIEM integration and Dashboard metrics."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Wazuh SIEM Integration Models
# =============================================================================

class WazuhStatus(BaseModel):
    """Runtime status of Wazuh SIEM integration."""

    connected: bool = Field(default=False, description="Whether an active Wazuh agent or manager was detected")
    status_text: str = Field(default="NOT CONNECTED", description="Human-readable status text")
    agent_installed: bool = Field(default=False, description="Whether Wazuh agent service is installed on host")
    manager_detected: bool = Field(default=False, description="Whether Wazuh manager socket/API is reachable")
    log_file_path: str = Field(..., description="Target JSONL log forwarding file path")
    total_events_exported: int = Field(default=0, description="Total security events written to log collector file")
    last_export_timestamp: Optional[str] = Field(default=None, description="ISO timestamp of last event export")
    details: str = Field(..., description="Configuration and connectivity details")


class WazuhExportResponse(BaseModel):
    """Result of exporting security audit events to Wazuh JSONL log file."""

    success: bool = Field(..., description="Whether export succeeded")
    events_exported: int = Field(..., description="Number of events written to JSONL")
    file_path: str = Field(..., description="Path to exported JSONL file")
    timestamp: str = Field(..., description="Export timestamp")
    sample_event: Optional[Dict[str, Any]] = Field(default=None, description="Sample structured event payload")


class WazuhAlertItem(BaseModel):
    """Structured security alert formatted for Wazuh SIEM."""

    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(..., description="Event timestamp")
    rule_id: str = Field(..., description="Wazuh rule ID (e.g. 100101)")
    rule_level: int = Field(..., description="Wazuh rule alert level (3 to 15)")
    rule_description: str = Field(..., description="Rule description")
    category: str = Field(..., description="Alert classification category")
    risk_id: Optional[str] = Field(default=None, description="Related OWASP risk ID")
    source: str = Field(..., description="Source application (Chatbot, Agent, MCP)")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    action_taken: str = Field(..., description="BLOCKED, MONITORED, or DENIED")
    details: Dict[str, Any] = Field(default_factory=dict, description="Redacted event metadata")


class WazuhAlertsResponse(BaseModel):
    """List of Wazuh alerts or offline simulated rule matches."""

    total_alerts: int = Field(..., description="Total alerts")
    connected: bool = Field(..., description="Whether connected to live Wazuh manager")
    message: str = Field(..., description="Connection status notification")
    alerts: List[WazuhAlertItem] = Field(default_factory=list, description="List of alert items")


# =============================================================================
# Dashboard Overview & Aggregation Models
# =============================================================================

class DashboardOverview(BaseModel):
    """Aggregated cybersecurity overview metrics for SOC dashboard."""

    total_tests_executed: int = Field(..., description="Total automated security test executions")
    blocked: int = Field(..., description="Total attacks successfully blocked")
    partial: int = Field(..., description="Partially mitigated attacks")
    succeeded: int = Field(..., description="Successful attacks (security failures)")
    attack_success_rate: float = Field(..., description="Overall Attack Success Rate (ASR %)")
    blocking_rate: float = Field(..., description="Overall attack blocking rate (%)")
    mitigation_effectiveness: float = Field(..., description="Percentage of attacks mitigated")
    active_security_mode: str = Field(..., description="'vulnerable' or 'protected'")
    total_mcp_events: int = Field(default=0, description="Total MCP events logged")
    mcp_improvement: float = Field(default=0.0, description="MCP security posture improvement (%)")


class RiskDistributionItem(BaseModel):
    """Risk-specific metrics for distribution charts."""

    risk_id: str = Field(..., description="Risk identifier (e.g. LLM01, ASI01, MCP-01)")
    risk_name: str = Field(..., description="Descriptive risk name")
    category: str = Field(..., description="OWASP LLM 2026, OWASP Agentic AI 2026, or MCP Protocol")
    total: int = Field(default=0)
    blocked: int = Field(default=0)
    partial: int = Field(default=0)
    succeeded: int = Field(default=0)
    asr: float = Field(default=0.0, description="Attack Success Rate (%)")


class RecentSecurityEvent(BaseModel):
    """Unified security event entry for the live dashboard feed."""

    event_id: str = Field(..., description="Unique event identifier")
    timestamp: str = Field(..., description="ISO timestamp")
    source: str = Field(..., description="Chatbot, Agent, MCP, PolicyEngine")
    event_type: str = Field(..., description="Attack execution, Tool invocation, RBAC rejection")
    risk_id: Optional[str] = Field(default=None)
    risk_name: Optional[str] = Field(default=None)
    severity: str = Field(default="MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    action_taken: str = Field(..., description="BLOCKED, PERMITTED, DENIED, FLAGGED")
    status: str = Field(..., description="BLOCKED, PARTIAL, SUCCEEDED")
    details: str = Field(..., description="Redacted summary description")

"""Pydantic schemas and domain models for the MCP subsystem."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from app.security.mode import SecurityMode
from app.testing.models import TestResultStatus


# =============================================================================
# 1. Server & Discovery Schemas
# =============================================================================

class MCPToolInfo(BaseModel):
    """Discovered MCP tool metadata."""

    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description provided by MCP server")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="JSON Schema of parameters")
    required_role: str = Field(default="guest", description="Minimum role required for execution")
    is_sensitive: bool = Field(default=False, description="Whether the tool performs privileged operations")


class MCPResourceInfo(BaseModel):
    """Discovered MCP resource metadata."""

    uri: str = Field(..., description="Unique resource URI (e.g. company://policies)")
    name: str = Field(..., description="Resource display name")
    description: Optional[str] = Field(default=None, description="Resource description")
    mime_type: str = Field(default="text/plain", description="MIME type of resource content")


class MCPPromptInfo(BaseModel):
    """Discovered MCP prompt template metadata."""

    name: str = Field(..., description="Prompt template identifier")
    description: Optional[str] = Field(default=None, description="Template description")
    arguments: List[Dict[str, Any]] = Field(default_factory=list, description="Template parameters")


class MCPServerStatus(BaseModel):
    """Runtime status of the MCP client and connected server."""

    connected: bool = Field(..., description="Whether a client session is active")
    server_id: str = Field(..., description="Connected or target server identifier")
    server_name: Optional[str] = Field(default=None, description="Server implementation name")
    server_version: Optional[str] = Field(default=None, description="Server protocol/impl version")
    transport: str = Field(..., description="Transport mechanism: 'stdio' or 'memory'")
    security_mode: SecurityMode = Field(..., description="Active security posture ('vulnerable' or 'protected')")
    is_trusted: bool = Field(..., description="Whether the connected server is in the trusted allowlist")
    tools_count: int = Field(default=0, description="Number of discovered tools")
    resources_count: int = Field(default=0, description="Number of discovered resources")
    prompts_count: int = Field(default=0, description="Number of discovered prompt templates")


class MCPConnectRequest(BaseModel):
    """Payload to establish connection with an MCP server."""

    server_id: str = Field(default="omnicorp-mcp-server", description="Server identifier to connect to")
    transport: Literal["memory", "stdio"] = Field(default="memory", description="Transport type")
    mode: Optional[SecurityMode] = Field(default=None, description="Security mode override ('vulnerable' or 'protected')")


class MCPToolInvokeRequest(BaseModel):
    """Payload to invoke a tool through MCP protocol."""

    tool_name: str = Field(..., description="Name of tool to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments dictionary")
    user_id: str = Field(default="guest", description="Requesting user ID")
    mode: Optional[SecurityMode] = Field(default=None, description="Security mode override")


class MCPToolInvokeResponse(BaseModel):
    """Response returned from MCP tool invocation."""

    tool_name: str = Field(..., description="Tool name")
    arguments: Dict[str, Any] = Field(..., description="Arguments passed")
    success: bool = Field(..., description="Whether execution completed successfully")
    output: Optional[Any] = Field(default=None, description="Output returned by MCP server")
    error: Optional[str] = Field(default=None, description="Error message if failed or denied")
    authorized: bool = Field(..., description="Whether tool execution was authorized")
    security_decision: str = Field(..., description="Policy decision: 'PERMITTED' or 'DENIED'")
    timestamp: str = Field(..., description="Execution timestamp")


# =============================================================================
# 2. Security Monitoring Schemas
# =============================================================================

class MCPSecurityEvent(BaseModel):
    """Audit log entry for an MCP security event."""

    id: Optional[int] = Field(default=None, description="Event ID")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    event_type: str = Field(
        ...,
        description="Type: server_connect, tool_discover, resource_read, tool_invoke, auth_denied, action_blocked, invalid_arguments",
    )
    server_id: str = Field(..., description="MCP server involved")
    tool_name: Optional[str] = Field(default=None, description="Tool name if applicable")
    resource_uri: Optional[str] = Field(default=None, description="Resource URI if applicable")
    user_id: str = Field(default="system", description="Caller user ID")
    user_role: str = Field(default="guest", description="Caller role")
    security_mode: str = Field(..., description="'vulnerable' or 'protected'")
    authorized: bool = Field(default=True, description="Whether action was authorized")
    details: str = Field(default="", description="Detailed event description")


# =============================================================================
# 3. Security Attack Scenarios & Evaluation Schemas
# =============================================================================

class MCPTestCase(BaseModel):
    """Specification of an MCP security test case."""

    __test__ = False
    test_id: str = Field(..., description="Identifier: MCP-01 to MCP-06")
    attack_name: str = Field(..., description="Name of attack scenario")
    attack_description: str = Field(..., description="Adversarial attack mechanics")
    server_id: str = Field(..., description="Target server ID")
    tool_or_resource: str = Field(..., description="Tool name or resource URI involved")
    attack_input: Any = Field(..., description="Adversarial input or prompt")
    expected_secure_behavior: str = Field(..., description="Expected behavior when protected")
    attack_objective: str = Field(..., description="Adversary's malicious goal")
    severity: str = Field(default="HIGH", description="Risk rating: MEDIUM, HIGH, CRITICAL")


class MCPTestResult(BaseModel):
    """Outcome of an individual MCP security test."""

    __test__ = False
    test_id: str = Field(..., description="Test ID")
    attack_name: str = Field(..., description="Attack scenario name")
    mode: str = Field(..., description="Security mode evaluated ('vulnerable' or 'protected')")
    status: TestResultStatus = Field(..., description="BLOCKED, PARTIAL, or SUCCEEDED")
    explanation: str = Field(..., description="Evaluation rationale based on telemetry")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Captured telemetry evidence")
    security_decision: str = Field(..., description="Security action taken")
    timestamp: str = Field(..., description="Execution timestamp")


class MCPComparisonDetail(BaseModel):
    """Comparative evaluation summary of MCP attacks across vulnerable and protected modes."""

    __test__ = False
    comparison_id: str = Field(..., description="Comparison identifier")
    timestamp: str = Field(..., description="Evaluation timestamp")
    total_tests: int = Field(..., description="Total tests compared")
    baseline_blocked: int = Field(default=0)
    baseline_partial: int = Field(default=0)
    baseline_succeeded: int = Field(default=0)
    protected_blocked: int = Field(default=0)
    protected_partial: int = Field(default=0)
    protected_succeeded: int = Field(default=0)
    baseline_asr: float = Field(..., description="Baseline Attack Success Rate (%)")
    protected_asr: float = Field(..., description="Protected Attack Success Rate (%)")
    baseline_blocking_rate: float = Field(..., description="Baseline Blocking Rate (%)")
    protected_blocking_rate: float = Field(..., description="Protected Blocking Rate (%)")
    overall_improvement: float = Field(..., description="ASR reduction (Baseline ASR - Protected ASR)")
    test_comparisons: List[Dict[str, Any]] = Field(default_factory=list)

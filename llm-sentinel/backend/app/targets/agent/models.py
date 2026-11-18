"""Pydantic schemas for the AI agent target."""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from app.security.mode import SecurityMode


class ToolInvocationRecord(BaseModel):
    """Record of an individual tool call during an agent execution."""

    tool_name: str = Field(..., description="Name of the invoked tool")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments passed to tool")
    authorized: bool = Field(..., description="Whether authorization was granted")
    success: bool = Field(..., description="Whether execution succeeded")
    output: Optional[Any] = Field(default=None, description="Tool output if successful")
    error: Optional[str] = Field(default=None, description="Error message if failed or denied")
    timestamp: str = Field(..., description="Execution timestamp")


class AgentRunRequest(BaseModel):
    """Request payload to initiate an agent run."""

    task: str = Field(
        ...,
        min_length=1,
        description="The task or instruction for the agent to execute",
        examples=["Read the acceptable use policy in public/acceptable_use_policy.txt"],
    )
    user_id: Optional[str] = Field(
        default="guest",
        description="User ID executing the task (e.g. 'guest', 'employee', 'admin')",
    )
    mode: Optional[SecurityMode] = Field(
        default=None,
        description="Optional security mode override ('vulnerable' or 'protected')",
    )
    max_steps: Optional[int] = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum tool calling iterations",
    )


class AgentRunResponse(BaseModel):
    """Response payload returned from an agent task execution."""

    task: str = Field(..., description="Original user task")
    user_id: str = Field(..., description="User ID")
    user_role: str = Field(..., description="Resolved user role")
    mode: str = Field(..., description="Active security mode")
    final_answer: str = Field(..., description="Final textual answer or summary from the agent")
    tool_invocations: List[ToolInvocationRecord] = Field(
        default_factory=list, description="Trace of all tool invocations and results"
    )
    status: Literal["completed", "max_steps_reached", "error"] = Field(
        ..., description="Execution completion status"
    )
    timestamp: str = Field(..., description="Completion timestamp")


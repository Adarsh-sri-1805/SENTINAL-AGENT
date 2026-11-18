"""Base tool definition and schemas."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Normalized output from a tool execution."""

    success: bool = Field(..., description="Whether tool execution completed without error")
    output: Optional[Any] = Field(default=None, description="Tool execution result data")
    error: Optional[str] = Field(default=None, description="Error message if execution failed")


class BaseTool(ABC):
    """Abstract base class for agent tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name used in LLM function calling."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description provided to LLM."""
        pass

    @property
    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """JSON Schema of tool arguments."""
        pass

    @property
    @abstractmethod
    def required_role(self) -> str:
        """Minimum user role required in protected mode."""
        pass

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with provided arguments."""
        pass

    def to_gemini_declaration(self) -> Dict[str, Any]:
        """Export tool declaration in Gemini FunctionDeclaration schema."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters_schema,
        }


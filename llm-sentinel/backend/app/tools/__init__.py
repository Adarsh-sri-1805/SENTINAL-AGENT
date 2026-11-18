"""Tools package and central registry."""

from typing import Any, Dict, List, Optional
from app.tools.base import BaseTool, ToolResult
from app.tools.execute_code import ExecuteCodeTool
from app.tools.http_request import HttpRequestTool
from app.tools.read_file import ReadFileTool
from app.tools.send_email import SendEmailTool

__all__ = [
    "BaseTool",
    "ToolResult",
    "ReadFileTool",
    "SendEmailTool",
    "HttpRequestTool",
    "ExecuteCodeTool",
    "ToolRegistry",
    "get_default_registry",
]


class ToolRegistry:
    """Registry managing available tools and their schema exports."""

    def __init__(self) -> None:
        self._tools: Dict[str, BaseTool] = {}
        # Register standard suite
        self.register(ReadFileTool())
        self.register(SendEmailTool())
        self.register(HttpRequestTool())
        self.register(ExecuteCodeTool())

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_all(self) -> List[BaseTool]:
        return list(self._tools.values())

    def get_tool_metadata(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters_schema,
                "required_role": t.required_role,
            }
            for t in self._tools.values()
        ]

    def get_gemini_declarations(self) -> List[Dict[str, Any]]:
        return [t.to_gemini_declaration() for t in self._tools.values()]


_default_registry = ToolRegistry()


def get_default_registry() -> ToolRegistry:
    """Return singleton tool registry."""
    return _default_registry


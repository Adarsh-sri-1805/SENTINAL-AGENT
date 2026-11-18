"""Tool to read files from the dedicated fake company directory with strict traversal containment."""

from pathlib import Path
from typing import Any, Dict
from app.tools.base import BaseTool, ToolResult

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "company_files"


class ReadFileTool(BaseTool):
    """File reader tool restricted to company fixtures directory."""

    @property
    def name(self) -> str:
        return "read_file"

    @property
    def description(self) -> str:
        return (
            "Read the contents of a company document from the internal repository. "
            "Pass relative paths such as 'public/welcome.txt' or 'restricted/credentials.txt'."
        )

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Relative path of the document to read within the company directory",
                }
            },
            "required": ["filepath"],
        }

    @property
    def required_role(self) -> str:
        return "employee"

    async def execute(self, filepath: str = "", **kwargs: Any) -> ToolResult:
        """Read requested file ensuring strict directory containment."""
        if not filepath or not filepath.strip():
            return ToolResult(success=False, error="Filepath argument cannot be empty.")

        clean_path = filepath.strip().replace("\\", "/")
        # Ensure base fixture dir exists
        base_dir = FIXTURE_DIR.resolve()
        target_path = (base_dir / clean_path).resolve()

        # Strict containment check: cannot traverse outside FIXTURE_DIR
        try:
            target_path.relative_to(base_dir)
        except ValueError:
            return ToolResult(
                success=False,
                error=(
                    "Containment violation: Access denied. Path traversal outside the company "
                    "directory is strictly blocked."
                ),
            )

        if not target_path.exists():
            return ToolResult(success=False, error=f"File not found: '{filepath}'.")

        if target_path.is_dir():
            return ToolResult(success=False, error=f"Target path '{filepath}' is a directory, not a file.")

        try:
            content = target_path.read_text(encoding="utf-8")
            return ToolResult(
                success=True,
                output={
                    "filepath": clean_path,
                    "content": content,
                    "bytes": len(content.encode("utf-8")),
                },
            )
        except Exception as exc:
            return ToolResult(success=False, error=f"Failed to read file: {str(exc)}")


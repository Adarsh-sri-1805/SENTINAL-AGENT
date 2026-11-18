"""Tool to execute code strictly inside an isolated Docker sandbox container."""

import logging
import shutil
import subprocess
from typing import Any, Callable, Dict, Optional
from app.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


def is_docker_daemon_available() -> bool:
    """Check if the Docker CLI and daemon are reachable."""
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return proc.returncode == 0
    except Exception:
        return False


class ExecuteCodeTool(BaseTool):
    """Secure code execution tool running exclusively inside a Docker container sandbox."""

    def __init__(self, runner: Optional[Callable[[str, str], ToolResult]] = None) -> None:
        """Initialize ExecuteCodeTool.

        Args:
            runner: Optional custom execution runner (used for dependency injection & testing).
        """
        self._custom_runner = runner

    @property
    def name(self) -> str:
        return "execute_code"

    @property
    def description(self) -> str:
        return (
            "Execute Python code in an isolated, sandboxed environment without network access. "
            "Pass the 'code' string to execute. Requires 'admin' privileges."
        )

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The Python code snippet to execute"},
                "language": {
                    "type": "string",
                    "enum": ["python"],
                    "default": "python",
                    "description": "Programming language",
                },
            },
            "required": ["code"],
        }

    @property
    def required_role(self) -> str:
        return "admin"

    async def execute(self, code: str = "", language: str = "python", **kwargs: Any) -> ToolResult:
        """Execute code strictly inside a Docker sandbox container.

        NEVER executes code on the host machine.
        """
        if not code or not code.strip():
            return ToolResult(success=False, error="Code parameter cannot be empty.")

        if language.lower() != "python":
            return ToolResult(success=False, error=f"Unsupported language '{language}'. Only 'python' is supported.")

        # If a custom runner is injected (e.g. for unit testing)
        if self._custom_runner is not None:
            return self._custom_runner(code, language)

        # Check real Docker daemon availability
        if not is_docker_daemon_available():
            logger.warning("Code execution rejected: Docker daemon is unavailable.")
            return ToolResult(
                success=False,
                error=(
                    "Docker sandbox unavailable: Docker daemon is not running or accessible. "
                    "Untrusted code execution on the host machine is strictly prohibited."
                ),
            )

        # Execute inside Docker with strict resource & network limits:
        # --network none    : Zero network access
        # --memory 128m     : 128 MB RAM ceiling
        # --cpus 0.5        : Half a CPU core maximum
        # --rm              : Auto-remove container upon exit
        # timeout 5s        : Wall-clock execution deadline
        try:
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                "-i",
                "python:3.11-slim",
                "python",
                "-c",
                code,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return ToolResult(
                success=proc.returncode == 0,
                output={
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "exit_code": proc.returncode,
                    "sandbox": "docker",
                    "network_isolated": True,
                },
                error=proc.stderr if proc.returncode != 0 else None,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                error="Execution timed out: Container exceeded maximum allowed runtime (5 seconds).",
            )
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"Sandbox container execution error: {str(exc)}",
            )


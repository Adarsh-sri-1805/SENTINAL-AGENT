"""Agent target package."""

from app.targets.agent.agent import OmniCorpAgent
from app.targets.agent.models import AgentRunRequest, AgentRunResponse, ToolInvocationRecord

__all__ = [
    "OmniCorpAgent",
    "AgentRunRequest",
    "AgentRunResponse",
    "ToolInvocationRecord",
]


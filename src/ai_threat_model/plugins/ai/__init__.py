"""
AI-specific plugins for threat modeling.

This module contains plugins for AI-native system types:
- LLM Applications
- Agentic Systems
- Multi-Agent Systems
- MCP Servers
"""

from .agentic_plugin import AgenticPlugin
from .llm_plugin import LLMPlugin
from .multi_agent_plugin import MultiAgentPlugin

# Plugin instances - these will be registered automatically
llm_plugin = LLMPlugin()
agentic_plugin = AgenticPlugin()
multi_agent_plugin = MultiAgentPlugin()

__all__ = [
    "LLMPlugin",
    "AgenticPlugin",
    "MultiAgentPlugin",
    "llm_plugin",
    "agentic_plugin",
    "multi_agent_plugin",
]

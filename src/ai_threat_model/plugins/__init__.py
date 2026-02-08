"""
Plugin system for threat modeling.

Plugins provide type-specific threat detection capabilities.
"""

from .base_plugin import ThreatModelPlugin, ThreatPattern, ValidationResult
from .registry import PluginRegistry, load_plugins

# Load and register all available plugins
load_plugins()

__all__ = [
    "ThreatModelPlugin",
    "ThreatPattern",
    "ValidationResult",
    "PluginRegistry",
    "load_plugins",
]

"""
Plugin registry for managing and loading threat modeling plugins.

Plugins are automatically discovered and registered based on system type.
"""

from typing import Dict, Optional

from ..core.models import SystemType

from .base_plugin import ThreatModelPlugin


class PluginRegistry:
    """Registry for threat modeling plugins."""

    _plugins: Dict[SystemType, ThreatModelPlugin] = {}

    @classmethod
    def register(cls, plugin: ThreatModelPlugin) -> None:
        """
        Register a plugin.

        Args:
            plugin: Plugin instance to register
        """
        cls._plugins[plugin.system_type] = plugin

    @classmethod
    def get_plugin(cls, system_type: SystemType) -> Optional[ThreatModelPlugin]:
        """
        Get plugin for system type.

        Args:
            system_type: System type to get plugin for

        Returns:
            Plugin instance or None if not found
        """
        return cls._plugins.get(system_type)

    @classmethod
    def list_plugins(cls) -> Dict[SystemType, ThreatModelPlugin]:
        """
        List all registered plugins.

        Returns:
            Dictionary mapping system types to plugins
        """
        return cls._plugins.copy()

    @classmethod
    def clear(cls) -> None:
        """Clear all registered plugins (mainly for testing)."""
        cls._plugins.clear()

    @classmethod
    def is_registered(cls, system_type: SystemType) -> bool:
        """
        Check if plugin is registered for system type.

        Args:
            system_type: System type to check

        Returns:
            True if plugin is registered
        """
        return system_type in cls._plugins


def load_plugins() -> None:
    """
    Load all available plugins.

    This function should be called at startup to register all plugins.
    Plugins are imported and registered automatically.
    """
    # Import plugins to trigger registration
    try:
        from .ai import llm_plugin, agentic_plugin, multi_agent_plugin

        # Register plugins
        PluginRegistry.register(llm_plugin)
        PluginRegistry.register(agentic_plugin)
        PluginRegistry.register(multi_agent_plugin)
    except ImportError as e:
        # Plugins not yet implemented or import error
        import warnings
        warnings.warn(f"Failed to load some plugins: {e}", ImportWarning)

    # Register PLOT4AI plugin (works for all AI types)
    try:
        from .ai.plot4ai_plugin import Plot4AIPlugin

        plot4ai_plugin = Plot4AIPlugin()
        # Register for LLM_APP (can be used for other types too)
        PluginRegistry.register(plot4ai_plugin)
    except ImportError as e:
        import warnings
        warnings.warn(f"Failed to load PLOT4AI plugin: {e}", ImportWarning)

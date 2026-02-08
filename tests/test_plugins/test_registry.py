"""
Tests for plugin registry.
"""

import pytest

from ai_threat_model.core.models import SystemType
from ai_threat_model.plugins.registry import PluginRegistry


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def setup_method(self):
        """Clear registry before each test."""
        PluginRegistry.clear()

    def teardown_method(self):
        """Clear registry after each test."""
        PluginRegistry.clear()

    def test_register_plugin(self):
        """Test registering a plugin."""
        from ai_threat_model.plugins.ai import llm_plugin

        PluginRegistry.register(llm_plugin)
        assert PluginRegistry.is_registered(SystemType.LLM_APP)

    def test_get_plugin(self):
        """Test getting a registered plugin."""
        from ai_threat_model.plugins.ai import llm_plugin

        PluginRegistry.register(llm_plugin)
        plugin = PluginRegistry.get_plugin(SystemType.LLM_APP)
        assert plugin is not None
        assert plugin.system_type == SystemType.LLM_APP

    def test_get_nonexistent_plugin(self):
        """Test getting a plugin that doesn't exist."""
        plugin = PluginRegistry.get_plugin(SystemType.WEB_APP)
        assert plugin is None

    def test_list_plugins(self):
        """Test listing all plugins."""
        from ai_threat_model.plugins.ai import agentic_plugin, llm_plugin

        PluginRegistry.register(llm_plugin)
        PluginRegistry.register(agentic_plugin)

        plugins = PluginRegistry.list_plugins()
        assert len(plugins) == 2
        assert SystemType.LLM_APP in plugins
        assert SystemType.AGENTIC_SYSTEM in plugins

    def test_is_registered(self):
        """Test checking if plugin is registered."""
        from ai_threat_model.plugins.ai import llm_plugin

        assert not PluginRegistry.is_registered(SystemType.LLM_APP)
        PluginRegistry.register(llm_plugin)
        assert PluginRegistry.is_registered(SystemType.LLM_APP)

    def test_load_plugins(self):
        """Test loading plugins."""
        from ai_threat_model.plugins.registry import load_plugins

        load_plugins()
        # Should have loaded at least LLM and Agentic plugins
        assert PluginRegistry.is_registered(SystemType.LLM_APP)
        assert PluginRegistry.is_registered(SystemType.AGENTIC_SYSTEM)

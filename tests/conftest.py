"""
Pytest configuration and shared fixtures.
"""

import pytest


@pytest.fixture(autouse=True)
def reset_plugin_registry():
    """Reset plugin registry before each test."""
    from ai_threat_model.plugins.registry import PluginRegistry, load_plugins

    PluginRegistry.clear()
    # Load plugins after clearing
    load_plugins()
    yield
    PluginRegistry.clear()

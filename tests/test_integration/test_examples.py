"""
Integration tests using example threat models.
"""

import json
from pathlib import Path

import pytest

from ai_threat_model.core.models import ThreatModel


class TestExampleThreatModels:
    """Integration tests for example threat models."""

    @pytest.fixture
    def examples_dir(self):
        """Get examples directory."""
        return Path(__file__).parent.parent.parent / "examples"

    def test_simple_llm_app_loads(self, examples_dir):
        """Test that simple LLM app example loads correctly."""
        example_file = examples_dir / "simple-llm-app.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        assert threat_model.system.name == "Simple LLM Chat App"
        assert threat_model.system.type.value == "llm-app"
        assert len(threat_model.system.components) > 0
        assert len(threat_model.system.data_flows) > 0

    def test_simple_llm_app_validates(self, examples_dir):
        """Test that simple LLM app example validates."""
        example_file = examples_dir / "simple-llm-app.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        errors = threat_model.validate()
        assert len(errors) == 0

    def test_agentic_system_loads(self, examples_dir):
        """Test that agentic system example loads correctly."""
        example_file = examples_dir / "agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        assert threat_model.system.name == "Research Assistant Agent"
        assert threat_model.system.type.value == "agentic-system"
        assert len(threat_model.system.components) > 0
        assert len(threat_model.system.data_flows) > 0

    def test_agentic_system_validates(self, examples_dir):
        """Test that agentic system example validates."""
        example_file = examples_dir / "agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        errors = threat_model.validate()
        assert len(errors) == 0

    def test_example_threat_detection_llm(self, examples_dir):
        """Test threat detection on LLM example."""
        from ai_threat_model.plugins import load_plugins
        from ai_threat_model.plugins.registry import PluginRegistry

        load_plugins()

        example_file = examples_dir / "simple-llm-app.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        plugin = PluginRegistry.get_plugin(threat_model.system.type)

        if plugin:
            threats = plugin.detect_threats(threat_model.system)
            # Should detect some threats
            assert len(threats) > 0
            # Should have LLM-related threats
            threat_categories = [t.category for t in threats]
            assert any(cat.startswith("LLM") for cat in threat_categories)

    def test_example_threat_detection_agentic(self, examples_dir):
        """Test threat detection on agentic example."""
        from ai_threat_model.plugins import load_plugins
        from ai_threat_model.plugins.registry import PluginRegistry

        load_plugins()

        example_file = examples_dir / "agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        plugin = PluginRegistry.get_plugin(threat_model.system.type)

        if plugin:
            threats = plugin.detect_threats(threat_model.system)
            # Should detect some threats
            assert len(threats) > 0
            # Should have agentic-related threats
            threat_categories = [t.category for t in threats]
            assert any(cat.startswith("AGENTIC") for cat in threat_categories)

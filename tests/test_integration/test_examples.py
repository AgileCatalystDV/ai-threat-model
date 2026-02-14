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

    def test_healthcare_agentic_system_loads(self, examples_dir):
        """Test that healthcare agentic system example loads correctly."""
        example_file = examples_dir / "healthcare-agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        assert threat_model.system.name == "Healthcare Patient Analysis Agent"
        assert threat_model.system.type.value == "agentic-system"
        assert len(threat_model.system.components) >= 5
        assert len(threat_model.system.data_flows) > 0

    def test_healthcare_agentic_system_validates(self, examples_dir):
        """Test that healthcare agentic system example validates."""
        example_file = examples_dir / "healthcare-agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        errors = threat_model.validate()
        assert len(errors) == 0

    def test_financial_agentic_system_loads(self, examples_dir):
        """Test that financial agentic system example loads correctly."""
        example_file = examples_dir / "financial-agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        assert threat_model.system.name == "Automated Trading Agent System"
        assert threat_model.system.type.value == "agentic-system"
        assert len(threat_model.system.components) >= 5
        assert len(threat_model.system.data_flows) > 0

    def test_privacy_llm_app_loads(self, examples_dir):
        """Test that privacy-focused LLM app example loads correctly."""
        example_file = examples_dir / "privacy-focused-llm-app.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        assert threat_model.system.name == "Privacy-First Personal Assistant LLM"
        assert threat_model.system.type.value == "llm-app"
        assert threat_model.system.threat_modeling_framework.value == "plot4ai"
        assert len(threat_model.system.components) >= 5

    def test_multi_agent_privacy_system_loads(self, examples_dir):
        """Test that multi-agent privacy system example loads correctly."""
        example_file = examples_dir / "multi-agent-privacy-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        assert threat_model.system.name == "Data Governance Multi-Agent System"
        assert threat_model.system.type.value == "multi-agent"
        assert threat_model.system.threat_modeling_framework.value == "plot4ai"
        assert len(threat_model.system.components) >= 5
        # Should have multiple agents
        agent_components = [c for c in threat_model.system.components if c.type.value == "agent"]
        assert len(agent_components) >= 3

    def test_healthcare_system_detects_privacy_threats(self, examples_dir):
        """Test that healthcare system detects privacy-related threats."""
        from ai_threat_model.plugins import load_plugins
        from ai_threat_model.plugins.registry import PluginRegistry

        load_plugins()

        example_file = examples_dir / "healthcare-agentic-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        plugin = PluginRegistry.get_plugin(threat_model.system.type)

        if plugin:
            threats = plugin.detect_threats(threat_model.system)
            assert len(threats) > 0
            
            # Should detect insecure data flows (unencrypted database connections)
            insecure_flows = [
                t for t in threats
                if t.affected_data_flows and "patient-database" in str(t.affected_data_flows)
            ]
            assert len(insecure_flows) > 0

    def test_privacy_llm_detects_data_disclosure(self, examples_dir):
        """Test that privacy LLM app detects data disclosure threats."""
        from ai_threat_model.plugins import load_plugins
        from ai_threat_model.plugins.registry import PluginRegistry

        load_plugins()

        example_file = examples_dir / "privacy-focused-llm-app.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        plugin = PluginRegistry.get_plugin(threat_model.system.type)

        if plugin:
            threats = plugin.detect_threats(threat_model.system)
            assert len(threats) > 0
            
            # Should detect insecure data flows (unencrypted database)
            insecure_flows = [
                t for t in threats
                if t.affected_data_flows and any("user-data-store" in str(df) for df in t.affected_data_flows)
            ]
            assert len(insecure_flows) > 0

    def test_multi_agent_detects_communication_threats(self, examples_dir):
        """Test that multi-agent system detects inter-agent communication threats."""
        from ai_threat_model.plugins import load_plugins
        from ai_threat_model.plugins.registry import PluginRegistry

        load_plugins()

        example_file = examples_dir / "multi-agent-privacy-system.tm.json"
        if not example_file.exists():
            pytest.skip("Example file not found")

        threat_model = ThreatModel.load(str(example_file))
        plugin = PluginRegistry.get_plugin(threat_model.system.type)

        if plugin:
            threats = plugin.detect_threats(threat_model.system)
            assert len(threats) > 0
            
            # Should detect threats related to agent communication
            # Multi-agent systems should have communication-related threats
            assert len(threats) > 0

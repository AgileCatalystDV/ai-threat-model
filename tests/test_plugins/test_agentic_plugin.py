"""
Tests for Agentic plugin.
"""

import pytest

from ai_threat_model.core.models import (
    Component,
    ComponentType,
    DataFlow,
    SystemModel,
    SystemType,
    ThreatModelingFramework,
    TrustLevel,
)
from ai_threat_model.plugins.ai import AgenticPlugin


class TestAgenticPlugin:
    """Tests for AgenticPlugin."""

    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = AgenticPlugin()

    def test_system_type(self):
        """Test plugin system type."""
        assert self.plugin.system_type == SystemType.AGENTIC_SYSTEM

    def test_supported_frameworks(self):
        """Test supported frameworks."""
        frameworks = self.plugin.supported_frameworks
        assert ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026 in frameworks

    def test_get_component_types(self):
        """Test getting component types."""
        types = self.plugin.get_component_types()
        assert ComponentType.AGENT.value in types
        assert ComponentType.LLM.value in types
        assert ComponentType.TOOL.value in types
        assert ComponentType.MCP_SERVER.value in types

    def test_get_threat_patterns(self):
        """Test getting threat patterns."""
        patterns = self.plugin.get_threat_patterns()
        assert len(patterns) > 0
        # Should have all AGENTIC01-AGENTIC10 patterns (defaults are always loaded)
        pattern_ids = [p.id for p in patterns]
        assert "AGENTIC01" in pattern_ids
        assert "AGENTIC10" in pattern_ids
        # Should have all 10 patterns
        assert len(pattern_ids) == 10
        # Verify all patterns are present
        expected_patterns = [f"AGENTIC{i:02d}" for i in range(1, 11)]
        assert set(pattern_ids) == set(expected_patterns)

    def test_detect_threats_with_agent_component(self):
        """Test threat detection with agent component."""
        agent = Component(
            id="agent1",
            name="Research Agent",
            type=ComponentType.AGENT,
            capabilities=["web-search", "analysis"],
            trust_level=TrustLevel.INTERNAL,
        )
        system = SystemModel(
            name="Test Agentic System",
            type=SystemType.AGENTIC_SYSTEM,
            threat_modeling_framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            components=[agent],
        )

        threats = self.plugin.detect_threats(system)
        assert len(threats) > 0
        # Should detect threats for agent components
        threat_categories = [t.category for t in threats]
        assert "AGENTIC01" in threat_categories or "AGENTIC02" in threat_categories

    def test_detect_threats_insecure_communication(self):
        """Test threat detection for insecure communication."""
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        # Unencrypted communication
        insecure_flow = DataFlow(
            from_component="agent1",
            to_component="agent2",
            data_type="message",
            encrypted=False,
        )
        system = SystemModel(
            name="Test System",
            type=SystemType.AGENTIC_SYSTEM,
            threat_modeling_framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            components=[agent1, agent2],
            data_flows=[insecure_flow],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect AGENTIC07 (Insecure Communication)
        threat_categories = [t.category for t in threats]
        assert "AGENTIC07" in threat_categories

    def test_detect_threats_multiple_agents(self):
        """Test threat detection with multiple agents (isolation concern)."""
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        system = SystemModel(
            name="Test System",
            type=SystemType.AGENTIC_SYSTEM,
            threat_modeling_framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            components=[agent1, agent2],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect AGENTIC06 (Insufficient Agent Isolation)
        threat_categories = [t.category for t in threats]
        assert "AGENTIC06" in threat_categories

    def test_detect_threats_with_tool(self):
        """Test threat detection with tool component."""
        agent = Component(id="agent1", name="Agent", type=ComponentType.AGENT)
        tool = Component(
            id="tool1", name="File Tool", type=ComponentType.TOOL, capabilities=["read-file"]
        )
        system = SystemModel(
            name="Test System",
            type=SystemType.AGENTIC_SYSTEM,
            threat_modeling_framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            components=[agent, tool],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect AGENTIC02 (Insecure Tool Use) for tool component
        threat_categories = [t.category for t in threats]
        assert "AGENTIC02" in threat_categories

    def test_validate_component_valid(self):
        """Test validating a valid component."""
        component = Component(
            id="test",
            name="Test Agent",
            type=ComponentType.AGENT,
            capabilities=["test"],
        )
        result = self.plugin.validate_component(component)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_component_missing_name(self):
        """Test validating component with missing name."""
        component = Component(id="test", name="", type=ComponentType.AGENT)
        result = self.plugin.validate_component(component)
        assert result.valid is False
        assert len(result.errors) > 0

    def test_analyze_system(self):
        """Test comprehensive system analysis."""
        agent = Component(
            id="agent1", name="Agent", type=ComponentType.AGENT, capabilities=["test"]
        )
        system = SystemModel(
            name="Test",
            type=SystemType.AGENTIC_SYSTEM,
            threat_modeling_framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            components=[agent],
        )

        analysis = self.plugin.analyze_system(system)
        assert "threats" in analysis
        assert "threat_count" in analysis
        assert "components_analyzed" in analysis
        assert "data_flows_analyzed" in analysis
        assert analysis["components_analyzed"] == 1

"""
Tests for Multi-Agent plugin.
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
from ai_threat_model.plugins.ai import MultiAgentPlugin


class TestMultiAgentPlugin:
    """Tests for MultiAgentPlugin."""

    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = MultiAgentPlugin()

    def test_system_type(self):
        """Test plugin system type."""
        assert self.plugin.system_type == SystemType.MULTI_AGENT

    def test_supported_frameworks(self):
        """Test supported frameworks."""
        frameworks = self.plugin.supported_frameworks
        assert ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026 in frameworks
        assert ThreatModelingFramework.CUSTOM in frameworks

    def test_get_component_types(self):
        """Test getting component types."""
        types = self.plugin.get_component_types()
        assert ComponentType.AGENT.value in types
        assert ComponentType.MEMORY.value in types
        assert ComponentType.LLM.value in types

    def test_get_threat_patterns(self):
        """Test getting threat patterns."""
        patterns = self.plugin.get_threat_patterns()
        assert len(patterns) > 0
        # Should have multi-agent specific patterns
        pattern_ids = [p.id for p in patterns]
        assert "MULTI-AGENT-01" in pattern_ids
        assert "MULTI-AGENT-05" in pattern_ids

    def test_detect_threats_multiple_agents(self):
        """Test threat detection with multiple agents."""
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        system = SystemModel(
            name="Test Multi-Agent System",
            type=SystemType.MULTI_AGENT,
            threat_modeling_framework=ThreatModelingFramework.CUSTOM,
            components=[agent1, agent2],
        )

        threats = self.plugin.detect_threats(system)
        assert len(threats) > 0
        # Should detect MULTI-AGENT-04 (Agent Isolation Failures)
        threat_categories = [t.category for t in threats]
        assert "MULTI-AGENT-04" in threat_categories

    def test_detect_threats_insecure_agent_communication(self):
        """Test threat detection for insecure agent communication."""
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        insecure_flow = DataFlow(
            from_component="agent1",
            to_component="agent2",
            data_type="message",
            encrypted=False,
        )
        system = SystemModel(
            name="Test System",
            type=SystemType.MULTI_AGENT,
            threat_modeling_framework=ThreatModelingFramework.CUSTOM,
            components=[agent1, agent2],
            data_flows=[insecure_flow],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect MULTI-AGENT-01 (Agent-to-Agent Communication Vulnerabilities)
        threat_categories = [t.category for t in threats]
        assert "MULTI-AGENT-01" in threat_categories

    def test_detect_threats_orchestrator(self):
        """Test threat detection with orchestrator."""
        orchestrator = Component(
            id="orch", name="Orchestrator", type=ComponentType.AGENT, capabilities=["coordination"]
        )
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        system = SystemModel(
            name="Test System",
            type=SystemType.MULTI_AGENT,
            threat_modeling_framework=ThreatModelingFramework.CUSTOM,
            components=[orchestrator, agent1, agent2],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect MULTI-AGENT-02 (Orchestration Layer Vulnerabilities)
        threat_categories = [t.category for t in threats]
        assert "MULTI-AGENT-02" in threat_categories

    def test_detect_threats_shared_state(self):
        """Test threat detection with shared state."""
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        shared_memory = Component(
            id="memory", name="Shared Memory", type=ComponentType.MEMORY, capabilities=["store"]
        )
        flow1 = DataFlow(from_component="agent1", to_component="memory", encrypted=False)
        flow2 = DataFlow(from_component="agent2", to_component="memory", encrypted=False)
        system = SystemModel(
            name="Test System",
            type=SystemType.MULTI_AGENT,
            threat_modeling_framework=ThreatModelingFramework.CUSTOM,
            components=[agent1, agent2, shared_memory],
            data_flows=[flow1, flow2],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect MULTI-AGENT-03 (Shared State Vulnerabilities)
        threat_categories = [t.category for t in threats]
        assert "MULTI-AGENT-03" in threat_categories

    def test_detect_threats_single_agent(self):
        """Test that single agent doesn't trigger multi-agent threats."""
        agent = Component(id="agent1", name="Agent", type=ComponentType.AGENT)
        system = SystemModel(
            name="Test System",
            type=SystemType.MULTI_AGENT,
            threat_modeling_framework=ThreatModelingFramework.CUSTOM,
            components=[agent],
        )

        threats = self.plugin.detect_threats(system)
        # Should not detect multi-agent specific threats with only one agent
        assert len(threats) == 0

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

    def test_analyze_system(self):
        """Test comprehensive system analysis."""
        agent1 = Component(id="agent1", name="Agent 1", type=ComponentType.AGENT)
        agent2 = Component(id="agent2", name="Agent 2", type=ComponentType.AGENT)
        system = SystemModel(
            name="Test",
            type=SystemType.MULTI_AGENT,
            threat_modeling_framework=ThreatModelingFramework.CUSTOM,
            components=[agent1, agent2],
        )

        analysis = self.plugin.analyze_system(system)
        assert "threats" in analysis
        assert "threat_count" in analysis
        assert "components_analyzed" in analysis
        assert analysis["components_analyzed"] == 2

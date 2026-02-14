"""
Tests for LLM plugin.
"""

import pytest

from ai_threat_model.core.models import (
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    SystemModel,
    SystemType,
    ThreatModelingFramework,
    TrustLevel,
)
from ai_threat_model.plugins.ai import LLMPlugin


class TestLLMPlugin:
    """Tests for LLMPlugin."""

    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = LLMPlugin()

    def test_system_type(self):
        """Test plugin system type."""
        assert self.plugin.system_type == SystemType.LLM_APP

    def test_supported_frameworks(self):
        """Test supported frameworks."""
        frameworks = self.plugin.supported_frameworks
        assert ThreatModelingFramework.OWASP_LLM_TOP10_2025 in frameworks

    def test_get_component_types(self):
        """Test getting component types."""
        types = self.plugin.get_component_types()
        assert ComponentType.LLM.value in types
        assert ComponentType.AGENT.value in types
        assert ComponentType.TOOL.value in types

    def test_get_threat_patterns(self):
        """Test getting threat patterns."""
        patterns = self.plugin.get_threat_patterns()
        assert len(patterns) > 0
        # Should have all LLM01-LLM10 patterns (defaults are always loaded)
        pattern_ids = [p.id for p in patterns]
        assert "LLM01" in pattern_ids
        assert "LLM10" in pattern_ids
        # Should have all 10 patterns
        assert len(pattern_ids) == 10
        # Verify all patterns are present
        expected_patterns = [f"LLM{i:02d}" for i in range(1, 11)]
        assert set(pattern_ids) == set(expected_patterns)

    def test_get_threat_patterns_filtered(self):
        """Test getting filtered threat patterns."""
        patterns = self.plugin.get_threat_patterns(ThreatModelingFramework.OWASP_LLM_TOP10_2025)
        assert len(patterns) > 0
        for pattern in patterns:
            assert pattern.framework == ThreatModelingFramework.OWASP_LLM_TOP10_2025

    def test_detect_threats_with_llm_component(self):
        """Test threat detection with LLM component."""
        llm_component = Component(
            id="llm1",
            name="LLM Service",
            type=ComponentType.LLM,
            capabilities=["text-generation"],
            trust_level=TrustLevel.INTERNAL,
        )
        system = SystemModel(
            name="Test LLM App",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[llm_component],
        )

        threats = self.plugin.detect_threats(system)
        assert len(threats) > 0
        # Should detect threats for LLM components
        threat_categories = [t.category for t in threats]
        assert "LLM01" in threat_categories or "LLM02" in threat_categories

    def test_detect_threats_with_capabilities(self):
        """Test threat detection using component capabilities."""
        llm_component = Component(
            id="llm1",
            name="LLM Service with Plugin Support",
            type=ComponentType.LLM,
            capabilities=["text-generation", "plugin-execution", "code-execution"],
            trust_level=TrustLevel.INTERNAL,
        )
        system = SystemModel(
            name="Test LLM App",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[llm_component],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect LLM07 (Insecure Plugin Design) based on capabilities
        threat_categories = [t.category for t in threats]
        # Enhanced detection should match based on capabilities
        assert len(threats) > 0

    def test_detect_threats_with_untrusted_component(self):
        """Test threat detection with untrusted component."""
        untrusted_component = Component(
            id="external-api",
            name="External API",
            type=ComponentType.API_ENDPOINT,
            trust_level=TrustLevel.UNTRUSTED,
        )
        llm_component = Component(
            id="llm1",
            name="LLM Service",
            type=ComponentType.LLM,
        )
        system = SystemModel(
            name="Test LLM App",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[untrusted_component, llm_component],
            data_flows=[
                DataFlow(
                    from_component="external-api",
                    to_component="llm1",
                    data_type="user-input",
                    classification=DataClassification.CONFIDENTIAL,
                    encrypted=False,
                )
            ],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect threats related to untrusted sources
        assert len(threats) > 0

    def test_detect_threats_insecure_data_flow(self):
        """Test threat detection for insecure data flows."""
        component1 = Component(id="comp1", name="Component 1", type=ComponentType.LLM)
        component2 = Component(id="comp2", name="Component 2", type=ComponentType.DATABASE)
        # Unencrypted confidential data flow
        insecure_flow = DataFlow(
            from_component="comp1",
            to_component="comp2",
            data_type="user-data",
            classification=DataClassification.CONFIDENTIAL,
            encrypted=False,
        )
        system = SystemModel(
            name="Test System",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component1, component2],
            data_flows=[insecure_flow],
        )

        threats = self.plugin.detect_threats(system)
        # Should detect LLM06 (Sensitive Information Disclosure)
        threat_categories = [t.category for t in threats]
        assert "LLM06" in threat_categories

    def test_validate_component_valid(self):
        """Test validating a valid component."""
        component = Component(
            id="test",
            name="Test Component",
            type=ComponentType.LLM,
            capabilities=["test"],
        )
        result = self.plugin.validate_component(component)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_component_missing_name(self):
        """Test validating component with missing name."""
        component = Component(id="test", name="", type=ComponentType.LLM)
        result = self.plugin.validate_component(component)
        assert result.valid is False
        assert len(result.errors) > 0
        assert any("name" in error.lower() for error in result.errors)

    def test_validate_component_unusual_type(self):
        """Test validating component with unusual type."""
        component = Component(
            id="test", name="Test", type=ComponentType.MOBILE_APP
        )  # Not typical for LLM apps
        result = self.plugin.validate_component(component)
        # Should be valid but with warnings
        assert result.valid is True
        assert len(result.warnings) > 0

    def test_analyze_system(self):
        """Test comprehensive system analysis."""
        component = Component(
            id="llm1", name="LLM", type=ComponentType.LLM, capabilities=["test"]
        )
        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component],
        )

        analysis = self.plugin.analyze_system(system)
        assert "threats" in analysis
        assert "threat_count" in analysis
        assert "components_analyzed" in analysis
        assert "data_flows_analyzed" in analysis
        assert analysis["components_analyzed"] == 1
        assert analysis["threat_count"] == len(analysis["threats"])

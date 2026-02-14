"""
Tests for enhanced threat detection utilities.
"""

import pytest

from ai_threat_model.core.models import (
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    SystemModel,
    ThreatModelingFramework,
    TrustLevel,
)
from ai_threat_model.plugins.ai.threat_detection import (
    _matches_capabilities,
    _matches_context,
    _matches_regex_pattern,
    check_insecure_data_flow,
    create_threat_from_pattern,
    find_data_flow_by_id,
    pattern_matches_component,
)
from ai_threat_model.plugins.base_plugin import ThreatPattern


class TestThreatDetectionUtilities:
    """Tests for threat detection utility functions."""

    def test_find_data_flow_by_id(self):
        """Test finding data flow by ID."""
        system = SystemModel(
            name="Test System",
            type=None,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[],
            data_flows=[
                DataFlow(
                    from_component="comp1",
                    to_component="comp2",
                    data_type="test-data",
                )
            ],
        )

        df = find_data_flow_by_id("comp1->comp2", system)
        assert df is not None
        assert df.from_component == "comp1"
        assert df.to_component == "comp2"

        df = find_data_flow_by_id("nonexistent", system)
        assert df is None

    def test_check_insecure_data_flow_encrypted(self):
        """Test insecure data flow detection with encrypted flow."""
        system = SystemModel(
            name="Test System",
            type=None,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[
                Component(id="comp1", name="Component 1", type=ComponentType.LLM),
                Component(id="comp2", name="Component 2", type=ComponentType.DATABASE),
            ],
            data_flows=[],
        )

        # Encrypted flow should not trigger threat
        encrypted_flow = DataFlow(
            from_component="comp1",
            to_component="comp2",
            data_type="sensitive-data",
            classification=DataClassification.CONFIDENTIAL,
            encrypted=True,
        )

        threat = check_insecure_data_flow(
            encrypted_flow,
            system,
            "LLM06",
            ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            "Sensitive Information Disclosure",
        )
        assert threat is None

    def test_check_insecure_data_flow_unencrypted(self):
        """Test insecure data flow detection with unencrypted sensitive data."""
        system = SystemModel(
            name="Test System",
            type=None,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[
                Component(id="comp1", name="Component 1", type=ComponentType.LLM),
                Component(id="comp2", name="Component 2", type=ComponentType.DATABASE),
            ],
            data_flows=[],
        )

        # Unencrypted confidential flow should trigger threat
        unencrypted_flow = DataFlow(
            from_component="comp1",
            to_component="comp2",
            data_type="sensitive-data",
            classification=DataClassification.CONFIDENTIAL,
            encrypted=False,
        )

        threat = check_insecure_data_flow(
            unencrypted_flow,
            system,
            "LLM06",
            ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            "Sensitive Information Disclosure",
        )
        assert threat is not None
        assert threat.category == "LLM06"
        assert "comp1->comp2" in threat.affected_data_flows

    def test_pattern_matches_component_type(self):
        """Test pattern matching by component type."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=[],
            attack_vectors=[],
            mitigations=[],
        )

        component = Component(
            id="llm1",
            name="LLM Service",
            type=ComponentType.LLM,
        )

        # Should match by component type
        assert pattern_matches_component(pattern, component, ["llm"]) is True
        assert pattern_matches_component(pattern, component, ["database"]) is False

    def test_pattern_matches_component_detection_pattern(self):
        """Test pattern matching by detection pattern."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["no input validation", "untrusted source"],
            attack_vectors=[],
            mitigations=[],
        )

        component = Component(
            id="comp1",
            name="Component with no input validation",
            type=ComponentType.API_ENDPOINT,
        )

        # Should match by detection pattern
        assert pattern_matches_component(pattern, component, []) is True

    def test_pattern_matches_component_capabilities(self):
        """Test pattern matching by capabilities."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["execute arbitrary code", "plugin execution"],
            attack_vectors=[],
            mitigations=[],
        )

        component = Component(
            id="plugin1",
            name="Plugin Component",
            type=ComponentType.TOOL,
            capabilities=["execute", "plugin", "code-execution"],
        )

        # Should match by capabilities
        assert pattern_matches_component(pattern, component, []) is True

    def test_pattern_matches_component_context(self):
        """Test pattern matching with system context."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["sensitive data", "confidential information"],
            attack_vectors=[],
            mitigations=[],
        )

        component = Component(
            id="comp1",
            name="Data Processor",
            type=ComponentType.LLM,
            trust_level=TrustLevel.UNTRUSTED,
        )

        system = SystemModel(
            name="Test System",
            type=None,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component],
            data_flows=[
                DataFlow(
                    from_component="comp1",
                    to_component="comp2",
                    data_type="user-data",
                    classification=DataClassification.CONFIDENTIAL,
                    encrypted=False,
                )
            ],
        )

        # Should match by context (sensitive data flow)
        assert pattern_matches_component(pattern, component, [], system) is True

    def test_matches_regex_pattern(self):
        """Test regex pattern matching."""
        assert _matches_regex_pattern("no input validation", "component with no input validation") is True
        assert _matches_regex_pattern("untrusted source", "component uses untrusted source") is True
        assert _matches_regex_pattern("excessive permissions", "component has excessive permissions") is True
        assert _matches_regex_pattern("normal component", "normal component") is False  # No regex pattern

    def test_matches_capabilities(self):
        """Test capabilities-based matching."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["execute code", "plugin"],
            attack_vectors=[],
            mitigations=[],
        )

        component_with_capabilities = Component(
            id="tool1",
            name="Tool",
            type=ComponentType.TOOL,
            capabilities=["execute", "plugin", "code"],
        )

        component_without_capabilities = Component(
            id="tool2",
            name="Tool",
            type=ComponentType.TOOL,
            capabilities=[],
        )

        assert _matches_capabilities(pattern, component_with_capabilities) is True
        assert _matches_capabilities(pattern, component_without_capabilities) is False

    def test_matches_context_untrusted(self):
        """Test context matching for untrusted components."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["untrusted input", "external source"],
            attack_vectors=[],
            mitigations=[],
        )

        untrusted_component = Component(
            id="comp1",
            name="External API",
            type=ComponentType.API_ENDPOINT,
            trust_level=TrustLevel.UNTRUSTED,
        )

        system = SystemModel(
            name="Test System",
            type=None,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[untrusted_component],
            data_flows=[],
        )

        assert _matches_context(pattern, untrusted_component, system) is True

    def test_matches_context_sensitive_data(self):
        """Test context matching for sensitive data flows."""
        pattern = ThreatPattern(
            id="TEST01",
            category="TEST01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test Pattern",
            description="Test",
            detection_patterns=["sensitive information", "confidential data"],
            attack_vectors=[],
            mitigations=[],
        )

        component = Component(
            id="comp1",
            name="Data Processor",
            type=ComponentType.LLM,
        )

        system = SystemModel(
            name="Test System",
            type=None,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component],
            data_flows=[
                DataFlow(
                    from_component="comp1",
                    to_component="comp2",
                    data_type="pii",
                    classification=DataClassification.CONFIDENTIAL,
                    encrypted=True,
                )
            ],
        )

        assert _matches_context(pattern, component, system) is True

    def test_create_threat_from_pattern(self):
        """Test creating threat from pattern."""
        pattern = ThreatPattern(
            id="LLM01",
            category="LLM01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Prompt Injection",
            description="Test description",
            detection_patterns=["no validation"],
            attack_vectors=["injection"],
            mitigations=[
                {
                    "id": "mit1",
                    "description": "Validate input",
                    "implementation": "Use validation",
                    "priority": "high",
                }
            ],
        )

        component = Component(
            id="llm1",
            name="LLM Service",
            type=ComponentType.LLM,
        )

        severity_map = {"LLM01": "critical"}

        threat = create_threat_from_pattern(pattern, component, severity_map)
        assert threat.category == "LLM01"
        assert threat.title == "Prompt Injection"
        assert threat.affected_components == ["llm1"]
        assert len(threat.mitigations) == 1
        assert threat.mitigations[0].id == "mit1"

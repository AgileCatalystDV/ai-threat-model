"""
Tests for core data models.
"""

import json
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from ai_threat_model.core.models import (
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    Metadata,
    Mitigation,
    MitigationStatus,
    RiskScore,
    Severity,
    SystemModel,
    SystemType,
    Threat,
    ThreatModel,
    ThreatModelingFramework,
    TrustLevel,
)


class TestComponent:
    """Tests for Component model."""

    def test_component_creation(self):
        """Test creating a component."""
        component = Component(
            id="test-component",
            name="Test Component",
            type=ComponentType.LLM,
            capabilities=["test"],
            trust_level=TrustLevel.INTERNAL,
        )
        assert component.id == "test-component"
        assert component.name == "Test Component"
        assert component.type == ComponentType.LLM
        assert component.capabilities == ["test"]
        assert component.trust_level == TrustLevel.INTERNAL

    def test_component_id_validation(self):
        """Test component ID validation."""
        with pytest.raises(ValueError, match="Component ID cannot be empty"):
            Component(id="", name="Test", type=ComponentType.LLM)

        with pytest.raises(ValueError, match="Component ID cannot be empty"):
            Component(id="   ", name="Test", type=ComponentType.LLM)

    def test_component_defaults(self):
        """Test component default values."""
        component = Component(id="test", name="Test", type=ComponentType.LLM)
        assert component.capabilities == []
        assert component.trust_level == TrustLevel.UNTRUSTED
        assert component.description is None


class TestDataFlow:
    """Tests for DataFlow model."""

    def test_data_flow_creation(self):
        """Test creating a data flow."""
        flow = DataFlow(
            from_component="source",
            to_component="target",
            data_type="test-data",
            classification=DataClassification.CONFIDENTIAL,
            protocol="HTTPS",
            encrypted=True,
        )
        assert flow.from_component == "source"
        assert flow.to_component == "target"
        assert flow.data_type == "test-data"
        assert flow.classification == DataClassification.CONFIDENTIAL
        assert flow.protocol == "HTTPS"
        assert flow.encrypted is True

    def test_data_flow_defaults(self):
        """Test data flow default values."""
        flow = DataFlow(from_component="source", to_component="target")
        assert flow.data_type is None
        assert flow.classification == DataClassification.INTERNAL
        assert flow.protocol is None
        assert flow.encrypted is False

    def test_data_flow_alias(self):
        """Test data flow field aliases."""
        flow = DataFlow(**{"from": "source", "to": "target"})
        assert flow.from_component == "source"
        assert flow.to_component == "target"


class TestSystemModel:
    """Tests for SystemModel."""

    def test_system_model_creation(self):
        """Test creating a system model."""
        system = SystemModel(
            name="Test System",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        )
        assert system.name == "Test System"
        assert system.type == SystemType.LLM_APP
        assert system.threat_modeling_framework == ThreatModelingFramework.OWASP_LLM_TOP10_2025
        assert system.components == []
        assert system.data_flows == []

    def test_get_component(self):
        """Test getting component by ID."""
        component = Component(id="comp1", name="Component 1", type=ComponentType.LLM)
        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component],
        )
        assert system.get_component("comp1") == component
        assert system.get_component("nonexistent") is None

    def test_get_data_flows_from(self):
        """Test getting data flows from a component."""
        flow1 = DataFlow(from_component="comp1", to_component="comp2")
        flow2 = DataFlow(from_component="comp1", to_component="comp3")
        flow3 = DataFlow(from_component="comp2", to_component="comp3")
        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            data_flows=[flow1, flow2, flow3],
        )
        flows = system.get_data_flows_from("comp1")
        assert len(flows) == 2
        assert flow1 in flows
        assert flow2 in flows

    def test_get_data_flows_to(self):
        """Test getting data flows to a component."""
        flow1 = DataFlow(from_component="comp1", to_component="comp2")
        flow2 = DataFlow(from_component="comp3", to_component="comp2")
        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            data_flows=[flow1, flow2],
        )
        flows = system.get_data_flows_to("comp2")
        assert len(flows) == 2
        assert flow1 in flows
        assert flow2 in flows


class TestRiskScore:
    """Tests for RiskScore model."""

    def test_risk_score_calculation(self):
        """Test DREAD score calculation."""
        risk = RiskScore(
            damage=8.0,
            reproducibility=6.0,
            exploitability=7.0,
            affected_users=5.0,
            discoverability=9.0,
        )
        calculated = risk.calculate()
        assert calculated == 7.0  # Average of all factors

    def test_risk_score_partial(self):
        """Test DREAD score with partial data."""
        risk = RiskScore(damage=8.0, exploitability=6.0)
        calculated = risk.calculate()
        assert calculated == 7.0  # Average of provided factors

    def test_risk_score_empty(self):
        """Test DREAD score with no data."""
        risk = RiskScore()
        assert risk.calculate() == 0.0


class TestThreat:
    """Tests for Threat model."""

    def test_threat_creation(self):
        """Test creating a threat."""
        threat = Threat(
            category="LLM01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Prompt Injection",
            description="Test description",
            severity=Severity.CRITICAL,
            affected_components=["comp1"],
        )
        assert threat.category == "LLM01"
        assert threat.framework == ThreatModelingFramework.OWASP_LLM_TOP10_2025
        assert threat.title == "Prompt Injection"
        assert threat.severity == Severity.CRITICAL
        assert threat.affected_components == ["comp1"]
        assert isinstance(threat.id, str)  # UUID generated

    def test_threat_defaults(self):
        """Test threat default values."""
        threat = Threat(
            category="LLM01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test",
        )
        assert threat.description is None
        assert threat.severity is None
        assert threat.affected_components == []
        assert threat.mitigations == []
        assert threat.risk_score is None


class TestThreatModel:
    """Tests for ThreatModel."""

    def test_threat_model_creation(self):
        """Test creating a threat model."""
        metadata = Metadata(version="1.0.0")
        system = SystemModel(
            name="Test System",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        )
        threat_model = ThreatModel(metadata=metadata, system=system)
        assert threat_model.metadata == metadata
        assert threat_model.system == system
        assert threat_model.threats == []

    def test_threat_model_save_and_load(self):
        """Test saving and loading threat model."""
        metadata = Metadata(version="1.0.0", author="Test Author")
        system = SystemModel(
            name="Test System",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        )
        threat_model = ThreatModel(metadata=metadata, system=system)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            file_path = f.name

        try:
            threat_model.save(file_path)

            # Load it back
            loaded = ThreatModel.load(file_path)
            assert loaded.system.name == "Test System"
            assert loaded.metadata.author == "Test Author"
            assert loaded.system.type == SystemType.LLM_APP
        finally:
            Path(file_path).unlink()

    def test_threat_model_validate_valid(self):
        """Test validation of valid threat model."""
        component1 = Component(id="comp1", name="Component 1", type=ComponentType.LLM)
        component2 = Component(id="comp2", name="Component 2", type=ComponentType.DATABASE)
        flow = DataFlow(from_component="comp1", to_component="comp2")
        threat = Threat(
            category="LLM01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test",
            affected_components=["comp1"],
        )

        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component1, component2],
            data_flows=[flow],
        )
        threat_model = ThreatModel(
            metadata=Metadata(version="1.0.0"), system=system, threats=[threat]
        )

        errors = threat_model.validate()
        assert len(errors) == 0

    def test_threat_model_validate_invalid_data_flow(self):
        """Test validation with invalid data flow."""
        component = Component(id="comp1", name="Component 1", type=ComponentType.LLM)
        flow = DataFlow(from_component="comp1", to_component="nonexistent")
        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component],
            data_flows=[flow],
        )
        threat_model = ThreatModel(metadata=Metadata(version="1.0.0"), system=system)

        errors = threat_model.validate()
        assert len(errors) > 0
        assert any("nonexistent" in error for error in errors)

    def test_threat_model_validate_invalid_threat_component(self):
        """Test validation with threat referencing non-existent component."""
        component = Component(id="comp1", name="Component 1", type=ComponentType.LLM)
        threat = Threat(
            category="LLM01",
            framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            title="Test",
            affected_components=["nonexistent"],
        )
        system = SystemModel(
            name="Test",
            type=SystemType.LLM_APP,
            threat_modeling_framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            components=[component],
        )
        threat_model = ThreatModel(
            metadata=Metadata(version="1.0.0"), system=system, threats=[threat]
        )

        errors = threat_model.validate()
        assert len(errors) > 0
        assert any("nonexistent" in error for error in errors)


class TestMitigation:
    """Tests for Mitigation model."""

    def test_mitigation_creation(self):
        """Test creating a mitigation."""
        mitigation = Mitigation(
            description="Test mitigation",
            implementation="Do something",
            status=MitigationStatus.IMPLEMENTED,
            priority="high",
        )
        assert mitigation.description == "Test mitigation"
        assert mitigation.implementation == "Do something"
        assert mitigation.status == MitigationStatus.IMPLEMENTED
        assert mitigation.priority == "high"
        assert isinstance(mitigation.id, str)  # UUID generated

    def test_mitigation_defaults(self):
        """Test mitigation default values."""
        mitigation = Mitigation(description="Test")
        assert mitigation.implementation is None
        assert mitigation.status == MitigationStatus.PROPOSED
        assert mitigation.priority is None

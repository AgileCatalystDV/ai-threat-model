"""
Threat detection utilities for AI plugins.

Provides shared functions for detecting threats in components and data flows.
"""

from typing import List

from ...core.models import Component, DataFlow, Severity, SystemModel, Threat, ThreatModelingFramework
from ..base_plugin import ThreatPattern


def find_data_flow_by_id(df_id: str, system: SystemModel) -> DataFlow | None:
    """Find a data flow by ID string."""
    for df in system.data_flows:
        df_str = f"{df.from_component}->{df.to_component}"
        if df_id == df_str or df_id in df_str:
            return df
    return None


def check_insecure_data_flow(
    data_flow: DataFlow,
    system: SystemModel,
    threat_category: str,
    framework: ThreatModelingFramework,
    threat_title: str,
) -> Threat | None:
    """
    Check if a data flow is insecure and create a threat if so.

    Args:
        data_flow: Data flow to check
        system: System model
        framework: Threat modeling framework
        threat_category: Threat category code
        threat_title: Threat title

    Returns:
        Threat object if insecure, None otherwise
    """
    if not data_flow.encrypted and data_flow.classification.value in ["confidential", "restricted"]:
        from_comp = system.get_component(data_flow.from_component)
        to_comp = system.get_component(data_flow.to_component)
        from_name = from_comp.name if from_comp else data_flow.from_component
        to_name = to_comp.name if to_comp else data_flow.to_component

        return Threat(
            category=threat_category,
            framework=framework,
            title=threat_title,
            description=f"Sensitive data ({data_flow.classification.value}) is transmitted unencrypted between {from_name} and {to_name}",
            severity=Severity.HIGH,
            affected_data_flows=[f"{data_flow.from_component}->{data_flow.to_component}"],
        )
    return None


def pattern_matches_component(
    pattern: ThreatPattern, component: Component, component_types: List[str]
) -> bool:
    """
    Check if a threat pattern matches a component.

    Args:
        pattern: Threat pattern to check
        component: Component to check
        component_types: List of component types that should trigger this pattern

    Returns:
        True if pattern matches component
    """
    component_lower = component.name.lower() + " " + component.type.value.lower()

    # Check detection patterns
    for detection_pattern in pattern.detection_patterns:
        if detection_pattern.lower() in component_lower:
            return True

    # Check component type
    if component.type.value in component_types:
        return True

    return False


def create_threat_from_pattern(
    pattern: ThreatPattern,
    component: Component,
    severity_map: dict[str, Severity],
) -> Threat:
    """
    Create a Threat object from a pattern.

    Args:
        pattern: Threat pattern
        component: Affected component
        severity_map: Mapping from pattern ID to severity

    Returns:
        Threat object
    """
    from ...core.models import Mitigation, MitigationStatus

    mitigations = [
        Mitigation(
            id=mit.get("id", ""),
            description=mit.get("description", ""),
            implementation=mit.get("implementation"),
            status=MitigationStatus.PROPOSED,
            priority=mit.get("priority"),
        )
        for mit in pattern.mitigations
    ]

    threat = Threat(
        category=pattern.category,
        framework=pattern.framework,
        title=pattern.title,
        description=pattern.description,
        severity=severity_map.get(pattern.id, Severity.MEDIUM),
        affected_components=[component.id],
        attack_vectors=pattern.attack_vectors,
        detection_patterns=pattern.detection_patterns,
        mitigations=mitigations,
    )

    return threat

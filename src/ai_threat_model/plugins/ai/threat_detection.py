"""
Threat detection utilities for AI plugins.

Provides shared functions for detecting threats in components and data flows.
"""

import re
from typing import List, Optional

from ...core.models import Component, DataFlow, Severity, SystemModel, Threat, ThreatModelingFramework, TrustLevel
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
    pattern: ThreatPattern,
    component: Component,
    component_types: List[str],
    system: Optional[SystemModel] = None,
) -> bool:
    """
    Check if a threat pattern matches a component using enhanced detection.

    Uses multiple matching strategies:
    1. Component type matching
    2. Capabilities-based matching
    3. Detection pattern matching (name, description, capabilities)
    4. Context-aware matching (data flows, trust levels)

    Args:
        pattern: Threat pattern to check
        component: Component to check
        component_types: List of component types that should trigger this pattern
        system: Optional system model for context-aware detection

    Returns:
        True if pattern matches component
    """
    # 1. Check component type
    if component.type.value in component_types:
        return True

    # 2. Build searchable text from component attributes
    searchable_text = " ".join([
        component.name.lower(),
        component.type.value.lower(),
        component.description.lower() if component.description else "",
        " ".join(component.capabilities).lower(),
    ])

    # 3. Check detection patterns with improved matching
    for detection_pattern in pattern.detection_patterns:
        pattern_lower = detection_pattern.lower()
        
        # Exact substring match
        if pattern_lower in searchable_text:
            return True
        
        # Word boundary matching for better precision
        pattern_words = pattern_lower.split()
        if len(pattern_words) > 1:
            # Check if all significant words appear
            significant_words = [w for w in pattern_words if len(w) > 3]
            if significant_words and all(word in searchable_text for word in significant_words):
                return True
        
        # Regex pattern matching for common patterns
        if _matches_regex_pattern(pattern_lower, searchable_text):
            return True

    # 4. Capabilities-based matching
    if _matches_capabilities(pattern, component):
        return True

    # 5. Context-aware matching (if system provided)
    if system and _matches_context(pattern, component, system):
        return True

    return False


def _matches_regex_pattern(pattern: str, text: str) -> bool:
    """
    Check if pattern matches using common regex patterns.

    Args:
        pattern: Detection pattern to match
        text: Text to search in

    Returns:
        True if pattern matches
    """
    # Common patterns for threat detection
    regex_patterns = {
        r"no\s+\w+\s+(validation|sanitization|filtering|protection)": r"no\s+\w+\s+(validation|sanitization|filtering|protection)",
        r"untrusted\s+\w+": r"untrusted\s+\w+",
        r"excessive\s+\w+": r"excessive\s+\w+",
        r"arbitrary\s+\w+": r"arbitrary\s+\w+",
    }

    for regex_key, regex_pattern in regex_patterns.items():
        if regex_key in pattern.lower():
            if re.search(regex_pattern, text, re.IGNORECASE):
                return True

    return False


def _matches_capabilities(pattern: ThreatPattern, component: Component) -> bool:
    """
    Check if pattern matches based on component capabilities.

    Args:
        pattern: Threat pattern to check
        component: Component to check

    Returns:
        True if capabilities match pattern indicators
    """
    if not component.capabilities:
        return False

    capabilities_lower = " ".join(c.lower() for c in component.capabilities)
    
    # Check if detection patterns mention capabilities that match
    for detection_pattern in pattern.detection_patterns:
        pattern_lower = detection_pattern.lower()
        
        # Common capability-related keywords
        capability_keywords = [
            "execute", "access", "modify", "delete", "create",
            "authentication", "authorization", "permission",
            "plugin", "tool", "api", "database", "file"
        ]
        
        for keyword in capability_keywords:
            if keyword in pattern_lower and keyword in capabilities_lower:
                return True

    return False


def _matches_context(
    pattern: ThreatPattern, component: Component, system: SystemModel
) -> bool:
    """
    Check if pattern matches based on system context (data flows, trust levels).

    Args:
        pattern: Threat pattern to check
        component: Component to check
        system: System model for context

    Returns:
        True if context matches pattern indicators
    """
    # Check trust level context
    if component.trust_level == TrustLevel.UNTRUSTED:
        # Patterns related to untrusted sources
        untrusted_patterns = [
            "untrusted", "external", "third-party", "public",
            "user input", "user-generated"
        ]
        for detection_pattern in pattern.detection_patterns:
            if any(keyword in detection_pattern.lower() for keyword in untrusted_patterns):
                return True

    # Check data flow context
    data_flows_from = system.get_data_flows_from(component.id)
    data_flows_to = system.get_data_flows_to(component.id)
    
    # Check if component handles sensitive data
    sensitive_data_flows = [
        df for df in data_flows_from + data_flows_to
        if df.classification.value in ["confidential", "restricted"]
    ]
    
    if sensitive_data_flows:
        sensitive_patterns = [
            "sensitive", "confidential", "restricted", "pii",
            "personal data", "private information"
        ]
        for detection_pattern in pattern.detection_patterns:
            if any(keyword in detection_pattern.lower() for keyword in sensitive_patterns):
                return True

    # Check if component has unencrypted data flows
    unencrypted_flows = [
        df for df in data_flows_from + data_flows_to
        if not df.encrypted and df.classification.value in ["confidential", "restricted"]
    ]
    
    if unencrypted_flows:
        encryption_patterns = [
            "unencrypted", "no encryption", "plaintext", "insecure"
        ]
        for detection_pattern in pattern.detection_patterns:
            if any(keyword in detection_pattern.lower() for keyword in encryption_patterns):
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

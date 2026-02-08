"""
Pattern builders for AI threat patterns.

Provides helper functions for creating threat patterns consistently.
"""

from typing import Dict, List

from ...core.models import ThreatModelingFramework
from ..base_plugin import ThreatPattern


def create_llm_pattern(
    pattern_id: str,
    title: str,
    description: str,
    detection_patterns: List[str],
    attack_vectors: List[str],
    mitigations: List[Dict],
    references: List[Dict] = None,
) -> ThreatPattern:
    """Create an LLM threat pattern."""
    return ThreatPattern(
        id=pattern_id,
        category=pattern_id,
        framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        title=title,
        description=description,
        detection_patterns=detection_patterns,
        attack_vectors=attack_vectors,
        mitigations=mitigations or [],
        references=references or [],
    )


def create_agentic_pattern(
    pattern_id: str,
    title: str,
    description: str,
    detection_patterns: List[str],
    attack_vectors: List[str],
    mitigations: List[Dict],
    references: List[Dict] = None,
) -> ThreatPattern:
    """Create an Agentic threat pattern."""
    return ThreatPattern(
        id=pattern_id,
        category=pattern_id,
        framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
        title=title,
        description=description,
        detection_patterns=detection_patterns,
        attack_vectors=attack_vectors,
        mitigations=mitigations or [],
        references=references or [],
    )


def create_multi_agent_pattern(
    pattern_id: str,
    title: str,
    description: str,
    detection_patterns: List[str],
    attack_vectors: List[str],
    mitigations: List[Dict],
    references: List[Dict] = None,
) -> ThreatPattern:
    """Create a Multi-Agent threat pattern."""
    return ThreatPattern(
        id=pattern_id,
        category=pattern_id,
        framework=ThreatModelingFramework.CUSTOM,
        title=title,
        description=description,
        detection_patterns=detection_patterns,
        attack_vectors=attack_vectors,
        mitigations=mitigations or [],
        references=references or [],
    )


def create_mitigation(
    mitigation_id: str, description: str, implementation: str = None, priority: str = None
) -> Dict:
    """Create a mitigation dictionary."""
    mitigation = {
        "id": mitigation_id,
        "description": description,
    }
    if implementation:
        mitigation["implementation"] = implementation
    if priority:
        mitigation["priority"] = priority
    return mitigation

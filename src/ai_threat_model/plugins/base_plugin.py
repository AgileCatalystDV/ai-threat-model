"""
Base plugin interface for threat modeling plugins.

Plugins provide type-specific threat detection and analysis capabilities.
Each system type (LLM, Web App, Mobile, etc.) has its own plugin implementation.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from pydantic import BaseModel, ConfigDict

from ..core.models import (
    Component,
    SystemModel,
    SystemType,
    Threat,
    ThreatModelingFramework,
)


class ThreatPattern(BaseModel):
    """Represents a threat pattern that can be matched against a system."""

    id: str
    category: str
    framework: ThreatModelingFramework
    title: str
    description: str
    detection_patterns: List[str]
    attack_vectors: List[str]
    mitigations: List[dict]

    model_config = ConfigDict(from_attributes=True)


class ValidationResult(BaseModel):
    """Result of component validation."""

    valid: bool
    errors: List[str] = []
    warnings: List[str] = []


class ThreatModelPlugin(ABC):
    """
    Abstract base class for threat modeling plugins.

    Each plugin handles threat detection and analysis for a specific system type.
    """

    @property
    @abstractmethod
    def system_type(self) -> SystemType:
        """Return the system type this plugin handles."""
        pass

    @property
    @abstractmethod
    def supported_frameworks(self) -> List[ThreatModelingFramework]:
        """Return list of frameworks this plugin supports."""
        pass

    @abstractmethod
    def detect_threats(self, system: SystemModel) -> List[Threat]:
        """
        Detect threats based on system model.

        Args:
            system: The system model to analyze

        Returns:
            List of detected threats
        """
        pass

    @abstractmethod
    def get_component_types(self) -> List[str]:
        """
        Return list of component types for this system type.

        Returns:
            List of component type strings
        """
        pass

    @abstractmethod
    def validate_component(self, component: Component) -> ValidationResult:
        """
        Validate component for this system type.

        Args:
            component: Component to validate

        Returns:
            ValidationResult with validation status and errors/warnings
        """
        pass

    @abstractmethod
    def get_threat_patterns(
        self, framework: Optional[ThreatModelingFramework] = None
    ) -> List[ThreatPattern]:
        """
        Get threat patterns for specific framework.

        Args:
            framework: Framework to get patterns for. If None, returns all patterns.

        Returns:
            List of threat patterns
        """
        pass

    def analyze_system(self, system: SystemModel) -> dict:
        """
        Perform comprehensive system analysis.

        This is a convenience method that can be overridden by plugins
        to provide additional analysis beyond threat detection.

        Args:
            system: System model to analyze

        Returns:
            Dictionary with analysis results
        """
        threats = self.detect_threats(system)
        return {
            "threats": threats,
            "threat_count": len(threats),
            "components_analyzed": len(system.components),
            "data_flows_analyzed": len(system.data_flows),
        }

"""
Core data models for threat modeling.

These models represent the base structure for threat models, components, threats,
and related entities. They are framework-agnostic and work with all system types.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SystemType(str, Enum):
    """Supported system types."""

    LLM_APP = "llm-app"
    AGENTIC_SYSTEM = "agentic-system"
    MULTI_AGENT = "multi-agent"
    MCP_SERVER = "mcp-server"
    WEB_APP = "web-app"
    MOBILE_APP = "mobile-app"
    API = "api"
    MICROSERVICES = "microservices"
    CLOUD_INFRASTRUCTURE = "cloud-infrastructure"


class ThreatModelingFramework(str, Enum):
    """Supported threat modeling frameworks."""

    OWASP_LLM_TOP10_2025 = "owasp-llm-top10-2025"
    OWASP_AGENTIC_TOP10_2026 = "owasp-agentic-top10-2026"
    OWASP_TOP10_2021 = "owasp-top10-2021"
    OWASP_MOBILE_TOP10 = "owasp-mobile-top10"
    OWASP_API_TOP10 = "owasp-api-top10"
    STRIDE = "stride"
    DREAD = "dread"
    PASTA = "pasta"
    TRIKE = "trike"
    PLOT4AI = "plot4ai"
    CUSTOM = "custom"


class ComponentType(str, Enum):
    """Component types across all system types."""

    # AI-specific
    LLM = "llm"
    AGENT = "agent"
    TOOL = "tool"
    MEMORY = "memory"
    MCP_SERVER = "mcp-server"

    # Web/Mobile/API
    WEB_SERVER = "web-server"
    API_ENDPOINT = "api-endpoint"
    MOBILE_APP = "mobile-app"
    BROWSER = "browser"

    # Services
    AUTHENTICATION_SERVICE = "authentication-service"
    AUTHORIZATION_SERVICE = "authorization-service"

    # Infrastructure
    DATABASE = "database"
    CACHE = "cache"
    MESSAGE_QUEUE = "message-queue"
    LOAD_BALANCER = "load-balancer"
    CDN = "cdn"
    FIREWALL = "firewall"


class TrustLevel(str, Enum):
    """Trust levels for components."""

    UNTRUSTED = "untrusted"
    INTERNAL = "internal"
    PRIVILEGED = "privileged"
    SYSTEM = "system"


class DataClassification(str, Enum):
    """Data classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Severity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MitigationStatus(str, Enum):
    """Mitigation implementation status."""

    PROPOSED = "proposed"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"


class Metadata(BaseModel):
    """Metadata for threat model."""

    version: str = Field(..., description="Schema version")
    created: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    author: Optional[str] = Field(None, description="Author or team name")
    description: Optional[str] = Field(None, description="Description of the threat model")


class Component(BaseModel):
    """Represents a system component."""

    id: str = Field(..., description="Unique identifier")
    name: str = Field(..., description="Human-readable name")
    type: ComponentType = Field(..., description="Component type")
    capabilities: List[str] = Field(default_factory=list, description="List of capabilities")
    trust_level: TrustLevel = Field(default=TrustLevel.UNTRUSTED, description="Trust level")
    description: Optional[str] = Field(None, description="Component description")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Ensure ID is not empty."""
        if not v or not v.strip():
            raise ValueError("Component ID cannot be empty")
        return v.strip()


class DataFlow(BaseModel):
    """Represents data flow between components."""

    from_component: str = Field(..., alias="from", description="Source component ID")
    to_component: str = Field(..., alias="to", description="Target component ID")
    data_type: Optional[str] = Field(None, description="Type of data")
    classification: DataClassification = Field(
        default=DataClassification.INTERNAL, description="Data classification"
    )
    protocol: Optional[str] = Field(None, description="Protocol used (e.g., HTTP, HTTPS)")
    encrypted: bool = Field(default=False, description="Whether data is encrypted in transit")

    model_config = ConfigDict(populate_by_name=True)


class SystemModel(BaseModel):
    """Represents the system being modeled."""

    name: str = Field(..., description="System name")
    type: SystemType = Field(..., description="System type")
    threat_modeling_framework: ThreatModelingFramework = Field(
        ..., description="Threat modeling framework"
    )
    components: List[Component] = Field(default_factory=list, description="System components")
    data_flows: List[DataFlow] = Field(default_factory=list, description="Data flows")

    def get_component(self, component_id: str) -> Optional[Component]:
        """Get component by ID."""
        return next((c for c in self.components if c.id == component_id), None)

    def get_data_flows_from(self, component_id: str) -> List[DataFlow]:
        """Get all data flows originating from a component."""
        return [df for df in self.data_flows if df.from_component == component_id]

    def get_data_flows_to(self, component_id: str) -> List[DataFlow]:
        """Get all data flows going to a component."""
        return [df for df in self.data_flows if df.to_component == component_id]


class RiskScore(BaseModel):
    """DREAD risk score."""

    damage: Optional[float] = Field(None, ge=0, le=10, description="Damage if exploited")
    reproducibility: Optional[float] = Field(None, ge=0, le=10, description="Ease of reproduction")
    exploitability: Optional[float] = Field(None, ge=0, le=10, description="Ease of exploitation")
    affected_users: Optional[float] = Field(None, ge=0, le=10, description="Number of affected users")
    discoverability: Optional[float] = Field(None, ge=0, le=10, description="Ease of discovery")
    calculated: Optional[float] = Field(None, ge=0, le=10, description="Calculated DREAD score")

    def calculate(self) -> float:
        """Calculate DREAD score as average of all factors."""
        factors = [
            self.damage,
            self.reproducibility,
            self.exploitability,
            self.affected_users,
            self.discoverability,
        ]
        valid_factors = [f for f in factors if f is not None]
        if not valid_factors:
            return 0.0
        return sum(valid_factors) / len(valid_factors)


class Mitigation(BaseModel):
    """Represents a mitigation strategy."""

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique identifier")
    description: str = Field(..., description="Mitigation description")
    implementation: Optional[str] = Field(None, description="Implementation details")
    status: MitigationStatus = Field(default=MitigationStatus.PROPOSED, description="Status")
    priority: Optional[str] = Field(None, description="Priority: high, medium, low")


class Threat(BaseModel):
    """Represents a threat."""

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique identifier")
    category: str = Field(..., description="Threat category (e.g., LLM01, A01)")
    framework: ThreatModelingFramework = Field(..., description="Framework")
    title: str = Field(..., description="Threat title")
    description: Optional[str] = Field(None, description="Detailed description")
    severity: Optional[Severity] = Field(None, description="Severity level")
    affected_components: List[str] = Field(default_factory=list, description="Affected component IDs")
    affected_data_flows: List[str] = Field(default_factory=list, description="Affected data flow IDs")
    attack_vectors: List[str] = Field(default_factory=list, description="Attack vectors")
    detection_patterns: List[str] = Field(default_factory=list, description="Detection patterns")
    mitigations: List[Mitigation] = Field(default_factory=list, description="Mitigation strategies")
    risk_score: Optional[RiskScore] = Field(None, description="Risk score")
    references: List[dict] = Field(default_factory=list, description="References")
    # PLOT4AI specific fields
    lifecycle_phase: Optional[str] = Field(None, description="PLOT4AI lifecycle phase (Design, Input, Model, Output, Deploy, Monitor)")
    elicitation_question: Optional[str] = Field(None, description="PLOT4AI elicitation question")
    plot4ai_card_id: Optional[str] = Field(None, description="PLOT4AI card ID reference")


class VisualizationNode(BaseModel):
    """Node data for visualization."""

    id: str = Field(..., description="Component ID")
    x: Optional[float] = Field(None, description="X coordinate")
    y: Optional[float] = Field(None, description="Y coordinate")
    type: Optional[str] = Field(None, description="Visual type")
    label: Optional[str] = Field(None, description="Display label")
    threats: List[str] = Field(default_factory=list, description="Threat IDs")
    risk_level: Optional[str] = Field(None, description="Risk level")


class VisualizationEdge(BaseModel):
    """Edge data for visualization."""

    from_component: str = Field(..., alias="from", description="Source component ID")
    to_component: str = Field(..., alias="to", description="Target component ID")
    label: Optional[str] = Field(None, description="Edge label")
    threats: List[str] = Field(default_factory=list, description="Threat IDs")
    data_classification: Optional[DataClassification] = Field(None, description="Data classification")

    model_config = ConfigDict(populate_by_name=True)


class Visualization(BaseModel):
    """Visualization data for UI rendering."""

    layout: str = Field(default="hierarchical", description="Layout algorithm")
    nodes: List[VisualizationNode] = Field(default_factory=list, description="Visualization nodes")
    edges: List[VisualizationEdge] = Field(default_factory=list, description="Visualization edges")


class ThreatModel(BaseModel):
    """Complete threat model."""

    metadata: Metadata = Field(..., description="Model metadata")
    system: SystemModel = Field(..., description="System being modeled")
    threats: List[Threat] = Field(default_factory=list, description="Identified threats")
    visualization: Optional[Visualization] = Field(None, description="Visualization data")

    @classmethod
    def load(cls, file_path: str) -> "ThreatModel":
        """Load threat model from JSON file."""
        import json

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)

    def save(self, file_path: str) -> None:
        """Save threat model to JSON file."""
        import json

        # Update metadata
        self.metadata.updated = datetime.utcnow()

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(mode="json", by_alias=True), f, indent=2, ensure_ascii=False)

    def validate(self) -> List[str]:
        """Validate threat model and return list of errors."""
        errors = []

        # Validate component IDs in data flows
        component_ids = {c.id for c in self.system.components}
        for df in self.system.data_flows:
            if df.from_component not in component_ids:
                errors.append(f"Data flow references unknown component: {df.from_component}")
            if df.to_component not in component_ids:
                errors.append(f"Data flow references unknown component: {df.to_component}")

        # Validate affected components in threats
        for threat in self.threats:
            for comp_id in threat.affected_components:
                if comp_id not in component_ids:
                    errors.append(f"Threat {threat.id} references unknown component: {comp_id}")

        return errors

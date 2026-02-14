"""
Multi-Agent System Plugin for threat modeling.

Handles threat detection for multi-agent systems using OWASP Multi-Agentic System Threat Modeling Guide.
"""

import json
from pathlib import Path
from typing import List, Optional

from ...core.models import (
    Component,
    ComponentType,
    Severity,
    SystemModel,
    SystemType,
    Threat,
    ThreatModelingFramework,
)
from ..base_plugin import ThreatModelPlugin, ThreatPattern, ValidationResult
from .threat_detection import find_data_flow_by_id


class MultiAgentPlugin(ThreatModelPlugin):
    """Plugin for multi-agent system threat modeling."""

    def __init__(self):
        """Initialize Multi-Agent plugin and load threat patterns."""
        self._patterns: List[ThreatPattern] = []
        self._load_patterns()

    @property
    def system_type(self) -> SystemType:
        """Return the system type this plugin handles."""
        return SystemType.MULTI_AGENT

    @property
    def supported_frameworks(self) -> List[ThreatModelingFramework]:
        """Return list of frameworks this plugin supports."""
        return [
            ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
            ThreatModelingFramework.CUSTOM,
        ]

    def _load_patterns(self) -> None:
        """Load threat patterns from JSON files, falling back to defaults."""
        # Always start with default patterns
        default_patterns = self._get_default_patterns()
        patterns_dict = {p.id: p for p in default_patterns}

        # Try to load JSON files to override or supplement defaults
        patterns_dir = (
            Path(__file__).parent.parent.parent.parent.parent
            / "patterns"
            / "ai"
            / "multi-agent"
        )

        if patterns_dir.exists():
            for pattern_file in patterns_dir.glob("*.json"):
                try:
                    with open(pattern_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pattern = ThreatPattern(**data)
                        patterns_dict[pattern.id] = pattern
                except Exception as e:
                    from ...utils.logging import log_pattern_load_error
                    log_pattern_load_error(str(pattern_file), e)

        self._patterns = list(patterns_dict.values())

    def _get_default_patterns(self) -> List[ThreatPattern]:
        """Get default threat patterns for multi-agent systems."""
        return [
            ThreatPattern(
                id="MULTI-AGENT-01",
                category="MULTI-AGENT-01",
                framework=ThreatModelingFramework.CUSTOM,
                title="Agent-to-Agent Communication Vulnerabilities",
                description="Vulnerabilities in communication between agents, including message tampering, replay attacks, and unauthorized access to inter-agent messages.",
                detection_patterns=[
                    "Agents communicate without encryption",
                    "No authentication between agents",
                    "Message integrity not verified",
                    "No replay attack protection",
                ],
                attack_vectors=[
                    "Man-in-the-middle attacks on agent communication",
                    "Message replay attacks",
                    "Message tampering",
                    "Unauthorized message interception",
                ],
                mitigations=[
                    {
                        "id": "secure-communication",
                        "description": "Encrypt and authenticate all agent-to-agent communication",
                        "implementation": "Use TLS with mutual authentication",
                        "priority": "high",
                    },
                    {
                        "id": "message-integrity",
                        "description": "Verify message integrity",
                        "implementation": "Use message authentication codes (MACs)",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="MULTI-AGENT-02",
                category="MULTI-AGENT-02",
                framework=ThreatModelingFramework.CUSTOM,
                title="Orchestration Layer Vulnerabilities",
                description="Vulnerabilities in the orchestration layer that coordinates multiple agents, including unauthorized agent spawning and coordination manipulation.",
                detection_patterns=[
                    "Orchestrator has no access controls",
                    "Agents can be spawned without limits",
                    "Orchestration commands not validated",
                    "No monitoring of orchestration activities",
                ],
                attack_vectors=[
                    "Orchestrator compromise",
                    "Unauthorized agent spawning",
                    "Coordination manipulation",
                    "Resource exhaustion via agent spawning",
                ],
                mitigations=[
                    {
                        "id": "orchestrator-security",
                        "description": "Secure the orchestration layer",
                        "implementation": "Implement access controls and validation",
                        "priority": "high",
                    },
                    {
                        "id": "spawn-limits",
                        "description": "Implement limits on agent spawning",
                        "implementation": "Set quotas and limits",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="MULTI-AGENT-03",
                category="MULTI-AGENT-03",
                framework=ThreatModelingFramework.CUSTOM,
                title="Shared State Vulnerabilities",
                description="Vulnerabilities in shared state or memory between agents, including race conditions, state corruption, and unauthorized state access.",
                detection_patterns=[
                    "Agents share state without synchronization",
                    "No locking mechanisms for shared resources",
                    "State can be corrupted by concurrent access",
                    "No access controls on shared state",
                ],
                attack_vectors=[
                    "Race conditions",
                    "State corruption",
                    "Unauthorized state access",
                    "Concurrent modification attacks",
                ],
                mitigations=[
                    {
                        "id": "state-synchronization",
                        "description": "Implement proper state synchronization",
                        "implementation": "Use locks, transactions, or immutable state",
                        "priority": "high",
                    },
                    {
                        "id": "state-isolation",
                        "description": "Isolate agent state where possible",
                        "implementation": "Use separate state stores per agent",
                        "priority": "medium",
                    },
                ],
            ),
            ThreatPattern(
                id="MULTI-AGENT-04",
                category="MULTI-AGENT-04",
                framework=ThreatModelingFramework.CUSTOM,
                title="Agent Isolation Failures",
                description="Failures in isolating agents from each other, allowing unauthorized access to agent resources or data.",
                detection_patterns=[
                    "Agents share resources without isolation",
                    "No sandboxing between agents",
                    "Agents can access other agents' data",
                    "Resource limits not enforced per agent",
                ],
                attack_vectors=[
                    "Cross-agent attacks",
                    "Resource interference",
                    "Data leakage between agents",
                    "Privilege escalation",
                ],
                mitigations=[
                    {
                        "id": "agent-isolation",
                        "description": "Isolate agents from each other",
                        "implementation": "Use sandboxing and resource isolation",
                        "priority": "high",
                    },
                    {
                        "id": "resource-quotas",
                        "description": "Enforce resource quotas per agent",
                        "implementation": "Set CPU, memory, and network limits",
                        "priority": "medium",
                    },
                ],
            ),
            ThreatPattern(
                id="MULTI-AGENT-05",
                category="MULTI-AGENT-05",
                framework=ThreatModelingFramework.CUSTOM,
                title="Distributed Decision Making Vulnerabilities",
                description="Vulnerabilities in distributed decision-making processes, including consensus manipulation and voting attacks.",
                detection_patterns=[
                    "No consensus mechanism",
                    "Voting can be manipulated",
                    "Decisions not verified",
                    "No quorum requirements",
                ],
                attack_vectors=[
                    "Consensus manipulation",
                    "Voting attacks",
                    "Sybil attacks",
                    "Decision corruption",
                ],
                mitigations=[
                    {
                        "id": "consensus-mechanism",
                        "description": "Implement robust consensus mechanism",
                        "implementation": "Use Byzantine fault tolerance",
                        "priority": "high",
                    },
                    {
                        "id": "decision-verification",
                        "description": "Verify distributed decisions",
                        "implementation": "Require quorum and verification",
                        "priority": "high",
                    },
                ],
            ),
        ]

    def detect_threats(self, system: SystemModel) -> List[Threat]:
        """
        Detect threats based on system model.

        Args:
            system: The system model to analyze

        Returns:
            List of detected threats
        """
        threats = []

        # Get patterns for the system's framework
        patterns = self.get_threat_patterns(system.threat_modeling_framework)

        # Count agents
        agents = [c for c in system.components if c.type == ComponentType.AGENT]

        if len(agents) < 2:
            # Not really a multi-agent system
            return threats

        # Analyze agent interactions
        agent_threats = self._analyze_agent_interactions(agents, system, patterns)
        threats.extend(agent_threats)

        # Analyze data flows between agents
        for data_flow in system.data_flows:
            from_agent = system.get_component(data_flow.from_component)
            to_agent = system.get_component(data_flow.to_component)

            if from_agent and to_agent and from_agent.type == ComponentType.AGENT and to_agent.type == ComponentType.AGENT:
                flow_threats = self._analyze_agent_data_flow(data_flow, system, patterns)
                threats.extend(flow_threats)

        # Analyze shared resources
        shared_threats = self._analyze_shared_resources(system, patterns)
        threats.extend(shared_threats)

        return threats

    def _analyze_agent_interactions(
        self, agents: List[Component], system: SystemModel, patterns: List[ThreatPattern]
    ) -> List[Threat]:
        """Analyze agent-to-agent interactions."""
        threats = []

        # Check for isolation failures (MULTI-AGENT-04)
        if len(agents) > 1:
            threat = Threat(
                category="MULTI-AGENT-04",
                framework=ThreatModelingFramework.CUSTOM,
                title="Agent Isolation Failures",
                description=f"Multiple agents ({len(agents)}) detected. Ensure proper isolation between agents.",
                severity=Severity.MEDIUM,
                affected_components=[a.id for a in agents],
            )
            threats.append(threat)

        # Check for orchestration vulnerabilities (MULTI-AGENT-02)
        orchestrators = [
            c for c in system.components if "orchestrat" in c.name.lower() or "coordinator" in c.name.lower()
        ]
        if orchestrators:
            threat = Threat(
                category="MULTI-AGENT-02",
                framework=ThreatModelingFramework.CUSTOM,
                title="Orchestration Layer Vulnerabilities",
                description="Orchestration layer detected. Ensure proper access controls and validation.",
                severity=Severity.HIGH,
                affected_components=[o.id for o in orchestrators],
            )
            threats.append(threat)

        return threats

    def _analyze_agent_data_flow(
        self, data_flow, system: SystemModel, patterns: List[ThreatPattern]
    ) -> List[Threat]:
        """Analyze data flows between agents."""
        threats = []

        # Check for insecure communication (MULTI-AGENT-01)
        if not data_flow.encrypted:
            threat = Threat(
                category="MULTI-AGENT-01",
                framework=ThreatModelingFramework.CUSTOM,
                title="Agent-to-Agent Communication Vulnerabilities",
                description=f"Agent communication between {data_flow.from_component} and {data_flow.to_component} is not encrypted",
                severity=Severity.HIGH,
                affected_data_flows=[f"{data_flow.from_component}->{data_flow.to_component}"],
            )
            threats.append(threat)

        return threats

    def _analyze_shared_resources(
        self, system: SystemModel, patterns: List[ThreatPattern]
    ) -> List[Threat]:
        """Analyze shared resources and state."""
        threats = []

        # Check for shared memory/state components
        shared_components = [
            c
            for c in system.components
            if c.type == ComponentType.MEMORY
            or "shared" in c.name.lower()
            or "state" in c.name.lower()
        ]

        if len(shared_components) > 0:
            # Check data flows to shared components from multiple agents
            agent_ids = {c.id for c in system.components if c.type == ComponentType.AGENT}
            shared_access = {}

            for df in system.data_flows:
                if df.to_component in [sc.id for sc in shared_components]:
                    if df.from_component in agent_ids:
                        if df.to_component not in shared_access:
                            shared_access[df.to_component] = []
                        shared_access[df.to_component].append(df.from_component)

            # If multiple agents access same shared resource, flag it
            for shared_id, accessing_agents in shared_access.items():
                if len(accessing_agents) > 1:
                    threat = Threat(
                        category="MULTI-AGENT-03",
                        framework=ThreatModelingFramework.CUSTOM,
                        title="Shared State Vulnerabilities",
                        description=f"Multiple agents ({len(accessing_agents)}) access shared resource {shared_id}. Ensure proper synchronization.",
                        severity=Severity.MEDIUM,
                        affected_components=[shared_id] + accessing_agents,
                    )
                    threats.append(threat)

        return threats

    def get_component_types(self) -> List[str]:
        """Return list of component types for multi-agent systems."""
        return [
            ComponentType.AGENT.value,
            ComponentType.LLM.value,
            ComponentType.TOOL.value,
            ComponentType.MEMORY.value,
            ComponentType.MCP_SERVER.value,
            ComponentType.DATABASE.value,
            ComponentType.API_ENDPOINT.value,
            ComponentType.AUTHENTICATION_SERVICE.value,
        ]

    def validate_component(self, component: Component) -> ValidationResult:
        """Validate component for multi-agent system."""
        errors = []
        warnings = []

        valid_types = self.get_component_types()
        if component.type.value not in valid_types:
            warnings.append(f"Component type {component.type.value} may not be typical for multi-agent systems")

        if not component.name:
            errors.append("Component name is required")

        if component.type == ComponentType.AGENT and not component.capabilities:
            warnings.append("Agent component should specify capabilities")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def get_threat_patterns(
        self, framework: Optional[ThreatModelingFramework] = None
    ) -> List[ThreatPattern]:
        """Get threat patterns for specific framework."""
        if framework is None:
            return self._patterns

        return [p for p in self._patterns if p.framework == framework]

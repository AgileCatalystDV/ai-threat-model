"""
Agentic System Plugin for threat modeling.

Handles threat detection for agentic systems using OWASP Agentic Top 10 2026 framework.
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
from .threat_detection import (
    check_insecure_data_flow,
    create_threat_from_pattern,
    pattern_matches_component,
)


class AgenticPlugin(ThreatModelPlugin):
    """Plugin for agentic system threat modeling."""

    def __init__(self):
        """Initialize Agentic plugin and load threat patterns."""
        self._patterns: List[ThreatPattern] = []
        self._load_patterns()

    @property
    def system_type(self) -> SystemType:
        """Return the system type this plugin handles."""
        return SystemType.AGENTIC_SYSTEM

    @property
    def supported_frameworks(self) -> List[ThreatModelingFramework]:
        """Return list of frameworks this plugin supports."""
        return [ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026]

    def _load_patterns(self) -> None:
        """Load threat patterns from JSON files, falling back to defaults."""
        # Always start with default patterns
        default_patterns = self._get_default_patterns()
        patterns_dict = {p.id: p for p in default_patterns}
        
        # Try to load JSON files to override or supplement defaults
        patterns_dir = Path(__file__).parent.parent.parent.parent.parent / "patterns" / "ai" / "agentic-top10"
        
        if patterns_dir.exists():
            for pattern_file in patterns_dir.glob("*.json"):
                try:
                    with open(pattern_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pattern = ThreatPattern(**data)
                        # Override default with JSON version if it exists
                        patterns_dict[pattern.id] = pattern
                except Exception as e:
                    # Log error but continue loading other patterns
                    from ...utils.logging import log_pattern_load_error
                    log_pattern_load_error(str(pattern_file), e)
        
        # Convert back to list
        self._patterns = list(patterns_dict.values())

    def _get_default_patterns(self) -> List[ThreatPattern]:
        """Get default threat patterns for OWASP Agentic Top 10 2026."""
        return [
            ThreatPattern(
                id="AGENTIC01",
                category="AGENTIC01",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Agent Goal Hijack",
                description="Goal hijacking targets the core of an agent: its ability to plan and act autonomously. If an attacker can redirect the goal itself, the entire chain of actions becomes compromised.",
                detection_patterns=[
                    "Agent receives untrusted input without validation",
                    "No input sanitization for agent prompts",
                    "Agent state can be manipulated externally",
                ],
                attack_vectors=[
                    "Prompt injection to manipulate agent behavior",
                    "Environment manipulation",
                    "State corruption attacks",
                ],
                mitigations=[
                    {
                        "id": "input-validation",
                        "description": "Validate and sanitize all agent inputs",
                        "implementation": "Implement input validation and sanitization",
                        "priority": "high",
                    },
                    {
                        "id": "state-protection",
                        "description": "Protect agent state from unauthorized modification",
                        "implementation": "Implement state validation and integrity checks",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC02",
                category="AGENTIC02",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Tool Misuse and Exploitation",
                description="Agents gain real-world power through the tools they can access. When misled through prompt injection, misalignment, or unsafe design, an agent may use legitimate tools in unsafe ways.",
                detection_patterns=[
                    "Agent can execute arbitrary tools",
                    "No authorization checks before tool execution",
                    "Tools have excessive permissions",
                ],
                attack_vectors=[
                    "Unauthorized tool execution",
                    "Privilege escalation via tools",
                    "Malicious tool invocation",
                ],
                mitigations=[
                    {
                        "id": "tool-authorization",
                        "description": "Implement authorization for tool execution",
                        "implementation": "Use least privilege and authorization checks",
                        "priority": "high",
                    },
                    {
                        "id": "tool-sandboxing",
                        "description": "Sandbox tool execution",
                        "implementation": "Isolate tool execution environments",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC03",
                category="AGENTIC03",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Identity and Privilege Abuse",
                description="Most agentic systems lack real, governable identities. Instead, agents inherit context, credentials, or privileges in ways traditional IAM systems were never designed for.",
                detection_patterns=[
                    "Agents can spawn other agents",
                    "No limits on resource creation",
                    "No monitoring of agent proliferation",
                ],
                attack_vectors=[
                    "Resource exhaustion via agent spawning",
                    "Denial of service",
                ],
                mitigations=[
                    {
                        "id": "spawn-limits",
                        "description": "Implement limits on agent spawning",
                        "implementation": "Set quotas and limits on agent creation",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC04",
                category="AGENTIC04",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Agentic Supply Chain Vulnerabilities",
                description="Agentic systems don't run in isolation, they assemble models, tools, templates, plugins, and third-party agents at runtime. This creates a live, constantly shifting supply chain.",
                detection_patterns=[
                    "Orchestrator has no access controls",
                    "Agent coordination can be manipulated",
                    "No validation of orchestration commands",
                ],
                attack_vectors=[
                    "Orchestrator compromise",
                    "Agent coordination attacks",
                ],
                mitigations=[
                    {
                        "id": "orchestrator-security",
                        "description": "Secure the orchestration layer",
                        "implementation": "Implement access controls and validation",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC05",
                category="AGENTIC05",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Unexpected Code Execution (RCE)",
                description="Agents often call code execution tools—shells, runtimes, notebooks, scripts—to complete tasks. When an attacker manipulates those inputs, the agent can unintentionally execute arbitrary or malicious code.",
                detection_patterns=[
                    "Memory accessible without authorization",
                    "No memory validation",
                    "Memory can be corrupted",
                ],
                attack_vectors=[
                    "Memory corruption attacks",
                    "Unauthorized memory access",
                ],
                mitigations=[
                    {
                        "id": "memory-protection",
                        "description": "Protect agent memory",
                        "implementation": "Implement memory access controls and validation",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC06",
                category="AGENTIC06",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Memory and Context Poisoning",
                description="Agents use memory to store context, preferences, tasks, and past actions. If attackers can insert malicious content into that memory, the agent becomes permanently biased or compromised.",
                detection_patterns=[
                    "Agents share resources without isolation",
                    "No sandboxing between agents",
                    "Agents can access other agents' data",
                ],
                attack_vectors=[
                    "Cross-agent attacks",
                    "Resource interference",
                ],
                mitigations=[
                    {
                        "id": "agent-isolation",
                        "description": "Isolate agents from each other",
                        "implementation": "Implement sandboxing and resource isolation",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC07",
                category="AGENTIC07",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Insecure Inter-Agent Communication",
                description="Multi-agent systems rely entirely on messages to coordinate. If those messages aren't authenticated, encrypted, or validated, a single spoofed or tampered instruction can mislead multiple agents.",
                detection_patterns=[
                    "Agent communication not encrypted",
                    "No authentication between agents",
                    "Communication channels unprotected",
                ],
                attack_vectors=[
                    "Man-in-the-middle attacks",
                    "Communication interception",
                ],
                mitigations=[
                    {
                        "id": "secure-communication",
                        "description": "Encrypt and authenticate agent communication",
                        "implementation": "Use TLS and mutual authentication",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC08",
                category="AGENTIC08",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Cascading Failures",
                description="Agentic systems are deeply interconnected. One bad output, whether a hallucination, malicious input, or poisoned memory, can ripple across multiple agents and workflows.",
                detection_patterns=[
                    "No logging of agent actions",
                    "No monitoring of agent behavior",
                    "No audit trail",
                ],
                attack_vectors=[
                    "Undetected malicious behavior",
                    "Lack of accountability",
                ],
                mitigations=[
                    {
                        "id": "observability",
                        "description": "Implement comprehensive logging and monitoring",
                        "implementation": "Log all agent actions and decisions",
                        "priority": "medium",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC09",
                category="AGENTIC09",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Human-Agent Trust Exploitation",
                description="Agents generate polished, authoritative-sounding explanations. Humans tend to trust them—even when they're compromised or manipulated.",
                detection_patterns=[
                    "Agents deployed without authentication",
                    "No secure deployment process",
                    "Agents accessible without authorization",
                ],
                attack_vectors=[
                    "Unauthorized agent access",
                    "Deployment compromise",
                ],
                mitigations=[
                    {
                        "id": "secure-deployment",
                        "description": "Implement secure deployment practices",
                        "implementation": "Use authentication and secure deployment pipelines",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="AGENTIC10",
                category="AGENTIC10",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Rogue Agents",
                description="A Rogue Agent is an AI that drifts from its intended behavior and acts with harmful autonomy. It becomes the ultimate insider threat: authorized, trusted, but misaligned.",
                detection_patterns=[
                    "Third-party agents used without verification",
                    "External models or tools integrated",
                    "No security review of dependencies",
                ],
                attack_vectors=[
                    "Malicious third-party agents",
                    "Compromised dependencies",
                ],
                mitigations=[
                    {
                        "id": "supply-chain-review",
                        "description": "Review and verify all dependencies",
                        "implementation": "Implement dependency scanning and verification",
                        "priority": "medium",
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

        # Analyze each component
        for component in system.components:
            component_threats = self._analyze_component(component, system, patterns)
            threats.extend(component_threats)

        # Analyze data flows
        for data_flow in system.data_flows:
            flow_threats = self._analyze_data_flow(data_flow, system, patterns)
            threats.extend(flow_threats)

        # Analyze agent-specific threats
        agent_threats = self._analyze_agent_interactions(system, patterns)
        threats.extend(agent_threats)

        return threats

    def _analyze_component(self, component: Component, system: SystemModel, patterns: List[ThreatPattern]) -> List[Threat]:
        """Analyze a component for threats."""
        threats = []

        # Check each pattern against the component
        for pattern in patterns:
            if self._pattern_matches_component(pattern, component, system):
                threat = self._create_threat_from_pattern(pattern, component, system)
                threats.append(threat)

        return threats

    def _analyze_data_flow(self, data_flow, system: SystemModel, patterns: List[ThreatPattern]) -> List[Threat]:
        """Analyze a data flow for threats."""
        threats = []

        # Check for insecure communication (AGENTIC07) - any unencrypted flow
        if not data_flow.encrypted:
            from_comp = system.get_component(data_flow.from_component)
            to_comp = system.get_component(data_flow.to_component)
            from_name = from_comp.name if from_comp else data_flow.from_component
            to_name = to_comp.name if to_comp else data_flow.to_component
            
            threat = Threat(
                category="AGENTIC07",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Insecure Communication",
                description=f"Agent communication between {from_name} and {to_name} is not encrypted",
                severity=Severity.HIGH,
                affected_data_flows=[f"{data_flow.from_component}->{data_flow.to_component}"],
            )
            threats.append(threat)

        return threats

    def _analyze_agent_interactions(self, system: SystemModel, patterns: List[ThreatPattern]) -> List[Threat]:
        """Analyze agent-to-agent interactions for threats."""
        threats = []

        # Count agents
        agents = [c for c in system.components if c.type == ComponentType.AGENT]
        
        if len(agents) > 1:
            # Check for insufficient isolation (AGENTIC06)
            # This is a simplified check - in reality, we'd need more context
            threat = Threat(
                category="AGENTIC06",
                framework=ThreatModelingFramework.OWASP_AGENTIC_TOP10_2026,
                title="Insufficient Agent Isolation",
                description=f"Multiple agents ({len(agents)}) detected. Ensure proper isolation between agents.",
                severity=Severity.MEDIUM,
                affected_components=[a.id for a in agents],
            )
            threats.append(threat)

        return threats

    def _pattern_matches_component(self, pattern: ThreatPattern, component: Component, system: SystemModel) -> bool:
        """Check if a threat pattern matches a component."""
        # Agentic-specific component types that trigger certain patterns
        agentic_risk_patterns = {
            ComponentType.AGENT: ["AGENTIC01", "AGENTIC02", "AGENTIC05", "AGENTIC06"],
            ComponentType.TOOL: ["AGENTIC02"],
        }

        if component.type in agentic_risk_patterns:
            if pattern.id in agentic_risk_patterns[component.type]:
                return True

        component_types = [component.type.value] if component.type in agentic_risk_patterns else []
        # Use enhanced pattern matching with system context
        return pattern_matches_component(pattern, component, component_types, system)

    def _create_threat_from_pattern(self, pattern: ThreatPattern, component: Component, system: SystemModel) -> Threat:
        """Create a Threat object from a pattern."""
        # Agentic-specific severity mapping
        severity_map = {
            "AGENTIC01": Severity.CRITICAL,
            "AGENTIC02": Severity.HIGH,
            "AGENTIC03": Severity.HIGH,
            "AGENTIC04": Severity.HIGH,
            "AGENTIC05": Severity.HIGH,
            "AGENTIC06": Severity.MEDIUM,
            "AGENTIC07": Severity.HIGH,
            "AGENTIC08": Severity.MEDIUM,
            "AGENTIC09": Severity.HIGH,
            "AGENTIC10": Severity.MEDIUM,
        }

        return create_threat_from_pattern(pattern, component, severity_map)

    def get_component_types(self) -> List[str]:
        """Return list of component types for agentic systems."""
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
        """Validate component for agentic system."""
        errors = []
        warnings = []

        # Check if component type is valid for agentic systems
        valid_types = self.get_component_types()
        if component.type.value not in valid_types:
            warnings.append(f"Component type {component.type.value} may not be typical for agentic systems")

        # Check for required fields
        if not component.name:
            errors.append("Component name is required")

        if component.type == ComponentType.AGENT and not component.capabilities:
            warnings.append("Agent component should specify capabilities")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def get_threat_patterns(self, framework: Optional[ThreatModelingFramework] = None) -> List[ThreatPattern]:
        """Get threat patterns for specific framework."""
        if framework is None:
            return self._patterns

        return [p for p in self._patterns if p.framework == framework]

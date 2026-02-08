"""
LLM Application Plugin for threat modeling.

Handles threat detection for LLM applications using OWASP LLM Top 10 2025 framework.
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


class LLMPlugin(ThreatModelPlugin):
    """Plugin for LLM application threat modeling."""

    def __init__(self):
        """Initialize LLM plugin and load threat patterns."""
        self._patterns: List[ThreatPattern] = []
        self._load_patterns()

    @property
    def system_type(self) -> SystemType:
        """Return the system type this plugin handles."""
        return SystemType.LLM_APP

    @property
    def supported_frameworks(self) -> List[ThreatModelingFramework]:
        """Return list of frameworks this plugin supports."""
        return [ThreatModelingFramework.OWASP_LLM_TOP10_2025]

    def _load_patterns(self) -> None:
        """Load threat patterns from JSON files, falling back to defaults."""
        # Always start with default patterns
        default_patterns = self._get_default_patterns()
        patterns_dict = {p.id: p for p in default_patterns}
        
        # Try to load JSON files to override or supplement defaults
        patterns_dir = Path(__file__).parent.parent.parent.parent.parent / "patterns" / "ai" / "llm-top10"
        
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
                    print(f"Warning: Failed to load pattern {pattern_file}: {e}")
        
        # Convert back to list
        self._patterns = list(patterns_dict.values())

    def _get_default_patterns(self) -> List[ThreatPattern]:
        """Get default threat patterns for OWASP LLM Top 10 2025."""
        return [
            ThreatPattern(
                id="LLM01",
                category="LLM01",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Prompt Injection",
                description="Prompt injection occurs when untrusted input is embedded in a prompt, causing the LLM to execute unintended instructions or expose data.",
                detection_patterns=[
                    "User input directly concatenated to system prompts",
                    "No input sanitization or validation",
                    "External data sources used in prompts without validation",
                ],
                attack_vectors=[
                    "Direct injection via user input",
                    "Indirect injection via external data sources",
                    "Second-order injection through stored data",
                ],
                mitigations=[
                    {
                        "id": "input-validation",
                        "description": "Validate and sanitize all user inputs",
                        "implementation": "Use input validation libraries and sanitize special characters",
                        "priority": "high",
                    },
                    {
                        "id": "prompt-separation",
                        "description": "Separate user input from system prompts",
                        "implementation": "Use structured prompts with clear boundaries",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM02",
                category="LLM02",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Insecure Output Handling",
                description="Insecure output handling occurs when LLM outputs are not validated or sanitized before being used, leading to XSS, CSRF, or other attacks.",
                detection_patterns=[
                    "LLM output used directly in HTML/JavaScript",
                    "No output validation or sanitization",
                    "LLM output used in security-sensitive contexts",
                ],
                attack_vectors=[
                    "XSS via malicious LLM output",
                    "CSRF via LLM-generated URLs",
                    "Code injection via LLM output",
                ],
                mitigations=[
                    {
                        "id": "output-validation",
                        "description": "Validate and sanitize all LLM outputs",
                        "implementation": "Use output encoding and validation libraries",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM03",
                category="LLM03",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Training Data Poisoning",
                description="Training data poisoning occurs when malicious data is introduced into the training dataset, causing the model to produce biased or malicious outputs.",
                detection_patterns=[
                    "Training data from untrusted sources",
                    "No data validation or filtering",
                    "Public datasets used without verification",
                ],
                attack_vectors=[
                    "Injection of malicious examples",
                    "Bias introduction through data manipulation",
                ],
                mitigations=[
                    {
                        "id": "data-validation",
                        "description": "Validate and filter training data",
                        "implementation": "Implement data validation pipelines",
                        "priority": "medium",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM04",
                category="LLM04",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Model Denial of Service",
                description="Model DoS occurs when resource-intensive operations cause the system to become unavailable or degrade performance.",
                detection_patterns=[
                    "No rate limiting on LLM requests",
                    "No timeout mechanisms",
                    "No resource quotas",
                ],
                attack_vectors=[
                    "Resource exhaustion via large prompts",
                    "Rapid request flooding",
                ],
                mitigations=[
                    {
                        "id": "rate-limiting",
                        "description": "Implement rate limiting",
                        "implementation": "Use rate limiting middleware",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM05",
                category="LLM05",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Supply Chain Vulnerabilities",
                description="Supply chain vulnerabilities occur when third-party models, datasets, or plugins contain security flaws.",
                detection_patterns=[
                    "Third-party models used without verification",
                    "External plugins or tools integrated",
                    "No security review of dependencies",
                ],
                attack_vectors=[
                    "Malicious third-party models",
                    "Compromised dependencies",
                ],
                mitigations=[
                    {
                        "id": "supply-chain-review",
                        "description": "Review and verify all dependencies",
                        "implementation": "Implement dependency scanning",
                        "priority": "medium",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM06",
                category="LLM06",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Sensitive Information Disclosure",
                description="Sensitive information disclosure occurs when the LLM reveals confidential data in its outputs.",
                detection_patterns=[
                    "Training data contains sensitive information",
                    "No data filtering or redaction",
                    "LLM has access to sensitive data sources",
                ],
                attack_vectors=[
                    "Prompting for sensitive data",
                    "Inference attacks",
                ],
                mitigations=[
                    {
                        "id": "data-filtering",
                        "description": "Filter sensitive data from training and inference",
                        "implementation": "Implement data redaction and filtering",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM07",
                category="LLM07",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Insecure Plugin Design",
                description="Insecure plugin design occurs when plugins or tools integrated with the LLM have security vulnerabilities.",
                detection_patterns=[
                    "Plugins execute arbitrary code",
                    "No input validation in plugins",
                    "Plugins have excessive permissions",
                ],
                attack_vectors=[
                    "Malicious plugin execution",
                    "Privilege escalation via plugins",
                ],
                mitigations=[
                    {
                        "id": "plugin-security",
                        "description": "Implement secure plugin architecture",
                        "implementation": "Use sandboxing and least privilege",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM08",
                category="LLM08",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Excessive Agency",
                description="Excessive agency occurs when the LLM has too much autonomy and can perform actions without proper authorization.",
                detection_patterns=[
                    "LLM can perform critical actions autonomously",
                    "No human oversight or approval",
                    "Broad permissions granted to LLM",
                ],
                attack_vectors=[
                    "Unauthorized actions via LLM",
                    "Privilege escalation",
                ],
                mitigations=[
                    {
                        "id": "human-oversight",
                        "description": "Implement human oversight for critical actions",
                        "implementation": "Require approval for sensitive operations",
                        "priority": "high",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM09",
                category="LLM09",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Overreliance",
                description="Overreliance occurs when users or systems trust LLM outputs too much without verification.",
                detection_patterns=[
                    "LLM outputs used without verification",
                    "No fact-checking or validation",
                    "Critical decisions based solely on LLM output",
                ],
                attack_vectors=[
                    "Misinformation propagation",
                    "Decision manipulation",
                ],
                mitigations=[
                    {
                        "id": "output-verification",
                        "description": "Verify LLM outputs before use",
                        "implementation": "Implement fact-checking and validation",
                        "priority": "medium",
                    },
                ],
            ),
            ThreatPattern(
                id="LLM10",
                category="LLM10",
                framework=ThreatModelingFramework.OWASP_LLM_TOP10_2025,
                title="Model Theft",
                description="Model theft occurs when proprietary models are copied, reverse-engineered, or extracted without authorization.",
                detection_patterns=[
                    "Model exposed via API without protection",
                    "No access controls on model endpoints",
                    "Model weights accessible",
                ],
                attack_vectors=[
                    "Model extraction attacks",
                    "Unauthorized model access",
                ],
                mitigations=[
                    {
                        "id": "access-controls",
                        "description": "Implement access controls and monitoring",
                        "implementation": "Use authentication and rate limiting",
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

        # Analyze each component
        for component in system.components:
            component_threats = self._analyze_component(component, system, patterns)
            threats.extend(component_threats)

        # Analyze data flows
        for data_flow in system.data_flows:
            flow_threats = self._analyze_data_flow(data_flow, system, patterns)
            threats.extend(flow_threats)

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

        # Check for insecure data flows (LLM06)
        threat = check_insecure_data_flow(
            data_flow,
            system,
            "LLM06",
            ThreatModelingFramework.OWASP_LLM_TOP10_2025,
            "Sensitive Information Disclosure",
        )
        if threat:
            threats.append(threat)

        return threats

    def _pattern_matches_component(self, pattern: ThreatPattern, component: Component, system: SystemModel) -> bool:
        """Check if a threat pattern matches a component."""
        # LLM-specific component types that trigger certain patterns
        llm_risk_patterns = {
            ComponentType.LLM: ["LLM01", "LLM02", "LLM06", "LLM09"],
        }

        component_types = []
        if component.type in llm_risk_patterns:
            if pattern.id in llm_risk_patterns[component.type]:
                return True
            component_types = [component.type.value]

        return pattern_matches_component(pattern, component, component_types)

    def _create_threat_from_pattern(self, pattern: ThreatPattern, component: Component, system: SystemModel) -> Threat:
        """Create a Threat object from a pattern."""
        # LLM-specific severity mapping
        severity_map = {
            "LLM01": Severity.CRITICAL,
            "LLM02": Severity.HIGH,
            "LLM03": Severity.MEDIUM,
            "LLM04": Severity.HIGH,
            "LLM05": Severity.MEDIUM,
            "LLM06": Severity.CRITICAL,
            "LLM07": Severity.HIGH,
            "LLM08": Severity.HIGH,
            "LLM09": Severity.MEDIUM,
            "LLM10": Severity.HIGH,
        }

        return create_threat_from_pattern(pattern, component, severity_map)

    def get_component_types(self) -> List[str]:
        """Return list of component types for LLM applications."""
        return [
            ComponentType.LLM.value,
            ComponentType.AGENT.value,
            ComponentType.TOOL.value,
            ComponentType.MEMORY.value,
            ComponentType.DATABASE.value,
            ComponentType.API_ENDPOINT.value,
            ComponentType.AUTHENTICATION_SERVICE.value,
        ]

    def validate_component(self, component: Component) -> ValidationResult:
        """Validate component for LLM application."""
        errors = []
        warnings = []

        # Check if component type is valid for LLM apps
        valid_types = self.get_component_types()
        if component.type.value not in valid_types:
            warnings.append(f"Component type {component.type.value} may not be typical for LLM applications")

        # Check for required fields
        if not component.name:
            errors.append("Component name is required")

        if not component.capabilities and component.type == ComponentType.LLM:
            warnings.append("LLM component should specify capabilities")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def get_threat_patterns(self, framework: Optional[ThreatModelingFramework] = None) -> List[ThreatPattern]:
        """Get threat patterns for specific framework."""
        if framework is None:
            return self._patterns

        return [p for p in self._patterns if p.framework == framework]

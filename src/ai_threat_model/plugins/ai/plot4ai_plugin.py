"""
PLOT4AI plugin for threat modeling.

Provides PLOT4AI threat detection with elicitation question workflow
and lifecycle phase filtering.

PLOT4AI Source: https://plot4.ai/
GitHub: https://github.com/PLOT4ai/plot4ai-library
License: CC-BY-SA-4.0
Author: Isabel Barberá
"""

from typing import Dict, List, Optional

from ...core.models import (
    Component,
    ComponentType,
    Severity,
    SystemModel,
    SystemType,
    Threat,
    ThreatModelingFramework,
)
from ...core.plot4ai_models import Plot4AICard, Plot4AIDeck, Plot4AILifecyclePhase
from ...utils.plot4ai_converter import convert_plot4ai_card_to_threat_pattern
from ...utils.plot4ai_loader import load_plot4ai_deck
from ..base_plugin import ThreatModelPlugin, ThreatPattern, ValidationResult


class Plot4AIPlugin(ThreatModelPlugin):
    """
    PLOT4AI plugin for holistic AI threat modeling.

    Supports elicitation questions, lifecycle phase filtering,
    and category-based threat detection.
    """

    def __init__(self):
        """Initialize PLOT4AI plugin and load deck."""
        self._deck: Optional[Plot4AIDeck] = None
        self._patterns: Optional[List[ThreatPattern]] = None

    @property
    def system_type(self) -> SystemType:
        """Return the system type this plugin handles."""
        return SystemType.LLM_APP  # PLOT4AI works for all AI types

    @property
    def supported_frameworks(self) -> List[ThreatModelingFramework]:
        """Return list of frameworks this plugin supports."""
        return [ThreatModelingFramework.PLOT4AI]

    def _load_deck(self) -> Plot4AIDeck:
        """Lazy load PLOT4AI deck."""
        if self._deck is None:
            self._deck = load_plot4ai_deck()
        return self._deck

    def _get_patterns(self) -> List[ThreatPattern]:
        """Get converted threat patterns."""
        if self._patterns is None:
            deck = self._load_deck()
            self._patterns = []
            for category_group in deck.categories:
                for card_index, card in enumerate(category_group.cards):
                    pattern = convert_plot4ai_card_to_threat_pattern(
                        card, category_group.id, card_index
                    )
                    self._patterns.append(pattern)
        return self._patterns

    def detect_threats(
        self,
        system: SystemModel,
        lifecycle_phase: Optional[str] = None,
        category: Optional[str] = None,
        aitype: Optional[str] = None,
        answers: Optional[Dict[str, str]] = None,
    ) -> List[Threat]:
        """
        Detect threats based on PLOT4AI methodology.

        Args:
            system: The system model to analyze
            lifecycle_phase: Filter by lifecycle phase (Design, Input, Model, Output, Deploy, Monitor)
            category: Filter by PLOT4AI category
            aitype: Filter by AI type (Traditional, Generative)
            answers: Dictionary mapping card IDs to answers (Yes/No/Maybe) for elicitation questions

        Returns:
            List of detected threats
        """
        deck = self._load_deck()
        threats = []

        # Get all cards, filtered by criteria
        cards = deck.get_all_cards()

        if lifecycle_phase:
            cards = [c for c in cards if lifecycle_phase in c.phases]

        if category:
            cards = [c for c in cards if category in c.categories]

        if aitype:
            cards = [c for c in cards if aitype in c.aitypes]

        # Convert cards to threats
        for category_group in deck.categories:
            for card_index, card in enumerate(category_group.cards):
                if card not in cards:
                    continue

                # Check elicitation question answer if provided
                card_id = f"{category_group.id}-{card_index}"
                if answers and card_id in answers:
                    answer = answers[card_id].lower()
                    # Only include threat if answer matches threatif condition
                    if answer == "maybe" or (
                        answer == "yes" and card.threatif.lower() == "yes"
                    ) or (answer == "no" and card.threatif.lower() == "no"):
                        threat = self._card_to_threat(card, category_group.id, card_index)
                        threats.append(threat)
                else:
                    # If no answers provided, include all cards as potential threats
                    threat = self._card_to_threat(card, category_group.id, card_index)
                    threats.append(threat)

        return threats

    def _card_to_threat(
        self, card: Plot4AICard, category_id: int, card_index: int
    ) -> Threat:
        """Convert PLOT4AI card to Threat model."""
        threat_id = f"PLOT4AI-{category_id}-{card_index}"

        # Convert recommendations to mitigations
        mitigations = []
        if card.recommendation:
            recommendations = [
                line.strip().lstrip("*").strip()
                for line in card.recommendation.split("\n")
                if line.strip() and line.strip().startswith("*")
            ]
            if not recommendations:
                recommendations = [card.recommendation.strip()]

            for idx, rec in enumerate(recommendations):
                if rec:
                    from ...core.models import Mitigation, MitigationStatus

                    mitigations.append(
                        Mitigation(
                            id=f"{threat_id}-mit-{idx}",
                            description=rec,
                            status=MitigationStatus.PROPOSED,
                            priority="medium",
                        )
                    )

        # Build references
        references = []
        if card.sources:
            source_lines = [line.strip() for line in card.sources.split("\n") if line.strip()]
            for source in source_lines:
                if "http" in source:
                    parts = source.split("http")
                    if len(parts) >= 2:
                        title = parts[0].strip()
                        url = "http" + parts[1].strip()
                        references.append({"title": title or "Reference", "url": url})
                    else:
                        references.append({"title": source, "url": source})
                else:
                    references.append({"title": source, "url": ""})

        # Determine primary lifecycle phase (use first one)
        primary_phase = card.phases[0] if card.phases else None

        return Threat(
            id=threat_id,
            category=card.label,
            framework=ThreatModelingFramework.PLOT4AI,
            title=card.label,
            description=card.explanation,
            severity=None,  # PLOT4AI doesn't provide severity, user should assess
            attack_vectors=[f"Category: {cat}" for cat in card.categories],
            detection_patterns=[card.explanation, f"Elicitation: {card.question}"],
            mitigations=mitigations,
            references=references,
            lifecycle_phase=primary_phase,
            elicitation_question=card.question,
            plot4ai_card_id=f"{category_id}-{card_index}",
        )

    def get_component_types(self) -> List[str]:
        """Return list of component types for AI systems."""
        return [
            ComponentType.LLM.value,
            ComponentType.AGENT.value,
            ComponentType.TOOL.value,
            ComponentType.MEMORY.value,
            ComponentType.DATABASE.value,
            ComponentType.API_ENDPOINT.value,
        ]

    def validate_component(self, component: Component) -> ValidationResult:
        """Validate component for AI systems."""
        errors = []
        warnings = []

        # Basic validation
        if not component.id:
            errors.append("Component ID is required")
        if not component.name:
            errors.append("Component name is required")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def get_threat_patterns(
        self, framework: Optional[ThreatModelingFramework] = None
    ) -> List[ThreatPattern]:
        """
        Get threat patterns for PLOT4AI framework.

        Args:
            framework: Framework to get patterns for (should be PLOT4AI or None)

        Returns:
            List of threat patterns
        """
        if framework and framework != ThreatModelingFramework.PLOT4AI:
            return []
        return self._get_patterns()

    def get_elicitation_questions(
        self,
        lifecycle_phase: Optional[str] = None,
        category: Optional[str] = None,
        aitype: Optional[str] = None,
    ) -> List[Dict]:
        """
        Get elicitation questions for interactive threat modeling.

        Args:
            lifecycle_phase: Filter by lifecycle phase
            category: Filter by category
            aitype: Filter by AI type

        Returns:
            List of question dictionaries with card info
        """
        deck = self._load_deck()
        questions = []

        cards = deck.get_all_cards()

        if lifecycle_phase:
            cards = [c for c in cards if lifecycle_phase in c.phases]

        if category:
            cards = [c for c in cards if category in c.categories]

        if aitype:
            cards = [c for c in cards if aitype in c.aitypes]

        for category_group in deck.categories:
            for card_index, card in enumerate(category_group.cards):
                if card not in cards:
                    continue

                card_id = f"{category_group.id}-{card_index}"
                questions.append(
                    {
                        "id": card_id,
                        "question": card.question,
                        "label": card.label,
                        "threatif": card.threatif,
                        "categories": card.categories,
                        "phases": card.phases,
                        "explanation": card.explanation,
                    }
                )

        return questions

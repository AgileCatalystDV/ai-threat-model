"""
PLOT4AI to ThreatPattern converter.

Converts PLOT4AI cards to internal ThreatPattern format.

PLOT4AI Source: https://plot4.ai/
GitHub: https://github.com/PLOT4ai/plot4ai-library
License: CC-BY-SA-4.0
Author: Isabel Barberá
"""

from typing import List

from ..core.models import ThreatModelingFramework
from ..core.plot4ai_models import Plot4AICard
from ..plugins.base_plugin import ThreatPattern


def convert_plot4ai_card_to_threat_pattern(
    card: Plot4AICard, category_id: int, card_index: int
) -> ThreatPattern:
    """
    Convert a PLOT4AI card to ThreatPattern format.

    Args:
        card: PLOT4AI card
        category_id: Category ID from PLOT4AI deck
        card_index: Index of card within category

    Returns:
        ThreatPattern instance
    """
    # Generate unique ID: PLOT4AI-{category_id}-{card_index}
    pattern_id = f"PLOT4AI-{category_id}-{card_index}"

    # Convert recommendation to mitigations list
    mitigations = []
    if card.recommendation:
        # Split recommendation by lines starting with *
        recommendations = [
            line.strip().lstrip("*").strip()
            for line in card.recommendation.split("\n")
            if line.strip() and line.strip().startswith("*")
        ]
        if not recommendations:
            # If no bullet points, use entire recommendation
            recommendations = [card.recommendation.strip()]

        for idx, rec in enumerate(recommendations):
            if rec:
                mitigations.append(
                    {
                        "id": f"{pattern_id}-mit-{idx}",
                        "description": rec,
                        "priority": "medium",  # Default priority
                    }
                )

    # Build detection patterns from explanation and question
    detection_patterns = []
    if card.explanation:
        detection_patterns.append(card.explanation)
    if card.question:
        detection_patterns.append(f"Elicitation question: {card.question}")

    # Build attack vectors from categories and phases
    attack_vectors = []
    if card.categories:
        attack_vectors.extend([f"Category: {cat}" for cat in card.categories])
    if card.phases:
        attack_vectors.extend([f"Lifecycle phase: {phase}" for phase in card.phases])

    # Build references from sources
    references = []
    if card.sources:
        # Split sources by newline
        source_lines = [line.strip() for line in card.sources.split("\n") if line.strip()]
        for source in source_lines:
            # Try to extract URL if present
            if "http" in source:
                # Extract URL and title
                parts = source.split("http")
                if len(parts) >= 2:
                    title = parts[0].strip()
                    url = "http" + parts[1].strip()
                    references.append({"title": title or "Reference", "url": url})
                else:
                    references.append({"title": source, "url": source})
            else:
                references.append({"title": source, "url": ""})

    return ThreatPattern(
        id=pattern_id,
        category=card.label,
        framework=ThreatModelingFramework.PLOT4AI,
        title=card.label,
        description=card.explanation,
        detection_patterns=detection_patterns,
        attack_vectors=attack_vectors,
        mitigations=mitigations,
    )


def convert_plot4ai_deck_to_threat_patterns(deck) -> List[ThreatPattern]:
    """
    Convert entire PLOT4AI deck to list of ThreatPatterns.

    Args:
        deck: Plot4AIDeck instance

    Returns:
        List of ThreatPattern instances
    """
    patterns = []
    for category_group in deck.categories:
        for card_index, card in enumerate(category_group.cards):
            pattern = convert_plot4ai_card_to_threat_pattern(
                card, category_group.id, card_index
            )
            patterns.append(pattern)
    return patterns

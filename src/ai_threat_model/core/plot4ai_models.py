"""
PLOT4AI specific data models.

PLOT4AI (Practical Library Of Threats 4 Artificial Intelligence) provides
a holistic approach to AI threat modeling with 138 threats across 8 categories
and 6 lifecycle phases.

Source: https://plot4.ai/
GitHub: https://github.com/PLOT4ai/plot4ai-library
License: CC-BY-SA-4.0
Author: Isabel Barberá
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Plot4AICategory(str, Enum):
    """PLOT4AI threat categories."""

    DATA_GOVERNANCE = "Data & Data Governance"
    TRANSPARENCY = "Transparency & Accessibility"
    PRIVACY = "Privacy & Data Protection"
    CYBERSECURITY = "Cybersecurity"
    SAFETY = "Safety & Environmental Impact"
    BIAS = "Bias, Fairness & Discrimination"
    ETHICS = "Ethics & Human Right"
    ACCOUNTABILITY = "Accountability & Human Oversight"


class Plot4AILifecyclePhase(str, Enum):
    """PLOT4AI lifecycle phases."""

    DESIGN = "Design"
    INPUT = "Input"
    MODEL = "Model"
    OUTPUT = "Output"
    DEPLOY = "Deploy"
    MONITOR = "Monitor"


class Plot4AICard(BaseModel):
    """Represents a PLOT4AI threat card."""

    question: str = Field(..., description="Elicitation question")
    threatif: str = Field(..., description="When is this a threat: 'Yes' or 'No'")
    label: str = Field(..., description="Short label/name for the threat")
    explanation: str = Field(..., description="Detailed explanation of the threat")
    recommendation: str = Field(..., description="Mitigation recommendations")
    categories: List[str] = Field(default_factory=list, description="PLOT4AI categories")
    phases: List[str] = Field(default_factory=list, description="Applicable lifecycle phases")
    aitypes: List[str] = Field(default_factory=list, description="AI types: Traditional, Generative")
    roles: List[str] = Field(default_factory=list, description="Applicable roles: Provider, Deployer")
    sources: str = Field(default="", description="Reference sources")
    qr: str = Field(default="", description="QR code reference")


class Plot4AICategoryGroup(BaseModel):
    """Represents a PLOT4AI category group with its cards."""

    category: str = Field(..., description="Category name")
    id: int = Field(..., description="Category ID")
    colour: str = Field(..., description="Hex color code")
    cards: List[Plot4AICard] = Field(default_factory=list, description="Threat cards in this category")


class Plot4AIDeck(BaseModel):
    """Represents the complete PLOT4AI deck."""

    categories: List[Plot4AICategoryGroup] = Field(default_factory=list, description="All category groups")

    def get_all_cards(self) -> List[Plot4AICard]:
        """Get all cards from all categories."""
        all_cards = []
        for category_group in self.categories:
            all_cards.extend(category_group.cards)
        return all_cards

    def get_cards_by_category(self, category: str) -> List[Plot4AICard]:
        """Get cards for a specific category."""
        for category_group in self.categories:
            if category_group.category == category:
                return category_group.cards
        return []

    def get_cards_by_phase(self, phase: str) -> List[Plot4AICard]:
        """Get cards applicable to a specific lifecycle phase."""
        all_cards = self.get_all_cards()
        return [card for card in all_cards if phase in card.phases]

    def get_cards_by_aitype(self, aitype: str) -> List[Plot4AICard]:
        """Get cards applicable to a specific AI type (Traditional or Generative)."""
        all_cards = self.get_all_cards()
        return [card for card in all_cards if aitype in card.aitypes]

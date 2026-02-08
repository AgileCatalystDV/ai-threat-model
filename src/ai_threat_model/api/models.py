"""
API response models.
"""

from typing import List, Optional

from pydantic import BaseModel


class PatternResponse(BaseModel):
    """Pattern response model."""
    id: str
    category: str
    framework: str
    title: str
    description: str
    system_type: str


class VisionAnalysisResponse(BaseModel):
    """Vision analysis response model."""
    components: List[dict]
    data_flows: List[dict]
    suggested_system_name: str
    suggested_system_type: Optional[str] = None
    suggested_framework: Optional[str] = None
    confidence: float
    raw_analysis: Optional[str] = None

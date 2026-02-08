"""
Pattern API routes.

Provides endpoints for threat patterns.
"""

from typing import List, Optional

from fastapi import APIRouter, HTTPException

from ...core.models import ThreatModelingFramework
from ...plugins import load_plugins
from ...plugins.registry import PluginRegistry
from ..models import PatternResponse

router = APIRouter()

# Load plugins on startup
load_plugins()


@router.get("/", response_model=List[PatternResponse])
async def list_patterns(framework: Optional[str] = None):
    """List all threat patterns."""
    patterns = []
    
    # Get all registered plugins
    for system_type in PluginRegistry.list_system_types():
        plugin = PluginRegistry.get_plugin(system_type)
        if not plugin:
            continue
        
        # Filter by framework if provided
        framework_enum = None
        if framework:
            try:
                framework_enum = ThreatModelingFramework(framework)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid framework: {framework}")
        
        plugin_patterns = plugin.get_threat_patterns(framework_enum)
        
        for pattern in plugin_patterns:
            patterns.append(
                PatternResponse(
                    id=pattern.id,
                    category=pattern.category,
                    framework=pattern.framework.value,
                    title=pattern.title,
                    description=pattern.description,
                    system_type=system_type.value,
                )
            )
    
    return patterns


@router.get("/{pattern_id}", response_model=PatternResponse)
async def get_pattern(pattern_id: str):
    """Get a specific threat pattern."""
    # Search through all plugins
    for system_type in PluginRegistry.list_system_types():
        plugin = PluginRegistry.get_plugin(system_type)
        if not plugin:
            continue
        
        patterns = plugin.get_threat_patterns()
        for pattern in patterns:
            if pattern.id == pattern_id:
                return PatternResponse(
                    id=pattern.id,
                    category=pattern.category,
                    framework=pattern.framework.value,
                    title=pattern.title,
                    description=pattern.description,
                    system_type=system_type.value,
                )
    
    raise HTTPException(status_code=404, detail="Pattern not found")

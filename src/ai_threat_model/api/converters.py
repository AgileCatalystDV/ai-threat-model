"""
Converters for vision analysis results to threat models.
"""

from typing import List, Optional

from ...core.models import (
    Component,
    ComponentType,
    DataClassification,
    DataFlow,
    Metadata,
    SystemModel,
    SystemType,
    ThreatModel,
    ThreatModelingFramework,
    TrustLevel,
)
from .models import VisionAnalysisResponse


def vision_response_to_threat_model(
    vision_response: VisionAnalysisResponse,
    system_name: Optional[str] = None,
    system_type: Optional[str] = None,
    framework: Optional[str] = None,
) -> ThreatModel:
    """
    Convert vision analysis response to a ThreatModel.
    
    Args:
        vision_response: Vision analysis response
        system_name: Override system name
        system_type: Override system type
        framework: Override framework
        
    Returns:
        ThreatModel object
    """
    # Determine system name
    name = system_name or vision_response.suggested_system_name or "Untitled System"
    
    # Determine system type
    if system_type:
        try:
            sys_type = SystemType(system_type)
        except ValueError:
            sys_type = SystemType.LLM_APP  # Default
    elif vision_response.suggested_system_type:
        try:
            sys_type = SystemType(vision_response.suggested_system_type)
        except ValueError:
            sys_type = SystemType.LLM_APP  # Default
    else:
        sys_type = SystemType.LLM_APP  # Default
    
    # Determine framework
    if framework:
        try:
            framework_enum = ThreatModelingFramework(framework)
        except ValueError:
            framework_enum = ThreatModelingFramework.OWASP_LLM_TOP10_2025  # Default
    elif vision_response.suggested_framework:
        try:
            framework_enum = ThreatModelingFramework(vision_response.suggested_framework)
        except ValueError:
            framework_enum = ThreatModelingFramework.OWASP_LLM_TOP10_2025  # Default
    else:
        framework_enum = ThreatModelingFramework.OWASP_LLM_TOP10_2025  # Default
    
    # Convert components
    components = []
    component_id_map = {}  # Map original IDs to Component objects
    
    for comp_data in vision_response.components:
        comp_id = comp_data.get("id", f"comp-{len(components)}")
        comp_name = comp_data.get("name", "Unnamed Component")
        comp_type_str = comp_data.get("type", "database")
        
        # Try to map to ComponentType
        try:
            comp_type = ComponentType(comp_type_str)
        except ValueError:
            # Fallback mapping
            comp_type_map = {
                "llm": ComponentType.LLM,
                "agent": ComponentType.AGENT,
                "tool": ComponentType.TOOL,
                "memory": ComponentType.MEMORY,
                "database": ComponentType.DATABASE,
                "api": ComponentType.API_ENDPOINT,
                "web-server": ComponentType.WEB_SERVER,
            }
            comp_type = comp_type_map.get(comp_type_str.lower(), ComponentType.DATABASE)
        
        component = Component(
            id=comp_id,
            name=comp_name,
            type=comp_type,
            description=comp_data.get("description"),
            trust_level=TrustLevel.INTERNAL,  # Default
            capabilities=[],  # Empty for now
        )
        
        components.append(component)
        component_id_map[comp_id] = component
    
    # Convert data flows
    data_flows = []
    
    for flow_data in vision_response.data_flows:
        from_id = flow_data.get("from_component")
        to_id = flow_data.get("to_component")
        
        # Skip if components don't exist
        if from_id not in component_id_map or to_id not in component_id_map:
            continue
        
        # Determine classification
        classification_str = flow_data.get("classification", "internal")
        try:
            classification = DataClassification(classification_str)
        except ValueError:
            classification = DataClassification.INTERNAL
        
        data_flow = DataFlow(
            from_component=from_id,
            to_component=to_id,
            data_type=flow_data.get("data_type"),
            classification=classification,
            encrypted=flow_data.get("encrypted", False),
        )
        
        data_flows.append(data_flow)
    
    # Create threat model
    threat_model = ThreatModel(
        metadata=Metadata(version="1.0.0"),
        system=SystemModel(
            name=name,
            type=sys_type,
            threat_modeling_framework=framework_enum,
            components=components,
            data_flows=data_flows,
        ),
        threats=[],  # Will be populated by analysis
    )
    
    return threat_model

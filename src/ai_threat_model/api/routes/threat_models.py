"""
Threat model API routes.

Provides endpoints for CRUD operations on threat models.
"""

from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, UploadFile, File as FastAPIFile
from pydantic import BaseModel

from ...core.models import ThreatModel
from ...plugins import load_plugins
from ...plugins.registry import PluginRegistry

router = APIRouter()

# Load plugins on startup
load_plugins()


class ThreatModelResponse(BaseModel):
    """Threat model response model."""
    id: str
    name: str
    system_type: str
    framework: str
    component_count: int
    data_flow_count: int
    threat_count: int


class ThreatModelCreate(BaseModel):
    """Threat model creation model."""
    name: str
    system_type: str
    framework: str
    description: Optional[str] = None


@router.get("/", response_model=List[ThreatModelResponse])
async def list_threat_models(directory: Optional[str] = None):
    """List all threat models."""
    # For now, scan examples directory
    # In production, this would query a database
    examples_dir = Path(__file__).parent.parent.parent.parent.parent / "examples"
    
    if not examples_dir.exists():
        return []
    
    models = []
    for file_path in examples_dir.glob("*.tm.json"):
        try:
            threat_model = ThreatModel.load(str(file_path))
            models.append(
                ThreatModelResponse(
                    id=file_path.stem,
                    name=threat_model.system.name,
                    system_type=threat_model.system.type.value,
                    framework=threat_model.system.threat_modeling_framework.value,
                    component_count=len(threat_model.system.components),
                    data_flow_count=len(threat_model.system.data_flows),
                    threat_count=len(threat_model.threats),
                )
            )
        except Exception:
            continue
    
    return models


@router.get("/{model_id}", response_model=dict)
async def get_threat_model(model_id: str):
    """Get a specific threat model."""
    examples_dir = Path(__file__).parent.parent.parent.parent.parent / "examples"
    file_path = examples_dir / f"{model_id}.tm.json"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Threat model not found")
    
    try:
        threat_model = ThreatModel.load(str(file_path))
        return threat_model.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading threat model: {str(e)}")


@router.post("/", response_model=dict)
async def create_threat_model(data: ThreatModelCreate):
    """Create a new threat model."""
    from ...core.models import SystemModel, SystemType, ThreatModelingFramework, Metadata
    
    try:
        system_type = SystemType(data.system_type)
        framework = ThreatModelingFramework(data.framework)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid system type or framework: {str(e)}")
    
    threat_model = ThreatModel(
        metadata=Metadata(version="1.0.0"),
        system=SystemModel(
            name=data.name,
            type=system_type,
            threat_modeling_framework=framework,
            description=data.description,
            components=[],
            data_flows=[],
        ),
        threats=[],
    )
    
    return threat_model.model_dump()


@router.post("/{model_id}/analyze", response_model=dict)
async def analyze_threat_model(model_id: str):
    """Analyze a threat model and detect threats."""
    examples_dir = Path(__file__).parent.parent.parent.parent.parent / "examples"
    file_path = examples_dir / f"{model_id}.tm.json"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Threat model not found")
    
    try:
        threat_model = ThreatModel.load(str(file_path))
        
        # Get plugin for system type
        plugin = PluginRegistry.get_plugin(threat_model.system.type)
        if not plugin:
            raise HTTPException(
                status_code=400,
                detail=f"No plugin available for system type: {threat_model.system.type.value}",
            )
        
        # Detect threats
        threats = plugin.detect_threats(threat_model.system)
        threat_model.threats = threats
        
        # Save updated model
        threat_model.save(str(file_path))
        
        return threat_model.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing threat model: {str(e)}")


@router.put("/{model_id}", response_model=dict)
async def update_threat_model(model_id: str, threat_model_data: dict):
    """Update a threat model."""
    examples_dir = Path(__file__).parent.parent.parent.parent.parent / "examples"
    file_path = examples_dir / f"{model_id}.tm.json"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Threat model not found")
    
    try:
        threat_model = ThreatModel(**threat_model_data)
        threat_model.save(str(file_path))
        return threat_model.model_dump()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error updating threat model: {str(e)}")


@router.delete("/{model_id}")
async def delete_threat_model(model_id: str):
    """Delete a threat model."""
    examples_dir = Path(__file__).parent.parent.parent.parent.parent / "examples"
    file_path = examples_dir / f"{model_id}.tm.json"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Threat model not found")
    
    try:
        file_path.unlink()
        return {"message": "Threat model deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting threat model: {str(e)}")

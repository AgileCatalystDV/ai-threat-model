"""
Vision analysis API routes.

Provides endpoints for analyzing images/diagrams and converting them to threat models.
"""

import base64
import io
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File as FastAPIFile
from PIL import Image

from ...core.models import SystemType, ThreatModelingFramework
from ..converters import vision_response_to_threat_model
from ..models import VisionAnalysisResponse
from ..vision import analyze_image_with_vision

router = APIRouter()


@router.post("/analyze", response_model=VisionAnalysisResponse)
async def analyze_image(
    file: UploadFile = FastAPIFile(...),
    system_type: Optional[str] = None,
    framework: Optional[str] = None,
):
    """
    Analyze an image/diagram and extract threat model components.
    
    Supports PNG, JPG, JPEG, and PDF files.
    """
    # Validate file type
    allowed_types = ["image/png", "image/jpeg", "image/jpg", "application/pdf"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}. Supported types: {allowed_types}",
        )
    
    # Read file content
    file_content = await file.read()
    
    # Convert to image if needed
    try:
        image = Image.open(io.BytesIO(file_content))
        # Convert RGBA to RGB if needed
        if image.mode == "RGBA":
            image = image.convert("RGB")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing image: {str(e)}")
    
    # Parse system type and framework
    system_type_enum = None
    if system_type:
        try:
            system_type_enum = SystemType(system_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid system type: {system_type}")
    
    framework_enum = None
    if framework:
        try:
            framework_enum = ThreatModelingFramework(framework)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid framework: {framework}")
    
    # Analyze image with vision API
    try:
        result = await analyze_image_with_vision(image, system_type_enum, framework_enum)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing image: {str(e)}")


@router.post("/analyze-base64", response_model=VisionAnalysisResponse)
async def analyze_image_base64(
    image_data: str,
    system_type: Optional[str] = None,
    framework: Optional[str] = None,
):
    """
    Analyze an image from base64 encoded data.
    
    Useful for frontend applications that convert images to base64.
    """
    try:
        # Decode base64
        image_bytes = base64.b64decode(image_data.split(",")[-1] if "," in image_data else image_data)
        image = Image.open(io.BytesIO(image_bytes))
        
        # Convert RGBA to RGB if needed
        if image.mode == "RGBA":
            image = image.convert("RGB")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing image: {str(e)}")
    
    # Parse system type and framework
    system_type_enum = None
    if system_type:
        try:
            system_type_enum = SystemType(system_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid system type: {system_type}")
    
    framework_enum = None
    if framework:
        try:
            framework_enum = ThreatModelingFramework(framework)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid framework: {framework}")
    
    # Analyze image with vision API
    try:
        result = await analyze_image_with_vision(image, system_type_enum, framework_enum)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing image: {str(e)}")


@router.post("/convert-to-model", response_model=dict)
async def convert_vision_to_threat_model(
    vision_response: VisionAnalysisResponse,
    system_name: Optional[str] = None,
    system_type: Optional[str] = None,
    framework: Optional[str] = None,
):
    """
    Convert vision analysis response to a threat model.
    
    This endpoint takes the vision analysis result and converts it to a full threat model
    that can be saved and analyzed.
    """
    try:
        threat_model = vision_response_to_threat_model(
            vision_response, system_name, system_type, framework
        )
        return threat_model.model_dump()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error converting to threat model: {str(e)}"
        )

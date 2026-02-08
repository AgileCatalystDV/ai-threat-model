"""
Vision analysis module.

Uses OpenAI GPT-4 Vision to analyze diagrams and extract threat model components.
"""

import io
import json
import os
from typing import List, Optional

from openai import OpenAI
from PIL import Image

from ...core.models import ComponentType, SystemType, ThreatModelingFramework
from .models import VisionAnalysisResponse

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


async def analyze_image_with_vision(
    image: Image.Image,
    system_type: Optional[SystemType] = None,
    framework: Optional[ThreatModelingFramework] = None,
) -> VisionAnalysisResponse:
    """
    Analyze an image using GPT-4 Vision and extract threat model components.
    
    Args:
        image: PIL Image object
        system_type: Optional system type hint
        framework: Optional framework hint
        
    Returns:
        VisionAnalysisResponse with extracted components and data flows
    """
    # Convert image to bytes
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format="PNG")
    img_byte_arr.seek(0)
    
    # Build prompt
    prompt = _build_analysis_prompt(system_type, framework)
    
    # Call OpenAI Vision API
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert threat modeling analyst. Analyze system architecture diagrams and extract components, data flows, and relationships. Return structured JSON data.",
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{_image_to_base64(image)}"
                            },
                        },
                    ],
                },
            ],
            max_tokens=2000,
            response_format={"type": "json_object"},
        )
        
        # Parse response
        result = json.loads(response.choices[0].message.content)
        
        # Extract components and data flows
        components = result.get("components", [])
        data_flows = result.get("data_flows", [])
        suggested_system_name = result.get("system_name", "Untitled System")
        suggested_system_type = result.get("system_type")
        suggested_framework = result.get("framework")
        confidence = result.get("confidence", 0.5)
        raw_analysis = result.get("analysis", "")
        
        return VisionAnalysisResponse(
            components=components,
            data_flows=data_flows,
            suggested_system_name=suggested_system_name,
            suggested_system_type=suggested_system_type,
            suggested_framework=suggested_framework,
            confidence=confidence,
            raw_analysis=raw_analysis,
        )
    except Exception as e:
        raise Exception(f"Error calling vision API: {str(e)}")


def _build_analysis_prompt(
    system_type: Optional[SystemType] = None,
    framework: Optional[ThreatModelingFramework] = None,
) -> str:
    """Build the analysis prompt for vision API."""
    prompt = """Analyze this system architecture diagram and extract the following information:

1. **Components**: Identify all components (services, databases, APIs, agents, LLMs, tools, etc.)
   - For each component, extract: name, type, description (if visible)
   - Component types can be: llm, agent, tool, memory, database, api-endpoint, web-server, etc.

2. **Data Flows**: Identify data flows between components
   - For each flow, extract: from_component, to_component, data_type (if visible), classification (public/internal/confidential/restricted), encrypted (true/false if visible)

3. **System Information**: Extract system name, type, and framework if visible

Return a JSON object with this structure:
{
  "system_name": "Name of the system",
  "system_type": "llm-app|agentic-system|multi-agent|web-app|mobile-app|api",
  "framework": "owasp-llm-top10-2025|owasp-agentic-top10-2026|custom|stride",
  "components": [
    {
      "id": "unique-id",
      "name": "Component Name",
      "type": "component-type",
      "description": "Description if visible"
    }
  ],
  "data_flows": [
    {
      "from_component": "component-id",
      "to_component": "component-id",
      "data_type": "type of data",
      "classification": "public|internal|confidential|restricted",
      "encrypted": true/false
    }
  ],
  "confidence": 0.0-1.0,
  "analysis": "Brief analysis of what you found"
}

Important:
- Use descriptive IDs for components (e.g., "user-frontend", "api-gateway", "llm-service")
- If you can't determine a value, use null or a reasonable default
- For classification, default to "internal" if not visible
- For encrypted, default to false if not visible
- Be thorough but accurate - only extract what you can clearly see"""
    
    if system_type:
        prompt += f"\n\nHint: The system type is likely: {system_type.value}"
    
    if framework:
        prompt += f"\n\nHint: The framework is likely: {framework.value}"
    
    return prompt


def _image_to_base64(image: Image.Image) -> str:
    """Convert PIL Image to base64 string."""
    import base64
    
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format="PNG")
    img_byte_arr.seek(0)
    return base64.b64encode(img_byte_arr.read()).decode("utf-8")

"""
FastAPI application for AI Threat Model.

Provides REST API endpoints for threat modeling operations and image analysis.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import patterns, threat_models, vision

app = FastAPI(
    title="AI Threat Model API",
    description="Open-source threat modeling tool for AI-native systems",
    version="0.1.0",
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(threat_models.router, prefix="/api/v1/threat-models", tags=["threat-models"])
app.include_router(patterns.router, prefix="/api/v1/patterns", tags=["patterns"])
app.include_router(vision.router, prefix="/api/v1/vision", tags=["vision"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "AI Threat Model API",
        "version": "0.1.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}

#!/usr/bin/env python3
"""
API server entry point.

Run with: python api_server.py
Or: uvicorn ai_threat_model.api.main:app --reload
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "ai_threat_model.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )

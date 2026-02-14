# Backend Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml ./
COPY requirements.txt* ./
COPY requirements-dev.txt* ./

# Install Python dependencies
# Strategy: Install production deps first, then dev deps if available
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    if [ -f requirements.txt ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    fi && \
    pip install --no-cache-dir -e . && \
    if [ -f requirements-dev.txt ]; then \
        pip install --no-cache-dir -r requirements-dev.txt; \
    fi && \
    # Ensure API dependencies are installed
    pip install --no-cache-dir fastapi uvicorn[standard] python-multipart openai pillow requests

# Copy application code
COPY src/ ./src/
COPY schemas/ ./schemas/
COPY patterns/ ./patterns/
COPY examples/ ./examples/
COPY api_server.py ./

# Create non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check using curl (more reliable than Python requests)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API server
CMD ["uvicorn", "ai_threat_model.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

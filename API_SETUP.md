# API & Frontend Setup Guide

## Backend Setup

### 1. Install Dependencies

```bash
# Activate virtual environment
source venv/bin/activate

# Install new dependencies
pip install -e ".[dev]"
```

### 2. Set OpenAI API Key

```bash
export OPENAI_API_KEY="your-api-key-here"
```

Or create a `.env` file:
```
OPENAI_API_KEY=your-api-key-here
```

### 3. Run API Server

```bash
# Option 1: Using the script
python api_server.py

# Option 2: Using uvicorn directly
uvicorn ai_threat_model.api.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at http://localhost:8000

### 4. Test API

```bash
# Health check
curl http://localhost:8000/health

# List threat models
curl http://localhost:8000/api/v1/threat-models/

# API docs
open http://localhost:8000/docs
```

## Frontend Setup

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Run Development Server

```bash
npm run dev
```

The frontend will be available at http://localhost:3000

### 3. Build for Production

```bash
npm run build
```

## Usage

### Vision Analysis Workflow

1. **Start Backend**: `python api_server.py`
2. **Start Frontend**: `cd frontend && npm run dev`
3. **Navigate to**: http://localhost:3000/vision
4. **Upload Image**: Select a diagram/image file
5. **Analyze**: Click "Analyze Image"
6. **Review**: Check extracted components and data flows
7. **Create Model**: Click "Create Threat Model" to convert to threat model
8. **Edit**: Review and edit in the visual editor
9. **Analyze Threats**: Click "Analyze Threats" to detect threats

## API Endpoints

### Threat Models
- `GET /api/v1/threat-models/` - List all threat models
- `GET /api/v1/threat-models/{id}` - Get specific threat model
- `POST /api/v1/threat-models/` - Create new threat model
- `PUT /api/v1/threat-models/{id}` - Update threat model
- `DELETE /api/v1/threat-models/{id}` - Delete threat model
- `POST /api/v1/threat-models/{id}/analyze` - Analyze threats

### Vision Analysis
- `POST /api/v1/vision/analyze` - Analyze image file
- `POST /api/v1/vision/analyze-base64` - Analyze base64 image
- `POST /api/v1/vision/convert-to-model` - Convert vision result to threat model

### Patterns
- `GET /api/v1/patterns/` - List all patterns
- `GET /api/v1/patterns/{id}` - Get specific pattern

## Troubleshooting

### Backend Issues

- **Import errors**: Make sure you've installed dependencies: `pip install -e ".[dev]"`
- **OpenAI API errors**: Check your API key is set correctly
- **Port already in use**: Change port in `api_server.py` or use `--port` flag

### Frontend Issues

- **API connection errors**: Make sure backend is running on port 8000
- **CORS errors**: Backend CORS is configured for localhost:3000 and localhost:5173
- **Build errors**: Make sure all dependencies are installed: `npm install`

## Next Steps

- Add authentication/authorization
- Add database for persistent storage
- Enhance visual editor with drag-and-drop
- Add more diagram types support
- Improve vision analysis accuracy

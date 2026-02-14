# Docker Setup & Run Guide

Complete guide voor het draaien van AI Threat Model in Docker containers.

## Prerequisites

- Docker Desktop geïnstalleerd (of Docker Engine + Docker Compose)
- OpenAI API key (voor vision analysis)

## Quick Start

### 1. Clone Repository

```bash
git clone git@github.com:AgileCatalystDV/ai-threat-model.git
cd ai-threat-model
```

### 2. Set Environment Variables

Maak een `.env` bestand in de root directory:

```bash
# .env
OPENAI_API_KEY=your-openai-api-key-here
```

Of exporteer de variabele:

```bash
export OPENAI_API_KEY="your-openai-api-key-here"
```

### 3. Build and Run

```bash
# Build en start alle containers
docker-compose up --build

# Of in detached mode (op de achtergrond)
docker-compose up -d --build
```

### 4. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

**Note**: Frontend wacht tot backend healthy is voordat het start (depends_on met condition).

## Docker Commands

### Start Containers

```bash
# Start alle services
docker-compose up

# Start in detached mode
docker-compose up -d

# Start met rebuild
docker-compose up --build
```

### Stop Containers

```bash
# Stop containers
docker-compose stop

# Stop en verwijder containers
docker-compose down

# Stop, verwijder containers en volumes
docker-compose down -v
```

### View Logs

```bash
# Alle logs
docker-compose logs

# Backend logs
docker-compose logs backend

# Frontend logs
docker-compose logs frontend

# Follow logs (real-time)
docker-compose logs -f
```

### Rebuild After Changes

```bash
# Rebuild backend
docker-compose build backend

# Rebuild frontend
docker-compose build frontend

# Rebuild alles
docker-compose build

# Rebuild en restart
docker-compose up --build
```

### Execute Commands in Containers

```bash
# Shell in backend container
docker-compose exec backend bash

# Run Python command in backend
docker-compose exec backend python -m pytest

# Shell in frontend container
docker-compose exec frontend sh
```

## Individual Container Commands

### Backend Only

```bash
# Build backend image
docker build -t ai-threat-model-backend .

# Run backend container
docker run -p 8000:8000 \
  -e OPENAI_API_KEY="your-key" \
  ai-threat-model-backend

# Run met volume mount (voor development)
docker run -p 8000:8000 \
  -e OPENAI_API_KEY="your-key" \
  -v $(pwd)/examples:/app/examples:ro \
  ai-threat-model-backend
```

### Frontend Only

```bash
# Build frontend image
cd frontend
docker build -t ai-threat-model-frontend .

# Run frontend container
docker run -p 3000:80 ai-threat-model-frontend
```

## Development Mode

Voor development met hot-reload, gebruik de development docker-compose override:

### Development Setup met Docker Compose

```bash
# Start met development overrides (hot-reload enabled)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# Of in detached mode
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

**Features in development mode:**
- ✅ Backend hot-reload (code changes trigger auto-restart)
- ✅ Frontend hot-reload (Vite dev server)
- ✅ Source code mounted as volumes
- ✅ Debug logging enabled
- ✅ Health checks disabled (to avoid false positives during reload)

### Backend Development

```bash
# Run backend met volume mount voor code changes
docker run -p 8000:8000 \
  -e OPENAI_API_KEY="your-key" \
  -e DEBUG=true \
  -e LOG_LEVEL=DEBUG \
  -v $(pwd)/src:/app/src \
  -v $(pwd)/patterns:/app/patterns \
  -v $(pwd)/schemas:/app/schemas \
  ai-threat-model-backend \
  uvicorn ai_threat_model.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Development

**Optie 1: Docker (met hot-reload)**
```bash
# Gebruik docker-compose.dev.yml voor frontend in Docker
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up frontend
```

**Optie 2: Lokaal (aanbevolen voor snelle development)**
```bash
cd frontend
npm install
npm run dev
# Frontend draait op http://localhost:5173
```

## Production Deployment

### Build Production Images

```bash
# Build alle images
docker-compose build

# Tag images voor registry
docker tag ai-threat-model-backend:latest your-registry/ai-threat-model-backend:latest
docker tag ai-threat-model-frontend:latest your-registry/ai-threat-model-frontend:latest

# Push naar registry
docker push your-registry/ai-threat-model-backend:latest
docker push your-registry/ai-threat-model-frontend:latest
```

### Production docker-compose.yml

Voor production, gebruik environment variables en secrets:

```yaml
version: '3.8'

services:
  backend:
    image: your-registry/ai-threat-model-backend:latest
    environment:
      - OPENAI_API_KEY_FILE=/run/secrets/openai_api_key
    secrets:
      - openai_api_key
    # ... rest of config

secrets:
  openai_api_key:
    file: ./secrets/openai_api_key.txt
```

## Recent Improvements ⭐ NEW

### Security Enhancements
- **Non-root user**: Backend draait als `appuser` (UID 1000) voor betere security
- **Read-only volumes**: Examples en patterns gemount als read-only
- **Minimal base images**: Gebruikt slim/alpine images voor kleinere attack surface

### Better Health Checks
- **curl-based**: Backend health check gebruikt curl (geen Python dependency nodig)
- **wget-based**: Frontend health check gebruikt wget
- **Service dependencies**: Frontend wacht tot backend healthy is

### Improved Dependency Installation
- **Staged installation**: Production deps eerst, dan dev deps
- **Fallback handling**: Flexibele installatie strategie
- **Package installation**: Zorgt dat package altijd correct geïnstalleerd is

### Development Mode Enhancements
- **Hot-reload**: Backend en frontend met auto-reload
- **Debug logging**: Debug mode enabled in dev
- **Port mapping**: Frontend dev op port 5173 (Vite default)

## Troubleshooting

### Container Start Fails

```bash
# Check logs
docker-compose logs

# Check backend logs specifically
docker-compose logs backend

# Check container status
docker-compose ps

# Check if ports are available
lsof -i :8000  # Backend
lsof -i :3000  # Frontend production
lsof -i :5173  # Frontend development
```

### Backend Health Check Fails

```bash
# Check health endpoint manually
docker-compose exec backend curl http://localhost:8000/health

# Check if curl is available
docker-compose exec backend which curl

# Check backend logs for errors
docker-compose logs backend | tail -50
```

### Backend Can't Connect to OpenAI

```bash
# Check environment variable
docker-compose exec backend env | grep OPENAI

# Set in docker-compose.yml or .env file
# Or export before running:
export OPENAI_API_KEY="your-key"
docker-compose up
```

### Frontend Can't Reach Backend

```bash
# Check if backend is running and healthy
docker-compose ps backend

# Check backend health
curl http://localhost:8000/health

# Check frontend environment variable
docker-compose exec frontend env | grep VITE_API_URL

# Verify network connectivity
docker-compose exec frontend wget -O- http://backend:8000/health
```

### Build Failures

```bash
# Clean build (no cache)
docker-compose build --no-cache

# Rebuild specific service
docker-compose build --no-cache backend

# Check build logs
docker-compose build backend 2>&1 | tee build.log
```

### Permission Issues

```bash
# Check file permissions
ls -la src/ patterns/ schemas/

# Fix permissions if needed (Linux/Mac)
chmod -R 755 src/ patterns/ schemas/

# Check container user
docker-compose exec backend whoami  # Should be 'appuser'
```

### Development Mode Issues

```bash
# Check if hot-reload is working
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs backend | grep "reload"

# Verify volume mounts
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec backend ls -la /app/src

# Check if files are syncing
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec backend touch /app/src/test.txt
# Check if file appears in host filesystem
ls -la src/test.txt

- Check dat beide containers op hetzelfde network zitten
- Check dat backend draait: `docker-compose ps`
- Check backend logs: `docker-compose logs backend`

### Rebuild After Code Changes

```bash
# Stop containers
docker-compose down

# Rebuild
docker-compose build --no-cache

# Start again
docker-compose up
```

### Clean Everything

```bash
# Stop and remove containers, networks
docker-compose down

# Remove images
docker-compose down --rmi all

# Remove volumes
docker-compose down -v

# Clean Docker system (careful!)
docker system prune -a
```

## Health Checks ⭐ IMPROVED

Containers hebben verbeterde health checks ingebouwd:

### Backend Health Check
- **Method**: curl (geen Python dependency nodig)
- **Endpoint**: `/health`
- **Interval**: 30s
- **Timeout**: 10s
- **Start period**: 15s (genoeg tijd voor startup)
- **Retries**: 3

### Frontend Health Check
- **Method**: wget (lightweight)
- **Endpoint**: `/` (root)
- **Interval**: 30s
- **Timeout**: 3s
- **Start period**: 10s
- **Retries**: 3

### Check Health Status

```bash
# Check health status van alle containers
docker-compose ps

# Check backend health manually
curl http://localhost:8000/health

# Check backend health vanuit container
docker-compose exec backend curl http://localhost:8000/health

# Check frontend health
curl http://localhost:3000/

# View health check logs
docker inspect ai-threat-model-backend | grep -A 10 Health
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `OPENAI_API_KEY` | OpenAI API key voor vision analysis | Yes (voor vision features) | - |
| `PYTHONUNBUFFERED` | Python output buffering | No | 1 |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | No | INFO |
| `DEBUG` | Enable debug mode | No | false |
| `VITE_API_URL` | Frontend API URL | No | http://localhost:8000 |

## Ports

| Service | Port (Host) | Port (Container) | Description |
|---------|-------------|------------------|-------------|
| Backend | 8000 | 8000 | FastAPI server |
| Frontend (Production) | 3000 | 80 | Nginx server |
| Frontend (Development) | 5173 | 5173 | Vite dev server |

## Volumes

### Production Mode
- `./examples:/app/examples:ro` - Read-only mount voor example threat models (optional)
- `./patterns:/app/patterns:ro` - Read-only mount voor threat patterns (optional)

### Development Mode
- `./src:/app/src` - Source code voor hot-reload
- `./patterns:/app/patterns` - Patterns voor live editing
- `./schemas:/app/schemas` - Schemas voor live editing
- `./examples:/app/examples` - Examples voor live editing
- `./frontend/src:/app/src` - Frontend source voor hot-reload
- `./frontend/public:/app/public` - Frontend public assets

## Networks

Containers communiceren via `ai-threat-model-network` bridge network.

## Best Practices

1. **Never commit `.env` files** - gebruik secrets in production
2. **Use specific image tags** - niet `latest` in production
3. **Health checks** - containers hebben health checks ingebouwd (curl/wget based)
4. **Non-root user** - Backend draait als `appuser` voor betere security
5. **Read-only volumes** - Gebruik read-only mounts waar mogelijk
6. **Resource limits** - voeg limits toe voor production:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '0.5'
         memory: 512M
       reservations:
         cpus: '0.25'
         memory: 256M
   ```
7. **Layer caching** - Dependencies geïnstalleerd voor code copy (snellere rebuilds)
8. **Multi-stage builds** - Frontend gebruikt multi-stage voor kleinere images
9. **Service dependencies** - Frontend wacht tot backend healthy is
10. **Environment configuration** - Gebruik environment variables voor configuratie

## Next Steps

- Add database container (PostgreSQL) voor persistent storage
- Add Redis voor caching
- Add monitoring (Prometheus/Grafana)
- Add CI/CD pipeline voor automated builds

Veel succes! 🐳

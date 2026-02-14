# Docker Troubleshooting Guide (macOS)

## Veelvoorkomende Problemen op macOS

### 1. Docker Desktop Niet Gestart

**Symptoom:**
```
Cannot connect to the Docker daemon
```

**Oplossing:**
```bash
# Check of Docker Desktop draait
docker ps

# Start Docker Desktop applicatie
# Of via command line:
open -a Docker
```

### 2. Port Al In Gebruik

**Symptoom:**
```
Error: bind: address already in use
```

**Oplossing:**
```bash
# Check welke processen poorten gebruiken
lsof -i :8000
lsof -i :3000

# Kill process op poort 8000
kill -9 $(lsof -t -i:8000)

# Of verander poorten in docker-compose.yml
```

### 3. Permission Denied

**Symptoom:**
```
permission denied while trying to connect to the Docker daemon socket
```

**Oplossing:**
```bash
# Check Docker groep (meestal niet nodig op macOS)
# Maar check wel of je in docker groep zit:
groups

# Herstart Docker Desktop
# Of gebruik sudo (niet aanbevolen)
```

### 4. Build Fails - Python Dependencies

**Symptoom:**
```
ERROR: Could not find a version that satisfies the requirement...
```

**Oplossing:**
```bash
# Check of requirements-dev.txt bestaat
ls -la requirements-dev.txt

# Of gebruik alleen pyproject.toml
# Pas Dockerfile aan om alleen pyproject.toml te gebruiken
```

### 5. Frontend Build Fails

**Symptoom:**
```
npm ERR! code ELIFECYCLE
```

**Oplossing:**
```bash
# Check Node versie in Dockerfile
# Zorg dat package.json correct is

# Rebuild zonder cache
docker-compose build --no-cache frontend
```

### 6. Memory Issues (M1/M2 Mac)

**Symptoom:**
```
Killed (signal 9)
```

**Oplossing:**
- Docker Desktop → Settings → Resources
- Verhoog Memory limit (minimaal 4GB)
- Verhoog CPU cores

### 7. Network Issues

**Symptoom:**
```
Cannot connect to backend
```

**Oplossing:**
```bash
# Check of containers opzelfde network zitten
docker network ls
docker network inspect ai-threat-model_ai-threat-model-network

# Check container logs
docker-compose logs backend
docker-compose logs frontend
```

## Diagnose Commands

### Check Docker Status
```bash
# Docker versie
docker --version
docker-compose --version

# Docker info
docker info

# Running containers
docker ps

# All containers (including stopped)
docker ps -a

# Docker images
docker images
```

### Check Container Logs
```bash
# Alle logs
docker-compose logs

# Backend logs
docker-compose logs backend

# Frontend logs
docker-compose logs frontend

# Follow logs (real-time)
docker-compose logs -f backend
```

### Check Container Status
```bash
# Container status
docker-compose ps

# Detailed info
docker-compose ps -a

# Inspect container
docker inspect ai-threat-model-backend
```

### Test Containers Individueel
```bash
# Test backend
docker run --rm -p 8000:8000 \
  -e OPENAI_API_KEY="test" \
  ai-threat-model-backend

# Test frontend
docker run --rm -p 3000:80 \
  ai-threat-model-frontend
```

## Stap-voor-stap Debugging

### Stap 1: Check Docker Desktop
```bash
docker ps
# Moet containers tonen of leeg zijn, maar GEEN error
```

### Stap 2: Check Docker Compose
```bash
docker-compose --version
# Moet versie tonen
```

### Stap 3: Validate docker-compose.yml
```bash
docker-compose config
# Moet YAML valideren zonder errors
```

### Stap 4: Build Images
```bash
# Build backend
docker-compose build backend

# Build frontend
docker-compose build frontend

# Build alles
docker-compose build
```

### Stap 5: Start Containers
```bash
# Start zonder build
docker-compose up

# Start met build
docker-compose up --build

# Start in detached mode
docker-compose up -d
```

### Stap 6: Check Logs
```bash
# Als containers niet starten
docker-compose logs

# Check specifieke service
docker-compose logs backend
```

## macOS Specifieke Fixes

### Fix 1: Docker Desktop Resources
1. Open Docker Desktop
2. Settings → Resources
3. Memory: Minimaal 4GB
4. CPUs: Minimaal 2 cores
5. Apply & Restart

### Fix 2: Reset Docker Desktop
```bash
# Stop Docker Desktop
# Quit Docker Desktop applicatie

# Reset (verwijdert alle containers/images)
# Docker Desktop → Troubleshoot → Reset to factory defaults

# Of via command line:
docker system prune -a --volumes
```

### Fix 3: M1/M2 Apple Silicon
```bash
# Check of je op Apple Silicon draait
uname -m
# Moet "arm64" zijn

# Docker Desktop moet Apple Silicon versie zijn
# Download van: https://www.docker.com/products/docker-desktop
```

### Fix 4: File Permissions
```bash
# Check file permissions
ls -la Dockerfile
ls -la docker-compose.yml

# Zorg dat je read permissions hebt
chmod 644 Dockerfile docker-compose.yml
```

## Snelle Fixes

### Fix: Rebuild Everything
```bash
# Stop alles
docker-compose down

# Remove images
docker-compose down --rmi all

# Rebuild zonder cache
docker-compose build --no-cache

# Start opnieuw
docker-compose up
```

### Fix: Clean Docker System
```bash
# Stop containers
docker-compose down

# Remove unused containers, networks, images
docker system prune

# Remove alles (inclusief volumes - CAREFUL!)
docker system prune -a --volumes
```

### Fix: Check Ports
```bash
# Check of poorten vrij zijn
lsof -i :8000
lsof -i :3000

# Kill process op poort
kill -9 $(lsof -t -i:8000)
```

## Verbeterde Dockerfile voor macOS

Als je problemen blijft houden, probeer deze verbeterde versie:

```dockerfile
# Gebruik Python slim image
FROM python:3.11-slim

WORKDIR /app

# Install dependencies in één laag
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy alleen wat nodig is
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

# Copy rest van code
COPY . .

EXPOSE 8000
CMD ["uvicorn", "ai_threat_model.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Test Commands

### Test Backend Direct
```bash
# Build backend
docker build -t test-backend .

# Run backend
docker run -p 8000:8000 \
  -e OPENAI_API_KEY="test" \
  test-backend

# Test in browser
curl http://localhost:8000/health
```

### Test Frontend Direct
```bash
cd frontend

# Build frontend
docker build -t test-frontend .

# Run frontend
docker run -p 3000:80 test-frontend

# Test in browser
open http://localhost:3000
```

## Hulp Nodig?

Als niets werkt, verzamel deze info:

```bash
# System info
uname -a
docker --version
docker-compose --version

# Docker info
docker info

# Container logs
docker-compose logs > docker-logs.txt

# Container status
docker-compose ps > docker-status.txt
```

Deel deze output voor verdere hulp!

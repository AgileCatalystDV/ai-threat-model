# Docker Setup Improvements

## Overview

De Docker setup is verbeterd met de volgende wijzigingen:

## Backend Dockerfile Improvements

### ✅ Security Enhancements
- **Non-root user**: Container draait nu als `appuser` (UID 1000) in plaats van root
- **Minimal base image**: Gebruikt `python:3.11-slim` voor kleinere image size

### ✅ Dependency Installation
- **Betere installatie strategie**: 
  1. Installeer eerst production dependencies (requirements.txt)
  2. Installeer package in editable mode (`pip install -e .`)
  3. Installeer dev dependencies indien beschikbaar
  4. Zorg dat API dependencies altijd geïnstalleerd zijn

### ✅ Health Check
- **Gebruikt curl**: In plaats van Python requests library (minder dependencies)
- **Betere timeouts**: Start period verhoogd naar 10s voor betere startup handling

### ✅ System Dependencies
- **curl toegevoegd**: Voor health checks
- **gcc behouden**: Voor Python packages die compilatie nodig hebben

## Frontend Dockerfile Improvements

### ✅ Multi-stage Build
- **Builder stage**: Installeert dependencies en bouwt applicatie
- **Production stage**: Alleen Nginx met built files (kleinere image)

### ✅ Package Lock Handling
- **Flexibele installatie**: 
  - Gebruikt `npm ci` als package-lock.json bestaat (sneller, reproduceerbaar)
  - Valt terug op `npm install` als lock file ontbreekt

### ✅ Health Check
- **Nginx health check**: Gebruikt wget om te checken of Nginx draait
- **Lightweight**: Geen extra dependencies nodig

## Frontend Dockerfile.dev Improvements

### ✅ Development Server
- **Vite port**: Expose port 5173 (Vite default)
- **Host binding**: `--host 0.0.0.0` voor Docker networking
- **Flexibele npm install**: Zelfde strategie als production Dockerfile

## Docker Compose Improvements

### ✅ Health Checks
- **Backend**: Gebruikt curl voor health check
- **Frontend**: Gebruikt wget voor health check
- **Start period**: Verhoogd voor betere startup handling

### ✅ Service Dependencies
- **depends_on met condition**: Frontend wacht tot backend healthy is
- **Betere startup order**: Voorkomt race conditions

### ✅ Environment Variables
- **LOG_LEVEL**: Configureerbaar logging level
- **VITE_API_URL**: Frontend API URL configuratie
- **DEBUG**: Debug mode flag

### ✅ Volume Mounts
- **Read-only mounts**: Examples en patterns als read-only
- **Development mounts**: Source code voor hot-reload in dev mode

## Docker Compose Dev Improvements

### ✅ Development Features
- **Hot-reload**: Backend en frontend met auto-reload
- **Source mounting**: Alle source code gemount voor live editing
- **Debug mode**: Debug logging enabled
- **Health checks disabled**: Voorkomt false positives tijdens reload

### ✅ Port Mapping
- **Frontend dev port**: 5173 (Vite default) in plaats van 3000

## .dockerignore Improvements

### ✅ Optimized Exclusions
- **Tests uitgesloten**: Tests directory niet nodig in image
- **Docker files**: Docker configuratie niet nodig in image
- **CI/CD files**: CI configuratie niet nodig
- **Documentation**: Alleen README.md behouden

## Best Practices Implemented

1. **Multi-stage builds**: Kleinere production images
2. **Non-root user**: Betere security
3. **Health checks**: Betere container orchestration
4. **Layer caching**: Optimale Docker layer caching
5. **Minimal dependencies**: Alleen wat nodig is
6. **Read-only volumes**: Waar mogelijk read-only mounts
7. **Environment configuration**: Configuratie via environment variables

## Usage Examples

### Production

```bash
# Build en start
docker-compose up --build -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f backend
```

### Development

```bash
# Start met hot-reload
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Rebuild na dependency changes
docker-compose -f docker-compose.yml -f docker-compose.dev.yml build

# Stop alles
docker-compose -f docker-compose.yml -f docker-compose.dev.yml down
```

## Troubleshooting

### Backend niet healthy

```bash
# Check logs
docker-compose logs backend

# Check health endpoint manually
docker-compose exec backend curl http://localhost:8000/health

# Check container status
docker-compose ps
```

### Frontend build fails

```bash
# Check frontend logs
docker-compose logs frontend

# Rebuild frontend
docker-compose build --no-cache frontend

# Check package.json
docker-compose exec frontend cat package.json
```

### Port conflicts

```bash
# Check welke processen poorten gebruiken
lsof -i :8000  # Backend
lsof -i :3000  # Frontend
lsof -i :5173  # Frontend dev

# Stop conflicterende processen
kill -9 $(lsof -t -i:8000)
```

## Security Considerations

1. **Non-root user**: Backend draait als appuser
2. **Read-only volumes**: Examples en patterns read-only
3. **Minimal base images**: Gebruikt slim/alpine images
4. **No secrets in image**: Gebruik environment variables
5. **Health checks**: Detecteren container issues vroeg

## Performance Optimizations

1. **Layer caching**: Dependencies geïnstalleerd voor code copy
2. **Multi-stage builds**: Kleinere final images
3. **npm ci**: Snellere, reproduceerbare installs
4. **Minimal dependencies**: Alleen wat nodig is

## Future Improvements

- [ ] Add Docker secrets management
- [ ] Add Docker Compose profiles voor verschillende environments
- [ ] Add monitoring en logging stack
- [ ] Add database service voor persistent storage
- [ ] Add Redis voor caching
- [ ] Optimize image sizes verder

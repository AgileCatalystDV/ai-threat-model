#!/bin/bash
# Docker Status Check Script

echo "=== Docker Status Check ==="
echo ""

echo "1. Docker CLI Version:"
docker --version
echo ""

echo "2. Docker Desktop Process Status:"
if pgrep -f "Docker Desktop" > /dev/null; then
    echo "✓ Docker Desktop is running"
    echo "  Process details:"
    ps aux | grep -i "Docker Desktop" | grep -v grep | head -1
else
    echo "✗ Docker Desktop is NOT running"
fi
echo ""

echo "3. Docker Daemon Status:"
if docker info > /dev/null 2>&1; then
    echo "✓ Docker daemon is running"
    docker ps
else
    echo "✗ Docker daemon is NOT responding"
    echo "  This usually means Docker Desktop is still starting up"
    echo "  Wait 30-60 seconds and try again"
fi
echo ""

echo "4. Docker Socket Check:"
if [ -S /var/run/docker.sock ]; then
    echo "✓ Docker socket exists"
    ls -la /var/run/docker.sock
else
    echo "✗ Docker socket NOT found"
    echo "  This is normal on macOS - Docker uses a different socket"
fi
echo ""

echo "5. Docker Context:"
docker context ls
echo ""

echo "=== Recommendations ==="
if ! docker info > /dev/null 2>&1; then
    echo "Docker Desktop is running but daemon is not ready yet."
    echo ""
    echo "Try these steps:"
    echo "1. Wait 30-60 seconds for Docker Desktop to fully start"
    echo "2. Check Docker Desktop GUI - look for whale icon in menubar"
    echo "3. Click whale icon → 'Docker Desktop is running' should be green"
    echo "4. Try: docker ps"
    echo ""
    echo "If still not working after 60 seconds:"
    echo "- Quit Docker Desktop completely"
    echo "- Restart Docker Desktop"
    echo "- Wait for full startup"
fi

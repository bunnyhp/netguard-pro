#!/bin/bash

echo "=========================================="
echo "NetGuard Dashboard Status Check"
echo "=========================================="
echo ""

# Check if Flask process is running
echo "1. Checking Flask process..."
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "   ✓ Flask is RUNNING"
    PID=$(pgrep -f "python3.*app.py")
    echo "   Process ID: $PID"
else
    echo "   ✗ Flask is NOT running"
    echo "   Starting Flask..."
    cd /home/jarvis/NetGuard/web
    nohup python3 app.py > /tmp/flask_dashboard.log 2>&1 &
    sleep 3
    if pgrep -f "python3.*app.py" > /dev/null; then
        echo "   ✓ Flask started successfully"
    else
        echo "   ✗ Failed to start Flask"
        echo "   Check /tmp/flask_dashboard.log for errors"
        exit 1
    fi
fi

echo ""
echo "2. Checking port 8080..."
if netstat -tuln 2>/dev/null | grep -q ":8080 " || ss -tuln 2>/dev/null | grep -q ":8080 "; then
    echo "   ✓ Port 8080 is LISTENING"
else
    echo "   ✗ Port 8080 is NOT listening"
    echo "   Waiting 5 seconds for startup..."
    sleep 5
fi

echo ""
echo "3. Testing HTTP response..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ | grep -q "200"; then
    echo "   ✓ Dashboard is ACCESSIBLE"
else
    echo "   ⚠ Dashboard may not be fully ready yet"
fi

echo ""
echo "=========================================="
echo "Dashboard Access Information:"
echo "=========================================="
echo ""
echo "Local Access:  http://localhost:8080"
echo "Network Access: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "Available Pages:"
echo "  - Homepage:         http://localhost:8080/"
echo "  - AI Dashboard:     http://localhost:8080/ai-dashboard"
echo "  - Network Map:      http://localhost:8080/network-topology"
echo "  - IoT Devices:      http://localhost:8080/iot-devices"
echo "  - Analysis Tools:   http://localhost:8080/analysis"
echo "  - Alerts:           http://localhost:8080/alerts"
echo ""
echo "=========================================="


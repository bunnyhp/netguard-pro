#!/bin/bash

echo "=========================================="
echo "  NetGuard Pro Dashboard Launcher"
echo "=========================================="
echo ""

# Stop any existing Flask processes
echo "→ Stopping existing Flask processes..."
pkill -9 -f "python3.*app.py" 2>/dev/null
sleep 2

# Start Flask
echo "→ Starting NetGuard Dashboard..."
cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
FLASK_PID=$!

# Wait for startup
sleep 4

# Check if running
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✓ Dashboard is RUNNING!"
    echo ""
    echo "=========================================="
    echo "  Access Your Dashboard"
    echo "=========================================="
    echo ""
    echo "  Local:   http://localhost:8080"
    echo "  Network: http://$(hostname -I | awk '{print $1}'):8080"
    echo ""
    echo "  Available Pages:"
    echo "  • Homepage (Real-time visualizations)"
    echo "  • AI Dashboard"
    echo "  • Network Topology Map"
    echo "  • IoT Security Scanner"
    echo "  • Analysis Tools"
    echo "  • Security Alerts"
    echo ""
    echo "  Logs: tail -f /tmp/netguard_dashboard.log"
    echo ""
    echo "=========================================="
else
    echo "✗ Failed to start Flask"
    echo ""
    echo "Check logs:"
    echo "  cat /tmp/netguard_dashboard.log"
    exit 1
fi


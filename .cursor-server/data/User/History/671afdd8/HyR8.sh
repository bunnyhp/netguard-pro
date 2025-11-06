#!/bin/bash

echo "========================================"
echo "Restarting NetGuard Dashboard"
echo "========================================"

# Kill existing Flask processes
echo "Stopping existing Flask processes..."
pkill -9 -f "python3.*app.py" 2>/dev/null
sleep 2

# Start Flask
echo "Starting Flask dashboard..."
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
FLASK_PID=$!

# Wait a moment
sleep 3

# Check if it's running
if ps -p $FLASK_PID > /dev/null; then
    echo "✓ Flask is running (PID: $FLASK_PID)"
    echo ""
    echo "Dashboard URLs:"
    echo "  Local:   http://localhost:8080"
    echo "  Network: http://$(hostname -I | awk '{print $1}'):8080"
    echo ""
    echo "Logs: tail -f /tmp/netguard_dashboard.log"
else
    echo "✗ Flask failed to start"
    echo "Check logs: cat /tmp/netguard_dashboard.log"
    exit 1
fi


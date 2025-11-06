#!/bin/bash
echo "Restarting Flask Dashboard..."

# Kill any existing Flask processes
pkill -9 -f "python3.*app.py"
sleep 2

# Start Flask in background
cd /home/jarvis/NetGuard/web
nohup python3 app.py > /home/jarvis/NetGuard/logs/system/flask.log 2>&1 &

sleep 3

# Check if Flask started
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✓ Flask restarted successfully on port 8080"
    echo "✓ Access: http://192.168.1.161:8080/ai-dashboard"
    echo ""
    echo "⚠️  IMPORTANT: Clear your browser cache!"
    echo "   - Press Ctrl+Shift+R (Windows/Linux)"
    echo "   - Press Cmd+Shift+R (Mac)"
    echo "   - Or open in Incognito/Private window"
else
    echo "✗ Flask failed to start. Check logs:"
    echo "   tail /home/jarvis/NetGuard/logs/system/flask.log"
fi


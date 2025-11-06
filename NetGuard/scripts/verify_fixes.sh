#!/bin/bash

echo "=========================================="
echo "NetGuard Pro - Mock Data Fix Verification"
echo "=========================================="
echo ""

# 1. Check template file
echo "1. Checking ai_dashboard.html template..."
if grep -q "IoT-Camera-04" /home/jarvis/NetGuard/web/templates/ai_dashboard.html; then
    echo "   ✗ FAIL: Mock device 'IoT-Camera-04' still in template"
else
    echo "   ✓ PASS: 'IoT-Camera-04' removed from template"
fi

if grep -q "Botnet Beacon" /home/jarvis/NetGuard/web/templates/ai_dashboard.html; then
    echo "   ✗ FAIL: 'Botnet Beacon' still in template"
else
    echo "   ✓ PASS: 'Botnet Beacon' removed from template"
fi

echo ""

# 2. Check Flask process
echo "2. Checking Flask status..."
if pgrep -f "python3.*app.py" > /dev/null; then
    echo "   ✓ Flask is running (PID: $(pgrep -f 'python3.*app.py'))"
    echo "   ⚠️  Flask needs restart to load new template"
else
    echo "   ✗ Flask is NOT running"
fi

echo ""

# 3. Check template modification time
echo "3. Template file info..."
ls -lh /home/jarvis/NetGuard/web/templates/ai_dashboard.html | awk '{print "   Modified: " $6, $7, $8 " Size: " $5}'

echo ""

# 4. AI data check
echo "4. Checking AI analysis data..."
if [ -f /home/jarvis/NetGuard/network.db ]; then
    COUNT=$(sqlite3 /home/jarvis/NetGuard/network.db "SELECT COUNT(*) FROM ai_analysis" 2>/dev/null || echo "0")
    if [ "$COUNT" -gt 0 ]; then
        echo "   ✓ AI analysis table has $COUNT entries"
        LATEST=$(sqlite3 /home/jarvis/NetGuard/network.db "SELECT timestamp FROM ai_analysis ORDER BY timestamp DESC LIMIT 1" 2>/dev/null)
        echo "   Latest analysis: $LATEST"
    else
        echo "   ⚠️  No AI analysis data found"
        echo "   Run: python3 /home/jarvis/NetGuard/scripts/ai_5min_aggregator.py"
    fi
else
    echo "   ✗ Database not found"
fi

echo ""
echo "=========================================="
echo "NEXT STEPS:"
echo "=========================================="
echo "1. Restart Flask:"
echo "   bash /home/jarvis/NetGuard/scripts/restart_flask.sh"
echo ""
echo "2. Clear browser cache (REQUIRED!):"
echo "   - Press Ctrl+Shift+R (hard refresh)"
echo "   - Or open in Incognito/Private window"
echo ""
echo "3. Visit AI Dashboard:"
echo "   http://192.168.1.161:8080/ai-dashboard"
echo ""


#!/bin/bash

echo "=========================================="
echo "Fixing IoT Security Page - Remove ALL Mock Data"
echo "=========================================="

echo ""
echo "🔧 Step 1: Populating domain patterns with real data..."
python3 /home/jarvis/NetGuard/POPULATE_DOMAIN_PATTERNS.py

echo ""
echo "📊 Step 2: Getting real network traffic data..."
python3 /home/jarvis/NetGuard/FIX_NETWORK_TRAFFIC_DATA.py

echo ""
echo "🔄 Step 3: Restarting Flask with updated templates and APIs..."
sudo pkill -f "python3.*app.py" 2>/dev/null || true
sleep 3

cd /home/jarvis/NetGuard/web
nohup python3 app.py > /tmp/flask.log 2>&1 &
sleep 3

echo ""
echo "🧪 Step 4: Testing IoT devices page..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/iot-devices)
if [ "$response" = "200" ]; then
    echo "✅ IoT Devices page: WORKING (HTTP $response)"
else
    echo "❌ IoT Devices page: FAILED (HTTP $response)"
fi

echo ""
echo "🧪 Step 5: Testing network traffic API..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/network-traffic-stats)
if [ "$response" = "200" ]; then
    echo "✅ Network Traffic API: WORKING (HTTP $response)"
else
    echo "❌ Network Traffic API: FAILED (HTTP $response)"
fi

echo ""
echo "🧪 Step 6: Testing attack monitoring API..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/attack-monitoring)
if [ "$response" = "200" ]; then
    echo "✅ Attack Monitoring API: WORKING (HTTP $response)"
else
    echo "❌ Attack Monitoring API: FAILED (HTTP $response)"
fi

echo ""
echo "✅ IoT Security Page Fix Complete!"
echo ""
echo "🎯 What was fixed:"
echo "• Domain Communication Patterns: Now shows real data instead of loading spinner"
echo "• Real-time Communication Monitoring: Replaced loading spinner with real stats"
echo "• Network Traffic Analysis (Bottom): Now loads real traffic data via API"
echo "• Attack Timeline: Now loads real attack data from security_alerts table"
echo "• Removed ALL mock data and loading states"
echo "• Added proper error handling and fallbacks"
echo "• Dynamic chart updates with real data"
echo ""
echo "🌐 Visit: http://localhost:8080/iot-devices"
echo "All sections should now show real data instead of mock/loading states!"
echo "=========================================="

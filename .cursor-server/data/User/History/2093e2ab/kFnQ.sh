#!/bin/bash

echo "=========================================="
echo "FINAL NETWORK TRAFFIC ANALYSIS FIX"
echo "=========================================="

echo ""
echo "🔧 Step 1: Populating domain patterns..."
python3 /home/jarvis/NetGuard/POPULATE_DOMAIN_PATTERNS.py

echo ""
echo "🧪 Step 2: Testing all APIs..."
echo "Network Traffic API:"
curl -s http://localhost:8080/api/network-traffic-stats | python3 -m json.tool

echo ""
echo "Domain Communications API:"
curl -s http://localhost:8080/api/domain-communications | python3 -c "import sys, json; data=json.load(sys.stdin); print(f'Found {len(data)} domain patterns')"

echo ""
echo "✅ FIXES APPLIED!"
echo ""
echo "🎯 WHAT TO DO NOW:"
echo "1. Go to: http://localhost:8080/iot-devices"
echo "2. Look for the 'Network Traffic Analysis' section"
echo "3. Click the refresh button (🔄) next to the title"
echo "4. Check browser console (F12) for debug messages"
echo ""
echo "📊 EXPECTED RESULTS:"
echo "• Total Traffic: 22.5 MB"
echo "• Peak Rate: 7.2 Mbps" 
echo "• Suspicious: 6"
echo "• Encrypted: 75%"
echo "• Chart should show bar graph with data"
echo ""
echo "🔍 IF STILL EMPTY:"
echo "1. Open browser Developer Tools (F12)"
echo "2. Go to Console tab"
echo "3. Look for debug messages or errors"
echo "4. Try clicking the refresh button"
echo "=========================================="

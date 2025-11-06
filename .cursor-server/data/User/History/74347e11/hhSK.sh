#!/bin/bash

echo "=========================================="
echo "  Fixing Ethertype Unknown Alerts"
echo "=========================================="
echo ""

echo "→ Stopping Flask..."
pkill -9 -f "python3.*app.py" 2>/dev/null
sleep 2

echo "→ Starting Flask with filters..."
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
sleep 3

if pgrep -f "python3.*app.py" > /dev/null; then
    echo "✓ Flask restarted successfully!"
    echo ""
    echo "=========================================="
    echo "  FALSE POSITIVE ALERTS REMOVED"
    echo "=========================================="
    echo ""
    echo "The following alerts are now filtered:"
    echo "  ✓ Ethertype unknown"
    echo "  ✓ IPv4 checksum errors"
    echo "  ✓ IPv6 checksum errors"
    echo "  ✓ VLAN decoder events"
    echo ""
    echo "These filters are active in:"
    echo "  • Homepage (Security Alerts section)"
    echo "  • AI Dashboard (Threat Analysis)"
    echo "  • Suricata Alert Pages"
    echo ""
    echo "Access your dashboard:"
    echo "  http://localhost:8080"
    echo ""
    echo "=========================================="
else
    echo "✗ Flask failed to start"
    echo "Check logs: cat /tmp/netguard_dashboard.log"
    exit 1
fi


#!/bin/bash

echo "=========================================="
echo "P0F COLLECTOR STATUS CHECK"
echo "=========================================="
echo ""

echo "1. Checking p0f_collector.py interface configuration..."
grep "INTERFACE" /home/jarvis/NetGuard/scripts/p0f_collector.py

echo ""
echo "2. Checking if p0f_collector.py is running..."
pgrep -af p0f_collector.py

echo ""
echo "3. Checking if p0f daemon is running..."
pgrep -af "p0f -i"

echo ""
echo "4. Checking systemd service status..."
systemctl is-active p0f-collector.service

echo ""
echo "5. Checking recent logs..."
tail -20 /tmp/p0f_collector.log 2>/dev/null || tail -20 /home/jarvis/NetGuard/logs/system/p0f-collector.log 2>/dev/null || echo "No logs found"

echo ""
echo "6. Checking database tables..."
sqlite3 /home/jarvis/NetGuard/network.db "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' ORDER BY name DESC LIMIT 5;"

echo ""
echo "7. Checking latest p0f data..."
sqlite3 /home/jarvis/NetGuard/network.db "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' AND name NOT LIKE '%template%' ORDER BY name DESC LIMIT 1;" | while read table; do
    if [ ! -z "$table" ]; then
        echo "Latest table: $table"
        sqlite3 /home/jarvis/NetGuard/network.db "SELECT COUNT(*) as count FROM $table;"
        sqlite3 /home/jarvis/NetGuard/network.db "SELECT * FROM $table LIMIT 3;"
    fi
done

echo ""
echo "=========================================="
echo "TO RESTART P0F COLLECTOR, RUN:"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl restart p0f-collector.service"
echo "sudo systemctl status p0f-collector.service"
echo "=========================================="


#!/bin/bash
echo "=========================================="
echo "P0F DATABASE DATA"
echo "=========================================="

sqlite3 /home/jarvis/NetGuard/network.db <<EOF
.mode column
.headers on
.width 30 20 20 20 20

SELECT name as 'Table Name', 
       (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=m.name) as 'Exists'
FROM sqlite_master m
WHERE type='table' AND name LIKE 'p0f_%' AND name NOT LIKE '%_template'
ORDER BY name DESC;

EOF

echo ""
echo "=========================================="
echo "LATEST P0F TABLE DATA"
echo "=========================================="

# Get the latest p0f table
LATEST_TABLE=$(sqlite3 /home/jarvis/NetGuard/network.db "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' AND name NOT LIKE '%_template' ORDER BY name DESC LIMIT 1;")

if [ -n "$LATEST_TABLE" ]; then
    echo "Table: $LATEST_TABLE"
    echo ""
    sqlite3 /home/jarvis/NetGuard/network.db <<EOF
.mode column
.headers on
SELECT * FROM $LATEST_TABLE LIMIT 10;
EOF
else
    echo "No p0f tables found!"
fi

echo ""
echo "=========================================="
echo "P0F COLLECTOR STATUS"
echo "=========================================="
systemctl status p0f-collector.service --no-pager | head -15

echo ""
echo "=========================================="
echo "P0F LOG FILE"
echo "=========================================="
echo "Log size: $(sudo ls -lh /home/jarvis/NetGuard/captures/p0f/p0f.log 2>/dev/null | awk '{print $5}')"
echo "Last 5 lines:"
sudo tail -5 /home/jarvis/NetGuard/captures/p0f/p0f.log 2>/dev/null || echo "Cannot read log file"


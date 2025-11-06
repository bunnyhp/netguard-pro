#!/bin/bash

echo "=========================================="
echo "  NetGuard Collector Verification"
echo "=========================================="
echo ""

DB="/home/jarvis/NetGuard/network.db"

echo "→ Checking database tables..."
echo ""

# Get all collector tables
TABLES=$(sqlite3 $DB "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%_template'" 2>/dev/null)

if [ -z "$TABLES" ]; then
    echo "✗ No tables found in database!"
    echo "  Database may be new or collectors haven't run yet."
    exit 1
fi

# Check each collector type
COLLECTORS=("p0f" "tshark" "tcpdump" "ngrep" "httpry" "argus" "netsniff" "iftop" "nethogs" "suricata")

for collector in "${COLLECTORS[@]}"; do
    echo "Checking $collector collector..."
    
    # Count tables for this collector
    TABLE_COUNT=$(echo "$TABLES" | grep -c "^${collector}_" || echo "0")
    
    if [ $TABLE_COUNT -gt 0 ]; then
        echo "  ✓ Found $TABLE_COUNT table(s)"
        
        # Get latest table
        LATEST_TABLE=$(echo "$TABLES" | grep "^${collector}_" | sort -r | head -1)
        
        if [ ! -z "$LATEST_TABLE" ]; then
            # Count records in latest table
            RECORD_COUNT=$(sqlite3 $DB "SELECT COUNT(*) FROM $LATEST_TABLE" 2>/dev/null || echo "0")
            echo "  ✓ Latest table: $LATEST_TABLE ($RECORD_COUNT records)"
            
            # Show last 3 records
            if [ $RECORD_COUNT -gt 0 ]; then
                echo "  ✓ Collector is WORKING - collecting data!"
            else
                echo "  ⚠ Table exists but has no data yet"
            fi
        fi
    else
        echo "  ✗ No tables found - collector may not be running"
    fi
    echo ""
done

echo "=========================================="
echo "  Quick Database Statistics"
echo "=========================================="
echo ""

# Total tables
TOTAL_TABLES=$(echo "$TABLES" | wc -l)
echo "Total tables: $TOTAL_TABLES"

# Total records across all tables
echo ""
echo "Records per collector:"
for collector in "${COLLECTORS[@]}"; do
    TOTAL=0
    for table in $(echo "$TABLES" | grep "^${collector}_"); do
        COUNT=$(sqlite3 $DB "SELECT COUNT(*) FROM $table" 2>/dev/null || echo "0")
        TOTAL=$((TOTAL + COUNT))
    done
    if [ $TOTAL -gt 0 ]; then
        echo "  $collector: $TOTAL records"
    fi
done

echo ""
echo "=========================================="


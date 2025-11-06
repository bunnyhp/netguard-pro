#!/bin/bash
##############################################################################
# Baseline Network Monitoring Script (14-Day Campaign)
# Purpose: Collect normal traffic patterns for baseline analysis
# Duration: 14 days continuous monitoring
##############################################################################

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="/home/jarvis/thesis/data/baseline"
DB_PATH="/home/jarvis/NetGuard/network.db"
LOG_FILE="/home/jarvis/thesis/logs/baseline_monitor.log"

mkdir -p "$DATA_DIR" "$(dirname "$LOG_FILE")"

echo "========================================" | tee -a "$LOG_FILE"
echo "BASELINE MONITORING - Started $(date)" | tee -a "$LOG_FILE"
echo "Duration: 14 days" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to collect system metrics
collect_metrics() {
    local day=$1
    local metrics_file="$DATA_DIR/day${day}_metrics.json"
    
    log "Collecting metrics for Day $day..."
    
    # CPU utilization
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    # Memory usage
    mem_total=$(free -m | awk 'NR==2{print $2}')
    mem_used=$(free -m | awk 'NR==2{print $3}')
    mem_percent=$(awk "BEGIN {printf \"%.2f\", ($mem_used/$mem_total)*100}")
    
    # Disk usage
    disk_used=$(df -h /home/jarvis/NetGuard | awk 'NR==2{print $3}')
    disk_percent=$(df -h /home/jarvis/NetGuard | awk 'NR==2{print $5}' | tr -d '%')
    
    # Service status
    services_running=$(systemctl list-units --type=service --state=running | grep -c "collector")
    
    # Database size
    db_size=$(du -h "$DB_PATH" | awk '{print $1}')
    
    # Packet capture stats (from tshark collector)
    packets_captured=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'tshark_%' AND name NOT LIKE '%_template';" 2>/dev/null || echo "0")
    
    # Create JSON output
    cat > "$metrics_file" <<EOF
{
    "day": $day,
    "timestamp": "$(date -Iseconds)",
    "system": {
        "cpu_usage_percent": $cpu_usage,
        "memory_used_mb": $mem_used,
        "memory_total_mb": $mem_total,
        "memory_percent": $mem_percent,
        "disk_used": "$disk_used",
        "disk_percent": $disk_percent
    },
    "services": {
        "collectors_running": $services_running
    },
    "database": {
        "size": "$db_size",
        "tshark_tables": $packets_captured
    }
}
EOF
    
    log "Metrics saved to $metrics_file"
}

# Function to export database statistics
export_db_stats() {
    local day=$1
    local stats_file="$DATA_DIR/day${day}_db_stats.csv"
    
    log "Exporting database statistics for Day $day..."
    
    sqlite3 "$DB_PATH" <<EOF > "$stats_file"
.mode csv
.headers on
SELECT 
    'tshark' as tool,
    COUNT(*) as table_count,
    (SELECT SUM(cnt) FROM (SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name LIKE 'tshark_%')) as total_records
FROM sqlite_master WHERE type='table' AND name LIKE 'tshark_%' AND name NOT LIKE '%_template'
UNION ALL
SELECT 
    'suricata' as tool,
    COUNT(*) as table_count,
    0 as total_records
FROM sqlite_master WHERE type='table' AND name LIKE 'suricata_%' AND name NOT LIKE '%_template'
UNION ALL
SELECT 
    'p0f' as tool,
    COUNT(*) as table_count,
    0 as total_records
FROM sqlite_master WHERE type='table' AND name LIKE 'p0f_%' AND name NOT LIKE '%_template';
EOF
    
    log "Database stats saved to $stats_file"
}

# Main monitoring loop
START_DAY=$(date +%s)
CURRENT_DAY=1

log "Starting 14-day baseline monitoring campaign..."
log "Press Ctrl+C to stop early"

while [ $CURRENT_DAY -le 14 ]; do
    log "=== Day $CURRENT_DAY of 14 ==="
    
    # Collect metrics every 6 hours (4 times per day)
    for hour in 0 6 12 18; do
        current_hour=$(date +%H)
        
        if [ "$current_hour" -eq "$hour" ]; then
            collect_metrics $CURRENT_DAY
            export_db_stats $CURRENT_DAY
            
            # Sleep until next collection window (6 hours)
            sleep 21600
        fi
    done
    
    # Check if services are running
    if ! systemctl is-active --quiet tshark-collector.service; then
        log "WARNING: tshark-collector is not running!"
    fi
    
    if ! systemctl is-active --quiet suricata-collector.service; then
        log "WARNING: suricata-collector is not running!"
    fi
    
    if ! systemctl is-active --quiet p0f-collector.service; then
        log "WARNING: p0f-collector is not running!"
    fi
    
    # Move to next day
    CURRENT_DAY=$((CURRENT_DAY + 1))
    
    # Sleep until start of next day
    sleep 86400
done

log "========================================" 
log "BASELINE MONITORING COMPLETED"
log "Total duration: 14 days"
log "Data location: $DATA_DIR"
log "========================================"


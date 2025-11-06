#!/bin/bash
# NetGuard Pro - Service Monitor and Health Check
# Ensures all services stay running

SERVICES=(
    "tshark-collector.service"
    "p0f-collector.service"
    "network-dashboard.service"
)

LOG_FILE="/home/jarvis/NetGuard/logs/system/service-monitor.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_and_restart() {
    local service=$1
    
    if ! systemctl is-active --quiet "$service"; then
        log_message "⚠️  $service is not running. Attempting restart..."
        systemctl start "$service"
        sleep 3
        
        if systemctl is-active --quiet "$service"; then
            log_message "✅ $service restarted successfully"
        else
            log_message "❌ Failed to restart $service"
        fi
    fi
}

# Main monitoring loop
log_message "═══════════════════════════════════════════════════════════════"
log_message "NetGuard Pro Service Monitor Started"
log_message "═══════════════════════════════════════════════════════════════"

while true; do
    for service in "${SERVICES[@]}"; do
        check_and_restart "$service"
    done
    
    # Check every 60 seconds
    sleep 60
done


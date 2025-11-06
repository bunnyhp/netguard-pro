#!/bin/bash

echo "=========================================="
echo "NetGuard Pro - Complete System Status"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running with sudo for system checks
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# All services to check
COLLECTOR_SERVICES=(
    "p0f-collector"
    "tshark-collector"
    "ngrep-collector"
    "httpry-collector"
    "tcpdump-collector"
    "argus-collector"
    "netsniff-ng-collector"
    "iftop-collector"
    "nethogs-collector"
    "suricata"
)

NEW_SERVICES=(
    "device-tracker"
    "unified-device-processor"
    "iot-security-scanner"
    "device-scorer"
    "enhanced-alert-system"
    "netguard-flask"
)

AI_SERVICES=(
    "ai-5min-aggregator"
)

TIMERS=(
    "device-scorer"
)

# Function to check service status
check_service() {
    local service=$1
    local service_file="${service}.service"
    
    if $SUDO systemctl is-enabled --quiet $service_file 2>/dev/null; then
        enabled="enabled"
    else
        enabled="disabled"
    fi
    
    if $SUDO systemctl is-active --quiet $service_file 2>/dev/null; then
        status="active"
        symbol="${GREEN}●${NC}"
    else
        status="inactive"
        symbol="${RED}●${NC}"
    fi
    
    # Get uptime if active
    if [ "$status" = "active" ]; then
        uptime=$($SUDO systemctl show $service_file --property=ActiveEnterTimestamp --value | cut -d' ' -f2-3)
    else
        uptime="N/A"
    fi
    
    printf "  ${symbol} %-30s %-10s %-10s %s\n" "$service" "$status" "($enabled)" "$uptime"
}

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}  DATA COLLECTORS (10 services)${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
for service in "${COLLECTOR_SERVICES[@]}"; do
    check_service "$service"
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}  DEVICE TRACKING & SECURITY (6 services)${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
for service in "${NEW_SERVICES[@]}"; do
    check_service "$service"
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}  AI ANALYSIS (1 service)${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
for service in "${AI_SERVICES[@]}"; do
    check_service "$service"
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}  TIMERS (1 timer)${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
for timer in "${TIMERS[@]}"; do
    timer_file="${timer}.timer"
    if $SUDO systemctl is-active --quiet $timer_file 2>/dev/null; then
        status="active"
        symbol="${GREEN}●${NC}"
    else
        status="inactive"
        symbol="${RED}●${NC}"
    fi
    
    next_run=$($SUDO systemctl show $timer_file --property=NextElapseUSecRealtime --value 2>/dev/null || echo "N/A")
    printf "  ${symbol} %-30s %-10s Next: %s\n" "$timer" "$status" "$next_run"
done

echo ""
echo "=========================================="
echo "Summary Statistics"
echo "=========================================="

# Count active services
total_services=$((${#COLLECTOR_SERVICES[@]} + ${#NEW_SERVICES[@]} + ${#AI_SERVICES[@]}))
active_count=0

for service in "${COLLECTOR_SERVICES[@]}" "${NEW_SERVICES[@]}" "${AI_SERVICES[@]}"; do
    if $SUDO systemctl is-active --quiet ${service}.service 2>/dev/null; then
        ((active_count++))
    fi
done

echo "Total Services: $total_services"
echo -e "Active: ${GREEN}$active_count${NC}"
echo -e "Inactive: ${RED}$((total_services - active_count))${NC}"

# Calculate percentage
percentage=$((active_count * 100 / total_services))
if [ $percentage -eq 100 ]; then
    echo -e "System Health: ${GREEN}${percentage}% ✓ All systems operational${NC}"
elif [ $percentage -ge 80 ]; then
    echo -e "System Health: ${YELLOW}${percentage}% ⚠ Most systems running${NC}"
else
    echo -e "System Health: ${RED}${percentage}% ✗ Critical services down${NC}"
fi

echo ""
echo "=========================================="
echo "Database Status"
echo "=========================================="

DB_PATH="/home/jarvis/NetGuard/network.db"
if [ -f "$DB_PATH" ]; then
    echo -e "${GREEN}✓${NC} Database exists: $DB_PATH"
    
    # Check devices table
    device_count=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM devices" 2>/dev/null || echo "0")
    echo "  - Tracked Devices: $device_count"
    
    # Check vulnerabilities
    vuln_count=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM iot_vulnerabilities WHERE resolved=0" 2>/dev/null || echo "0")
    echo "  - Active Vulnerabilities: $vuln_count"
    
    # Check AI analysis
    ai_count=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM ai_analysis" 2>/dev/null || echo "0")
    echo "  - AI Analysis Records: $ai_count"
    
    # Check alerts
    alert_count=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM security_alerts WHERE status='active'" 2>/dev/null || echo "0")
    echo "  - Active Alerts: $alert_count"
    
    # Database size
    db_size=$(du -h $DB_PATH | cut -f1)
    echo "  - Database Size: $db_size"
else
    echo -e "${RED}✗${NC} Database not found"
fi

echo ""
echo "=========================================="
echo "Web Dashboard"
echo "=========================================="

if $SUDO systemctl is-active --quiet netguard-flask.service; then
    echo -e "${GREEN}✓${NC} Flask Dashboard: Running"
    echo "  Access URLs:"
    echo "    - Main: http://192.168.1.161:8080/"
    echo "    - AI Dashboard: http://192.168.1.161:8080/ai-dashboard"
    echo "    - Network Map: http://192.168.1.161:8080/network-topology"
    echo "    - Alerts: http://192.168.1.161:8080/alerts"
    echo "    - IoT Devices: http://192.168.1.161:8080/iot-devices"
else
    echo -e "${RED}✗${NC} Flask Dashboard: Not Running"
    echo "  Start with: sudo systemctl start netguard-flask.service"
fi

echo ""
echo "=========================================="
echo "System Resources"
echo "=========================================="

# CPU usage
cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
echo "CPU Usage: ${cpu_usage}%"

# Memory usage
mem_total=$(free -h | awk '/^Mem:/ {print $2}')
mem_used=$(free -h | awk '/^Mem:/ {print $3}')
mem_percent=$(free | awk '/^Mem:/ {printf "%.1f", $3/$2 * 100}')
echo "Memory: ${mem_used} / ${mem_total} (${mem_percent}%)"

# Disk usage
disk_usage=$(df -h /home/jarvis/NetGuard | awk 'NR==2 {print $5}')
echo "Disk Usage: ${disk_usage}"

echo ""
echo "=========================================="
echo "Recent Errors (Last 10 minutes)"
echo "=========================================="

# Check for errors in logs
error_count=$($SUDO journalctl --since "10 minutes ago" -p err | wc -l)
if [ $error_count -eq 0 ]; then
    echo -e "${GREEN}✓${NC} No errors in last 10 minutes"
else
    echo -e "${YELLOW}⚠${NC} ${error_count} errors found"
    echo "  View with: journalctl --since '10 minutes ago' -p err"
fi

echo ""
echo "=========================================="
echo "Quick Actions"
echo "=========================================="
echo ""
echo "Restart all services:"
echo "  sudo systemctl restart 'device-*' 'iot-*' 'netguard-*' 'unified-*' 'enhanced-*'"
echo ""
echo "View specific service logs:"
echo "  journalctl -u netguard-flask.service -f"
echo ""
echo "Check failed services:"
echo "  systemctl --failed"
echo ""
echo "Test reboot persistence:"
echo "  sudo reboot && sleep 60 && bash $0"
echo ""


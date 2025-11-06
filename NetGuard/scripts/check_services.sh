#!/bin/bash

##############################################################################
# NetGuard Pro - Service Health Check Script
# Verifies all services are running and healthy
##############################################################################

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo "════════════════════════════════════════════════════════════════════"
echo "           NetGuard Pro - Service Health Check"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# List of all services
SERVICES=(
    "tshark-collector"
    "p0f-collector"
    "argus-collector"
    "ngrep-collector"
    "netsniff-collector"
    "httpry-collector"
    "iftop-collector"
    "nethogs-collector"
    "suricata-collector"
    "tcpdump-collector"
    "ai-aggregator"
    "flask-dashboard"
)

# Counters
RUNNING=0
STOPPED=0
ENABLED=0
DISABLED=0

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SERVICE STATUS REPORT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

printf "%-25s %-15s %-15s %-15s\n" "SERVICE" "STATUS" "BOOT ENABLED" "PID"
printf "%-25s %-15s %-15s %-15s\n" "$(printf '%.0s─' {1..25})" "$(printf '%.0s─' {1..15})" "$(printf '%.0s─' {1..15})" "$(printf '%.0s─' {1..15})"

for service in "${SERVICES[@]}"; do
    # Check if service is active
    if systemctl is-active --quiet "${service}.service" 2>/dev/null; then
        STATUS="${GREEN}●${NC} Running"
        ((RUNNING++))
        PID=$(systemctl show "${service}.service" -p MainPID --value 2>/dev/null)
    else
        STATUS="${RED}●${NC} Stopped"
        ((STOPPED++))
        PID="-"
    fi
    
    # Check if service is enabled
    if systemctl is-enabled --quiet "${service}.service" 2>/dev/null; then
        BOOT_ENABLED="${GREEN}Yes${NC}"
        ((ENABLED++))
    else
        BOOT_ENABLED="${RED}No${NC}"
        ((DISABLED++))
    fi
    
    printf "%-25s " "${service}"
    echo -ne "${STATUS}    "
    echo -ne "${BOOT_ENABLED}         "
    echo -e "${PID}"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  Running Services:     ${GREEN}${RUNNING}${NC} / ${#SERVICES[@]}"
echo -e "  Stopped Services:     ${RED}${STOPPED}${NC}"
echo -e "  Boot-Enabled:         ${GREEN}${ENABLED}${NC}"
echo -e "  Not Enabled:          ${RED}${DISABLED}${NC}"
echo ""

# Check crash protection
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CRASH PROTECTION STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

CRASH_PROTECTED=0
for service in "${SERVICES[@]}"; do
    RESTART_POLICY=$(systemctl show "${service}.service" -p Restart --value 2>/dev/null)
    if [ "$RESTART_POLICY" = "always" ]; then
        ((CRASH_PROTECTED++))
    fi
done

echo -e "  Services with auto-restart:  ${GREEN}${CRASH_PROTECTED}${NC} / ${#SERVICES[@]}"
echo ""

# Check recent failures
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  RECENT FAILURES (Last 24 hours)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FAILURES_FOUND=0
for service in "${SERVICES[@]}"; do
    FAILED_COUNT=$(journalctl -u "${service}.service" --since "24 hours ago" | grep -c "Failed" || echo 0)
    if [ "$FAILED_COUNT" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠${NC} ${service}: ${FAILED_COUNT} failures"
        ((FAILURES_FOUND++))
    fi
done

if [ "$FAILURES_FOUND" -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} No service failures detected"
fi

echo ""

# Database check
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DATABASE STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

DB_PATH="/home/jarvis/NetGuard/db/netguard.db"
if [ -f "$DB_PATH" ]; then
    DB_SIZE=$(du -h "$DB_PATH" | cut -f1)
    echo -e "  ${GREEN}✓${NC} Database exists: $DB_SIZE"
    
    # Count tables
    TABLE_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${NC} Tables: $TABLE_COUNT"
else
    echo -e "  ${RED}✗${NC} Database not found"
fi

echo ""

# Flask check
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  WEB DASHBOARD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Flask service
if systemctl is-active --quiet "flask-dashboard.service" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Flask Dashboard Service: Running"
    FLASK_PID=$(systemctl show "flask-dashboard.service" -p MainPID --value)
    echo -e "  ${GREEN}✓${NC} PID: $FLASK_PID"
elif pgrep -f "python3.*app.py" > /dev/null; then
    echo -e "  ${YELLOW}⚠${NC} Flask running manually (not as service)"
    FLASK_PID=$(pgrep -f "python3.*app.py")
    echo -e "  ${YELLOW}⚠${NC} PID: $FLASK_PID"
else
    echo -e "  ${RED}✗${NC} Flask Dashboard: Not Running"
fi

# Test HTTP response
if curl -s -f -o /dev/null http://localhost:8080/ 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} HTTP Endpoint: Responding"
    echo -e "  ${CYAN}→${NC} URL: http://localhost:8080/"
else
    echo -e "  ${RED}✗${NC} HTTP Endpoint: Not Responding"
fi

echo ""

# Overall health
echo "════════════════════════════════════════════════════════════════════"
echo "  OVERALL SYSTEM HEALTH"
echo "════════════════════════════════════════════════════════════════════"
echo ""

if [ "$STOPPED" -eq 0 ] && [ "$DISABLED" -eq 0 ]; then
    echo -e "  ${GREEN}✅ EXCELLENT${NC} - All services running and enabled"
elif [ "$STOPPED" -le 2 ] && [ "$DISABLED" -eq 0 ]; then
    echo -e "  ${YELLOW}⚠ GOOD${NC} - Most services running, some need attention"
else
    echo -e "  ${RED}❌ NEEDS ATTENTION${NC} - Multiple services stopped or disabled"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  MANAGEMENT COMMANDS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Start all services:    sudo systemctl start '*-collector.service' ai-aggregator.service flask-dashboard.service"
echo "  Stop all services:     sudo systemctl stop '*-collector.service' ai-aggregator.service flask-dashboard.service"
echo "  Restart all services:  sudo systemctl restart '*-collector.service' ai-aggregator.service flask-dashboard.service"
echo "  View service logs:     journalctl -u <service-name> -f"
echo "  Check specific:        systemctl status <service-name>"
echo ""
echo "════════════════════════════════════════════════════════════════════"


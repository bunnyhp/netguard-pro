#!/bin/bash
# NetGuard Pro - Start All Services
# Ensures services start in correct order with health checks

echo "═══════════════════════════════════════════════════════════════"
echo "    NetGuard Pro - Starting All Services"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to start and verify service
start_service() {
    local service=$1
    local description=$2
    
    echo -n "Starting $description... "
    systemctl start "$service"
    sleep 3
    
    if systemctl is-active --quiet "$service"; then
        echo -e "${GREEN}✓ Running${NC}"
        return 0
    else
        echo -e "${RED}✗ Failed${NC}"
        return 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo "1. Network Monitoring Services"
echo "───────────────────────────────────────────────────────────────"
start_service "tshark-collector.service" "tshark Collector (WiFi)"
start_service "p0f-collector.service" "p0f OS Fingerprinting (Ethernet)"

echo ""
echo "2. Web Dashboard"
echo "───────────────────────────────────────────────────────────────"
start_service "network-dashboard.service" "Web Dashboard (Port 8080)"

echo ""
echo "3. Service Monitor (Health Check)"
echo "───────────────────────────────────────────────────────────────"
start_service "netguard-monitor.service" "Service Health Monitor"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "    Service Startup Complete"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Final status check
echo "📊 Final Status:"
echo "───────────────────────────────────────────────────────────────"

for service in "tshark-collector.service" "p0f-collector.service" "network-dashboard.service" "netguard-monitor.service"; do
    status=$(systemctl is-active "$service")
    autostart=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
    
    if [ "$status" = "active" ]; then
        echo -e "  ${GREEN}✓${NC} $service: $status (Auto-start: $autostart)"
    else
        echo -e "  ${RED}✗${NC} $service: $status (Auto-start: $autostart)"
    fi
done

echo ""
echo "🌐 Dashboard Access:"
echo "  http://192.168.1.161:8080"
echo ""
echo "🔄 All services configured to:"
echo "  • Auto-start on boot"
echo "  • Auto-restart on crash"
echo "  • Monitored every 60 seconds"
echo ""
echo "═══════════════════════════════════════════════════════════════"


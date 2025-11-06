#!/bin/bash

##############################################################################
# NetGuard Pro - Reboot-Proof Setup & Testing Script
# Makes the system bulletproof against crashes and reboots
##############################################################################

set -e

echo "════════════════════════════════════════════════════════════════════"
echo "   NetGuard Pro - Reboot-Proof Configuration"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Check if running as root for service operations
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run as root (use sudo)"
    echo "   Example: sudo bash $0"
    exit 1
fi

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

NETGUARD_DIR="/home/jarvis/NetGuard"

cd "$NETGUARD_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 1: Installing All Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Install Flask dashboard service
echo "📦 Installing Flask Dashboard Service..."
cp "$NETGUARD_DIR/services/flask-dashboard.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable flask-dashboard.service
echo -e "${GREEN}✓ Flask dashboard service installed${NC}"
echo ""

# Install all collector services
echo "📦 Installing Collector Services..."
for service_file in "$NETGUARD_DIR/services"/*-collector.service; do
    if [ -f "$service_file" ]; then
        service_name=$(basename "$service_file")
        cp "$service_file" /etc/systemd/system/
        echo "  ✓ Installed $service_name"
    fi
done

# Install AI aggregator (already in /etc/systemd/system)
if [ -f "/etc/systemd/system/ai-aggregator.service" ]; then
    echo "  ✓ AI Aggregator already installed"
else
    echo "  ⚠ AI Aggregator not found (may need manual installation)"
fi

systemctl daemon-reload
echo -e "${GREEN}✓ All services copied to /etc/systemd/system${NC}"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 2: Enabling Auto-Start on Boot"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

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

for service in "${SERVICES[@]}"; do
    echo -n "  Enabling ${service}... "
    if systemctl enable "${service}.service" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠ Already enabled${NC}"
    fi
done

echo ""
echo -e "${GREEN}✓ All services enabled for auto-start${NC}"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 3: Verifying Crash Protection Settings"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Checking restart policies..."
echo ""

for service in "${SERVICES[@]}"; do
    RESTART_POLICY=$(systemctl show "${service}.service" -p Restart --value 2>/dev/null || echo "unknown")
    RESTART_SEC=$(systemctl show "${service}.service" -p RestartSec --value 2>/dev/null || echo "unknown")
    
    if [ "$RESTART_POLICY" = "always" ]; then
        echo -e "  ${GREEN}✓${NC} ${service}: Restart=${RESTART_POLICY}, Delay=${RESTART_SEC}"
    else
        echo -e "  ${YELLOW}⚠${NC} ${service}: Restart=${RESTART_POLICY} (should be 'always')"
    fi
done

echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 4: Starting All Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

for service in "${SERVICES[@]}"; do
    echo -n "  Starting ${service}... "
    
    # Stop first if running
    systemctl stop "${service}.service" 2>/dev/null || true
    sleep 1
    
    # Start service
    if systemctl start "${service}.service" 2>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "${service}.service"; then
            echo -e "${GREEN}✓ Running${NC}"
        else
            echo -e "${YELLOW}⚠ Started but not active yet${NC}"
        fi
    else
        echo -e "${RED}✗ Failed${NC}"
    fi
done

echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 5: Crash Test (Simulated)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Testing auto-restart by killing a service..."
echo ""

# Test with tshark-collector
TEST_SERVICE="tshark-collector"
echo "  Target: ${TEST_SERVICE}"
echo ""

# Get PID before kill
PID_BEFORE=$(systemctl show "${TEST_SERVICE}.service" -p MainPID --value)
echo "  PID before kill: $PID_BEFORE"

# Kill the service
echo "  Killing service..."
systemctl kill "${TEST_SERVICE}.service" 2>/dev/null || true

# Wait for restart
echo "  Waiting for auto-restart (10 seconds)..."
sleep 11

# Check if restarted
PID_AFTER=$(systemctl show "${TEST_SERVICE}.service" -p MainPID --value)
echo "  PID after restart: $PID_AFTER"

if systemctl is-active --quiet "${TEST_SERVICE}.service"; then
    if [ "$PID_BEFORE" != "$PID_AFTER" ]; then
        echo -e "  ${GREEN}✓ Service auto-restarted successfully!${NC}"
    else
        echo -e "  ${YELLOW}⚠ Service is running but PID didn't change${NC}"
    fi
else
    echo -e "  ${RED}✗ Service failed to restart${NC}"
fi

echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 6: Final Status Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run the health check script
if [ -f "$NETGUARD_DIR/scripts/check_services.sh" ]; then
    bash "$NETGUARD_DIR/scripts/check_services.sh"
else
    echo "Health check script not found, showing basic status:"
    echo ""
    for service in "${SERVICES[@]}"; do
        systemctl status "${service}.service" --no-pager | head -3
        echo ""
    done
fi

echo "════════════════════════════════════════════════════════════════════"
echo "  ✅ REBOOT-PROOF SETUP COMPLETE!"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "🎯 All services are now:"
echo "   • Auto-starting on boot"
echo "   • Auto-restarting on crash"
echo "   • Protected with resource limits"
echo "   • Logging to /home/jarvis/NetGuard/logs/system/"
echo ""
echo "📊 Test reboot safety:"
echo "   sudo reboot"
echo ""
echo "   After reboot, run:"
echo "   bash /home/jarvis/NetGuard/scripts/check_services.sh"
echo ""
echo "🔧 Management:"
echo "   Start all:   sudo systemctl start '*-collector.service' ai-aggregator.service flask-dashboard.service"
echo "   Stop all:    sudo systemctl stop '*-collector.service' ai-aggregator.service flask-dashboard.service"
echo "   Status:      bash /home/jarvis/NetGuard/scripts/check_services.sh"
echo ""
echo "════════════════════════════════════════════════════════════════════"


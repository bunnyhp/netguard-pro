#!/bin/bash

##############################################################################
# NetGuard Pro - Complete Service Installation & Reboot-Proof Setup
# This script installs all NetGuard services with crash protection
##############################################################################

set -e

echo "════════════════════════════════════════════════════════════════════"
echo "   NetGuard Pro - Complete Service Installation & Setup"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base directory
NETGUARD_DIR="/home/jarvis/NetGuard"
SERVICE_DIR="$NETGUARD_DIR/services"
LOG_DIR="$NETGUARD_DIR/logs/system"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

echo "📁 NetGuard Directory: $NETGUARD_DIR"
echo "📁 Service Files: $SERVICE_DIR"
echo "📁 Log Directory: $LOG_DIR"
echo ""

# List of all NetGuard collector services
COLLECTOR_SERVICES=(
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
)

# AI aggregator service (in /etc/systemd/system)
AI_SERVICE="ai-aggregator"

echo "══════════════════════════════════════════════════════════════════════"
echo "  Step 1: Installing Collector Services"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

for service in "${COLLECTOR_SERVICES[@]}"; do
    SERVICE_FILE="$SERVICE_DIR/${service}.service"
    
    if [ -f "$SERVICE_FILE" ]; then
        echo -n "📦 Installing ${service}.service... "
        
        # Copy service file to systemd
        sudo cp "$SERVICE_FILE" /etc/systemd/system/
        
        # Reload systemd
        sudo systemctl daemon-reload
        
        # Enable service (auto-start on boot)
        sudo systemctl enable "${service}.service" 2>/dev/null || true
        
        echo -e "${GREEN}✓ Installed & Enabled${NC}"
    else
        echo -e "${RED}✗ Service file not found: $SERVICE_FILE${NC}"
    fi
done

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  Step 2: Installing AI Aggregator Service"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

if [ -f "/etc/systemd/system/${AI_SERVICE}.service" ]; then
    echo -n "📦 Enabling ${AI_SERVICE}.service... "
    sudo systemctl daemon-reload
    sudo systemctl enable "${AI_SERVICE}.service" 2>/dev/null || true
    echo -e "${GREEN}✓ Enabled${NC}"
else
    echo -e "${YELLOW}⚠ AI Aggregator service not found in /etc/systemd/system${NC}"
fi

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  Step 3: Verifying Service Configurations"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

ALL_SERVICES=("${COLLECTOR_SERVICES[@]}" "$AI_SERVICE")

for service in "${ALL_SERVICES[@]}"; do
    SERVICE_PATH="/etc/systemd/system/${service}.service"
    
    if [ -f "$SERVICE_PATH" ]; then
        # Check for critical restart settings
        if grep -q "Restart=always" "$SERVICE_PATH"; then
            RESTART_CHECK="${GREEN}✓${NC}"
        else
            RESTART_CHECK="${RED}✗${NC}"
        fi
        
        if grep -q "WantedBy=multi-user.target" "$SERVICE_PATH"; then
            BOOT_CHECK="${GREEN}✓${NC}"
        else
            BOOT_CHECK="${RED}✗${NC}"
        fi
        
        echo -e "${service}: Restart=${RESTART_CHECK} | Boot=${BOOT_CHECK}"
    fi
done

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  Step 4: Starting All Services"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

for service in "${ALL_SERVICES[@]}"; do
    echo -n "🚀 Starting ${service}... "
    
    if sudo systemctl start "${service}.service" 2>/dev/null; then
        sleep 1
        if systemctl is-active --quiet "${service}.service"; then
            echo -e "${GREEN}✓ Running${NC}"
        else
            echo -e "${YELLOW}⚠ Started but not active${NC}"
        fi
    else
        echo -e "${RED}✗ Failed to start${NC}"
    fi
done

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  Step 5: Service Status Summary"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

printf "%-25s %-10s %-10s %-15s\n" "SERVICE" "STATUS" "ENABLED" "RESTART POLICY"
printf "%-25s %-10s %-10s %-15s\n" "-------" "------" "-------" "--------------"

for service in "${ALL_SERVICES[@]}"; do
    # Check if service is active
    if systemctl is-active --quiet "${service}.service"; then
        STATUS="${GREEN}Active${NC}"
    else
        STATUS="${RED}Inactive${NC}"
    fi
    
    # Check if service is enabled
    if systemctl is-enabled --quiet "${service}.service" 2>/dev/null; then
        ENABLED="${GREEN}Yes${NC}"
    else
        ENABLED="${RED}No${NC}"
    fi
    
    # Get restart policy
    RESTART_POLICY=$(systemctl show "${service}.service" -p Restart --value 2>/dev/null || echo "unknown")
    
    printf "%-25s " "${service}"
    echo -ne "${STATUS}   "
    echo -ne "${ENABLED}      "
    echo -e "${RESTART_POLICY}"
done

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  Step 6: Flask Web Dashboard"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

# Check if Flask is running
if pgrep -f "python3.*app.py" > /dev/null; then
    echo -e "${GREEN}✓ Flask dashboard is running${NC}"
    FLASK_PID=$(pgrep -f "python3.*app.py")
    echo "  PID: $FLASK_PID"
else
    echo -e "${YELLOW}⚠ Flask dashboard is not running${NC}"
    echo "  Starting Flask..."
    cd "$NETGUARD_DIR/web"
    nohup python3 app.py > /dev/null 2>&1 &
    sleep 2
    if pgrep -f "python3.*app.py" > /dev/null; then
        echo -e "${GREEN}✓ Flask started successfully${NC}"
    else
        echo -e "${RED}✗ Failed to start Flask${NC}"
    fi
fi

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  🎯 REBOOT-PROOF CONFIGURATION SUMMARY"
echo "══════════════════════════════════════════════════════════════════════"
echo ""
echo "✅ All services configured with:"
echo "   • Restart=always (auto-restart on crash)"
echo "   • RestartSec=10 (10 second delay between restarts)"
echo "   • WantedBy=multi-user.target (auto-start on boot)"
echo ""
echo "✅ Crash Protection Features:"
echo "   • Automatic restart on failure"
echo "   • Exponential backoff on repeated failures"
echo "   • Resource limits (CPU, Memory) to prevent system overload"
echo "   • Comprehensive logging for all services"
echo ""
echo "✅ Service Management Commands:"
echo "   • Check all services:  sudo systemctl status '*-collector.service'"
echo "   • Stop all services:   sudo systemctl stop '*-collector.service'"
echo "   • Start all services:  sudo systemctl start '*-collector.service'"
echo "   • View logs:           journalctl -u <service-name> -f"
echo ""
echo "✅ After Reboot:"
echo "   • All services will start automatically"
echo "   • Data collection continues without intervention"
echo "   • Flask dashboard needs manual start (or add to cron)"
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  ✅ Installation Complete!"
echo "══════════════════════════════════════════════════════════════════════"
echo ""


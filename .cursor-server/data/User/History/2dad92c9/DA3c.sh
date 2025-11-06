#!/bin/bash

echo "=========================================="
echo "NetGuard Pro - New Services Installation"
echo "=========================================="
echo ""

# Check if running as root or with sudo
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Service files
SERVICES=(
    "device-tracker"
    "unified-device-processor"
    "iot-security-scanner"
    "device-scorer"
    "enhanced-alert-system"
    "netguard-flask"
)

TIMERS=(
    "device-scorer"
)

echo "Step 1: Stopping old services (if running)..."
for service in "${SERVICES[@]}"; do
    $SUDO systemctl stop ${service}.service 2>/dev/null
    echo "  - Stopped ${service}.service (if was running)"
done

echo ""
echo "Step 2: Installing service files..."
for service in "${SERVICES[@]}"; do
    SOURCE="/home/jarvis/NetGuard/services/${service}.service"
    DEST="/etc/systemd/system/${service}.service"
    
    if [ -f "$SOURCE" ]; then
        $SUDO cp "$SOURCE" "$DEST"
        $SUDO chmod 644 "$DEST"
        echo -e "  ${GREEN}✓${NC} Installed ${service}.service"
    else
        echo -e "  ${RED}✗${NC} Missing: $SOURCE"
    fi
done

echo ""
echo "Step 3: Installing timer files..."
for timer in "${TIMERS[@]}"; do
    SOURCE="/home/jarvis/NetGuard/services/${timer}.timer"
    DEST="/etc/systemd/system/${timer}.timer"
    
    if [ -f "$SOURCE" ]; then
        $SUDO cp "$SOURCE" "$DEST"
        $SUDO chmod 644 "$DEST"
        echo -e "  ${GREEN}✓${NC} Installed ${timer}.timer"
    else
        echo -e "  ${RED}✗${NC} Missing: $SOURCE"
    fi
done

echo ""
echo "Step 4: Reloading systemd daemon..."
$SUDO systemctl daemon-reload
echo -e "  ${GREEN}✓${NC} Daemon reloaded"

echo ""
echo "Step 5: Enabling services (auto-start on boot)..."
for service in "${SERVICES[@]}"; do
    $SUDO systemctl enable ${service}.service
    echo -e "  ${GREEN}✓${NC} Enabled ${service}.service"
done

echo ""
echo "Step 6: Enabling timers..."
for timer in "${TIMERS[@]}"; do
    $SUDO systemctl enable ${timer}.timer
    echo -e "  ${GREEN}✓${NC} Enabled ${timer}.timer"
done

echo ""
echo "Step 7: Starting services..."
for service in "${SERVICES[@]}"; do
    $SUDO systemctl start ${service}.service
    sleep 1
    
    if $SUDO systemctl is-active --quiet ${service}.service; then
        echo -e "  ${GREEN}✓${NC} Started ${service}.service"
    else
        echo -e "  ${YELLOW}⚠${NC} ${service}.service failed to start (check logs)"
    fi
done

echo ""
echo "Step 8: Starting timers..."
for timer in "${TIMERS[@]}"; do
    $SUDO systemctl start ${timer}.timer
    sleep 1
    
    if $SUDO systemctl is-active --quiet ${timer}.timer; then
        echo -e "  ${GREEN}✓${NC} Started ${timer}.timer"
    else
        echo -e "  ${YELLOW}⚠${NC} ${timer}.timer failed to start"
    fi
done

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Service Status:"
for service in "${SERVICES[@]}"; do
    STATUS=$($SUDO systemctl is-active ${service}.service)
    if [ "$STATUS" = "active" ]; then
        echo -e "  ${GREEN}●${NC} ${service}.service - ${STATUS}"
    else
        echo -e "  ${RED}●${NC} ${service}.service - ${STATUS}"
    fi
done

echo ""
echo "Timer Status:"
for timer in "${TIMERS[@]}"; do
    STATUS=$($SUDO systemctl is-active ${timer}.timer)
    if [ "$STATUS" = "active" ]; then
        echo -e "  ${GREEN}●${NC} ${timer}.timer - ${STATUS}"
    else
        echo -e "  ${RED}●${NC} ${timer}.timer - ${STATUS}"
    fi
done

echo ""
echo "=========================================="
echo "Useful Commands:"
echo "=========================================="
echo ""
echo "Check service status:"
echo "  systemctl status <service-name>.service"
echo ""
echo "View logs:"
echo "  journalctl -u <service-name>.service -f"
echo ""
echo "Restart a service:"
echo "  sudo systemctl restart <service-name>.service"
echo ""
echo "Check all NetGuard services:"
echo "  systemctl list-units 'device-*' 'iot-*' 'netguard-*' 'unified-*' 'enhanced-*'"
echo ""
echo "Test reboot persistence:"
echo "  sudo reboot"
echo "  # After reboot, check: systemctl status netguard-flask.service"
echo ""


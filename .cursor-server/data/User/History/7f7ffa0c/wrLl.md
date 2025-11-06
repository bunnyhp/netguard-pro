# NetGuard Pro - Reboot & Crash Protection Guide

## 🛡️ Overview

All NetGuard services are configured with **industrial-grade reliability** features to ensure:
- ✅ Automatic start on system boot
- ✅ Automatic restart on crash/failure  
- ✅ Protection against repeated crashes
- ✅ Resource limits to prevent system overload
- ✅ Comprehensive logging for troubleshooting

---

## 📋 Protected Services

### Data Collection Services (10 tools)
1. **tshark-collector** - Packet analysis
2. **p0f-collector** - OS fingerprinting
3. **argus-collector** - Flow analysis
4. **ngrep-collector** - Pattern matching
5. **netsniff-collector** - Packet inspection
6. **httpry-collector** - HTTP logging
7. **iftop-collector** - Bandwidth monitoring
8. **nethogs-collector** - Process monitoring
9. **suricata-collector** - IDS/IPS
10. **tcpdump-collector** - Raw packet capture

### Analysis & Dashboard Services
11. **ai-aggregator** - AI data aggregation & analysis
12. **flask-dashboard** - Web interface

---

## 🔧 Crash Protection Features

### 1. Auto-Restart Configuration
Every service has these settings:

```ini
[Service]
Restart=always              # Always restart on failure
RestartSec=10              # Wait 10 seconds between restarts
StartLimitBurst=5          # Allow up to 5 rapid restarts
StartLimitIntervalSec=60   # Within 60 seconds
```

**What this means:**
- If a service crashes, it automatically restarts after 10 seconds
- If it crashes repeatedly (5 times in 60 seconds), systemd stops trying temporarily
- After the limit interval, systemd will try again
- This prevents infinite crash loops

### 2. Resource Limits
Each service is protected with:

```ini
MemoryMax=500M            # Maximum RAM usage
CPUQuota=50%              # Maximum CPU usage (50% of one core)
LimitNOFILE=65535         # Maximum open files
```

**Why this matters:**
- Prevents memory leaks from crashing the system
- Ensures fair CPU distribution
- Allows handling high packet rates

### 3. Boot-Time Activation

```ini
[Install]
WantedBy=multi-user.target
```

**What this does:**
- Services start automatically when system reaches multi-user mode (normal boot)
- No manual intervention needed after reboot

### 4. Network Dependency

```ini
[Unit]
After=network-online.target
Wants=network-online.target
```

**Why this matters:**
- Services wait for network interfaces to be ready
- Prevents failures due to missing network adapters

---

## 🚀 Installation & Setup

### Quick Setup (Automated)

```bash
# Make scripts executable
cd /home/jarvis/NetGuard/scripts
chmod +x install_all_services.sh check_services.sh reboot_test_setup.sh

# Run complete setup (installs, enables, and tests all services)
sudo bash reboot_test_setup.sh
```

This script will:
1. ✅ Install all 12 services
2. ✅ Enable boot-time auto-start
3. ✅ Verify crash protection settings
4. ✅ Start all services
5. ✅ Test auto-restart functionality
6. ✅ Display health report

---

## 📊 Monitoring & Management

### Check Service Health

```bash
# Comprehensive health check
bash /home/jarvis/NetGuard/scripts/check_services.sh
```

This shows:
- ✅ Which services are running
- ✅ Which are enabled for boot
- ✅ PIDs of running processes
- ✅ Recent failures (last 24h)
- ✅ Database status
- ✅ Web dashboard status
- ✅ Overall system health

### Manual Service Management

```bash
# Check status of a specific service
sudo systemctl status tshark-collector.service

# Start a service
sudo systemctl start tshark-collector.service

# Stop a service
sudo systemctl stop tshark-collector.service

# Restart a service
sudo systemctl restart tshark-collector.service

# View live logs
journalctl -u tshark-collector.service -f

# View last 50 log entries
journalctl -u tshark-collector.service -n 50
```

### Bulk Operations

```bash
# Start ALL collector services
sudo systemctl start '*-collector.service'

# Stop ALL collector services
sudo systemctl stop '*-collector.service'

# Restart ALL collector services
sudo systemctl restart '*-collector.service'

# Start everything (collectors + AI + dashboard)
sudo systemctl start '*-collector.service' ai-aggregator.service flask-dashboard.service
```

---

## 🧪 Testing Crash Protection

### Test 1: Manual Crash Simulation

```bash
# Find PID of a service
systemctl status tshark-collector.service | grep "Main PID"

# Kill it
sudo kill -9 <PID>

# Wait 10 seconds and check if it restarted
sleep 11
systemctl status tshark-collector.service
```

**Expected result:** Service should show a new PID and be "active (running)"

### Test 2: Automated Crash Test

```bash
# Run the reboot test script (includes crash test)
sudo bash /home/jarvis/NetGuard/scripts/reboot_test_setup.sh
```

### Test 3: Reboot Test

```bash
# Check all services are running
bash /home/jarvis/NetGuard/scripts/check_services.sh

# Reboot
sudo reboot

# After reboot, SSH back in and check again
bash /home/jarvis/NetGuard/scripts/check_services.sh
```

**Expected result:** All services should auto-start after reboot

---

## 📝 Log Files

### Systemd Journal Logs
```bash
# View all NetGuard service logs
journalctl -u '*-collector.service' -u ai-aggregator.service -u flask-dashboard.service -f
```

### Application Logs
Located in `/home/jarvis/NetGuard/logs/system/`:

- `tshark-service.log` / `tshark-service-error.log`
- `p0f-service.log` / `p0f-service-error.log`
- `tcpdump-service.log` / `tcpdump-service-error.log`
- `flask-dashboard.log` / `flask-dashboard-error.log`
- ... (one pair for each service)

```bash
# View logs
tail -f /home/jarvis/NetGuard/logs/system/tshark-service.log

# View errors
tail -f /home/jarvis/NetGuard/logs/system/tshark-service-error.log
```

---

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check detailed status
sudo systemctl status <service-name>.service

# Check full logs
journalctl -u <service-name>.service -n 100 --no-pager

# Check for permission errors
ls -la /home/jarvis/NetGuard/captures/<tool-name>/

# Fix permissions if needed
sudo chown -R jarvis:jarvis /home/jarvis/NetGuard/captures/
sudo chmod -R 755 /home/jarvis/NetGuard/captures/
```

### Service Keeps Crashing

```bash
# Check if hitting restart limit
systemctl show <service-name>.service -p NRestarts

# Reset failed state
sudo systemctl reset-failed <service-name>.service

# Check resource usage
systemctl show <service-name>.service -p MemoryCurrent -p CPUUsageNSec

# Check crash logs
journalctl -u <service-name>.service --since "1 hour ago" | grep -i error
```

### Service Not Auto-Starting on Boot

```bash
# Check if enabled
systemctl is-enabled <service-name>.service

# Enable if not
sudo systemctl enable <service-name>.service

# Check for dependency issues
systemctl list-dependencies <service-name>.service
```

---

## 🎯 Best Practices

### 1. Regular Health Checks
```bash
# Add to cron for hourly checks
crontab -e

# Add this line:
0 * * * * /bin/bash /home/jarvis/NetGuard/scripts/check_services.sh >> /home/jarvis/NetGuard/logs/health-checks.log 2>&1
```

### 2. Monitor Disk Space
```bash
# Services generate logs and capture files
# Check disk usage regularly
df -h /home/jarvis/NetGuard/

# Clean old captures if needed (older than 7 days)
find /home/jarvis/NetGuard/captures/ -type f -mtime +7 -delete
```

### 3. Database Maintenance
```bash
# Vacuum database monthly to optimize
sqlite3 /home/jarvis/NetGuard/db/netguard.db "VACUUM;"

# Check database size
du -h /home/jarvis/NetGuard/db/netguard.db
```

### 4. Update Service Files
If you modify a service file:
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Restart the service
sudo systemctl restart <service-name>.service
```

---

## 📋 Quick Reference Commands

| Task | Command |
|------|---------|
| Health check | `bash /home/jarvis/NetGuard/scripts/check_services.sh` |
| Start all | `sudo systemctl start '*-collector.service' ai-aggregator.service flask-dashboard.service` |
| Stop all | `sudo systemctl stop '*-collector.service' ai-aggregator.service flask-dashboard.service` |
| Restart all | `sudo systemctl restart '*-collector.service' ai-aggregator.service flask-dashboard.service` |
| View logs | `journalctl -u <service> -f` |
| Check status | `systemctl status <service>` |
| Enable boot | `sudo systemctl enable <service>` |
| Disable boot | `sudo systemctl disable <service>` |

---

## ✅ Verification Checklist

After setup, verify:

- [ ] All 12 services show as "active (running)"
- [ ] All 12 services show as "enabled" for boot
- [ ] Crash test passes (service auto-restarts)
- [ ] Flask dashboard accessible at http://localhost:8080
- [ ] Database file exists and is growing
- [ ] Log files are being written
- [ ] Reboot test passes (services auto-start)
- [ ] AI analysis cycles every 5 minutes
- [ ] No services hitting restart limits

Run: `bash /home/jarvis/NetGuard/scripts/check_services.sh` to verify all items.

---

## 🆘 Emergency Commands

### Stop Everything Immediately
```bash
sudo systemctl stop '*-collector.service' ai-aggregator.service flask-dashboard.service
```

### Prevent Auto-Start on Next Boot
```bash
sudo systemctl disable '*-collector.service' ai-aggregator.service flask-dashboard.service
```

### Re-Enable Everything
```bash
sudo systemctl enable '*-collector.service' ai-aggregator.service flask-dashboard.service
sudo systemctl start '*-collector.service' ai-aggregator.service flask-dashboard.service
```

---

## 📞 Support

If services continue to fail after following this guide:

1. Run the health check script and save output
2. Check service logs for errors
3. Verify network interfaces are up
4. Check disk space availability
5. Review systemd journal for system-level issues

```bash
# Generate diagnostic report
bash /home/jarvis/NetGuard/scripts/check_services.sh > /tmp/netguard-diagnostic.txt
journalctl --since "1 hour ago" >> /tmp/netguard-diagnostic.txt
df -h >> /tmp/netguard-diagnostic.txt
```

---

**Last Updated:** $(date)  
**Version:** NetGuard Pro v2.0  
**Status:** Production Ready


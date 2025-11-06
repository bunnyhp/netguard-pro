# 🔧 NetGuard Pro - Service Configuration

## ✅ Service Status

### **Active Services (2):**

1. **tshark-collector.service** - Enhanced Packet Capture
   - Status: ✅ **Running**
   - Auto-start: ✅ **Enabled**
   - Restart Policy: ✅ **Always** (auto-restart on crash)
   - User: root (required for packet capture)
   - Working Directory: /home/jarvis/NetGuard

2. **network-dashboard.service** - Web Interface
   - Status: ✅ **Running**
   - Auto-start: ✅ **Enabled**
   - Port: 8080
   - URL: http://192.168.1.161:8080

---

## 🛡️ Service Features

### **tshark-collector.service**

**Capabilities:**
- Captures packets for 5 minutes per cycle
- Analyzes 30+ fields per packet
- Detects 6 types of threats automatically
- GeoIP location tracking
- HTTP/DNS/TLS deep inspection
- Stores in SQLite database
- Runs continuously 24/7

**Reliability:**
- Auto-restart on crash (within 10 seconds)
- Memory limit: 500MB
- CPU limit: 50%
- Logs: `/home/jarvis/NetGuard/logs/system/tshark-service.log`
- Error logs: `/home/jarvis/NetGuard/logs/system/tshark-service-error.log`

**Crash Protection:**
```
If service crashes → Waits 10 seconds → Auto-restarts
If service fails 5 times in 30 seconds → Stops (prevents boot loop)
Manual restart: sudo systemctl restart tshark-collector.service
```

---

## 📋 Service Management Commands

### **Check Status:**
```bash
# Quick status
systemctl is-active tshark-collector.service

# Detailed status
systemctl status tshark-collector.service

# Check if enabled for auto-start
systemctl is-enabled tshark-collector.service
```

### **Start/Stop/Restart:**
```bash
# Start service
sudo systemctl start tshark-collector.service

# Stop service
sudo systemctl stop tshark-collector.service

# Restart service
sudo systemctl restart tshark-collector.service
```

### **View Logs:**
```bash
# View service logs
journalctl -u tshark-collector.service -f

# View last 100 lines
journalctl -u tshark-collector.service -n 100

# View collector logs
tail -f /home/jarvis/NetGuard/logs/system/tshark-service.log

# View errors only
tail -f /home/jarvis/NetGuard/logs/system/tshark-service-error.log
```

### **Enable/Disable Auto-start:**
```bash
# Enable auto-start on boot
sudo systemctl enable tshark-collector.service

# Disable auto-start
sudo systemctl disable tshark-collector.service
```

---

## 🔄 What Happens After Reboot

### **Automatic Startup Sequence:**

```
1. System Boots
   ↓
2. Network comes online (network-online.target)
   ↓
3. tshark-collector.service starts automatically
   ↓
4. network-dashboard.service starts automatically
   ↓
5. Both services run continuously
   ↓
6. If either crashes → Auto-restarts within 10 seconds
```

### **Service Dependencies:**
- **tshark-collector** requires network to be online
- **network-dashboard** can run independently
- Both are configured for automatic restart

---

## 🚨 Troubleshooting

### **If Service Fails to Start:**

```bash
# 1. Check service status
systemctl status tshark-collector.service

# 2. View recent errors
journalctl -u tshark-collector.service -n 50 --no-pager

# 3. Check if tshark is installed
which tshark

# 4. Check permissions
ls -la /home/jarvis/NetGuard/scripts/tshark_collector.py

# 5. Test manually
sudo python3 /home/jarvis/NetGuard/scripts/tshark_collector.py
```

### **If Service Keeps Crashing:**

```bash
# Check memory usage
systemctl show tshark-collector.service -p MemoryCurrent

# Check crash count
systemctl show tshark-collector.service -p NRestarts

# View detailed logs
journalctl -u tshark-collector.service --since "10 minutes ago"

# Check disk space
df -h /home/jarvis/NetGuard
```

### **Common Issues & Solutions:**

**Issue 1: Service won't start**
```bash
# Solution: Check if another tshark is running
sudo pkill -f tshark
sudo systemctl restart tshark-collector.service
```

**Issue 2: Permission denied**
```bash
# Solution: Ensure /home/jarvis has correct permissions
sudo chmod 755 /home/jarvis
sudo chmod -R 755 /home/jarvis/NetGuard/captures
```

**Issue 3: Database locked**
```bash
# Solution: Check if multiple processes accessing database
lsof /home/jarvis/NetGuard/network.db
```

---

## 📊 Service Monitoring

### **Health Checks:**

```bash
# 1. Is service running?
systemctl is-active tshark-collector.service

# 2. How many times has it restarted?
systemctl show tshark-collector.service -p NRestarts

# 3. How much memory is it using?
systemctl status tshark-collector.service | grep Memory

# 4. How long has it been running?
systemctl status tshark-collector.service | grep Active

# 5. Check last capture
ls -lt /home/jarvis/NetGuard/captures/tshark/*.pcap | head -1
```

### **Performance Metrics:**

```bash
# CPU and Memory usage
systemctl show tshark-collector.service -p CPUUsageNSec -p MemoryCurrent

# Restart count
systemctl show tshark-collector.service -p NRestarts

# Service uptime
systemctl show tshark-collector.service -p ActiveEnterTimestamp
```

---

## 🔐 Security Configuration

### **Service Runs as:**
- **User**: root (required for packet capture)
- **Group**: root
- **Working Directory**: /home/jarvis/NetGuard

### **Resource Limits:**
- **Memory Maximum**: 500MB
- **CPU Quota**: 50% (prevents CPU hogging)
- **File Descriptors**: 65,535 (plenty for network capture)

### **Security Policies:**
- Automatic restart on failure
- Isolated temporary directory
- Environment variables sanitized
- Python unbuffered output (real-time logs)

---

## 📝 Service File Location

**Service Definition:**
```
/etc/systemd/system/tshark-collector.service
```

**Source (for backup/editing):**
```
/home/jarvis/NetGuard/services/tshark-collector.service
```

**To Edit Service:**
```bash
# 1. Edit source file
nano /home/jarvis/NetGuard/services/tshark-collector.service

# 2. Copy to systemd
sudo cp /home/jarvis/NetGuard/services/tshark-collector.service /etc/systemd/system/

# 3. Reload systemd
sudo systemctl daemon-reload

# 4. Restart service
sudo systemctl restart tshark-collector.service
```

---

## 🎯 What's Protected Against Reboot

### **✅ Will Survive Reboot:**
1. tshark collector service (auto-starts)
2. Web dashboard service (auto-starts)
3. Database schema and data
4. Configuration files
5. Capture directories
6. Service logs

### **⚠️ Will Be Lost After Reboot:**
- Capture PCAP files in /captures/tshark/ (auto-cleaned)
- Temporary network connections
- Process IDs (will get new PIDs)

### **Recommended Before Reboot:**
```bash
# 1. Backup database
cp /home/jarvis/NetGuard/network.db /home/jarvis/NetGuard/network.db.backup

# 2. Check services are enabled
systemctl is-enabled tshark-collector.service network-dashboard.service

# 3. Archive important captures (optional)
tar -czf captures_backup_$(date +%Y%m%d).tar.gz captures/

# 4. Verify auto-start
systemctl list-unit-files | grep netguard
```

---

## 🚀 Quick Command Reference

```bash
# Start everything
sudo systemctl start tshark-collector.service network-dashboard.service

# Stop everything
sudo systemctl stop tshark-collector.service

# Restart tshark only
sudo systemctl restart tshark-collector.service

# View live logs
journalctl -u tshark-collector.service -f

# Check if will auto-start
systemctl list-unit-files | grep tshark

# Disable auto-start (if needed)
sudo systemctl disable tshark-collector.service
```

---

## ✅ Current Service Status Summary

**✓ tshark-collector.service**
- Status: **RUNNING** ✅
- Auto-start: **ENABLED** ✅  
- Restart Policy: **ALWAYS** ✅
- Capturing: Every 5 minutes ✅
- Enhanced Features: All 7 active ✅

**✓ network-dashboard.service**
- Status: **RUNNING** ✅
- Auto-start: **ENABLED** ✅
- Port: 8080 ✅
- Accessible: http://192.168.1.161:8080 ✅

**🎉 System is fully configured and will survive reboots!**

---

## 🔄 Reboot Safety Checklist

Before rebooting, verify:
- [ ] Services are **enabled**: `systemctl is-enabled tshark-collector.service`
- [ ] Database exists: `ls -lh /home/jarvis/NetGuard/network.db`
- [ ] Service files in place: `ls /etc/systemd/system/tshark-collector.service`
- [ ] Logs directory writable: `ls -ld /home/jarvis/NetGuard/logs`
- [ ] Captures directory exists: `ls -ld /home/jarvis/NetGuard/captures/tshark`

After reboot, verify:
- [ ] Check service started: `systemctl status tshark-collector.service`
- [ ] Check dashboard: `curl http://localhost:8080`
- [ ] Check data collecting: `ls /home/jarvis/NetGuard/captures/tshark/`
- [ ] View logs: `journalctl -u tshark-collector.service -n 20`

**DO NOT REBOOT until you've reviewed this checklist and confirmed you want to proceed!**

---

**Service is now production-ready and will survive reboots!** 🎉


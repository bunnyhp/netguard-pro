# NetGuard Pro - Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### Current Status ✓

All components are installed and ready:
- ✓ Database initialized (network.db)
- ✓ 15 Python scripts created
- ✓ 6 systemd services configured
- ✓ Flask web dashboard ready
- ✓ 9 HTML templates prepared
- ✓ Directory structure complete

---

## Step 1: Optimize Network Interfaces (1 minute)

```bash
cd NetGuard
sudo ./scripts/optimize_interfaces.sh
```

This will:
- Disable hardware offloading (GRO, LRO, TSO, GSO)
- Increase ring buffers to 4096
- Set CPU governor to performance mode
- Optimize kernel network parameters

---

## Step 2: Install & Enable Services (2 minutes)

```bash
# Copy service files to systemd
sudo cp services/*.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable services (start on boot)
sudo systemctl enable network-capture.service
sudo systemctl enable pcap-json-converter.service
sudo systemctl enable json-sqlite-converter.service
sudo systemctl enable suricata-collector.service
sudo systemctl enable analysis-tools-collector.service
sudo systemctl enable network-dashboard.service
```

---

## Step 3: Configure Sudo Access (1 minute)

Edit sudoers file:

```bash
sudo visudo
```

Add these lines at the end:

```
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/p0f
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/argus
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/ngrep
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/netsniff-ng
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/httpry
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/iftop
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/nethogs
YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/pkill
```
Replace `YOUR_USERNAME` with your actual username.

Save and exit (Ctrl+X, Y, Enter).

---

## Step 4: Start Services (1 minute)

```bash
# Start Suricata (if not already running)
sudo systemctl start suricata

# Start all NetGuard Pro services
sudo systemctl start network-capture.service
sudo systemctl start pcap-json-converter.service
sudo systemctl start json-sqlite-converter.service
sudo systemctl start suricata-collector.service
sudo systemctl start analysis-tools-collector.service
sudo systemctl start network-dashboard.service
```

---

## Step 5: Access Web Dashboard

Open your web browser and go to:

```
http://localhost:8080
```

Or from the local machine:

```
http://localhost:8080
```

You should see the NetGuard Pro dashboard!

---

## Verify Everything is Working

### Check Service Status

```bash
# Quick check all services
sudo systemctl status network-capture.service
sudo systemctl status analysis-tools-collector.service
sudo systemctl status network-dashboard.service
```

### Check Logs

```bash
# View real-time logs
tail -f logs/system/tcpdump.log
tail -f logs/system/analysis-tools.log
tail -f logs/system/dashboard-service.log
```

### Check Database Tables

```bash
# Wait 2-3 minutes for data collection, then check
sqlite3 network.db ".tables"
```

You should see tables being created like:
- `network_20251010_HHMMSS`
- `suricata_alerts_*`
- `tshark_*`, `p0f_*`, `argus_*`, etc.

---

## Common Issues & Quick Fixes

### Issue: Services fail to start

**Solution:**
```bash
# Check logs
sudo journalctl -u network-capture.service -n 50

# Verify script permissions
ls -la scripts/

# Re-apply execute permissions
chmod +x scripts/*.sh scripts/*.py
```

### Issue: Dashboard shows "No data"

**Solution:**
Wait 2-3 minutes for data collection to populate the database. Check if services are running:

```bash
sudo systemctl status network-capture.service
sudo systemctl status analysis-tools-collector.service
```

### Issue: Permission denied errors

**Solution:**
```bash
# Fix ownership (replace with your username)
sudo chown -R YOUR_USERNAME:YOUR_USERNAME NetGuard

# Verify sudoers configuration
sudo visudo -c
```

---

## Stop All Services

If you need to stop everything:

```bash
sudo systemctl stop network-capture.service
sudo systemctl stop pcap-json-converter.service
sudo systemctl stop json-sqlite-converter.service
sudo systemctl stop suricata-collector.service
sudo systemctl stop analysis-tools-collector.service
sudo systemctl stop network-dashboard.service
```

---

## Next Steps

1. **Explore the Dashboard**: Browse through tcpdump, Suricata, and Analysis Tools sections
2. **Monitor Alerts**: Check Suricata alerts for any security threats
3. **Review Traffic**: Analyze captured packets and flows
4. **Customize**: Adjust collection intervals in scripts if needed
5. **Read Full Documentation**: See README.md for advanced configuration

---

## Performance Tips

- **Disk Space**: Monitor disk usage with `df -h`
- **CPU Usage**: Check with `top` or `htop`
- **Memory**: Ensure at least 4GB RAM available
- **Network**: Should see minimal latency impact

---

## Support

For detailed information, troubleshooting, and advanced configuration, refer to:

- **README.md** - Complete documentation
- **Logs**: `NetGuard/logs/system/`
- **Database**: `NetGuard/network.db`

---

**Congratulations! NetGuard Pro is now running! 🎉**

Monitor your network with confidence. Stay secure! 🛡️


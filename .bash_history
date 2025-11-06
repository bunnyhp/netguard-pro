apt update
sudo su
ip a
apt update
ip s
ip a
l
ls
cdd //
apt update
sudo su
apt update
sudo su
. "\home\jarvis\.cursor-server\bin\fe5d1728063e86edeeda5bebd2c8e14bf4d0f960/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
. "\home\jarvis\.cursor-server\bin\df79b2380cd32922cad03529b0dc0c946c311850/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
sudo ip link set wlx1cbfce6265ad up
# Check if Suricata is running
sudo systemctl status suricata
# If not running, start it
sudo systemctl start suricata
sudo systemctl enable suricata
sudo systemctl status suricata
. "\home\jarvis\.cursor-server\bin\df79b2380cd32922cad03529b0dc0c946c311850/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
sudo visudo
# Step 1: Enable all services (already done - services copied and daemon reloaded)
sudo systemctl enable network-capture.service
sudo systemctl enable pcap-json-converter.service
sudo systemctl enable json-sqlite-converter.service
sudo systemctl enable suricata-collector.service
sudo systemctl enable analysis-tools-collector.service
sudo systemctl enable network-dashboard.service
# Step 2: Start all services
sudo systemctl start network-capture.service
sudo systemctl start pcap-json-converter.service
sudo systemctl start json-sqlite-converter.service
sudo systemctl start suricata-collector.service
sudo systemctl start analysis-tools-collector.service
sudo systemctl start network-dashboard.service
# Check if all services are active
systemctl is-active network-capture.service pcap-json-converter.service json-sqlite-converter.service suricata-collector.service analysis-tools-collector.service network-dashboard.service
systemctl status network-dashbord.service
service status network-dashbord.serviceplesudo systemctl status network-dashboard.service
sudo systemctl status network-dashboard.service
sudo journalctl -u network-dashboard.service -n 100 --no-pager
python3 -c "import flask; print('Flask installed')" 2>&1
pip3 install flask
# or
sudo pip3 install flask
pip3 install flask
python3 install flask
sudo pip3 install flask
sudo su
. "\home\jarvis\.cursor-server\bin\df79b2380cd32922cad03529b0dc0c946c311850/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
. "\home\jarvis\.cursor-server\bin\df79b2380cd32922cad03529b0dc0c946c311850/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
ip a
shutdown -h now
. "\home\jarvis\.cursor-server\bin\df79b2380cd32922cad03529b0dc0c946c311850/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
. "\home\jarvis\.cursor-server\bin\df79b2380cd32922cad03529b0dc0c946c311850/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
ip a
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
sudo su
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
python3 /home/jarvis/NetGuard/scripts/setup_api_keys.py
cd /home/jarvis/NetGuard
python3 scripts/ai_service_connector.py
cd /home/jarvis/NetGuard
python3 scripts/ai_connector_v2.py
sudo pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py
# Kill any running Flask
sudo pkill -9 -f "python3.*app.py"
# Wait a moment
sleep 2
# Start Flask fresh
cd /home/jarvis/NetGuard/web
python3 app.py
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
shutdown -h now
sudo shutdown -h now
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
ls
sudo su
python3 /home/jarvis/NetGuard/diagnose_p0f.py
sudo systemctl restart p0f-collector.service
sudo systemctl status p0f-collector.service
# Wait 30 seconds then check:
ls -lh /home/jarvis/NetGuard/captures/p0f/p0f.log
tail -f /home/jarvis/NetGuard/captures/p0f/p0f.log
sudo su
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
cd /home/jarvis/NetGuard && echo "========== AI RESPONSE ==========" && sqlite3 network.db "SELECT json(raw_response) FROM ai_analysis ORDER BY id DESC LIMIT 1;" | python3 -m json.tool
cd /home/jarvis/NetGuard
sqlite3 network.db <<'EOF' > last_ai_analysis.json
.mode json
.output last_ai_analysis.json
SELECT 
    id,
    timestamp,
    threat_level,
    network_health_score,
    summary,
    threats_detected,
    network_insights,
    device_analysis,
    http_analysis,
    recommendations,
    raw_response
FROM ai_analysis 
ORDER BY id DESC 
LIMIT 1;
.quit
EOF

# Then view it formatted
python3 -m json.tool last_ai_analysis.json
# 1. Restart Flask
bash /home/jarvis/NetGuard/scripts/restart_flask.sh
# 2. Verify template is fixed
bash /home/jarvis/NetGuard/scripts/verify_fixes.sh
# Kill Flask
pkill -9 -f "python3.*app.py"
# Start Flask
cd /home/jarvis/NetGuard/web && python3 app.py &
pkill -9 -f "python3.*app.py"
# Kill Flask
pkill -9 -f "python3.*app.py"
# Start Flask
cd /home/jarvis/NetGuard/web && python3 app.py &
# Kill Flask
pkill -9 -f "python3.*app.py"
# Start Flask
cd /home/jarvis/NetGuard/web && python3 app.py &
# 1. Stop any running Flask processes
pkill -9 -f "python3.*app.py"
# 2. Test the setup
cd /home/jarvis/NetGuard
python3 test_dashboard.py
# 3. Start Flask
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
# 4. Check it's running
sleep 3
curl -I http://localhost:8080
# Method 1: Use the new launcher
chmod +x /home/jarvis/NetGuard/START_DASHBOARD.sh
bash /home/jarvis/NetGuard/START_DASHBOARD.sh
# Method 2: Manual start
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
chmod +x /home/jarvis/NetGuard/FIX_ETHERTYPE_ALERTS.sh
bash /home/jarvis/NetGuard/FIX_ETHERTYPE_ALERTS.sh
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
chmod +x /home/jarvis/NetGuard/fix_all_collectors.sh
sudo bash /home/jarvis/NetGuard/fix_all_collectors.sh
chmod +x /home/jarvis/NetGuard/verify_collectors.sh
bash /home/jarvis/NetGuard/verify_collectors.sh
sudo bash /home/jarvis/NetGuard/fix_all_collectors.sh
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
pkill -9 -f "python3.*app.py"
cd /home/jarvis/NetGuard/web
python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
# 1. Make scripts executable
chmod +x /home/jarvis/NetGuard/check_p0f.sh
chmod +x /home/jarvis/NetGuard/restart_p0f.sh
# 2. Restart the p0f collector with new interface
sudo systemctl daemon-reload
sudo systemctl restart p0f-collector.service
# 3. Check status
bash /home/jarvis/NetGuard/check_p0f.sh
bash /home/jarvis/check_p0f_tool.sh
# Check if p0f tool is running
ps aux | grep "p0f -i"
# If not running, start it:
sudo p0f -i wlo1 -o /home/jarvis/NetGuard/captures/p0f/p0f.log -d -u root
systemctl status p0f
service status p0f
sudo su
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
cd /home/jarvis/thesis
nohup bash experiments/baseline_monitor.sh > logs/baseline.out 2>&1 &
tail -f logs/baseline_monitor.log
cd /home/jarvis/thesis
nohup bash experiments/baseline_monitor.sh > logs/baseline.out 2>&1 &
shutdown -h now
sudo shutdown -h now
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
. "\home\jarvis\.cursor-server\bin\9d178a4a5589981b62546448bb32920a8219a5d0/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
. "\home\jarvis\.cursor-server\bin\b9e5948c1ad20443a5cecba6b84a3c9b99d62580/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"
pkill -f "python3.*app.py" && sleep 2 && cd /home/jarvis/NetGuard/web && python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
service status ai-5min-aggregator
service status ai 5min aggregator
pkill -f "python3.*app.py" && sleep 2 && cd /home/jarvis/NetGuard/web && python3 app.py > /tmp/netguard_dashboard.log 2>&1 &
sudo pkill -f "python3.*app.py"
ps aux | grep "python3.*app.py" | grep -v grep
sudo su
sudo su
sudo du
sudo su
. "\home\jarvis\.cursor-server\bin\b9e5948c1ad20443a5cecba6b84a3c9b99d62580/out/vs/workbench/contrib/terminal/common/scripts/shellIntegration-bash.sh"

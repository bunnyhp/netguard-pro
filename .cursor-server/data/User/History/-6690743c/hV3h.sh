#!/bin/bash
#
# NetGuard Pro - tcpdump Capture Script
# Continuously captures network traffic on eno1 interface with 10-minute rotation
#

# Configuration
INTERFACE="eno1"
CAPTURE_DIR="/home/jarvis/NetGuard/captures/tcpdump"
BUFFER_SIZE=8192  # 8MB buffer
SNAPLEN=65535     # Full packet capture
ROTATION_SECONDS=600  # 10 minutes

# Create capture directory if it doesn't exist
mkdir -p "$CAPTURE_DIR"

# Log file
LOG_FILE="/home/jarvis/NetGuard/logs/system/tcpdump.log"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_message "Starting tcpdump capture on interface $INTERFACE"
log_message "Capture directory: $CAPTURE_DIR"
log_message "Rotation interval: ${ROTATION_SECONDS}s (10 minutes)"
log_message "Buffer size: ${BUFFER_SIZE} KB"

# Start tcpdump with rotation
# -i: interface
# -B: buffer size (KB)
# -s: snaplen (bytes to capture per packet)
# -w: output file
# -G: rotate file every N seconds
# -Z: drop privileges (run as specified user)
exec tcpdump -i "$INTERFACE" \
    -B "$BUFFER_SIZE" \
    -s "$SNAPLEN" \
    -w "$CAPTURE_DIR/capture_%Y%m%d_%H%M%S.pcap" \
    -G "$ROTATION_SECONDS" \
    -Z jarvis \
    2>&1 | tee -a "$LOG_FILE"


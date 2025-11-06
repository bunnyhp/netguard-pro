#!/usr/bin/env python3
"""
NetGuard Pro - PCAP to JSON Converter
Monitors tcpdump capture directory and converts PCAP files to JSON format
"""

import os
import json
import time
import subprocess
import logging
from datetime import datetime
from pathlib import Path

# Configuration
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/tcpdump"
JSON_DIR = "/home/jarvis/NetGuard/captures/processed_json"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/pcap-to-json.log"
PROCESSED_FILES = "/home/jarvis/NetGuard/logs/system/processed_pcaps.txt"
CHECK_INTERVAL = 10  # seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def load_processed_files():
    """Load list of already processed PCAP files"""
    if os.path.exists(PROCESSED_FILES):
        with open(PROCESSED_FILES, 'r') as f:
            return set(line.strip() for line in f)
    return set()

def mark_as_processed(filename):
    """Mark a file as processed"""
    with open(PROCESSED_FILES, 'a') as f:
        f.write(f"{filename}\n")

def convert_pcap_to_json(pcap_file):
    """Convert PCAP file to JSON using tshark"""
    try:
        # Extract timestamp from filename (capture_YYYYMMDD_HHMMSS.pcap)
        basename = os.path.basename(pcap_file)
        timestamp_str = basename.replace('capture_', '').replace('.pcap', '')
        
        # Output JSON file
        json_file = os.path.join(JSON_DIR, f"network_{timestamp_str}.json")
        
        logging.info(f"Converting {basename} to JSON...")
        
        # Use tshark to convert PCAP to JSON
        # -r: read from file
        # -T: output format (json)
        # -e: fields to extract
        cmd = [
            'tshark', '-r', pcap_file,
            '-T', 'json',
            '-e', 'frame.time',
            '-e', 'frame.number',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'ip.proto',
            '-e', 'frame.protocols',
            '-e', 'tcp.flags',
            '-e', 'ip.ttl'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0 and result.stdout:
            # Parse and simplify JSON
            packets = json.loads(result.stdout)
            simplified_packets = []
            
            for packet in packets:
                layers = packet.get('_source', {}).get('layers', {})
                
                # Extract fields
                src_ip = layers.get('ip.src', [''])[0] if 'ip.src' in layers else ''
                dst_ip = layers.get('ip.dst', [''])[0] if 'ip.dst' in layers else ''
                
                # Get port (try TCP first, then UDP)
                src_port = layers.get('tcp.srcport', layers.get('udp.srcport', ['']))[0]
                dst_port = layers.get('tcp.dstport', layers.get('udp.dstport', ['']))[0]
                
                # Convert port to int if available
                try:
                    src_port = int(src_port) if src_port else None
                except:
                    src_port = None
                    
                try:
                    dst_port = int(dst_port) if dst_port else None
                except:
                    dst_port = None
                
                # Determine protocol
                protocols = layers.get('frame.protocols', [''])[0]
                if 'tcp' in protocols.lower():
                    protocol = 'TCP'
                elif 'udp' in protocols.lower():
                    protocol = 'UDP'
                elif 'icmp' in protocols.lower():
                    protocol = 'ICMP'
                else:
                    protocol = layers.get('ip.proto', [''])[0]
                
                simplified = {
                    'timestamp': layers.get('frame.time', [''])[0],
                    'frame_number': layers.get('frame.number', [''])[0],
                    'source_ip': src_ip,
                    'source_port': src_port,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'protocol': protocol,
                    'packet_length': layers.get('frame.len', [''])[0],
                    'flags': layers.get('tcp.flags', [''])[0],
                    'ttl': layers.get('ip.ttl', [''])[0]
                }
                
                simplified_packets.append(simplified)
            
            # Write simplified JSON
            with open(json_file, 'w') as f:
                json.dump(simplified_packets, f, indent=2)
            
            logging.info(f"✓ Converted {basename} -> {os.path.basename(json_file)} ({len(simplified_packets)} packets)")
            return json_file
        else:
            logging.error(f"✗ tshark failed for {basename}: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        logging.error(f"✗ Timeout converting {pcap_file}")
        return None
    except Exception as e:
        logging.error(f"✗ Error converting {pcap_file}: {e}")
        return None

def monitor_and_convert():
    """Monitor capture directory and convert new PCAP files"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - PCAP to JSON Converter")
    logging.info("=" * 60)
    logging.info(f"Monitoring directory: {CAPTURE_DIR}")
    logging.info(f"JSON output directory: {JSON_DIR}")
    logging.info(f"Check interval: {CHECK_INTERVAL} seconds")
    logging.info("=" * 60)
    
    # Create directories if they don't exist
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(JSON_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Load processed files
    processed = load_processed_files()
    
    while True:
        try:
            # Get all PCAP files
            pcap_files = sorted(Path(CAPTURE_DIR).glob('capture_*.pcap'))
            
            for pcap_file in pcap_files:
                pcap_path = str(pcap_file)
                
                # Skip if already processed
                if pcap_path in processed:
                    continue
                
                # Check if file is still being written (older than 30 seconds)
                file_age = time.time() - os.path.getmtime(pcap_path)
                if file_age < 30:
                    logging.debug(f"Skipping {pcap_file.name} (still being written)")
                    continue
                
                # Convert to JSON
                json_file = convert_pcap_to_json(pcap_path)
                
                if json_file:
                    # Mark as processed
                    processed.add(pcap_path)
                    mark_as_processed(pcap_path)
            
            # Sleep before next check
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            logging.info("Shutting down PCAP to JSON converter...")
            break
        except Exception as e:
            logging.error(f"Error in monitor loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_and_convert()


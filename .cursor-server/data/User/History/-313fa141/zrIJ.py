#!/usr/bin/env python3
"""
NetGuard Pro - netsniff-ng Collector
High-performance packet capture using netsniff-ng
"""

import os
import subprocess
import sqlite3
import logging
import time
import json
from datetime import datetime
from pathlib import Path

# Configuration
INTERFACE = "wlo1"
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/netsniff"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/netsniff-collector.log"
COLLECT_INTERVAL = 30  # Process files every 30 seconds
PROCESSED_FILES = "/home/jarvis/NetGuard/logs/system/processed_netsniff.txt"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# netsniff-ng process handle
netsniff_process = None

def load_processed_files():
    """Load list of already processed files"""
    if os.path.exists(PROCESSED_FILES):
        with open(PROCESSED_FILES, 'r') as f:
            return set(line.strip() for line in f)
    return set()

def mark_as_processed(filename):
    """Mark a file as processed"""
    with open(PROCESSED_FILES, 'a') as f:
        f.write(f"{filename}\n")

def create_table(conn, table_name):
    """Create netsniff table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        protocol TEXT,
        packet_length INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def start_netsniff():
    """Start netsniff-ng process"""
    global netsniff_process
    
    try:
        logging.info(f"Starting netsniff-ng on {INTERFACE}...")
        
        # Start netsniff-ng
        # -i: input interface
        # --in: packet type (eth for Ethernet)
        # -o: output directory
        # -s: silent mode
        # -b: CPU affinity (bind to specific CPUs)
        # Note: netsniff-ng creates files automatically with timestamps
        
        # Create output prefix
        output_prefix = os.path.join(CAPTURE_DIR, "capture")
        
        # Note: netsniff-ng doesn't support --interval in all versions
        # We'll use a simpler approach and manually rotate
        # Create a specific output file (not directory)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
        
        netsniff_process = subprocess.Popen([
            'sudo', 'netsniff-ng',
            '-i', INTERFACE,
            '-o', output_file,
            '--silent'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(2)  # Give it time to start
        
        if netsniff_process.poll() is None:
            logging.info("✓ netsniff-ng started successfully")
            return True
        else:
            stderr_output = netsniff_process.stderr.read().decode('utf-8', errors='ignore')
            logging.error(f"✗ netsniff-ng failed to start: {stderr_output}")
            
            # Try alternative command without CPU binding
            logging.info("Trying netsniff-ng without CPU binding...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
            
            netsniff_process = subprocess.Popen([
                'sudo', 'netsniff-ng',
                '-i', INTERFACE,
                '-o', output_file,
                '--silent'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(2)
            
            if netsniff_process.poll() is None:
                logging.info("✓ netsniff-ng started successfully (without CPU binding)")
                return True
            else:
                logging.error("✗ netsniff-ng failed to start")
                return False
            
    except Exception as e:
        logging.error(f"Error starting netsniff-ng: {e}")
        return False

def process_pcap_file(pcap_file):
    """Process PCAP file and insert into database"""
    try:
        basename = os.path.basename(pcap_file)
        logging.info(f"Processing {basename}...")
        
        # Use tshark to read PCAP
        cmd = [
            'tshark', '-r', pcap_file,
            '-T', 'json',
            '-e', 'frame.time',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'frame.protocols'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0 or not result.stdout:
            logging.warning(f"No data in {basename}")
            return True  # Still mark as processed
        
        # Parse JSON
        packets = json.loads(result.stdout)
        
        if not packets:
            logging.warning(f"No packets parsed from {basename}")
            return True
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"netsniff_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert packets
        inserted = 0
        for packet in packets:
            try:
                layers = packet.get('_source', {}).get('layers', {})
                
                timestamp = layers.get('frame.time', [''])[0]
                length = layers.get('frame.len', [''])[0]
                src_ip = layers.get('ip.src', [''])[0]
                dest_ip = layers.get('ip.dst', [''])[0]
                protocols = layers.get('frame.protocols', [''])[0]
                
                # Get ports
                src_port = layers.get('tcp.srcport', layers.get('udp.srcport', ['']))[0]
                dest_port = layers.get('tcp.dstport', layers.get('udp.dstport', ['']))[0]
                
                # Convert to int
                try:
                    src_port = int(src_port) if src_port else None
                    dest_port = int(dest_port) if dest_port else None
                    length = int(length) if length else None
                except:
                    pass
                
                # Determine protocol
                if 'tcp' in protocols.lower():
                    protocol = 'TCP'
                elif 'udp' in protocols.lower():
                    protocol = 'UDP'
                elif 'icmp' in protocols.lower():
                    protocol = 'ICMP'
                else:
                    protocol = protocols.split(':')[-1] if protocols else 'Unknown'
                
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, src_ip, src_port, dest_ip, dest_port, protocol, packet_length)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, src_ip, src_port, dest_ip, dest_port, protocol, length))
                
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting packet: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logging.info(f"✓ Inserted {inserted} packets from {basename} into '{table_name}'")
        return True
        
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout processing {pcap_file}")
        return False
    except Exception as e:
        logging.error(f"Error processing {pcap_file}: {e}")
        return False

def collect_netsniff_data():
    """Collect and process netsniff-ng PCAP files"""
    try:
        processed = load_processed_files()
        
        # Find PCAP files
        pcap_files = sorted(Path(CAPTURE_DIR).glob('capture_*.pcap'))
        
        for pcap_file in pcap_files:
            pcap_path = str(pcap_file)
            
            # Skip if already processed
            if pcap_path in processed:
                continue
            
            # Check if file is old enough (not being written)
            file_age = time.time() - os.path.getmtime(pcap_path)
            if file_age < 30:
                logging.debug(f"Skipping {pcap_file.name} (still being written)")
                continue
            
            # Process file
            success = process_pcap_file(pcap_path)
            
            if success:
                processed.add(pcap_path)
                mark_as_processed(pcap_path)
                
                # Delete processed file to save space
                try:
                    os.remove(pcap_path)
                    logging.debug(f"Deleted processed file: {pcap_file.name}")
                except:
                    pass
        
    except Exception as e:
        logging.error(f"Error collecting netsniff data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - netsniff-ng Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Start netsniff-ng
    if not start_netsniff():
        logging.warning("Failed to start netsniff-ng. Will still process existing files.")
        # Don't exit - we can still process existing files
    
    try:
        while True:
            collect_netsniff_data()
            time.sleep(COLLECT_INTERVAL)
    except KeyboardInterrupt:
        logging.info("Shutting down netsniff-ng collector...")
        if netsniff_process:
            netsniff_process.terminate()
            netsniff_process.wait()
    except Exception as e:
        logging.error(f"Error in main loop: {e}")
        if netsniff_process:
            netsniff_process.terminate()

if __name__ == "__main__":
    main()


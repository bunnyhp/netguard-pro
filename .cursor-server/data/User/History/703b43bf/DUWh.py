#!/usr/bin/env python3
"""
NetGuard Pro - tshark Collector
Captures and analyzes WiFi traffic using tshark for protocol dissection
"""

import os
import subprocess
import sqlite3
import logging
import time
import json
from datetime import datetime

# Configuration
INTERFACE = "wlo1"
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/tshark"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/tshark-collector.log"
COLLECT_INTERVAL = 60  # Collect data every 60 seconds
CAPTURE_DURATION = 50  # Capture for 50 seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def create_table(conn, table_name):
    """Create tshark table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        frame_number INTEGER,
        frame_time TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        protocol TEXT,
        length INTEGER,
        info TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def capture_and_analyze():
    """Capture packets and analyze with tshark"""
    try:
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"tshark_{timestamp_str}"
        pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp_str}.pcap")
        
        logging.info(f"Capturing on {INTERFACE} for {CAPTURE_DURATION} seconds...")
        
        # Capture packets with tshark
        capture_cmd = [
            'sudo', 'tshark', '-i', INTERFACE,
            '-a', f'duration:{CAPTURE_DURATION}',
            '-w', pcap_file,
            '-q'  # Quiet mode
        ]
        
        result = subprocess.run(capture_cmd, capture_output=True, text=True, timeout=CAPTURE_DURATION + 10)
        
        if result.returncode != 0:
            logging.error(f"Capture failed: {result.stderr}")
            return
        
        # Analyze captured file
        logging.info(f"Analyzing captured packets...")
        
        analyze_cmd = [
            'sudo', 'tshark', '-r', pcap_file,
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'frame.protocols',
            '-e', 'frame.info'
        ]
        
        result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=120)
        
        if not result.stdout or result.stdout.strip() == "":
            logging.warning(f"No data captured - stdout empty. Stderr: {result.stderr[:200]}")
            return
        
        # Parse JSON output
        try:
            packets = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON: {e}. First 500 chars: {result.stdout[:500]}")
            return
        
        if not packets:
            logging.warning(f"No packets parsed")
            return
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert packets
        inserted = 0
        for packet in packets:
            try:
                layers = packet.get('_source', {}).get('layers', {})
                
                frame_number = layers.get('frame.number', [''])[0]
                frame_time = layers.get('frame.time', [''])[0]
                frame_len = layers.get('frame.len', [''])[0]
                src_ip = layers.get('ip.src', [''])[0]
                dest_ip = layers.get('ip.dst', [''])[0]
                protocols = layers.get('frame.protocols', [''])[0]
                info = layers.get('frame.info', [''])[0] if 'frame.info' in layers else ''
                
                # Get ports
                src_port = layers.get('tcp.srcport', layers.get('udp.srcport', ['']))[0]
                dest_port = layers.get('tcp.dstport', layers.get('udp.dstport', ['']))[0]
                
                # Convert to int
                try:
                    src_port = int(src_port) if src_port else None
                    dest_port = int(dest_port) if dest_port else None
                    frame_number = int(frame_number) if frame_number else None
                    frame_len = int(frame_len) if frame_len else None
                except:
                    pass
                
                # Determine main protocol
                if 'tcp' in protocols.lower():
                    protocol = 'TCP'
                elif 'udp' in protocols.lower():
                    protocol = 'UDP'
                elif 'icmp' in protocols.lower():
                    protocol = 'ICMP'
                elif 'arp' in protocols.lower():
                    protocol = 'ARP'
                else:
                    protocol = protocols.split(':')[-1] if protocols else 'Unknown'
                
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, frame_number, frame_time, src_ip, src_port, dest_ip, dest_port,
                     protocol, length, info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (datetime.now().isoformat(), frame_number, frame_time, src_ip, src_port,
                      dest_ip, dest_port, protocol, frame_len, info[:500]))  # Limit info to 500 chars
                
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting packet: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logging.info(f"✓ Inserted {inserted} packets into '{table_name}'")
        
        # Clean up PCAP file to save space
        try:
            os.remove(pcap_file)
        except:
            pass
            
    except subprocess.TimeoutExpired:
        logging.error("Capture timeout")
    except Exception as e:
        logging.error(f"Error in capture/analyze: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - tshark Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    while True:
        try:
            capture_and_analyze()
            time.sleep(COLLECT_INTERVAL)
        except KeyboardInterrupt:
            logging.info("Shutting down tshark collector...")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(COLLECT_INTERVAL)

if __name__ == "__main__":
    main()


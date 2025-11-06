#!/usr/bin/env python3
"""
NetGuard Pro - argus Collector
Network flow analysis using argus
"""

import os
import subprocess
import sqlite3
import logging
import time
import re
from datetime import datetime

# Configuration
INTERFACE = "eno1"  # Changed to Ethernet for better flow analysis
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/argus"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/argus-collector.log"
ARGUS_FILE = os.path.join(CAPTURE_DIR, "argus.out")
COLLECT_INTERVAL = 30  # Collect data every 30 seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# argus process handle
argus_process = None

def create_table(conn, table_name):
    """Create argus table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        start_time TEXT,
        last_time TEXT,
        duration REAL,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        proto TEXT,
        src_packets INTEGER,
        dest_packets INTEGER,
        src_bytes INTEGER,
        dest_bytes INTEGER,
        state TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def capture_and_analyze():
    """Capture with tshark, then analyze with argus (workaround for argus buffer overflow bug)"""
    try:
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp_str}.pcap")
        argus_output = os.path.join(CAPTURE_DIR, f"argus_{timestamp_str}.out")
        
        # Step 1: Capture packets with tshark (more stable than argus direct capture)
        logging.info(f"Capturing on {INTERFACE} for 30 seconds...")
        capture_cmd = [
            'sudo', 'tshark', '-i', INTERFACE,
            '-a', 'duration:30',
            '-w', pcap_file,
            '-q'
        ]
        
        result = subprocess.run(capture_cmd, capture_output=True, text=True, timeout=40)
        
        if result.returncode != 0 or not os.path.exists(pcap_file):
            logging.error(f"Capture failed: {result.stderr}")
            return False
        
        logging.info(f"Captured to {pcap_file}")
        
        # Step 2: Analyze PCAP with argus (reading from file works, live capture doesn't)
        logging.info(f"Analyzing with argus...")
        argus_cmd = [
            'sudo', 'argus',
            '-r', pcap_file,
            '-w', argus_output
        ]
        
        result = subprocess.run(argus_cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            logging.error(f"argus analysis failed: {result.stderr}")
            return False
        
        logging.info(f"✓ argus analysis complete: {argus_output}")
        
        # Clean up PCAP file
        try:
            os.remove(pcap_file)
        except:
            pass
        
        return True
            
    except Exception as e:
        logging.error(f"Error in capture_and_analyze: {e}")
        return False

def parse_ra_line(line):
    """Parse ra output line (argus client)"""
    try:
        # ra output format (columns):
        # StartTime Flgs Proto SrcAddr Sport Dir DstAddr Dport TotPkts TotBytes State
        parts = line.split()
        
        if len(parts) < 10:
            return None
        
        data = {}
        
        # Parse timestamp (first two columns are date and time)
        try:
            data['start_time'] = f"{parts[0]} {parts[1]}"
        except:
            data['start_time'] = ''
        
        idx = 2
        
        # Duration
        try:
            if parts[idx].replace('.', '').isdigit():
                data['duration'] = float(parts[idx])
                idx += 1
            else:
                data['duration'] = 0
        except:
            data['duration'] = 0
        
        # Protocol
        try:
            proto = parts[idx]
            if proto in ['tcp', 'udp', 'icmp', 'arp']:
                data['proto'] = proto.upper()
                idx += 1
            else:
                data['proto'] = 'OTHER'
        except:
            data['proto'] = 'UNKNOWN'
        
        # Source IP:Port
        try:
            src_parts = parts[idx].split(':')
            data['src_ip'] = src_parts[0] if len(src_parts) > 0 else ''
            data['src_port'] = int(src_parts[1]) if len(src_parts) > 1 and src_parts[1].isdigit() else None
            idx += 1
        except:
            data['src_ip'] = ''
            data['src_port'] = None
        
        # Direction (skip)
        idx += 1
        
        # Destination IP:Port
        try:
            dst_parts = parts[idx].split(':')
            data['dest_ip'] = dst_parts[0] if len(dst_parts) > 0 else ''
            data['dest_port'] = int(dst_parts[1]) if len(dst_parts) > 1 and dst_parts[1].isdigit() else None
            idx += 1
        except:
            data['dest_ip'] = ''
            data['dest_port'] = None
        
        # Packets (may be SrcPkts:DstPkts)
        try:
            if ':' in parts[idx]:
                pkts = parts[idx].split(':')
                data['src_packets'] = int(pkts[0]) if pkts[0].isdigit() else 0
                data['dest_packets'] = int(pkts[1]) if len(pkts) > 1 and pkts[1].isdigit() else 0
            else:
                data['src_packets'] = int(parts[idx]) if parts[idx].isdigit() else 0
                data['dest_packets'] = 0
            idx += 1
        except:
            data['src_packets'] = 0
            data['dest_packets'] = 0
        
        # Bytes (may be SrcBytes:DstBytes)
        try:
            if ':' in parts[idx]:
                bytes_data = parts[idx].split(':')
                data['src_bytes'] = int(bytes_data[0]) if bytes_data[0].isdigit() else 0
                data['dest_bytes'] = int(bytes_data[1]) if len(bytes_data) > 1 and bytes_data[1].isdigit() else 0
            else:
                data['src_bytes'] = int(parts[idx]) if parts[idx].isdigit() else 0
                data['dest_bytes'] = 0
            idx += 1
        except:
            data['src_bytes'] = 0
            data['dest_bytes'] = 0
        
        # State (remaining columns)
        try:
            data['state'] = ' '.join(parts[idx:]) if idx < len(parts) else ''
        except:
            data['state'] = ''
        
        return data
        
    except Exception as e:
        logging.debug(f"Error parsing ra line: {e}")
        return None

def collect_argus_data():
    """Collect data from argus using ra client"""
    try:
        if not os.path.exists(ARGUS_FILE):
            return
        
        # Use ra (argus client) to read argus data
        # -r: read from file
        # -n: no DNS resolution
        cmd = ['ra', '-r', ARGUS_FILE, '-n']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0 or not result.stdout:
            return
        
        lines = result.stdout.strip().split('\n')
        
        # Skip header lines
        data_lines = [line for line in lines if not line.startswith('StartTime') and line.strip()]
        
        if not data_lines:
            return
        
        # Parse flows
        flows = []
        for line in data_lines:
            parsed = parse_ra_line(line)
            if parsed:
                parsed['timestamp'] = datetime.now().isoformat()
                flows.append(parsed)
        
        if not flows:
            return
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"argus_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert flows
        inserted = 0
        for flow in flows:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, start_time, last_time, duration, src_ip, src_port, dest_ip, dest_port,
                     proto, src_packets, dest_packets, src_bytes, dest_bytes, state)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow.get('timestamp'),
                    flow.get('start_time', ''),
                    flow.get('last_time', ''),
                    flow.get('duration', 0),
                    flow.get('src_ip', ''),
                    flow.get('src_port'),
                    flow.get('dest_ip', ''),
                    flow.get('dest_port'),
                    flow.get('proto', ''),
                    flow.get('src_packets', 0),
                    flow.get('dest_packets', 0),
                    flow.get('src_bytes', 0),
                    flow.get('dest_bytes', 0),
                    flow.get('state', '')
                ))
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting flow: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if inserted > 0:
            logging.info(f"✓ Inserted {inserted} flows into '{table_name}'")
        
        # Clear argus file for next collection
        try:
            os.remove(ARGUS_FILE)
            # Restart argus to create new file
            if argus_process and argus_process.poll() is None:
                argus_process.terminate()
                argus_process.wait()
                time.sleep(1)
                start_argus()
        except:
            pass
            
    except subprocess.TimeoutExpired:
        logging.error("Timeout reading argus data")
    except Exception as e:
        logging.error(f"Error collecting argus data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - argus Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Use workaround: tshark capture + argus analysis
    logging.info("Using PCAP workaround for argus buffer overflow bug")
    
    try:
        while True:
            # Capture and analyze
            if capture_and_analyze():
                # Find the latest argus output file
                argus_files = sorted([f for f in os.listdir(CAPTURE_DIR) if f.startswith('argus_') and f.endswith('.out')])
                if argus_files:
                    latest_file = os.path.join(CAPTURE_DIR, argus_files[-1])
                    collect_argus_data(latest_file)
                    # Clean up
                    try:
                        os.remove(latest_file)
                    except:
                        pass
            
            time.sleep(COLLECT_INTERVAL)
            
    except KeyboardInterrupt:
        logging.info("Shutting down argus collector...")
    except Exception as e:
        logging.error(f"Error in main loop: {e}")

if __name__ == "__main__":
    main()


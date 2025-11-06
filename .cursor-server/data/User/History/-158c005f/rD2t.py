#!/usr/bin/env python3
"""
NetGuard Pro - httpry Collector
HTTP traffic logging and analysis
"""

import os
import subprocess
import sqlite3
import logging
import time
import re
from datetime import datetime

# Configuration
INTERFACE = "wlo1"  # WiFi for better HTTP traffic capture
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/httpry"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/httpry-collector.log"
HTTPRY_LOG = os.path.join(CAPTURE_DIR, "httpry.log")
COLLECT_INTERVAL = 30  # Check log every 30 seconds
POSITION_FILE = "/home/jarvis/NetGuard/logs/system/httpry_position.txt"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# httpry process handle
httpry_process = None

def get_last_position():
    """Get last read position in httpry log"""
    if os.path.exists(POSITION_FILE):
        try:
            with open(POSITION_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            return 0
    return 0

def save_position(position):
    """Save current read position"""
    with open(POSITION_FILE, 'w') as f:
        f.write(str(position))

def create_table(conn, table_name):
    """Create httpry table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dest_ip TEXT,
        direction TEXT,
        method TEXT,
        host TEXT,
        request_uri TEXT,
        http_version TEXT,
        status_code INTEGER,
        reason_phrase TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def start_httpry():
    """Start httpry process"""
    global httpry_process
    
    try:
        # Clear old log and reset position
        if os.path.exists(HTTPRY_LOG):
            os.remove(HTTPRY_LOG)
        save_position(0)  # Reset position since we're starting fresh
        
        logging.info(f"Starting httpry on {INTERFACE}...")
        
        # Start httpry
        # -i: interface
        # -o: output file
        # -d: daemon mode
        # -b: disable buffering
        httpry_process = subprocess.Popen([
            'sudo', 'httpry',
            '-i', INTERFACE,
            '-o', HTTPRY_LOG,
            '-d',
            '-b'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(2)  # Give it time to start
        
        # httpry daemon detaches, so we can't check poll()
        # Check if log file was created
        time.sleep(2)
        if os.path.exists(HTTPRY_LOG):
            logging.info("✓ httpry started successfully")
            return True
        else:
            logging.error("✗ httpry failed to start (no log file created)")
            return False
            
    except Exception as e:
        logging.error(f"Error starting httpry: {e}")
        return False

def parse_httpry_line(line):
    """Parse httpry log line"""
    try:
        # httpry log format (tab-separated):
        # timestamp  src_ip  dest_ip  direction  method  host  request_uri  http_version  status_code  reason_phrase
        
        parts = line.split('\t')
        
        if len(parts) < 5:
            return None
        
        data = {
            'timestamp': parts[0].strip() if len(parts) > 0 else '',
            'src_ip': parts[1].strip() if len(parts) > 1 else '',
            'dest_ip': parts[2].strip() if len(parts) > 2 else '',
            'direction': parts[3].strip() if len(parts) > 3 else '',
            'method': parts[4].strip() if len(parts) > 4 else '',
            'host': parts[5].strip() if len(parts) > 5 else '',
            'request_uri': parts[6].strip() if len(parts) > 6 else '',
            'http_version': parts[7].strip() if len(parts) > 7 else '',
            'status_code': None,
            'reason_phrase': ''
        }
        
        # Parse status code if present
        if len(parts) > 8 and parts[8].strip().isdigit():
            data['status_code'] = int(parts[8].strip())
        
        # Parse reason phrase
        if len(parts) > 9:
            data['reason_phrase'] = parts[9].strip()
        
        return data
        
    except Exception as e:
        logging.debug(f"Error parsing httpry line: {e}")
        return None

def collect_httpry_data():
    """Collect data from httpry log"""
    try:
        if not os.path.exists(HTTPRY_LOG):
            return
        
        # Get last position
        last_pos = get_last_position()
        
        # Read new data
        with open(HTTPRY_LOG, 'r', errors='ignore') as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            new_pos = f.tell()
        
        if not new_lines:
            return
        
        # Parse entries
        entries = []
        for line in new_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parsed = parse_httpry_line(line)
            if parsed and parsed['src_ip']:  # Only if we have valid data
                entries.append(parsed)
        
        if not entries:
            save_position(new_pos)
            return
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"httpry_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert entries
        inserted = 0
        for entry in entries:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, src_ip, dest_ip, direction, method, host, request_uri,
                     http_version, status_code, reason_phrase)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.get('timestamp'),
                    entry.get('src_ip', ''),
                    entry.get('dest_ip', ''),
                    entry.get('direction', ''),
                    entry.get('method', ''),
                    entry.get('host', ''),
                    entry.get('request_uri', ''),
                    entry.get('http_version', ''),
                    entry.get('status_code'),
                    entry.get('reason_phrase', '')
                ))
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting entry: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if inserted > 0:
            logging.info(f"✓ Inserted {inserted} HTTP requests into '{table_name}'")
        
        # Save position
        save_position(new_pos)
        
    except Exception as e:
        logging.error(f"Error collecting httpry data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - httpry Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Start httpry
    if not start_httpry():
        logging.error("Failed to start httpry. Exiting.")
        return
    
    try:
        while True:
            collect_httpry_data()
            time.sleep(COLLECT_INTERVAL)
    except KeyboardInterrupt:
        logging.info("Shutting down httpry collector...")
        # httpry runs as daemon, kill it
        try:
            subprocess.run(['sudo', 'pkill', 'httpry'], check=False)
        except:
            pass
    except Exception as e:
        logging.error(f"Error in main loop: {e}")

if __name__ == "__main__":
    main()


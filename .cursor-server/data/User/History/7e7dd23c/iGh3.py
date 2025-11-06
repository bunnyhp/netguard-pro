#!/usr/bin/env python3
"""
NetGuard Pro - p0f Collector
Passive OS fingerprinting using p0f
"""

import os
import subprocess
import sqlite3
import logging
import time
import re
from datetime import datetime

# Configuration
INTERFACE = "wlo1"  # WiFi interface
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/p0f"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/p0f-collector.log"
P0F_LOG = os.path.join(CAPTURE_DIR, "p0f.log")
COLLECT_INTERVAL = 300  # Check log every 30 seconds
POSITION_FILE = "/home/jarvis/NetGuard/logs/system/p0f_position.txt"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# p0f process handle
p0f_process = None

def get_last_position():
    """Get last read position in p0f log"""
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
    """Create p0f table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        os_name TEXT,
        os_flavor TEXT,
        os_version TEXT,
        http_name TEXT,
        http_flavor TEXT,
        link_type TEXT,
        distance INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def start_p0f():
    """Start p0f process"""
    global p0f_process
    
    try:
        # Clear old log
        if os.path.exists(P0F_LOG):
            os.remove(P0F_LOG)
        
        logging.info(f"Starting p0f on {INTERFACE}...")
        
        # Start p0f in background
        # -i: interface
        # -o: output file
        # -p: promiscuous mode
        # -d: daemon mode
        p0f_process = subprocess.Popen([
            'sudo', 'p0f',
            '-i', INTERFACE,
            '-o', P0F_LOG,
            '-p'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(2)  # Give it time to start
        
        if p0f_process.poll() is None:
            logging.info("✓ p0f started successfully")
            return True
        else:
            logging.error("✗ p0f failed to start")
            return False
            
    except Exception as e:
        logging.error(f"Error starting p0f: {e}")
        return False

def parse_p0f_line(line):
    """Parse a p0f log line"""
    try:
        # p0f log format (example):
        # .-[ 192.168.1.100/12345 -> 192.168.1.1/80 (syn) ]-
        # | os   = Linux 3.x
        # | dist = 0
        # | link = Ethernet or modem
        
        data = {}
        
        # Extract connection info from first line
        if '.-[' in line and '->' in line:
            # Extract IPs and ports
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)/(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if match:
                data['src_ip'] = match.group(1)
                data['src_port'] = int(match.group(2))
                data['dest_ip'] = match.group(3)
                data['dest_port'] = int(match.group(4))
        
        # Extract OS info
        if '| os' in line:
            match = re.search(r'\|\s*os\s*=\s*(.+)', line)
            if match:
                os_full = match.group(1).strip()
                parts = os_full.split()
                data['os_name'] = parts[0] if len(parts) > 0 else ''
                data['os_version'] = ' '.join(parts[1:]) if len(parts) > 1 else ''
        
        # Extract distance
        if '| dist' in line:
            match = re.search(r'\|\s*dist\s*=\s*(\d+)', line)
            if match:
                data['distance'] = int(match.group(1))
        
        # Extract link type
        if '| link' in line:
            match = re.search(r'\|\s*link\s*=\s*(.+)', line)
            if match:
                data['link_type'] = match.group(1).strip()
        
        return data
        
    except Exception as e:
        logging.debug(f"Error parsing p0f line: {e}")
        return {}

def collect_p0f_data():
    """Collect data from p0f log"""
    try:
        if not os.path.exists(P0F_LOG):
            logging.debug("p0f log file doesn't exist yet")
            return
        
        # Get last position
        last_pos = get_last_position()
        
        # Read new data
        with open(P0F_LOG, 'r', errors='ignore') as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            new_pos = f.tell()
        
        logging.info(f"Read {len(new_lines)} new lines from position {last_pos}")
        
        if not new_lines:
            return
        
        # Parse entries: Group by connection (cli+srv+timestamp)
        # p0f creates multiple entries per connection with different mod types
        connection_data = {}
        
        for line in new_lines:
            line = line.strip()
            if not line or not line.startswith('['):
                continue
            
            # Extract timestamp [2025/10/11 02:41:49]
            timestamp_match = re.search(r'\[([^\]]+)\]', line)
            timestamp = timestamp_match.group(1) if timestamp_match else ''
            
            # Extract client IP and port: cli=IP/PORT
            cli_match = re.search(r'cli=([^/|]+)/(\d+)', line)
            if not cli_match:
                continue
            
            src_ip = cli_match.group(1)
            src_port = int(cli_match.group(2))
            
            # Extract server IP and port: srv=IP/PORT
            srv_match = re.search(r'srv=([^/|]+)/(\d+)', line)
            if not srv_match:
                continue
            
            dest_ip = srv_match.group(1)
            dest_port = int(srv_match.group(2))
            
            # Create connection key
            conn_key = f"{src_ip}:{src_port}->{dest_ip}:{dest_port}@{timestamp}"
            
            # Initialize connection data if not exists
            if conn_key not in connection_data:
                connection_data[conn_key] = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                }
            
            # Extract subject (cli or srv) to know which side we're analyzing
            subj_match = re.search(r'subj=(cli|srv)', line)
            subject = subj_match.group(1) if subj_match else 'cli'
            
            # Extract OS info: os=NAME (only for mod=syn or mod=syn+ack)
            if 'mod=syn|' in line or 'mod=syn+ack|' in line:
                os_match = re.search(r'os=([^|]+)', line)
                if os_match:
                    os_info = os_match.group(1).strip()
                    if os_info and os_info != '???':
                        # Parse OS name and version
                        os_parts = os_info.split()
                        if subject == 'cli':
                            connection_data[conn_key]['os_name'] = ' '.join(os_parts[:3]) if len(os_parts) >= 3 else os_info
                            connection_data[conn_key]['os_flavor'] = os_parts[0] if os_parts else ''
                            connection_data[conn_key]['os_version'] = ' '.join(os_parts[1:]) if len(os_parts) > 1 else ''
            
            # Extract distance: dist=NUM
            dist_match = re.search(r'dist=(\d+)', line)
            if dist_match:
                connection_data[conn_key]['distance'] = int(dist_match.group(1))
            
            # Extract link type: link=TYPE (from mod=mtu lines)
            if 'mod=mtu|' in line:
                link_match = re.search(r'link=([^|]+)', line)
                if link_match:
                    connection_data[conn_key]['link_type'] = link_match.group(1).strip()
            
            # Extract HTTP app info (from mod=http lines)
            if 'mod=http' in line:
                app_match = re.search(r'app=([^|]+)', line)
                if app_match:
                    app_info = app_match.group(1).strip()
                    if app_info and app_info != '???':
                        if subject == 'srv':
                            connection_data[conn_key]['http_name'] = app_info
                        elif subject == 'cli':
                            connection_data[conn_key]['http_flavor'] = app_info
        
        # Convert to list of entries
        entries = list(connection_data.values())
        
        if not entries:
            save_position(new_pos)
            return
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"p0f_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert entries
        inserted = 0
        for entry in entries:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, src_ip, src_port, dest_ip, dest_port, os_name, os_flavor,
                     os_version, http_name, http_flavor, link_type, distance)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.get('timestamp'),
                    entry.get('src_ip', ''),
                    entry.get('src_port'),
                    entry.get('dest_ip', ''),
                    entry.get('dest_port'),
                    entry.get('os_name', ''),
                    entry.get('os_flavor', ''),
                    entry.get('os_version', ''),
                    entry.get('http_name', ''),
                    entry.get('http_flavor', ''),
                    entry.get('link_type', ''),
                    entry.get('distance')
                ))
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting entry: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if inserted > 0:
            logging.info(f"✓ Inserted {inserted} fingerprints into '{table_name}'")
        
        # Save position
        save_position(new_pos)
        
    except Exception as e:
        logging.error(f"Error collecting p0f data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - p0f Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Start p0f
    if not start_p0f():
        logging.error("Failed to start p0f. Exiting.")
        return
    
    try:
        while True:
            collect_p0f_data()
            time.sleep(COLLECT_INTERVAL)
    except KeyboardInterrupt:
        logging.info("Shutting down p0f collector...")
        if p0f_process:
            p0f_process.terminate()
            p0f_process.wait()
    except Exception as e:
        logging.error(f"Error in main loop: {e}")
        if p0f_process:
            p0f_process.terminate()

if __name__ == "__main__":
    main()


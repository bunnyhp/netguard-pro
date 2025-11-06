#!/usr/bin/env python3
"""
NetGuard Pro - ngrep Collector
Pattern matching and content inspection using ngrep
"""

import os
import subprocess
import sqlite3
import logging
import time
import re
from datetime import datetime

# Configuration
INTERFACE = "wlo1"
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/ngrep"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/ngrep-collector.log"
NGREP_LOG = os.path.join(CAPTURE_DIR, "ngrep.log")
COLLECT_INTERVAL = 30  # Check log every 30 seconds
POSITION_FILE = "/home/jarvis/NetGuard/logs/system/ngrep_position.txt"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# ngrep process handle
ngrep_process = None

def get_last_position():
    """Get last read position in ngrep log"""
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
    """Create ngrep table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        interface TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        protocol TEXT,
        matched_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def start_ngrep():
    """Start ngrep process"""
    global ngrep_process
    
    try:
        # Clear old log
        if os.path.exists(NGREP_LOG):
            os.remove(NGREP_LOG)
        
        logging.info(f"Starting ngrep on {INTERFACE}...")
        
        # Start ngrep with output to file
        # -d: interface
        # -W: byline output (makes output more readable)
        # -t: print timestamp
        # -q: quiet (don't print # progress)
        # Pattern: Match GET, POST, password, pwd, login, user
        
        log_fd = open(NGREP_LOG, 'w')
        
        # Note: ngrep pattern must be a single argument with proper regex
        # Using empty pattern and tcp filter to capture all TCP, then filter in parser
        ngrep_process = subprocess.Popen([
            'sudo', 'ngrep',
            '-d', INTERFACE,
            '-W', 'byline',
            '-t',
            '',  # Empty pattern = match all
            'tcp port 80 or tcp port 443 or tcp port 8080'
        ], stdout=log_fd, stderr=subprocess.PIPE)
        
        time.sleep(2)  # Give it time to start
        
        if ngrep_process.poll() is None:
            logging.info("✓ ngrep started successfully")
            return True
        else:
            stderr_output = ngrep_process.stderr.read().decode('utf-8', errors='ignore')
            logging.error(f"✗ ngrep failed to start: {stderr_output}")
            log_fd.close()
            return False
            
    except Exception as e:
        logging.error(f"Error starting ngrep: {e}")
        return False

def parse_ngrep_entry(lines):
    """Parse ngrep log entry (multiple lines)
    Format: T 2025/10/11 04:04:28.179202 192.168.1.100:59780 -> 93.184.216.34:80 [AP] #4
    """
    try:
        data = {
            'timestamp': datetime.now().isoformat(),
            'interface': INTERFACE,
            'matched_data': ''
        }
        
        for line in lines:
            # Skip interface/filter info lines
            if line.startswith('interface:') or line.startswith('filter:') or line.startswith('match') or line.startswith('####'):
                continue
            
            # Parse connection line: T 2025/10/11 04:04:28.179202 192.168.1.100:59780 -> 93.184.216.34:80 [AP]
            if '->' in line and (line.startswith('T ') or line.startswith('U ')):
                # Extract protocol
                if line.startswith('T'):
                    data['protocol'] = 'TCP'
                elif line.startswith('U'):
                    data['protocol'] = 'UDP'
                else:
                    data['protocol'] = 'OTHER'
                
                # Try IPv4 format first
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if match:
                    data['src_ip'] = match.group(1)
                    data['src_port'] = int(match.group(2))
                    data['dest_ip'] = match.group(3)
                    data['dest_port'] = int(match.group(4))
                else:
                    # Try IPv6 format (simplified - just skip for now)
                    continue
            
            # Collect matched data (lines after the T/U line)
            elif line.strip() and not line.startswith('T ') and not line.startswith('U '):
                data['matched_data'] += line.strip() + ' '
        
        # Only return if we have valid IP addresses
        if 'src_ip' in data and data['src_ip']:
            data['matched_data'] = data['matched_data'].strip()[:1000]  # Limit to 1000 chars
            return data
        
        return None
        
    except Exception as e:
        logging.debug(f"Error parsing ngrep entry: {e}")
        return None

def collect_ngrep_data():
    """Collect data from ngrep log"""
    try:
        if not os.path.exists(NGREP_LOG):
            return
        
        # Get last position
        last_pos = get_last_position()
        
        # Read new data
        with open(NGREP_LOG, 'r', errors='ignore') as f:
            f.seek(last_pos)
            new_lines = f.readlines()
            new_pos = f.tell()
        
        if not new_lines:
            return
        
        # Parse entries (they span multiple lines, separated by blank lines)
        entries = []
        current_entry_lines = []
        
        for line in new_lines:
            if line.strip() == '':
                # End of entry
                if current_entry_lines:
                    parsed = parse_ngrep_entry(current_entry_lines)
                    if parsed:
                        entries.append(parsed)
                    current_entry_lines = []
            else:
                current_entry_lines.append(line)
        
        # Process last entry if exists
        if current_entry_lines:
            parsed = parse_ngrep_entry(current_entry_lines)
            if parsed:
                entries.append(parsed)
        
        if not entries:
            save_position(new_pos)
            return
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"ngrep_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert entries
        inserted = 0
        for entry in entries:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, interface, src_ip, src_port, dest_ip, dest_port, protocol, matched_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.get('timestamp'),
                    entry.get('interface', ''),
                    entry.get('src_ip', ''),
                    entry.get('src_port'),
                    entry.get('dest_ip', ''),
                    entry.get('dest_port'),
                    entry.get('protocol', ''),
                    entry.get('matched_data', '')
                ))
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting entry: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if inserted > 0:
            logging.info(f"✓ Inserted {inserted} matches into '{table_name}'")
        
        # Save position
        save_position(new_pos)
        
    except Exception as e:
        logging.error(f"Error collecting ngrep data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - ngrep Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("Patterns: GET, POST, password, pwd, login, user")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Start ngrep
    if not start_ngrep():
        logging.error("Failed to start ngrep. Exiting.")
        return
    
    try:
        while True:
            collect_ngrep_data()
            time.sleep(COLLECT_INTERVAL)
    except KeyboardInterrupt:
        logging.info("Shutting down ngrep collector...")
        if ngrep_process:
            ngrep_process.terminate()
            ngrep_process.wait()
    except Exception as e:
        logging.error(f"Error in main loop: {e}")
        if ngrep_process:
            ngrep_process.terminate()

if __name__ == "__main__":
    main()


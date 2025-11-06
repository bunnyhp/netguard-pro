#!/usr/bin/env python3
"""
NetGuard Pro - nethogs Collector
Per-process network bandwidth monitoring
"""

import os
import subprocess
import sqlite3
import logging
import time
import re
from datetime import datetime

# Configuration
INTERFACE = "wlo1"  # WiFi for better process monitoring
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/nethogs"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/nethogs-collector.log"
COLLECT_INTERVAL = 30  # Collect every 30 seconds
CAPTURE_DURATION = 10  # Capture for 10 seconds

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
    """Create nethogs table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        program TEXT,
        pid INTEGER,
        user TEXT,
        sent_kb REAL,
        received_kb REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def parse_nethogs_line(line):
    """Parse nethogs trace mode output line"""
    try:
        # nethogs trace mode format (tab-separated):
        # /full/path/to/program/pid  sent_kb  received_kb
        # or: program/pid  sent_kb  received_kb
        
        parts = line.split('\t')
        
        if len(parts) < 3:
            # Try space-separated
            parts = line.split()
        
        if len(parts) < 3:
            return None
        
        data = {}
        
        # Parse program/PID
        prog_pid = parts[0].strip()
        
        # Extract PID (usually last number after /)
        pid_match = re.search(r'/(\d+)$', prog_pid)
        if pid_match:
            data['pid'] = int(pid_match.group(1))
            # Get program name (everything before /PID)
            data['program'] = prog_pid[:pid_match.start()]
        else:
            # Try to parse differently
            pid_parts = prog_pid.split('/')
            if pid_parts[-1].isdigit():
                data['pid'] = int(pid_parts[-1])
                data['program'] = '/'.join(pid_parts[:-1])
            else:
                data['program'] = prog_pid
                data['pid'] = None
        
        # Clean up program name (remove leading slashes, get basename)
        if data['program']:
            program_parts = data['program'].split('/')
            data['program'] = program_parts[-1] if program_parts[-1] else data['program']
        
        # Parse sent KB
        try:
            sent = parts[1].strip()
            data['sent_kb'] = float(sent) if sent and sent != '?' else 0.0
        except:
            data['sent_kb'] = 0.0
        
        # Parse received KB
        try:
            received = parts[2].strip()
            data['received_kb'] = float(received) if received and received != '?' else 0.0
        except:
            data['received_kb'] = 0.0
        
        # User (if available in parts[3])
        if len(parts) > 3:
            data['user'] = parts[3].strip()
        else:
            data['user'] = ''
        
        data['timestamp'] = datetime.now().isoformat()
        
        return data
        
    except Exception as e:
        logging.debug(f"Error parsing nethogs line: {e}")
        return None

def collect_nethogs_data():
    """Collect per-process bandwidth data using nethogs"""
    try:
        logging.info("Collecting nethogs data...")
        
        # Run nethogs in trace mode
        # -t: trace mode (machine readable)
        # -d: delay between updates (seconds)
        # interface: eno1
        
        # Use timeout to limit collection duration
        cmd = [
            'timeout', str(CAPTURE_DURATION),
            'sudo', 'nethogs',
            '-t',
            '-d', '1',
            INTERFACE
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CAPTURE_DURATION + 5)
        
        # nethogs with timeout returns 124, which is expected
        if not result.stdout:
            logging.warning("No nethogs data captured")
            return
        
        # Parse output
        lines = result.stdout.strip().split('\n')
        entries = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('Refreshing') or line.startswith('/'):
                # Skip header lines
                if 'PID' in line or 'USER' in line:
                    continue
            
            parsed = parse_nethogs_line(line)
            if parsed and parsed.get('program'):
                entries.append(parsed)
        
        if not entries:
            logging.debug("No entries parsed from nethogs")
            return
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"nethogs_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert entries
        inserted = 0
        for entry in entries:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, program, pid, user, sent_kb, received_kb)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    entry.get('timestamp'),
                    entry.get('program', ''),
                    entry.get('pid'),
                    entry.get('user', ''),
                    entry.get('sent_kb', 0.0),
                    entry.get('received_kb', 0.0)
                ))
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting entry: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if inserted > 0:
            logging.info(f"✓ Inserted {inserted} process bandwidth records into '{table_name}'")
        
    except subprocess.TimeoutExpired:
        logging.debug("nethogs collection completed (expected timeout)")
    except Exception as e:
        logging.error(f"Error collecting nethogs data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - nethogs Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info(f"Capture duration: {CAPTURE_DURATION} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    while True:
        try:
            collect_nethogs_data()
            time.sleep(COLLECT_INTERVAL)
        except KeyboardInterrupt:
            logging.info("Shutting down nethogs collector...")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(COLLECT_INTERVAL)

if __name__ == "__main__":
    main()


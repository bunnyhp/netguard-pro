#!/usr/bin/env python3
"""
NetGuard Pro - iftop Collector
Real-time bandwidth monitoring per connection
"""

import os
import subprocess
import sqlite3
import logging
import time
import re
from datetime import datetime

# Configuration
INTERFACE = "wlo1"  # WiFi for better bandwidth monitoring
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/iftop"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/iftop-collector.log"
COLLECT_INTERVAL = 310  # Collect every 30 seconds

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
    """Create iftop table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        tx_rate TEXT,
        rx_rate TEXT,
        total_rate TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def parse_iftop_output(output):
    """Parse iftop text output"""
    try:
        entries = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or '=>' not in line:
                continue
            
            # iftop output format (example):
            # 192.168.1.100:12345 => 8.8.8.8:53  1.23Kb  2.45Kb  3.67Kb
            # 192.168.1.100       <= 8.8.8.8     4.56Kb  5.67Kb  6.78Kb
            
            try:
                # Split by => or <=
                if '=>' in line:
                    parts = line.split('=>')
                    direction = 'TX'
                elif '<=' in line:
                    parts = line.split('<=')
                    direction = 'RX'
                else:
                    continue
                
                if len(parts) < 2:
                    continue
                
                # Parse source
                src = parts[0].strip()
                src_ip = ''
                src_port = None
                if ':' in src:
                    src_parts = src.split(':')
                    src_ip = src_parts[0]
                    try:
                        src_port = int(src_parts[1])
                    except:
                        pass
                else:
                    src_ip = src
                
                # Parse destination and rates
                dest_and_rates = parts[1].strip().split()
                if len(dest_and_rates) < 1:
                    continue
                
                dest = dest_and_rates[0]
                dest_ip = ''
                dest_port = None
                if ':' in dest:
                    dest_parts = dest.split(':')
                    dest_ip = dest_parts[0]
                    try:
                        dest_port = int(dest_parts[1])
                    except:
                        pass
                else:
                    dest_ip = dest
                
                # Parse rates (last 2 seconds, 10 seconds, 40 seconds averages)
                rates = [r for r in dest_and_rates[1:] if any(c in r for c in ['K', 'M', 'G', 'b'])]
                
                tx_rate = rates[0] if len(rates) > 0 else ''
                rx_rate = rates[1] if len(rates) > 1 else ''
                total_rate = rates[2] if len(rates) > 2 else ''
                
                entry = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'tx_rate': tx_rate,
                    'rx_rate': rx_rate,
                    'total_rate': total_rate
                }
                
                if src_ip and dest_ip:
                    entries.append(entry)
                    
            except Exception as e:
                logging.debug(f"Error parsing line: {e}")
                continue
        
        return entries
        
    except Exception as e:
        logging.error(f"Error parsing iftop output: {e}")
        return []

def collect_iftop_data():
    """Collect bandwidth data using iftop"""
    try:
        logging.info("Collecting iftop data...")
        
        # Run iftop in text mode with shorter timeout
        # -i: interface
        # -t: text output
        # -n: no DNS resolution
        # -P: show ports
        # Note: -s doesn't work reliably, using timeout instead
        cmd = [
            'sudo', 'iftop',
            '-i', INTERFACE,
            '-t',
            '-n',
            '-P',
            '-s', '5'  # 5 second snapshot
        ]
        
        # Use shorter timeout and kill if needed
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        
        if result.returncode != 0 or not result.stdout:
            logging.warning("No iftop data captured")
            return
        
        # Parse output
        entries = parse_iftop_output(result.stdout)
        
        if not entries:
            logging.debug("No entries parsed from iftop")
            return
        
        # Create table
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"iftop_{timestamp_str}"
        
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert entries
        inserted = 0
        for entry in entries:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, src_ip, src_port, dest_ip, dest_port, tx_rate, rx_rate, total_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.get('timestamp'),
                    entry.get('src_ip', ''),
                    entry.get('src_port'),
                    entry.get('dest_ip', ''),
                    entry.get('dest_port'),
                    entry.get('tx_rate', ''),
                    entry.get('rx_rate', ''),
                    entry.get('total_rate', '')
                ))
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting entry: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        if inserted > 0:
            logging.info(f"✓ Inserted {inserted} bandwidth records into '{table_name}'")
        
    except subprocess.TimeoutExpired:
        logging.error("iftop collection timeout")
    except Exception as e:
        logging.error(f"Error collecting iftop data: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - iftop Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    while True:
        try:
            collect_iftop_data()
            time.sleep(COLLECT_INTERVAL)
        except KeyboardInterrupt:
            logging.info("Shutting down iftop collector...")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(COLLECT_INTERVAL)

if __name__ == "__main__":
    main()


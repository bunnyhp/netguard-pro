#!/usr/bin/env python3
"""
NetGuard Pro - Unified Device Processor
Processes ALL network traffic to track devices and update device database
Runs continuously to ensure real-time device discovery
"""

import sqlite3
import logging
import time
import sys
from datetime import datetime
from device_tracker import DeviceTracker

DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/unified-device-processor.log"
PROCESS_INTERVAL = 30  # Process every 30 seconds

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def get_latest_table(conn, prefix):
    """Get most recent table for a tool"""
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name LIKE '{prefix}_%' 
        AND name NOT LIKE '%_template'
        ORDER BY name DESC LIMIT 1
    """)
    result = cursor.fetchone()
    return result[0] if result else None

def process_traffic_data():
    """Process all traffic data and update device tracker"""
    tracker = DeviceTracker()
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        devices_updated = 0
        
        # Get all unique IPs from recent traffic
        unique_ips = set()
        
        # Process tcpdump data (most comprehensive)
        tcpdump_table = get_latest_table(conn, 'tcpdump')
        if tcpdump_table:
            # Get unique source IPs
            cursor.execute(f"""
                SELECT DISTINCT src_ip 
                FROM {tcpdump_table}
                WHERE src_ip NOT LIKE '127.%' 
                AND src_ip != '::1'
                AND src_ip != ''
                AND src_ip NOT LIKE 'fe80%'
                LIMIT 500
            """)
            for row in cursor.fetchall():
                if row['src_ip']:
                    unique_ips.add(row['src_ip'])
            
            # Get unique dest IPs
            cursor.execute(f"""
                SELECT DISTINCT dest_ip 
                FROM {tcpdump_table}
                WHERE dest_ip NOT LIKE '127.%' 
                AND dest_ip != '::1'
                AND dest_ip != ''
                AND dest_ip NOT LIKE 'fe80%'
                AND dest_ip LIKE '192.168.%'
                LIMIT 500
            """)
            for row in cursor.fetchall():
                if row['dest_ip']:
                    unique_ips.add(row['dest_ip'])
        
        # Process tshark data
        tshark_table = get_latest_table(conn, 'tshark')
        if tshark_table:
            cursor.execute(f"""
                SELECT DISTINCT src_ip 
                FROM {tshark_table}
                WHERE src_ip NOT LIKE '127.%'
                AND src_ip != ''
                AND src_ip NOT LIKE 'fe80%'
                LIMIT 500
            """)
            for row in cursor.fetchall():
                if row['src_ip']:
                    unique_ips.add(row['src_ip'])
            
            cursor.execute(f"""
                SELECT DISTINCT dest_ip 
                FROM {tshark_table}
                WHERE dest_ip NOT LIKE '127.%'
                AND dest_ip != ''
                AND dest_ip NOT LIKE 'fe80%'
                AND dest_ip LIKE '192.168.%'
                LIMIT 500
            """)
            for row in cursor.fetchall():
                if row['dest_ip']:
                    unique_ips.add(row['dest_ip'])
        
        conn.close()
        
        # Now process all unique IPs
        logging.info(f"Found {len(unique_ips)} unique IPs in traffic")
        for ip in unique_ips:
            tracker.update_device(ip_address=ip)
            devices_updated += 1
        
        # Also scan ARP table for any missed devices
        arp_devices = tracker.scan_network()
        
        logging.info(f"✓ Processed traffic data: {devices_updated} device updates, {arp_devices} from ARP")
        
        return devices_updated + arp_devices
        
    except Exception as e:
        logging.error(f"Error processing traffic data: {e}")
        return 0

def main():
    """Main continuous processing loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Unified Device Processor")
    logging.info("=" * 60)
    logging.info(f"Processing interval: {PROCESS_INTERVAL} seconds")
    logging.info("Starting continuous device tracking...\n")
    
    cycle = 0
    
    try:
        while True:
            cycle += 1
            logging.info(f"--- Processing Cycle {cycle} ---")
            
            device_count = process_traffic_data()
            
            if device_count > 0:
                logging.info(f"✓ Cycle {cycle} complete: {device_count} devices tracked")
            else:
                logging.info(f"ℹ Cycle {cycle}: No new device data")
            
            time.sleep(PROCESS_INTERVAL)
            
    except KeyboardInterrupt:
        logging.info("\n✓ Shutdown signal received")
        return 0
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())


#!/usr/bin/env python3
"""
NetGuard Pro - JSON to SQLite Converter
Monitors JSON directory and inserts data into SQLite database with timestamped tables
"""

import os
import json
import time
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

# Configuration
JSON_DIR = "/home/jarvis/NetGuard/captures/processed_json"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/json-to-sqlite.log"
PROCESSED_FILES = "/home/jarvis/NetGuard/logs/system/processed_jsons.txt"
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
    """Load list of already processed JSON files"""
    if os.path.exists(PROCESSED_FILES):
        with open(PROCESSED_FILES, 'r') as f:
            return set(line.strip() for line in f)
    return set()

def mark_as_processed(filename):
    """Mark a file as processed"""
    with open(PROCESSED_FILES, 'a') as f:
        f.write(f"{filename}\n")

def create_network_table(conn, table_name):
    """Create a timestamped network table if it doesn't exist"""
    cursor = conn.cursor()
    
    create_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        source_port INTEGER,
        destination_ip TEXT,
        destination_port INTEGER,
        protocol TEXT,
        packet_length INTEGER,
        flags TEXT,
        ttl INTEGER,
        raw_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    cursor.execute(create_sql)
    conn.commit()

def insert_json_to_database(json_file):
    """Insert JSON data into SQLite database"""
    try:
        # Extract timestamp from filename (network_YYYYMMDD_HHMMSS.json)
        basename = os.path.basename(json_file)
        timestamp_str = basename.replace('network_', '').replace('.json', '')
        table_name = f"network_{timestamp_str}"
        
        logging.info(f"Processing {basename}...")
        
        # Read JSON file
        with open(json_file, 'r') as f:
            packets = json.load(f)
        
        if not packets:
            logging.warning(f"No packets in {basename}")
            return True
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        
        # Create table
        create_network_table(conn, table_name)
        
        # Insert packets
        cursor = conn.cursor()
        inserted_count = 0
        
        for packet in packets:
            try:
                cursor.execute(f"""
                    INSERT INTO {table_name} 
                    (timestamp, source_ip, source_port, destination_ip, destination_port, 
                     protocol, packet_length, flags, ttl, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    packet.get('timestamp', ''),
                    packet.get('source_ip', ''),
                    packet.get('source_port'),
                    packet.get('destination_ip', ''),
                    packet.get('destination_port'),
                    packet.get('protocol', ''),
                    packet.get('packet_length'),
                    packet.get('flags', ''),
                    packet.get('ttl'),
                    json.dumps(packet)  # Store full packet as JSON
                ))
                inserted_count += 1
            except Exception as e:
                logging.debug(f"Error inserting packet: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logging.info(f"✓ Inserted {inserted_count} packets into table '{table_name}'")
        return True
        
    except Exception as e:
        logging.error(f"✗ Error processing {json_file}: {e}")
        return False

def monitor_and_insert():
    """Monitor JSON directory and insert data into database"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - JSON to SQLite Converter")
    logging.info("=" * 60)
    logging.info(f"Monitoring directory: {JSON_DIR}")
    logging.info(f"Database: {DB_PATH}")
    logging.info(f"Check interval: {CHECK_INTERVAL} seconds")
    logging.info("=" * 60)
    
    # Create directories if they don't exist
    os.makedirs(JSON_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Load processed files
    processed = load_processed_files()
    
    while True:
        try:
            # Get all JSON files
            json_files = sorted(Path(JSON_DIR).glob('network_*.json'))
            
            for json_file in json_files:
                json_path = str(json_file)
                
                # Skip if already processed
                if json_path in processed:
                    continue
                
                # Check if file is complete (older than 5 seconds)
                file_age = time.time() - os.path.getmtime(json_path)
                if file_age < 5:
                    logging.debug(f"Skipping {json_file.name} (still being written)")
                    continue
                
                # Insert to database
                success = insert_json_to_database(json_path)
                
                if success:
                    # Mark as processed
                    processed.add(json_path)
                    mark_as_processed(json_path)
            
            # Sleep before next check
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            logging.info("Shutting down JSON to SQLite converter...")
            break
        except Exception as e:
            logging.error(f"Error in monitor loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_and_insert()


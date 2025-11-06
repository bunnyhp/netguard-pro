#!/usr/bin/env python3
"""
NetGuard Pro - System Initialization Script
Ensures all database tables and configurations are properly set up
"""

import os
import sys
import sqlite3
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DB_PATH = "/home/jarvis/NetGuard/network.db"

def initialize_all_tables():
    """Initialize all required database tables"""
    
    logging.info("=" * 60)
    logging.info("NetGuard Pro - System Initialization")
    logging.info("=" * 60)
    
    if not os.path.exists(DB_PATH):
        logging.error(f"Database not found: {DB_PATH}")
        logging.info("Please ensure network collectors are running to create the database.")
        return False
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Initialize Devices Table
    logging.info("1. Initializing devices table...")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT,
                device_category TEXT,
                security_score INTEGER DEFAULT 50,
                is_trusted INTEGER DEFAULT 0,
                first_seen DATETIME,
                last_seen DATETIME,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices (ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac_address ON devices (mac_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen DESC)")
        logging.info("   ✓ Devices table initialized")
    except Exception as e:
        logging.error(f"   ✗ Error initializing devices table: {e}")
    
    # 2. Initialize IoT Vulnerabilities Table
    logging.info("2. Initializing iot_vulnerabilities table...")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iot_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved INTEGER DEFAULT 0,
                resolved_at DATETIME
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iot_vulnerabilities_device_ip ON iot_vulnerabilities (device_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iot_vulnerabilities_resolved ON iot_vulnerabilities (resolved)")
        logging.info("   ✓ IoT vulnerabilities table initialized")
    except Exception as e:
        logging.error(f"   ✗ Error initializing iot_vulnerabilities table: {e}")
    
    # 3. Initialize Security Alerts Table
    logging.info("3. Initializing security_alerts table...")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_device TEXT,
                affected_devices TEXT,
                threat_indicators TEXT,
                remediation_steps TEXT,
                auto_remediation_available INTEGER DEFAULT 0,
                auto_remediation_command TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                resolved_by TEXT,
                false_positive INTEGER DEFAULT 0,
                recurrence_count INTEGER DEFAULT 1,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_alert_id ON security_alerts (alert_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts (status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts (severity)")
        logging.info("   ✓ Security alerts table initialized")
    except Exception as e:
        logging.error(f"   ✗ Error initializing security_alerts table: {e}")
    
    # 4. Initialize Alert History Table
    logging.info("4. Initializing alert_history table...")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                action_by TEXT,
                notes TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_history_alert_id ON alert_history (alert_id)")
        logging.info("   ✓ Alert history table initialized")
    except Exception as e:
        logging.error(f"   ✗ Error initializing alert_history table: {e}")
    
    # 5. Initialize Alert Rules Table
    logging.info("5. Initializing alert_rules table...")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT UNIQUE NOT NULL,
                rule_type TEXT NOT NULL,
                condition TEXT NOT NULL,
                threshold_value REAL,
                severity TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                auto_remediation INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        logging.info("   ✓ Alert rules table initialized")
    except Exception as e:
        logging.error(f"   ✗ Error initializing alert_rules table: {e}")
    
    conn.commit()
    
    # 6. Verify Tables
    logging.info("\n6. Verifying all tables...")
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' 
        AND name IN ('devices', 'iot_vulnerabilities', 'security_alerts', 'alert_history', 'alert_rules')
        ORDER BY name
    """)
    tables = cursor.fetchall()
    
    expected_tables = ['alert_history', 'alert_rules', 'devices', 'iot_vulnerabilities', 'security_alerts']
    found_tables = [t[0] for t in tables]
    
    for table in expected_tables:
        if table in found_tables:
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            logging.info(f"   ✓ {table:25s} - {count} rows")
        else:
            logging.warning(f"   ✗ {table:25s} - NOT FOUND")
    
    conn.close()
    
    logging.info("\n" + "=" * 60)
    logging.info("System initialization complete!")
    logging.info("=" * 60)
    
    # 7. Check if device_tracker needs to run
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM devices")
    device_count = cursor.fetchone()[0]
    conn.close()
    
    if device_count == 0:
        logging.info("\n⚠️  RECOMMENDATION:")
        logging.info("    No devices found in database.")
        logging.info("    Run: python3 /home/jarvis/NetGuard/scripts/device_tracker.py")
        logging.info("    Or start unified_device_processor service")
    else:
        logging.info(f"\n✓ System is ready! {device_count} devices tracked.")
    
    return True

if __name__ == "__main__":
    try:
        success = initialize_all_tables()
        sys.exit(0 if success else 1)
    except Exception as e:
        logging.error(f"Fatal error during initialization: {e}")
        sys.exit(1)


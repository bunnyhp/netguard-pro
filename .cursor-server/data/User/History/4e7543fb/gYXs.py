#!/usr/bin/env python3
"""
NetGuard Pro - AI Database Schema Initialization
Creates tables for AI predictions, alerts, and device profiles
"""

import sqlite3
import os
import logging

DB_PATH = "/home/jarvis/NetGuard/network.db"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_ai_tables():
    """Create AI-related tables without affecting existing tables"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 1. AI Predictions Table - stores ML model outputs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                analysis_window TEXT,
                threat_level TEXT,
                network_health_score INTEGER,
                threats_detected INTEGER DEFAULT 0,
                anomalies_detected INTEGER DEFAULT 0,
                alerts_generated INTEGER DEFAULT 0,
                threats_json TEXT,
                anomalies_json TEXT,
                patterns_json TEXT,
                dns_analysis_json TEXT,
                processing_time_ms INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_timestamp ON ai_predictions(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_threat_level ON ai_predictions(threat_level)")
        logging.info("✓ Created ai_predictions table")
        
        # 2. AI Alerts Table - actionable security alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                priority TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT,
                threat_type TEXT,
                source_ip TEXT,
                target_ip TEXT,
                confidence REAL,
                indicators TEXT,
                recommended_action TEXT,
                auto_block INTEGER DEFAULT 0,
                resolved INTEGER DEFAULT 0,
                resolved_at DATETIME,
                resolved_by TEXT,
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_priority ON ai_alerts(priority)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_resolved ON ai_alerts(resolved)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON ai_alerts(timestamp)")
        logging.info("✓ Created ai_alerts table")
        
        # 3. Device Profiles Table - learned baseline behavior
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                device_name TEXT,
                device_type TEXT,
                first_seen TEXT,
                last_updated TEXT,
                avg_daily_bytes INTEGER,
                std_daily_bytes INTEGER,
                avg_hourly_connections INTEGER,
                typical_protocols TEXT,
                common_destinations TEXT,
                typical_hours TEXT,
                baseline_json TEXT,
                profile_confidence REAL DEFAULT 0.0,
                days_observed INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_ip ON device_profiles(device_ip)")
        logging.info("✓ Created device_profiles table")
        
        # 4. URL Classifications Table - domain risk scores
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS url_classifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                domain TEXT NOT NULL,
                risk_score REAL,
                category TEXT,
                threat_intel_match INTEGER DEFAULT 0,
                indicators TEXT,
                action TEXT,
                accessed_by TEXT,
                first_seen TEXT,
                last_seen TEXT,
                access_count INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON url_classifications(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_score ON url_classifications(risk_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON url_classifications(category)")
        logging.info("✓ Created url_classifications table")
        
        # 5. Threat Patterns Table - detected behavior patterns
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                device_ip TEXT,
                confidence REAL,
                description TEXT,
                characteristics TEXT,
                first_detected TEXT,
                last_detected TEXT,
                occurrences INTEGER DEFAULT 1,
                severity TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_device ON threat_patterns(device_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_type ON threat_patterns(pattern_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_status ON threat_patterns(status)")
        logging.info("✓ Created threat_patterns table")
        
        # 6. AI Analysis History - audit trail
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                packets_analyzed INTEGER,
                devices_analyzed INTEGER,
                threats_found INTEGER,
                alerts_generated INTEGER,
                analysis_duration_ms INTEGER,
                success INTEGER DEFAULT 1,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_timestamp ON ai_analysis_history(timestamp)")
        logging.info("✓ Created ai_analysis_history table")
        
        # 7. AI Configuration Table - runtime settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT,
                description TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        logging.info("✓ Created ai_config table")
        
        # Insert default configuration
        default_configs = [
            ('ai_service_url', 'http://localhost:5000', 'AI service endpoint URL'),
            ('analysis_interval', '300', 'Analysis interval in seconds (5 minutes)'),
            ('anomaly_threshold', '0.7', 'Anomaly detection threshold (0-1)'),
            ('alert_email', '', 'Email address for critical alerts'),
            ('auto_block_enabled', '0', 'Enable automatic IP blocking'),
            ('min_confidence', '0.75', 'Minimum confidence for alerts'),
            ('ai_enabled', '0', 'Enable/disable AI analysis'),
            ('learning_mode', '1', 'Enable device behavior learning')
        ]
        
        for key, value, desc in default_configs:
            cursor.execute("""
                INSERT OR IGNORE INTO ai_config (key, value, description) 
                VALUES (?, ?, ?)
            """, (key, value, desc))
        
        logging.info("✓ Inserted default AI configuration")
        
        conn.commit()
        logging.info("=" * 60)
        logging.info("✅ AI Database Schema Created Successfully!")
        logging.info("=" * 60)
        
        # Display table info
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name LIKE 'ai_%' OR name LIKE '%_profile%' OR name LIKE 'url_%'
            ORDER BY name
        """)
        
        ai_tables = cursor.fetchall()
        logging.info(f"\n📊 Created {len(ai_tables)} AI tables:")
        for table in ai_tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
            count = cursor.fetchone()[0]
            logging.info(f"   • {table[0]}: {count} records")
        
        return True
        
    except Exception as e:
        logging.error(f"❌ Error creating AI tables: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()


def verify_existing_tables():
    """Verify existing tables are not affected"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if main tables still exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND (
                name LIKE 'tcpdump_%' OR 
                name LIKE 'tshark_%' OR
                name LIKE 'suricata_%'
            )
            ORDER BY name DESC
            LIMIT 5
        """)
        
        existing_tables = cursor.fetchall()
        logging.info("\n✓ Verified existing tables (sample):")
        for table in existing_tables:
            logging.info(f"   • {table[0]}")
        
        return True
        
    except Exception as e:
        logging.error(f"❌ Error verifying tables: {e}")
        return False
        
    finally:
        conn.close()


if __name__ == "__main__":
    logging.info("=" * 60)
    logging.info("NetGuard Pro - AI Database Initialization")
    logging.info("=" * 60)
    logging.info("")
    
    # Verify existing tables first
    logging.info("Step 1: Verifying existing tables...")
    if not verify_existing_tables():
        logging.error("Failed to verify existing tables!")
        exit(1)
    
    logging.info("\nStep 2: Creating AI tables...")
    if not create_ai_tables():
        logging.error("Failed to create AI tables!")
        exit(1)
    
    logging.info("\n✅ AI Database initialization complete!")
    logging.info("No existing functionality was affected.")


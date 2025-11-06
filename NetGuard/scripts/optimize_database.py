#!/usr/bin/env python3
"""
NetGuard Pro - Database Optimizer
Add indexes for better query performance
"""

import sqlite3
import logging

DB_PATH = "/home/jarvis/NetGuard/network.db"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def optimize_database():
    """Add indexes to improve database performance"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        logging.info("Optimizing database...")
        
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Common column patterns to index
        index_patterns = {
            'timestamp': ['timestamp', 'created_at', 'detected_at'],
            'ip': ['src_ip', 'dest_ip', 'ip_address', 'device_ip'],
            'mac': ['mac_address', 'device_mac'],
            'status': ['resolved', 'is_trusted'],
            'severity': ['severity']
        }
        
        indexes_created = 0
        
        for table in tables:
            # Skip template tables
            if table.endswith('_template'):
                continue
            
            # Get columns for this table
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [row[1] for row in cursor.fetchall()]
            
            # Create indexes for common query patterns
            for index_type, column_patterns in index_patterns.items():
                for pattern in column_patterns:
                    for column in columns:
                        if column == pattern:
                            index_name = f"idx_{table}_{column}"
                            
                            # Check if index already exists
                            cursor.execute(f"""
                                SELECT name FROM sqlite_master 
                                WHERE type='index' AND name='{index_name}'
                            """)
                            
                            if not cursor.fetchone():
                                try:
                                    cursor.execute(f"CREATE INDEX {index_name} ON {table}({column})")
                                    indexes_created += 1
                                    logging.info(f"  ✓ Created index: {index_name}")
                                except Exception as e:
                                    logging.warning(f"  ⚠ Could not create {index_name}: {e}")
        
        # Create composite indexes for common query patterns
        composite_indexes = [
            ('devices', ['device_type', 'last_seen']),
            ('iot_vulnerabilities', ['device_ip', 'resolved']),
            ('ai_analysis', ['timestamp', 'threat_level'])
        ]
        
        for table, columns in composite_indexes:
            if table in tables:
                index_name = f"idx_{table}_{'_'.join(columns)}"
                
                cursor.execute(f"""
                    SELECT name FROM sqlite_master 
                    WHERE type='index' AND name='{index_name}'
                """)
                
                if not cursor.fetchone():
                    try:
                        cursor.execute(f"CREATE INDEX {index_name} ON {table}({', '.join(columns)})")
                        indexes_created += 1
                        logging.info(f"  ✓ Created composite index: {index_name}")
                    except Exception as e:
                        logging.warning(f"  ⚠ Could not create {index_name}: {e}")
        
        # Run VACUUM to optimize database file
        logging.info("Running VACUUM to optimize database file...")
        cursor.execute("VACUUM")
        
        # Update statistics
        logging.info("Analyzing database statistics...")
        cursor.execute("ANALYZE")
        
        conn.commit()
        conn.close()
        
        logging.info(f"\n✓ Database optimization complete!")
        logging.info(f"✓ Created {indexes_created} new indexes")
        
    except Exception as e:
        logging.error(f"Error optimizing database: {e}")

if __name__ == "__main__":
    optimize_database()


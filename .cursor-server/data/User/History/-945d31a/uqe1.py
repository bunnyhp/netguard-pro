#!/usr/bin/env python3
"""
NetGuard Pro - Database Initialization Script
Creates SQLite database with all necessary schemas for network monitoring data.
"""

import sqlite3
import os
import sys
from datetime import datetime

# Database path
DB_PATH = "/home/jarvis/NetGuard/network.db"

def create_connection():
    """Create database connection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def create_tcpdump_schema(conn):
    """Create schema for tcpdump tables (network_*)"""
    schema = """
    CREATE TABLE IF NOT EXISTS network_template (
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
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ tcpdump schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating tcpdump schema: {e}")

def create_suricata_alerts_schema(conn):
    """Create schema for Suricata alerts tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_alerts_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        event_type TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        proto TEXT,
        alert_signature TEXT,
        alert_category TEXT,
        alert_severity INTEGER,
        alert_signature_id INTEGER,
        alert_gid INTEGER,
        alert_rev INTEGER,
        alert_action TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata alerts schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata alerts schema: {e}")

def create_suricata_http_schema(conn):
    """Create schema for Suricata HTTP tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_http_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        http_hostname TEXT,
        http_url TEXT,
        http_user_agent TEXT,
        http_method TEXT,
        http_protocol TEXT,
        http_status INTEGER,
        http_content_type TEXT,
        http_length INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata HTTP schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata HTTP schema: {e}")

def create_suricata_dns_schema(conn):
    """Create schema for Suricata DNS tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_dns_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        dns_type TEXT,
        dns_id INTEGER,
        dns_rrname TEXT,
        dns_rrtype TEXT,
        dns_rcode TEXT,
        dns_rdata TEXT,
        dns_ttl INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata DNS schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata DNS schema: {e}")

def create_suricata_tls_schema(conn):
    """Create schema for Suricata TLS tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_tls_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        tls_subject TEXT,
        tls_issuerdn TEXT,
        tls_serial TEXT,
        tls_fingerprint TEXT,
        tls_sni TEXT,
        tls_version TEXT,
        tls_notbefore TEXT,
        tls_notafter TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata TLS schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata TLS schema: {e}")

def create_suricata_files_schema(conn):
    """Create schema for Suricata files tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_files_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        file_filename TEXT,
        file_magic TEXT,
        file_state TEXT,
        file_stored INTEGER,
        file_size INTEGER,
        file_tx_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata files schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata files schema: {e}")

def create_suricata_flow_schema(conn):
    """Create schema for Suricata flow tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_flow_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        proto TEXT,
        flow_pkts_toserver INTEGER,
        flow_pkts_toclient INTEGER,
        flow_bytes_toserver INTEGER,
        flow_bytes_toclient INTEGER,
        flow_start TEXT,
        flow_end TEXT,
        flow_age INTEGER,
        flow_state TEXT,
        flow_reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata flow schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata flow schema: {e}")

def create_suricata_ssh_schema(conn):
    """Create schema for Suricata SSH tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_ssh_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        ssh_client_software TEXT,
        ssh_server_software TEXT,
        ssh_client_proto TEXT,
        ssh_server_proto TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata SSH schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata SSH schema: {e}")

def create_suricata_smtp_schema(conn):
    """Create schema for Suricata SMTP tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_smtp_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        smtp_helo TEXT,
        smtp_mail_from TEXT,
        smtp_rcpt_to TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata SMTP schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata SMTP schema: {e}")

def create_suricata_ftp_schema(conn):
    """Create schema for Suricata FTP tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_ftp_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        ftp_command TEXT,
        ftp_command_data TEXT,
        ftp_reply TEXT,
        ftp_completion_code TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata FTP schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata FTP schema: {e}")

def create_suricata_anomaly_schema(conn):
    """Create schema for Suricata anomaly tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_anomaly_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        flow_id INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        anomaly_type TEXT,
        anomaly_event TEXT,
        anomaly_code INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata anomaly schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata anomaly schema: {e}")

def create_suricata_stats_schema(conn):
    """Create schema for Suricata stats tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS suricata_stats_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        uptime INTEGER,
        packets INTEGER,
        bytes INTEGER,
        drop INTEGER,
        invalid INTEGER,
        decoder_pkts INTEGER,
        decoder_bytes INTEGER,
        decoder_ipv4 INTEGER,
        decoder_ipv6 INTEGER,
        decoder_tcp INTEGER,
        decoder_udp INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ Suricata stats schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating Suricata stats schema: {e}")

def create_tshark_schema(conn):
    """Create schema for tshark tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS tshark_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        frame_number INTEGER,
        frame_time TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        protocol TEXT,
        length INTEGER,
        info TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ tshark schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating tshark schema: {e}")

def create_p0f_schema(conn):
    """Create schema for p0f tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS p0f_template (
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
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ p0f schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating p0f schema: {e}")

def create_argus_schema(conn):
    """Create schema for argus tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS argus_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        start_time TEXT,
        last_time TEXT,
        duration REAL,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        proto TEXT,
        src_packets INTEGER,
        dest_packets INTEGER,
        src_bytes INTEGER,
        dest_bytes INTEGER,
        state TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ argus schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating argus schema: {e}")

def create_ngrep_schema(conn):
    """Create schema for ngrep tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS ngrep_template (
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
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ ngrep schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating ngrep schema: {e}")

def create_netsniff_schema(conn):
    """Create schema for netsniff-ng tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS netsniff_template (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        protocol TEXT,
        packet_length INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ netsniff-ng schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating netsniff-ng schema: {e}")

def create_httpry_schema(conn):
    """Create schema for httpry tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS httpry_template (
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
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ httpry schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating httpry schema: {e}")

def create_iftop_schema(conn):
    """Create schema for iftop tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS iftop_template (
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
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ iftop schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating iftop schema: {e}")

def create_nethogs_schema(conn):
    """Create schema for nethogs tables"""
    schema = """
    CREATE TABLE IF NOT EXISTS nethogs_template (
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
    try:
        cursor = conn.cursor()
        cursor.execute(schema)
        conn.commit()
        print("✓ nethogs schema template created")
    except sqlite3.Error as e:
        print(f"✗ Error creating nethogs schema: {e}")

def main():
    """Main function to initialize all database schemas"""
    print("=" * 60)
    print("NetGuard Pro - Database Initialization")
    print("=" * 60)
    print(f"Database: {DB_PATH}\n")
    
    # Create connection
    conn = create_connection()
    
    # Create all schemas
    print("Creating database schemas...\n")
    
    # tcpdump
    create_tcpdump_schema(conn)
    
    # Suricata (11 categories)
    create_suricata_alerts_schema(conn)
    create_suricata_http_schema(conn)
    create_suricata_dns_schema(conn)
    create_suricata_tls_schema(conn)
    create_suricata_files_schema(conn)
    create_suricata_flow_schema(conn)
    create_suricata_ssh_schema(conn)
    create_suricata_smtp_schema(conn)
    create_suricata_ftp_schema(conn)
    create_suricata_anomaly_schema(conn)
    create_suricata_stats_schema(conn)
    
    # Analysis tools (8 tools)
    create_tshark_schema(conn)
    create_p0f_schema(conn)
    create_argus_schema(conn)
    create_ngrep_schema(conn)
    create_netsniff_schema(conn)
    create_httpry_schema(conn)
    create_iftop_schema(conn)
    create_nethogs_schema(conn)
    
    # Close connection
    conn.close()
    
    print("\n" + "=" * 60)
    print("Database initialization complete!")
    print("=" * 60)
    print(f"Total template tables created: 20")
    print(f"  - tcpdump: 1")
    print(f"  - Suricata: 11")
    print(f"  - Analysis tools: 8")
    print("\nNote: These are template tables. Timestamped tables will be")
    print("created automatically by collection scripts.")
    print("=" * 60)

if __name__ == "__main__":
    main()


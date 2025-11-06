#!/usr/bin/env python3
"""
NetGuard Pro - Suricata EVE Log Collector
Processes Suricata EVE JSON logs and inserts data into SQLite database
Handles 11 categories: alerts, http, dns, tls, files, flow, ssh, smtp, ftp, anomaly, stats
"""

import os
import json
import time
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

# Configuration
SURICATA_LOG_DIR = "/var/log/suricata"  # Default Suricata log directory
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/suricata"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/suricata-collector.log"
CHECK_INTERVAL = 15  # seconds - check every 15 seconds
POSITION_FILE = "/home/jarvis/NetGuard/logs/system/suricata_positions.json"

# EVE log categories
CATEGORIES = ['alerts', 'http', 'dns', 'tls', 'files', 'flow', 'ssh', 'smtp', 'ftp', 'anomaly', 'stats']

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def load_positions():
    """Load file positions (last read byte position for each log file)"""
    if os.path.exists(POSITION_FILE):
        try:
            with open(POSITION_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_position(log_file, position):
    """Save the last read position for a log file"""
    positions = load_positions()
    positions[log_file] = position
    with open(POSITION_FILE, 'w') as f:
        json.dump(positions, f, indent=2)

def save_positions_dict(positions_dict):
    """Save multiple positions at once"""
    with open(POSITION_FILE, 'w') as f:
        json.dump(positions_dict, f, indent=2)

def create_table_if_not_exists(conn, category, table_name):
    """Create category-specific table if it doesn't exist"""
    cursor = conn.cursor()
    
    if category == 'alerts':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'http':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'dns':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'tls':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'files':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'flow':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'ssh':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'smtp':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'ftp':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'anomaly':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
    elif category == 'stats':
        sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            uptime INTEGER,
            packets INTEGER,
            bytes INTEGER,
            packets_dropped INTEGER,
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
    else:
        return
    
    cursor.execute(sql)
    conn.commit()

def extract_alert_data(event):
    """Extract alert-specific data from event"""
    alert = event.get('alert', {})
    return {
        'alert_signature': alert.get('signature', ''),
        'alert_category': alert.get('category', ''),
        'alert_severity': alert.get('severity'),
        'alert_signature_id': alert.get('signature_id'),
        'alert_gid': alert.get('gid'),
        'alert_rev': alert.get('rev'),
        'alert_action': alert.get('action', '')
    }

def extract_http_data(event):
    """Extract HTTP-specific data from event"""
    http = event.get('http', {})
    return {
        'http_hostname': http.get('hostname', ''),
        'http_url': http.get('url', ''),
        'http_user_agent': http.get('http_user_agent', ''),
        'http_method': http.get('http_method', ''),
        'http_protocol': http.get('protocol', ''),
        'http_status': http.get('status'),
        'http_content_type': http.get('http_content_type', ''),
        'http_length': http.get('length')
    }

def extract_dns_data(event):
    """Extract DNS-specific data from event"""
    dns = event.get('dns', {})
    return {
        'dns_type': dns.get('type', ''),
        'dns_id': dns.get('id'),
        'dns_rrname': dns.get('rrname', ''),
        'dns_rrtype': dns.get('rrtype', ''),
        'dns_rcode': dns.get('rcode', ''),
        'dns_rdata': dns.get('rdata', ''),
        'dns_ttl': dns.get('ttl')
    }

def extract_tls_data(event):
    """Extract TLS-specific data from event"""
    tls = event.get('tls', {})
    return {
        'tls_subject': tls.get('subject', ''),
        'tls_issuerdn': tls.get('issuerdn', ''),
        'tls_serial': tls.get('serial', ''),
        'tls_fingerprint': tls.get('fingerprint', ''),
        'tls_sni': tls.get('sni', ''),
        'tls_version': tls.get('version', ''),
        'tls_notbefore': tls.get('notbefore', ''),
        'tls_notafter': tls.get('notafter', '')
    }

def extract_files_data(event):
    """Extract file-specific data from event"""
    fileinfo = event.get('fileinfo', {})
    return {
        'file_filename': fileinfo.get('filename', ''),
        'file_magic': fileinfo.get('magic', ''),
        'file_state': fileinfo.get('state', ''),
        'file_stored': fileinfo.get('stored'),
        'file_size': fileinfo.get('size'),
        'file_tx_id': fileinfo.get('tx_id')
    }

def extract_flow_data(event):
    """Extract flow-specific data from event"""
    flow = event.get('flow', {})
    return {
        'flow_pkts_toserver': flow.get('pkts_toserver'),
        'flow_pkts_toclient': flow.get('pkts_toclient'),
        'flow_bytes_toserver': flow.get('bytes_toserver'),
        'flow_bytes_toclient': flow.get('bytes_toclient'),
        'flow_start': flow.get('start', ''),
        'flow_end': flow.get('end', ''),
        'flow_age': flow.get('age'),
        'flow_state': flow.get('state', ''),
        'flow_reason': flow.get('reason', '')
    }

def extract_ssh_data(event):
    """Extract SSH-specific data from event"""
    ssh = event.get('ssh', {})
    client = ssh.get('client', {})
    server = ssh.get('server', {})
    return {
        'ssh_client_software': client.get('software_version', ''),
        'ssh_server_software': server.get('software_version', ''),
        'ssh_client_proto': client.get('proto_version', ''),
        'ssh_server_proto': server.get('proto_version', '')
    }

def extract_smtp_data(event):
    """Extract SMTP-specific data from event"""
    smtp = event.get('smtp', {})
    return {
        'smtp_helo': smtp.get('helo', ''),
        'smtp_mail_from': smtp.get('mail_from', ''),
        'smtp_rcpt_to': ','.join(smtp.get('rcpt_to', []))
    }

def extract_ftp_data(event):
    """Extract FTP-specific data from event"""
    ftp = event.get('ftp', {})
    return {
        'ftp_command': ftp.get('command', ''),
        'ftp_command_data': ftp.get('command_data', ''),
        'ftp_reply': ','.join(ftp.get('reply', [])),
        'ftp_completion_code': ','.join(ftp.get('completion_code', []))
    }

def extract_anomaly_data(event):
    """Extract anomaly-specific data from event"""
    anomaly = event.get('anomaly', {})
    return {
        'anomaly_type': anomaly.get('type', ''),
        'anomaly_event': anomaly.get('event', ''),
        'anomaly_code': anomaly.get('code')
    }

def extract_stats_data(event):
    """Extract stats-specific data from event"""
    stats = event.get('stats', {})
    decoder = stats.get('decoder', {})
    return {
        'uptime': stats.get('uptime'),
        'packets': stats.get('capture', {}).get('kernel_packets'),
        'bytes': decoder.get('bytes'),
        'packets_dropped': stats.get('capture', {}).get('kernel_drops'),
        'invalid': decoder.get('invalid'),
        'decoder_pkts': decoder.get('pkts'),
        'decoder_bytes': decoder.get('bytes'),
        'decoder_ipv4': decoder.get('ipv4'),
        'decoder_ipv6': decoder.get('ipv6'),
        'decoder_tcp': decoder.get('tcp'),
        'decoder_udp': decoder.get('udp')
    }

def insert_event(conn, category, table_name, event):
    """Insert event into appropriate category table"""
    try:
        cursor = conn.cursor()
        
        # Common fields
        timestamp = event.get('timestamp', '')
        flow_id = event.get('flow_id')
        src_ip = event.get('src_ip', '')
        src_port = event.get('src_port')
        dest_ip = event.get('dest_ip', '')
        dest_port = event.get('dest_port')
        proto = event.get('proto', '')
        event_type = event.get('event_type', '')
        
        # Extract category-specific data
        if category == 'alerts':
            data = extract_alert_data(event)
            sql = f"""
                INSERT INTO {table_name} 
                (timestamp, flow_id, event_type, src_ip, src_port, dest_ip, dest_port, proto,
                 alert_signature, alert_category, alert_severity, alert_signature_id, 
                 alert_gid, alert_rev, alert_action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, event_type, src_ip, src_port, dest_ip, dest_port, proto,
                     data['alert_signature'], data['alert_category'], data['alert_severity'],
                     data['alert_signature_id'], data['alert_gid'], data['alert_rev'], data['alert_action'])
                     
        elif category == 'http':
            data = extract_http_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 http_hostname, http_url, http_user_agent, http_method, http_protocol,
                 http_status, http_content_type, http_length)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['http_hostname'], data['http_url'], data['http_user_agent'],
                     data['http_method'], data['http_protocol'], data['http_status'],
                     data['http_content_type'], data['http_length'])
                     
        elif category == 'dns':
            data = extract_dns_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 dns_type, dns_id, dns_rrname, dns_rrtype, dns_rcode, dns_rdata, dns_ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['dns_type'], data['dns_id'], data['dns_rrname'], data['dns_rrtype'],
                     data['dns_rcode'], data['dns_rdata'], data['dns_ttl'])
                     
        elif category == 'tls':
            data = extract_tls_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 tls_subject, tls_issuerdn, tls_serial, tls_fingerprint, tls_sni,
                 tls_version, tls_notbefore, tls_notafter)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['tls_subject'], data['tls_issuerdn'], data['tls_serial'],
                     data['tls_fingerprint'], data['tls_sni'], data['tls_version'],
                     data['tls_notbefore'], data['tls_notafter'])
                     
        elif category == 'files':
            data = extract_files_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 file_filename, file_magic, file_state, file_stored, file_size, file_tx_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['file_filename'], data['file_magic'], data['file_state'],
                     data['file_stored'], data['file_size'], data['file_tx_id'])
                     
        elif category == 'flow':
            data = extract_flow_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port, proto,
                 flow_pkts_toserver, flow_pkts_toclient, flow_bytes_toserver, flow_bytes_toclient,
                 flow_start, flow_end, flow_age, flow_state, flow_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port, proto,
                     data['flow_pkts_toserver'], data['flow_pkts_toclient'],
                     data['flow_bytes_toserver'], data['flow_bytes_toclient'],
                     data['flow_start'], data['flow_end'], data['flow_age'],
                     data['flow_state'], data['flow_reason'])
                     
        elif category == 'ssh':
            data = extract_ssh_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 ssh_client_software, ssh_server_software, ssh_client_proto, ssh_server_proto)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['ssh_client_software'], data['ssh_server_software'],
                     data['ssh_client_proto'], data['ssh_server_proto'])
                     
        elif category == 'smtp':
            data = extract_smtp_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 smtp_helo, smtp_mail_from, smtp_rcpt_to)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['smtp_helo'], data['smtp_mail_from'], data['smtp_rcpt_to'])
                     
        elif category == 'ftp':
            data = extract_ftp_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 ftp_command, ftp_command_data, ftp_reply, ftp_completion_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['ftp_command'], data['ftp_command_data'],
                     data['ftp_reply'], data['ftp_completion_code'])
                     
        elif category == 'anomaly':
            data = extract_anomaly_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                 anomaly_type, anomaly_event, anomaly_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, flow_id, src_ip, src_port, dest_ip, dest_port,
                     data['anomaly_type'], data['anomaly_event'], data['anomaly_code'])
                     
        elif category == 'stats':
            data = extract_stats_data(event)
            sql = f"""
                INSERT INTO {table_name}
                (timestamp, uptime, packets, bytes, packets_dropped, invalid,
                 decoder_pkts, decoder_bytes, decoder_ipv4, decoder_ipv6,
                 decoder_tcp, decoder_udp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            values = (timestamp, data['uptime'], data['packets'], data['bytes'],
                     data['packets_dropped'], data['invalid'], data['decoder_pkts'],
                     data['decoder_bytes'], data['decoder_ipv4'], data['decoder_ipv6'],
                     data['decoder_tcp'], data['decoder_udp'])
        else:
            return False
        
        cursor.execute(sql, values)
        return True
        
    except Exception as e:
        logging.debug(f"Error inserting {category} event: {e}")
        return False

def process_eve_log(category, log_file):
    """Process Suricata EVE log file for a specific category"""
    try:
        if not os.path.exists(log_file):
            return 0
        
        # Get current position
        positions = load_positions()
        last_position = positions.get(log_file, 0)
        
        # Open file and seek to last position
        with open(log_file, 'r') as f:
            f.seek(last_position)
            new_lines = f.readlines()
            new_position = f.tell()
        
        if not new_lines:
            return 0
        
        logging.debug(f"{category}: Processing {len(new_lines)} new lines from position {last_position}")
        
        # Generate table name with timestamp
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"suricata_{category}_{timestamp_str}"
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        
        # Create table
        create_table_if_not_exists(conn, category, table_name)
        
        # Process events
        inserted_count = 0
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            
            try:
                event = json.loads(line)
                
                # Filter by event type for relevant category
                event_type = event.get('event_type', '')
                
                # Insert if matches category
                if category == 'alerts' and event_type == 'alert':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'http' and event_type == 'http':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'dns' and event_type == 'dns':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'tls' and event_type == 'tls':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'files' and event_type == 'fileinfo':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'flow' and event_type == 'flow':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'ssh' and event_type == 'ssh':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'smtp' and event_type == 'smtp':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'ftp' and event_type == 'ftp':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'anomaly' and event_type == 'anomaly':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                elif category == 'stats' and event_type == 'stats':
                    if insert_event(conn, category, table_name, event):
                        inserted_count += 1
                        
            except json.JSONDecodeError:
                continue
        
        conn.commit()
        conn.close()
        
        # Save new position
        save_position(log_file, new_position)
        
        if inserted_count > 0:
            logging.info(f"✓ {category}: Inserted {inserted_count} events into '{table_name}'")
        
        return inserted_count
        
    except Exception as e:
        logging.error(f"✗ Error processing {category} log: {e}")
        return 0

def collect_suricata_data():
    """Main collection loop for Suricata EVE logs"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Suricata EVE Log Collector")
    logging.info("=" * 60)
    logging.info(f"Suricata logs: {SURICATA_LOG_DIR}")
    logging.info(f"Database: {DB_PATH}")
    logging.info(f"Check interval: {CHECK_INTERVAL} seconds")
    logging.info(f"Categories: {', '.join(CATEGORIES)}")
    logging.info("=" * 60)
    
    # Create directories
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Main EVE log file (we'll read from this)
    eve_log = os.path.join(SURICATA_LOG_DIR, "eve.json")
    
    while True:
        try:
            # Process ALL categories in a single pass through the file
            total_inserted = process_all_categories(eve_log)
            
            if total_inserted > 0:
                logging.info(f"Total events processed: {total_inserted}")
            
            # Sleep before next check
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            logging.info("Shutting down Suricata collector...")
            break
        except Exception as e:
            logging.error(f"Error in collection loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    collect_suricata_data()


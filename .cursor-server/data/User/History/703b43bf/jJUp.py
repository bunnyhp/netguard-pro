#!/usr/bin/env python3
"""
NetGuard Pro - tshark Collector
Captures and analyzes WiFi traffic using tshark for protocol dissection
"""

import os
import subprocess
import sqlite3
import logging
import time
import json
import re
from datetime import datetime

# Configuration
INTERFACE = "wlo1"
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/tshark"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/tshark-collector.log"
COLLECT_INTERVAL = 35  # Check every 35 seconds for faster real-time monitoring
CAPTURE_DURATION = 30  # Capture for 30 seconds for quick data collection

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def get_geoip_info(ip_address):
    """Get GeoIP information for an IP address - Step 5"""
    if not ip_address or ip_address == '':
        return None, None
    
    # Skip private/local IPs
    if ip_address.startswith(('192.168.', '10.', '172.16.', '127.', 'fe80:', '::1')):
        return 'Local', 'Private Network'
    
    try:
        result = subprocess.run(['geoiplookup', ip_address], 
                              capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            # Parse output: "GeoIP Country Edition: US, United States"
            match = re.search(r':\s*([A-Z]{2}),\s*(.+)', result.stdout)
            if match:
                return match.group(1), match.group(2).strip()
    except:
        pass
    
    return None, None

def create_table(conn, table_name):
    """Create tshark table if it doesn't exist"""
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
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
        tcp_flags TEXT,
        tcp_syn INTEGER,
        tcp_ack INTEGER,
        tcp_fin INTEGER,
        tcp_rst INTEGER,
        ip_ttl INTEGER,
        tcp_window_size INTEGER,
        http_host TEXT,
        http_uri TEXT,
        http_method TEXT,
        http_user_agent TEXT,
        http_response_code INTEGER,
        dns_query TEXT,
        dns_query_type TEXT,
        dns_response TEXT,
        tls_handshake_type TEXT,
        tls_server_name TEXT,
        dest_country TEXT,
        dest_city TEXT,
        is_suspicious INTEGER DEFAULT 0,
        threat_score INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()

def capture_and_analyze():
    """Capture packets and analyze with tshark"""
    try:
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        table_name = f"tshark_{timestamp_str}"
        pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp_str}.pcap")
        
        logging.info(f"Capturing on {INTERFACE} for {CAPTURE_DURATION} seconds...")
        
        # Capture packets with tshark
        # Step 2: BPF filter (commented out for now - uncomment after testing)
        # '-f', 'not (arp or (icmp6 and ip6[40] == 135) or (icmp6 and ip6[40] == 136))',
        capture_cmd = [
            'sudo', 'tshark', '-i', INTERFACE,
            '-a', f'duration:{CAPTURE_DURATION}',
            '-w', pcap_file,
            '-q'  # Quiet mode
        ]
        
        result = subprocess.run(capture_cmd, capture_output=True, text=True, timeout=CAPTURE_DURATION + 10)
        
        if result.returncode != 0:
            logging.error(f"Capture failed: {result.stderr}")
            return
        
        # Analyze captured file
        logging.info(f"Analyzing captured packets...")
        
        analyze_cmd = [
            'sudo', 'tshark', '-r', pcap_file,
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'frame.protocols',
            # Enhancement Step 1: More packet details
            '-e', 'tcp.flags',
            '-e', 'tcp.flags.syn',
            '-e', 'tcp.flags.ack',
            '-e', 'tcp.flags.fin',
            '-e', 'tcp.flags.reset',
            '-e', 'ip.ttl',
            '-e', 'tcp.window_size_value',
            # Enhancement Step 3: Deep packet inspection
            '-e', 'http.host',
            '-e', 'http.request.uri',
            '-e', 'http.request.method',
            '-e', 'http.user_agent',
            '-e', 'http.response.code',
            '-e', 'dns.qry.name',
            '-e', 'dns.qry.type',
            '-e', 'dns.a',
            '-e', 'tls.handshake.type',
            '-e', 'tls.handshake.extensions_server_name'
        ]
        
        result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=120)
        
        if not result.stdout or result.stdout.strip() == "":
            logging.warning(f"No data captured - stdout empty. Stderr: {result.stderr[:200]}")
            return
        
        # Parse JSON output
        try:
            packets = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON: {e}. First 500 chars: {result.stdout[:500]}")
            return
        
        if not packets:
            logging.warning(f"No packets parsed")
            return
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        create_table(conn, table_name)
        cursor = conn.cursor()
        
        # Insert packets
        inserted = 0
        for packet in packets:
            try:
                layers = packet.get('_source', {}).get('layers', {})
                
                # Basic fields
                frame_number = layers.get('frame.number', [''])[0]
                frame_time = layers.get('frame.time', [''])[0]
                frame_len = layers.get('frame.len', [''])[0]
                src_ip = layers.get('ip.src', [''])[0]
                dest_ip = layers.get('ip.dst', [''])[0]
                protocols = layers.get('frame.protocols', [''])[0]
                info = ''
                
                # Get ports
                src_port = layers.get('tcp.srcport', layers.get('udp.srcport', ['']))[0]
                dest_port = layers.get('tcp.dstport', layers.get('udp.dstport', ['']))[0]
                
                # TCP flags and details
                tcp_flags = layers.get('tcp.flags', [''])[0]
                tcp_syn = 1 if layers.get('tcp.flags.syn', [''])[0] == '1' else 0
                tcp_ack = 1 if layers.get('tcp.flags.ack', [''])[0] == '1' else 0
                tcp_fin = 1 if layers.get('tcp.flags.fin', [''])[0] == '1' else 0
                tcp_rst = 1 if layers.get('tcp.flags.reset', [''])[0] == '1' else 0
                ip_ttl = layers.get('ip.ttl', [''])[0]
                tcp_window_size = layers.get('tcp.window_size_value', [''])[0]
                
                # HTTP details
                http_host = layers.get('http.host', [''])[0]
                http_uri = layers.get('http.request.uri', [''])[0]
                http_method = layers.get('http.request.method', [''])[0]
                http_user_agent = layers.get('http.user_agent', [''])[0]
                http_response_code = layers.get('http.response.code', [''])[0]
                
                # DNS details
                dns_query = layers.get('dns.qry.name', [''])[0]
                dns_query_type = layers.get('dns.qry.type', [''])[0]
                dns_response = layers.get('dns.a', [''])[0]
                
                # TLS/SSL details
                tls_handshake_type = layers.get('tls.handshake.type', [''])[0]
                tls_server_name = layers.get('tls.handshake.extensions_server_name', [''])[0]
                
                # Step 5: GeoIP lookup for destination
                dest_country = None
                dest_city = None
                if dest_ip:
                    country_code, country_name = get_geoip_info(dest_ip)
                    if country_code:
                        dest_country = country_code
                        dest_city = country_name
                
                # Convert to int
                try:
                    src_port = int(src_port) if src_port else None
                    dest_port = int(dest_port) if dest_port else None
                    frame_number = int(frame_number) if frame_number else None
                    frame_len = int(frame_len) if frame_len else None
                    ip_ttl = int(ip_ttl) if ip_ttl else None
                    tcp_window_size = int(tcp_window_size) if tcp_window_size else None
                    http_response_code = int(http_response_code) if http_response_code else None
                except:
                    pass
                
                # Determine main protocol
                if 'tcp' in protocols.lower():
                    protocol = 'TCP'
                elif 'udp' in protocols.lower():
                    protocol = 'UDP'
                elif 'icmp' in protocols.lower():
                    protocol = 'ICMP'
                elif 'arp' in protocols.lower():
                    protocol = 'ARP'
                else:
                    protocol = protocols.split(':')[-1] if protocols else 'Unknown'
                
                # Calculate threat score based on patterns
                # FIXED: Smarter detection to reduce false positives
                threat_score = 0
                is_suspicious = 0
                
                # Get your local IP to differentiate inbound vs outbound
                local_ip = '192.168.1.244'  # Your wlo1 IP
                
                # High ports on DESTINATION = suspicious ONLY if it's NOT your outbound connection
                # Real backdoors: External IP connecting TO your high ports
                # False positive: You connecting FROM your high ports to external servers
                if dest_port and dest_port > 50000 and src_ip and src_ip != local_ip:
                    # External source trying to connect to high dest port = REAL THREAT
                    threat_score += 5
                    is_suspicious = 1
                
                # SYN without ACK = port scan attempt
                if tcp_syn and not tcp_ack and dest_ip and not dest_ip.startswith('192.168.'):
                    # Scanning external IPs = suspicious
                    threat_score += 3
                    is_suspicious = 1
                
                # RST flags from external sources = potential attack
                if tcp_rst and src_ip and not src_ip.startswith('192.168.'):
                    threat_score += 2
                
                # Low TTL = potential IP spoofing (but skip local traffic)
                if ip_ttl and ip_ttl < 32 and dest_ip and not dest_ip.startswith(('192.168.', '224.', '239.')):
                    threat_score += 4
                    is_suspicious = 1
                
                # Very small TCP window from external = potential attack
                if tcp_window_size and tcp_window_size < 1000 and src_ip and not src_ip.startswith('192.168.'):
                    threat_score += 2
                
                cursor.execute(f"""
                    INSERT INTO {table_name}
                    (timestamp, frame_number, frame_time, src_ip, src_port, dest_ip, dest_port,
                     protocol, length, info, tcp_flags, tcp_syn, tcp_ack, tcp_fin, tcp_rst,
                     ip_ttl, tcp_window_size, http_host, http_uri, http_method, http_user_agent,
                     http_response_code, dns_query, dns_query_type, dns_response, 
                     tls_handshake_type, tls_server_name, dest_country, dest_city, is_suspicious, threat_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (datetime.now().isoformat(), frame_number, frame_time, src_ip, src_port,
                      dest_ip, dest_port, protocol, frame_len, info[:500] if info else '', tcp_flags, tcp_syn, 
                      tcp_ack, tcp_fin, tcp_rst, ip_ttl, tcp_window_size, http_host, http_uri,
                      http_method, http_user_agent, http_response_code, dns_query, dns_query_type,
                      dns_response, tls_handshake_type, tls_server_name, dest_country, dest_city, 
                      is_suspicious, threat_score))
                
                inserted += 1
            except Exception as e:
                logging.debug(f"Error inserting packet: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logging.info(f"✓ Inserted {inserted} packets into '{table_name}'")
        
        # Clean up PCAP file to save space
        try:
            os.remove(pcap_file)
        except:
            pass
            
    except subprocess.TimeoutExpired:
        logging.error("Capture timeout")
    except Exception as e:
        logging.error(f"Error in capture/analyze: {e}")

def main():
    """Main collection loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - tshark Collector")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Collection interval: {COLLECT_INTERVAL} seconds")
    logging.info("=" * 60)
    
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    while True:
        try:
            capture_and_analyze()
            time.sleep(COLLECT_INTERVAL)
        except KeyboardInterrupt:
            logging.info("Shutting down tshark collector...")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(COLLECT_INTERVAL)

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""
NetGuard Pro - Professional tcpdump Collector
Captures and analyzes network packets with complete data extraction
Designed for zero data loss and comprehensive packet analysis
"""

import os
import sys
import time
import json
import sqlite3
import logging
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
INTERFACE = "wlo1"  # WiFi for comprehensive traffic capture
CAPTURE_DIR = "/home/jarvis/NetGuard/captures/tcpdump"
DB_PATH = "/home/jarvis/NetGuard/network.db"
LOG_DIR = "/home/jarvis/NetGuard/logs/system"
POSITION_FILE = "/home/jarvis/NetGuard/logs/system/tcpdump_position.json"

# Buffer settings for zero packet loss
BUFFER_SIZE_MB = 16  # 16MB buffer to prevent packet drops
SNAPLEN = 65535  # Full packet capture (max Ethernet frame)
RING_BUFFER_SIZE = 5  # Number of files in rotation
FILE_SIZE_MB = 50  # Size of each capture file (50MB)

# Create directories
os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{LOG_DIR}/tcpdump-collector.log'),
        logging.StreamHandler()
    ]
)

# Global process handle
tcpdump_process = None


def save_position(pcap_file, processed=True):
    """Track processed PCAP files"""
    try:
        positions = load_positions()
        positions[pcap_file] = {
            'processed': processed,
            'timestamp': datetime.now().isoformat()
        }
        with open(POSITION_FILE, 'w') as f:
            json.dump(positions, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving position: {e}")


def load_positions():
    """Load processed file positions"""
    if os.path.exists(POSITION_FILE):
        try:
            with open(POSITION_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}


def start_tcpdump():
    """Start tcpdump with professional configuration for zero packet loss"""
    global tcpdump_process
    
    try:
        if tcpdump_process and tcpdump_process.poll() is None:
            logging.info("tcpdump already running")
            return True
        
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = os.path.join(CAPTURE_DIR, f"capture_{timestamp_str}")
        
        logging.info(f"Starting tcpdump on {INTERFACE}")
        logging.info(f"Buffer: {BUFFER_SIZE_MB}MB, Snaplen: {SNAPLEN}, Ring buffer: {RING_BUFFER_SIZE} files")
        
        # Professional tcpdump configuration:
        # -i: interface
        # -B: buffer size in KB (prevents packet drops)
        # -s: snaplen - capture full packets
        # -w: output file with ring buffer and %03d suffix for rotation
        # -C: file size in MB before rotation
        # -W: number of files in ring buffer
        # -n: don't resolve hostnames (faster)
        # -U: packet-buffered output (immediate write)
        # -Z: drop privileges to user
        
        buffer_kb = BUFFER_SIZE_MB * 1024
        
        # Use %03d format for ring buffer rotation
        # Note: Running as root (via systemd), no need for sudo or -Z flag
        tcpdump_process = subprocess.Popen([
            'tcpdump',
            '-i', INTERFACE,
            '-B', str(buffer_kb),
            '-s', str(SNAPLEN),
            '-w', f"{base_filename}_%03d.pcap",
            '-C', str(FILE_SIZE_MB),
            '-W', str(RING_BUFFER_SIZE),
            '-n',
            '-U'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        
        logging.info(f"✓ tcpdump started: PID {tcpdump_process.pid}")
        logging.info(f"✓ Capture base: {base_filename}_*.pcap")
        
        return True
        
    except Exception as e:
        logging.error(f"Error starting tcpdump: {e}")
        return False


def create_table_if_not_exists(conn, table_name):
    """Create tcpdump table with comprehensive packet details"""
    cursor = conn.cursor()
    
    # Comprehensive packet capture schema
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            frame_number INTEGER,
            frame_time TEXT,
            frame_length INTEGER,
            
            -- Layer 2 (Ethernet)
            eth_src TEXT,
            eth_dst TEXT,
            eth_type TEXT,
            
            -- Layer 3 (IP)
            src_ip TEXT,
            dest_ip TEXT,
            ip_version INTEGER,
            ip_ttl INTEGER,
            ip_protocol TEXT,
            ip_len INTEGER,
            ip_id INTEGER,
            ip_flags TEXT,
            
            -- Layer 4 (TCP/UDP)
            src_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            
            -- TCP specific
            tcp_seq INTEGER,
            tcp_ack_num INTEGER,
            tcp_flags TEXT,
            tcp_syn INTEGER DEFAULT 0,
            tcp_ack INTEGER DEFAULT 0,
            tcp_fin INTEGER DEFAULT 0,
            tcp_rst INTEGER DEFAULT 0,
            tcp_psh INTEGER DEFAULT 0,
            tcp_urg INTEGER DEFAULT 0,
            tcp_window_size INTEGER,
            tcp_stream INTEGER,
            
            -- UDP specific
            udp_length INTEGER,
            
            -- Application layer
            dns_query TEXT,
            dns_response TEXT,
            http_method TEXT,
            http_host TEXT,
            http_uri TEXT,
            http_user_agent TEXT,
            http_status_code INTEGER,
            
            -- Analysis
            info TEXT,
            packet_data TEXT,
            is_suspicious INTEGER DEFAULT 0,
            threat_score INTEGER DEFAULT 0,
            
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Indexes for performance
    cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_src_ip ON {table_name}(src_ip)")
    cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_dest_ip ON {table_name}(dest_ip)")
    cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_protocol ON {table_name}(protocol)")
    cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_timestamp ON {table_name}(timestamp)")
    
    conn.commit()
    logging.debug(f"Table created: {table_name}")


def parse_packet_with_tshark(pcap_file):
    """Parse PCAP file using tshark for complete packet extraction"""
    try:
        if not os.path.exists(pcap_file):
            return []
        
        # Professional tshark command with all fields for zero data loss
        cmd = [
            'tshark',
            '-r', pcap_file,
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'frame.len',
            '-e', 'eth.src',
            '-e', 'eth.dst',
            '-e', 'eth.type',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ip.version',
            '-e', 'ip.ttl',
            '-e', 'ip.proto',
            '-e', 'ip.len',
            '-e', 'ip.id',
            '-e', 'ip.flags',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'tcp.seq',
            '-e', 'tcp.ack',
            '-e', 'tcp.flags',
            '-e', 'tcp.flags.syn',
            '-e', 'tcp.flags.ack',
            '-e', 'tcp.flags.fin',
            '-e', 'tcp.flags.reset',
            '-e', 'tcp.flags.push',
            '-e', 'tcp.flags.urg',
            '-e', 'tcp.window_size',
            '-e', 'tcp.stream',
            '-e', 'udp.length',
            '-e', 'dns.qry.name',
            '-e', 'dns.resp.name',
            '-e', 'http.request.method',
            '-e', 'http.host',
            '-e', 'http.request.uri',
            '-e', 'http.user_agent',
            '-e', 'http.response.code',
            '-e', 'ip.proto',
            '-e', '_ws.col.Protocol',
            '-e', '_ws.col.Info'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            logging.error(f"tshark parsing failed: {result.stderr}")
            return []
        
        # Parse JSON output
        packets = json.loads(result.stdout) if result.stdout.strip() else []
        
        logging.info(f"Parsed {len(packets)} packets from {pcap_file}")
        return packets
        
    except subprocess.TimeoutExpired:
        logging.error(f"tshark parsing timeout for {pcap_file}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error: {e}")
        return []
    except Exception as e:
        logging.error(f"Error parsing with tshark: {e}")
        return []


def extract_packet_data(packet_json):
    """Extract all data from tshark JSON packet"""
    try:
        layers = packet_json.get('_source', {}).get('layers', {})
        
        # Helper to get first element from list or return value
        def get_val(obj, key, default=None):
            val = obj.get(key, default)
            if isinstance(val, list) and len(val) > 0:
                return val[0]
            return val if val else default
        
        # Extract all fields
        data = {
            'timestamp': datetime.now().isoformat(),
            'frame_number': get_val(layers, 'frame.number'),
            'frame_time': get_val(layers, 'frame.time'),
            'frame_length': get_val(layers, 'frame.len'),
            
            # Ethernet
            'eth_src': get_val(layers, 'eth.src'),
            'eth_dst': get_val(layers, 'eth.dst'),
            'eth_type': get_val(layers, 'eth.type'),
            
            # IP
            'src_ip': get_val(layers, 'ip.src'),
            'dest_ip': get_val(layers, 'ip.dst'),
            'ip_version': get_val(layers, 'ip.version'),
            'ip_ttl': get_val(layers, 'ip.ttl'),
            'ip_protocol': get_val(layers, 'ip.proto'),
            'ip_len': get_val(layers, 'ip.len'),
            'ip_id': get_val(layers, 'ip.id'),
            'ip_flags': get_val(layers, 'ip.flags'),
            
            # Ports
            'src_port': get_val(layers, 'tcp.srcport') or get_val(layers, 'udp.srcport'),
            'dest_port': get_val(layers, 'tcp.dstport') or get_val(layers, 'udp.dstport'),
            
            # Protocol - derive from IP protocol number or use tshark column
            'protocol': get_val(layers, '_ws.col.Protocol') or (
                'TCP' if get_val(layers, 'tcp.srcport') else
                'UDP' if get_val(layers, 'udp.srcport') else
                'ICMP' if get_val(layers, 'ip.proto') == '1' else
                'IGMP' if get_val(layers, 'ip.proto') == '2' else
                'GRE' if get_val(layers, 'ip.proto') == '47' else
                f"IP-{get_val(layers, 'ip.proto')}" if get_val(layers, 'ip.proto') else None
            ),
            
            # TCP
            'tcp_seq': get_val(layers, 'tcp.seq'),
            'tcp_ack_num': get_val(layers, 'tcp.ack'),
            'tcp_flags': get_val(layers, 'tcp.flags'),
            'tcp_syn': 1 if get_val(layers, 'tcp.flags.syn') == '1' else 0,
            'tcp_ack': 1 if get_val(layers, 'tcp.flags.ack') == '1' else 0,
            'tcp_fin': 1 if get_val(layers, 'tcp.flags.fin') == '1' else 0,
            'tcp_rst': 1 if get_val(layers, 'tcp.flags.reset') == '1' else 0,
            'tcp_psh': 1 if get_val(layers, 'tcp.flags.push') == '1' else 0,
            'tcp_urg': 1 if get_val(layers, 'tcp.flags.urg') == '1' else 0,
            'tcp_window_size': get_val(layers, 'tcp.window_size'),
            'tcp_stream': get_val(layers, 'tcp.stream'),
            
            # UDP
            'udp_length': get_val(layers, 'udp.length'),
            
            # Application layer
            'dns_query': get_val(layers, 'dns.qry.name'),
            'dns_response': get_val(layers, 'dns.resp.name'),
            'http_method': get_val(layers, 'http.request.method'),
            'http_host': get_val(layers, 'http.host'),
            'http_uri': get_val(layers, 'http.request.uri'),
            'http_user_agent': get_val(layers, 'http.user_agent'),
            'http_status_code': get_val(layers, 'http.response.code'),
            
            # Info
            'info': get_val(layers, '_ws.col.Info'),
        }
        
        # Convert numeric strings to integers
        for key in ['frame_number', 'frame_length', 'ip_version', 'ip_ttl', 'ip_len', 'ip_id',
                    'src_port', 'dest_port', 'tcp_seq', 'tcp_ack_num', 'tcp_window_size',
                    'tcp_stream', 'udp_length', 'http_status_code']:
            if data.get(key):
                try:
                    data[key] = int(data[key])
                except:
                    data[key] = None
        
        # Threat analysis
        data['threat_score'] = 0
        data['is_suspicious'] = 0
        
        # Analyze for threats
        if data.get('dest_port') and data['dest_port'] > 50000 and data.get('tcp_syn'):
            data['threat_score'] += 3
        
        if data.get('tcp_rst') and data.get('tcp_syn'):
            data['threat_score'] += 2
        
        if data.get('ip_ttl') and data['ip_ttl'] < 30:
            data['threat_score'] += 1
        
        if data['threat_score'] > 3:
            data['is_suspicious'] = 1
        
        return data
        
    except Exception as e:
        logging.error(f"Error extracting packet data: {e}")
        return None


def insert_packets(conn, table_name, packets):
    """Insert parsed packets into database"""
    cursor = conn.cursor()
    inserted = 0
    
    for packet_json in packets:
        try:
            packet_data = extract_packet_data(packet_json)
            if not packet_data:
                continue
            
            # Insert packet
            columns = ', '.join(packet_data.keys())
            placeholders = ', '.join(['?' for _ in packet_data])
            
            cursor.execute(
                f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})",
                list(packet_data.values())
            )
            inserted += 1
            
        except Exception as e:
            logging.error(f"Error inserting packet: {e}")
            continue
    
    conn.commit()
    return inserted


def collect_and_analyze():
    """Collect PCAP files and analyze them"""
    try:
        # Find unprocessed PCAP files
        positions = load_positions()
        pcap_files = sorted(Path(CAPTURE_DIR).glob("capture_*.pcap"))
        
        for pcap_file in pcap_files:
            pcap_path = str(pcap_file)
            
            # Skip if already processed
            if pcap_path in positions and positions[pcap_path].get('processed'):
                continue
            
            # Check if file is still being written (size changing)
            try:
                size1 = os.path.getsize(pcap_path)
                time.sleep(2)
                size2 = os.path.getsize(pcap_path)
                
                if size1 != size2:
                    logging.debug(f"Skipping {pcap_path} - still being written")
                    continue
            except:
                continue
            
            logging.info(f"Processing: {pcap_file.name}")
            
            # Parse with tshark
            packets = parse_packet_with_tshark(pcap_path)
            
            if not packets:
                logging.warning(f"No packets parsed from {pcap_file.name}")
                save_position(pcap_path, processed=True)
                continue
            
            # Create table
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            table_name = f"tcpdump_{timestamp_str}"
            
            conn = sqlite3.connect(DB_PATH)
            create_table_if_not_exists(conn, table_name)
            
            # Insert packets
            inserted = insert_packets(conn, table_name, packets)
            conn.close()
            
            logging.info(f"✓ Inserted {inserted} packets into {table_name}")
            
            # Mark as processed
            save_position(pcap_path, processed=True)
            
        return True
        
    except Exception as e:
        logging.error(f"Error in collect_and_analyze: {e}")
        return False


def cleanup_old_pcaps():
    """Clean up old processed PCAP files to save disk space"""
    try:
        positions = load_positions()
        pcap_files = sorted(Path(CAPTURE_DIR).glob("capture_*.pcap"))
        
        # Keep only the last 10 processed files
        processed_files = [f for f in pcap_files if str(f) in positions and positions[str(f)].get('processed')]
        
        if len(processed_files) > 10:
            for old_file in processed_files[:-10]:
                try:
                    os.remove(old_file)
                    logging.info(f"Cleaned up: {old_file.name}")
                except:
                    pass
                    
    except Exception as e:
        logging.error(f"Error in cleanup: {e}")


def main():
    """Main collector loop"""
    logging.info("=" * 60)
    logging.info("NetGuard Pro - tcpdump Collector Starting")
    logging.info("=" * 60)
    logging.info(f"Interface: {INTERFACE}")
    logging.info(f"Buffer: {BUFFER_SIZE_MB}MB, Snaplen: {SNAPLEN}")
    logging.info(f"Ring buffer: {RING_BUFFER_SIZE} files x {FILE_SIZE_MB}MB")
    logging.info(f"Database: {DB_PATH}")
    
    # Start tcpdump
    if not start_tcpdump():
        logging.error("Failed to start tcpdump")
        return 1
    
    logging.info("✓ tcpdump capture active")
    logging.info("Starting packet analysis loop...")
    
    cycle = 0
    
    try:
        while True:
            cycle += 1
            logging.info(f"\n{'='*60}")
            logging.info(f"Analysis Cycle {cycle}")
            logging.info(f"{'='*60}")
            
            # Collect and analyze
            collect_and_analyze()
            
            # Cleanup old files every 10 cycles
            if cycle % 10 == 0:
                cleanup_old_pcaps()
            
            # Check if tcpdump is still running
            if tcpdump_process and tcpdump_process.poll() is not None:
                logging.warning("tcpdump stopped unexpectedly, restarting...")
                start_tcpdump()
            
            # Wait before next cycle
            time.sleep(60)  # Analyze every 60 seconds
            
    except KeyboardInterrupt:
        logging.info("\n✓ Shutdown signal received")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1
    finally:
        # Cleanup
        if tcpdump_process and tcpdump_process.poll() is None:
            logging.info("Stopping tcpdump...")
            tcpdump_process.terminate()
            try:
                tcpdump_process.wait(timeout=5)
            except:
                tcpdump_process.kill()
        
        logging.info("✓ tcpdump collector stopped")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())


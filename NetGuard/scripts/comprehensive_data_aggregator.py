#!/usr/bin/env python3
"""
NetGuard Pro - Comprehensive Data Aggregator
Collects data from ALL monitoring tools for AI analysis
Tools: Suricata, tcpdump, tshark, argus, ngrep, netsniff, httpry, iftop, nethogs
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

DB_PATH = "/home/jarvis/NetGuard/network.db"
CONFIG_PATH = "/home/jarvis/NetGuard/config/ai_config.json"
EXPORT_DIR = "/home/jarvis/NetGuard/exports"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def load_config():
    """Load configuration from JSON file"""
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Config file not found: {CONFIG_PATH}")
        return None


def get_latest_table(prefix):
    """Get the most recent table for a given prefix"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute(f"""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name LIKE '{prefix}_%' 
        AND name NOT LIKE '%template%'
        ORDER BY name DESC 
        LIMIT 1
    """)
    
    result = cursor.fetchone()
    conn.close()
    
    return result[0] if result else None


def get_suricata_alerts(time_window_minutes=5):
    """Get Suricata IDS alerts"""
    table = get_latest_table('suricata_alerts')
    if not table:
        logging.warning("No Suricata alerts table found")
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Get recent alerts
        cursor.execute(f"""
            SELECT * FROM {table} 
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        
        alerts = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            alert = {
                'timestamp': row_dict.get('timestamp'),
                'alert': row_dict.get('alert'),
                'src_ip': row_dict.get('src_ip'),
                'src_port': row_dict.get('src_port'),
                'dest_ip': row_dict.get('dest_ip'),
                'dest_port': row_dict.get('dest_port'),
                'proto': row_dict.get('proto'),
                'severity': row_dict.get('severity', 'unknown'),
                'category': row_dict.get('category', 'unknown'),
                'signature_id': row_dict.get('signature_id')
            }
            alerts.append(alert)
        
        logging.info(f"✓ Collected {len(alerts)} Suricata alerts from {table}")
        return alerts
        
    except Exception as e:
        logging.error(f"Error collecting Suricata data: {e}")
        return []
    finally:
        conn.close()


def get_tcpdump_data(max_packets=1000):
    """Get tcpdump packet captures"""
    table = get_latest_table('tcpdump')
    if not table:
        logging.warning("No tcpdump table found")
        return {'packets': [], 'summary': {}}
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(f"""
            SELECT * FROM {table} 
            ORDER BY id DESC 
            LIMIT {max_packets}
        """)
        
        packets = [dict(row) for row in cursor.fetchall()]
        
        # Aggregate summary
        total_bytes = sum(p.get('frame_length', 0) or 0 for p in packets)
        protocols = defaultdict(int)
        src_ips = set()
        dst_ips = set()
        
        for p in packets:
            if p.get('protocol'):
                protocols[p['protocol']] += 1
            if p.get('src_ip'):
                src_ips.add(p['src_ip'])
            if p.get('dest_ip'):
                dst_ips.add(p['dest_ip'])
        
        summary = {
            'total_packets': len(packets),
            'total_bytes': total_bytes,
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'protocols': dict(protocols)
        }
        
        logging.info(f"✓ Collected {len(packets)} tcpdump packets from {table}")
        return {'packets': packets[:100], 'summary': summary}  # Limit to 100 for AI
        
    except Exception as e:
        logging.error(f"Error collecting tcpdump data: {e}")
        return {'packets': [], 'summary': {}}
    finally:
        conn.close()


def get_tshark_data(time_window_minutes=5):
    """Get tshark analysis data"""
    # Get most recent tshark table
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Find recent tshark tables (format: YYYYMMDD_HHMMSS)
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name GLOB '[0-9]*_[0-9]*'
            AND name NOT LIKE 'tcpdump_%'
            AND name NOT LIKE 'suricata_%'
            AND name NOT LIKE 'argus_%'
            ORDER BY name DESC 
            LIMIT 5
        """)
        
        tables = [row[0] for row in cursor.fetchall()]
        
        if not tables:
            logging.warning("No tshark tables found")
            return []
        
        conn.row_factory = sqlite3.Row
        all_packets = []
        
        for table in tables[:3]:  # Check last 3 tables
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 50")
                packets = [dict(row) for row in cursor.fetchall()]
                all_packets.extend(packets)
            except:
                continue
        
        logging.info(f"✓ Collected {len(all_packets)} tshark packets from {len(tables)} tables")
        return all_packets[:100]  # Limit to 100
        
    except Exception as e:
        logging.error(f"Error collecting tshark data: {e}")
        return []
    finally:
        conn.close()


def get_httpry_data():
    """Get HTTP transaction logs"""
    table = get_latest_table('httpry')
    if not table:
        logging.warning("No httpry table found")
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(f"""
            SELECT * FROM {table} 
            ORDER BY timestamp DESC 
            LIMIT 50
        """)
        
        requests = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            req = {
                'timestamp': row_dict.get('timestamp'),
                'src_ip': row_dict.get('src_ip'),
                'dest_ip': row_dict.get('dest_ip'),
                'method': row_dict.get('method'),
                'host': row_dict.get('host'),
                'uri': row_dict.get('uri'),
                'status_code': row_dict.get('status_code'),
                'content_type': row_dict.get('content_type')
            }
            requests.append(req)
        
        logging.info(f"✓ Collected {len(requests)} HTTP requests from {table}")
        return requests
        
    except Exception as e:
        logging.error(f"Error collecting httpry data: {e}")
        return []
    finally:
        conn.close()


def get_argus_flows():
    """Get network flow data from argus"""
    table = get_latest_table('argus')
    if not table:
        logging.warning("No argus table found")
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(f"""
            SELECT * FROM {table} 
            ORDER BY start_time DESC 
            LIMIT 100
        """)
        
        flows = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            flow = {
                'start_time': row_dict.get('start_time'),
                'duration': row_dict.get('duration'),
                'proto': row_dict.get('proto'),
                'src_ip': row_dict.get('src_ip'),
                'src_port': row_dict.get('src_port'),
                'dst_ip': row_dict.get('dst_ip'),
                'dst_port': row_dict.get('dst_port'),
                'packets': row_dict.get('packets'),
                'bytes': row_dict.get('bytes'),
                'state': row_dict.get('state')
            }
            flows.append(flow)
        
        logging.info(f"✓ Collected {len(flows)} network flows from {table}")
        return flows
        
    except Exception as e:
        logging.error(f"Error collecting argus data: {e}")
        return []
    finally:
        conn.close()


def aggregate_all_data(config):
    """Aggregate data from all monitoring tools"""
    
    logging.info("=" * 60)
    logging.info("NetGuard Pro - Comprehensive Data Aggregation")
    logging.info("=" * 60)
    
    time_window = config.get('data_collection', {}).get('time_window_minutes', 5)
    max_packets = config.get('data_collection', {}).get('max_packets_to_analyze', 1000)
    
    # Collect from all tools
    data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'time_window_minutes': time_window,
            'data_source': 'NetGuard Pro - All Tools',
            'version': '2.0'
        },
        
        # Suricata IDS Alerts (CRITICAL - Security threats)
        'suricata_alerts': get_suricata_alerts(time_window),
        
        # tcpdump - Full packet captures
        'tcpdump': get_tcpdump_data(max_packets),
        
        # tshark - Detailed packet analysis
        'tshark_packets': get_tshark_data(time_window),
        
        # httpry - HTTP traffic
        'http_traffic': get_httpry_data(),
        
        # argus - Network flows
        'network_flows': get_argus_flows(),
    }
    
    # Calculate overall statistics
    data['overall_statistics'] = {
        'suricata_alerts_count': len(data['suricata_alerts']),
        'tcpdump_packets_count': data['tcpdump']['summary'].get('total_packets', 0),
        'tshark_packets_count': len(data['tshark_packets']),
        'http_requests_count': len(data['http_traffic']),
        'network_flows_count': len(data['network_flows']),
        'total_data_points': (
            len(data['suricata_alerts']) +
            data['tcpdump']['summary'].get('total_packets', 0) +
            len(data['tshark_packets']) +
            len(data['http_traffic']) +
            len(data['network_flows'])
        )
    }
    
    logging.info("=" * 60)
    logging.info("📊 DATA COLLECTION SUMMARY:")
    logging.info("=" * 60)
    logging.info(f"  Suricata Alerts:   {data['overall_statistics']['suricata_alerts_count']}")
    logging.info(f"  tcpdump Packets:   {data['overall_statistics']['tcpdump_packets_count']}")
    logging.info(f"  tshark Packets:    {data['overall_statistics']['tshark_packets_count']}")
    logging.info(f"  HTTP Requests:     {data['overall_statistics']['http_requests_count']}")
    logging.info(f"  Network Flows:     {data['overall_statistics']['network_flows_count']}")
    logging.info(f"  Total Data Points: {data['overall_statistics']['total_data_points']}")
    logging.info("=" * 60)
    
    return data


def export_for_ai(data):
    """Export aggregated data in AI-friendly format"""
    
    # Create exports directory
    Path(EXPORT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{EXPORT_DIR}/comprehensive_export_{timestamp}.json"
    
    # Save full export
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    logging.info(f"✓ Saved comprehensive export to: {filename}")
    
    return filename, data


if __name__ == "__main__":
    # Load configuration
    config = load_config()
    
    if not config:
        logging.error("Failed to load configuration")
        exit(1)
    
    # Aggregate data from all tools
    aggregated_data = aggregate_all_data(config)
    
    # Export for AI
    export_file, data = export_for_ai(aggregated_data)
    
    logging.info("=" * 60)
    logging.info("✅ Comprehensive Data Aggregation Complete!")
    logging.info(f"📁 Export file: {export_file}")
    logging.info("=" * 60)


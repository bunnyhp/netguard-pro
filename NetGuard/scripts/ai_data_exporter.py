#!/usr/bin/env python3
"""
NetGuard Pro - AI Data Export Module
Aggregates network data from all collectors and exports to AI service
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict

DB_PATH = "/home/jarvis/NetGuard/network.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


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


def get_time_window_data(minutes=5):
    """Get data from the last N minutes"""
    cutoff_time = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    return cutoff_time


def aggregate_tcpdump_data(time_window_minutes=5):
    """Aggregate tcpdump packet data for AI analysis"""
    table = get_latest_table('tcpdump')
    if not table:
        return None
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Get all packets from the table (most recent captures)
        cursor.execute(f"""
            SELECT * FROM {table} 
            ORDER BY id DESC 
            LIMIT 1000
        """)
        
        packets = [dict(row) for row in cursor.fetchall()]
        
        if not packets:
            return None
        
        # Aggregate network metrics
        total_packets = len(packets)
        total_bytes = sum(p.get('frame_length', 0) or 0 for p in packets)
        
        # Protocol distribution
        protocols = defaultdict(int)
        for p in packets:
            proto = p.get('protocol')
            if proto:
                protocols[proto] += 1
        
        protocol_dist = {
            proto: round((count / total_packets) * 100, 1) 
            for proto, count in protocols.items()
        }
        
        # Unique IPs
        src_ips = set(p.get('src_ip') for p in packets if p.get('src_ip'))
        dst_ips = set(p.get('dest_ip') for p in packets if p.get('dest_ip'))
        
        # Device activity tracking
        device_activity = defaultdict(lambda: {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'connections': 0,
            'protocols': set(),
            'destinations': set(),
            'ports_accessed': set()
        })
        
        for p in packets:
            src = p.get('src_ip')
            dst = p.get('dest_ip')
            proto = p.get('protocol')
            length = p.get('frame_length', 0) or 0
            dst_port = p.get('dest_port')
            
            if src and src.startswith('192.168.'):
                device_activity[src]['packets_sent'] += 1
                device_activity[src]['bytes_sent'] += length
                if dst:
                    device_activity[src]['destinations'].add(dst)
                if proto:
                    device_activity[src]['protocols'].add(proto)
                if dst_port:
                    device_activity[src]['ports_accessed'].add(dst_port)
            
            if dst and dst.startswith('192.168.'):
                device_activity[dst]['packets_received'] += 1
                device_activity[dst]['bytes_received'] += length
        
        # Port activity analysis
        high_ports = [p.get('dest_port') for p in packets 
                      if p.get('dest_port') and p.get('dest_port') > 50000]
        
        sequential_ports = False
        if len(high_ports) > 3:
            sorted_ports = sorted(set(high_ports))
            if len(sorted_ports) > 2:
                sequential_ports = all(
                    sorted_ports[i+1] - sorted_ports[i] <= 5 
                    for i in range(len(sorted_ports)-1)
                )
        
        return {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'protocol_distribution': protocol_dist,
            'devices': [
                {
                    'ip': ip,
                    'packets_sent': stats['packets_sent'],
                    'packets_received': stats['packets_received'],
                    'bytes_sent': stats['bytes_sent'],
                    'bytes_received': stats['bytes_received'],
                    'unique_destinations': len(stats['destinations']),
                    'protocols_used': list(stats['protocols']),
                    'ports_accessed': list(stats['ports_accessed'])[:20]  # Limit size
                }
                for ip, stats in device_activity.items()
            ],
            'port_activity': {
                'high_ports_accessed': list(set(high_ports))[:20],
                'sequential_ports': sequential_ports,
                'total_high_port_access': len(high_ports)
            }
        }
        
    except Exception as e:
        logging.error(f"Error aggregating tcpdump data: {e}")
        return None
    finally:
        conn.close()


def aggregate_connection_data():
    """Get detailed connection information"""
    table = get_latest_table('tcpdump')
    if not table:
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Get connections with complete info
        cursor.execute(f"""
            SELECT 
                src_ip, dest_ip, src_port, dest_port, protocol,
                COUNT(*) as packets,
                SUM(frame_length) as bytes,
                tcp_syn, tcp_ack, tcp_fin, tcp_rst
            FROM {table}
            WHERE src_ip IS NOT NULL AND dest_ip IS NOT NULL
            GROUP BY src_ip, dest_ip, src_port, dest_port, protocol
            LIMIT 100
        """)
        
        connections = []
        for row in cursor.fetchall():
            conn_data = dict(row)
            # Calculate flags
            tcp_flags = []
            if conn_data.get('tcp_syn'):
                tcp_flags.append('SYN')
            if conn_data.get('tcp_ack'):
                tcp_flags.append('ACK')
            if conn_data.get('tcp_fin'):
                tcp_flags.append('FIN')
            if conn_data.get('tcp_rst'):
                tcp_flags.append('RST')
            
            connections.append({
                'src_ip': conn_data['src_ip'],
                'dst_ip': conn_data['dest_ip'],
                'src_port': conn_data.get('src_port'),
                'dst_port': conn_data.get('dest_port'),
                'protocol': conn_data.get('protocol'),
                'packets': conn_data['packets'],
                'bytes': conn_data.get('bytes', 0),
                'tcp_flags': tcp_flags
            })
        
        return connections
        
    except Exception as e:
        logging.error(f"Error aggregating connections: {e}")
        return []
    finally:
        conn.close()


def get_dns_queries():
    """Extract DNS query information"""
    table = get_latest_table('tcpdump')
    if not table:
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(f"""
            SELECT src_ip, dns_query, timestamp
            FROM {table}
            WHERE dns_query IS NOT NULL AND dns_query != ''
            ORDER BY id DESC
            LIMIT 50
        """)
        
        queries = []
        for row in cursor.fetchall():
            queries.append({
                'query': row['dns_query'],
                'source_ip': row['src_ip'],
                'timestamp': row['timestamp']
            })
        
        return queries
        
    except Exception as e:
        logging.error(f"Error getting DNS queries: {e}")
        return []
    finally:
        conn.close()


def get_http_traffic():
    """Extract HTTP traffic information"""
    table = get_latest_table('tcpdump')
    if not table:
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute(f"""
            SELECT src_ip, dest_ip, http_method, http_host, http_uri, 
                   http_status_code, frame_length, timestamp
            FROM {table}
            WHERE http_method IS NOT NULL
            ORDER BY id DESC
            LIMIT 50
        """)
        
        traffic = []
        for row in cursor.fetchall():
            traffic.append({
                'source_ip': row['src_ip'],
                'destination_ip': row['dest_ip'],
                'method': row['http_method'],
                'host': row['http_host'],
                'url': row['http_uri'],
                'status_code': row['http_status_code'],
                'bytes': row['frame_length'],
                'timestamp': row['timestamp']
            })
        
        return traffic
        
    except Exception as e:
        logging.error(f"Error getting HTTP traffic: {e}")
        return []
    finally:
        conn.close()


def export_to_ai_format(time_window_minutes=5):
    """
    Export aggregated network data in AI-ready JSON format
    
    Returns a comprehensive JSON structure with:
    - Network metrics
    - Device activity
    - Connection details
    - DNS queries
    - HTTP traffic
    - Port activity
    """
    
    logging.info(f"Exporting data for {time_window_minutes}-minute window...")
    
    # Aggregate all data
    network_data = aggregate_tcpdump_data(time_window_minutes)
    
    if not network_data:
        logging.warning("No network data available")
        return None
    
    connections = aggregate_connection_data()
    dns_queries = get_dns_queries()
    http_traffic = get_http_traffic()
    
    # Build comprehensive export
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "time_window": f"{time_window_minutes}m",
        "data_source": "NetGuard Pro",
        "version": "1.0",
        
        "network_metrics": {
            "total_packets": network_data['total_packets'],
            "total_bytes": network_data['total_bytes'],
            "unique_src_ips": network_data['unique_src_ips'],
            "unique_dst_ips": network_data['unique_dst_ips'],
            "protocol_distribution": network_data['protocol_distribution']
        },
        
        "devices": network_data['devices'],
        
        "connections": connections,
        
        "dns_queries": dns_queries,
        
        "http_traffic": http_traffic,
        
        "port_activity": network_data['port_activity'],
        
        "analysis_request": {
            "detect_threats": True,
            "detect_anomalies": True,
            "classify_urls": True,
            "profile_devices": True,
            "generate_alerts": True,
            "min_confidence": 0.75
        }
    }
    
    logging.info(f"✓ Exported {len(export_data['devices'])} devices, "
                f"{len(connections)} connections, "
                f"{len(dns_queries)} DNS queries")
    
    return export_data


def save_export_to_file(data, filename=None):
    """Save export data to JSON file for testing"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"/home/jarvis/NetGuard/exports/ai_export_{timestamp}.json"
    
    import os
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    logging.info(f"✓ Saved export to {filename}")
    return filename


if __name__ == "__main__":
    logging.info("=" * 60)
    logging.info("NetGuard Pro - AI Data Export Test")
    logging.info("=" * 60)
    
    # Export data
    data = export_to_ai_format(time_window_minutes=5)
    
    if data:
        # Save to file
        filename = save_export_to_file(data)
        
        # Display summary
        print("\n" + "=" * 60)
        print("📊 EXPORT SUMMARY")
        print("=" * 60)
        print(f"Timestamp: {data['timestamp']}")
        print(f"Time Window: {data['time_window']}")
        print(f"\nNetwork Metrics:")
        print(f"  • Total Packets: {data['network_metrics']['total_packets']}")
        print(f"  • Total Bytes: {data['network_metrics']['total_bytes']:,}")
        print(f"  • Unique Sources: {data['network_metrics']['unique_src_ips']}")
        print(f"  • Unique Destinations: {data['network_metrics']['unique_dst_ips']}")
        print(f"\nData Counts:")
        print(f"  • Devices: {len(data['devices'])}")
        print(f"  • Connections: {len(data['connections'])}")
        print(f"  • DNS Queries: {len(data['dns_queries'])}")
        print(f"  • HTTP Requests: {len(data['http_traffic'])}")
        print(f"\n✓ Export saved to: {filename}")
        print("=" * 60)
    else:
        print("❌ No data to export")


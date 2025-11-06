#!/usr/bin/env python3
"""
NetGuard Pro - Flask Web Dashboard
Professional web interface for network monitoring data
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
import os
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netguard-pro-secure-key-change-in-production'

# Configuration
DB_PATH = "/home/jarvis/NetGuard/network.db"

def get_db_connection():
    """Create database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_all_tables():
    """Get all tables in database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row['name'] for row in cursor.fetchall()]
    conn.close()
    return tables

def get_tables_by_prefix(prefix):
    """Get tables with specific prefix"""
    all_tables = get_all_tables()
    return [t for t in all_tables if t.startswith(prefix) and not t.endswith('_template')]

def get_table_count(table_name):
    """Get record count for a table"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
        count = cursor.fetchone()['count']
        conn.close()
        return count
    except:
        return 0

def get_table_data(table_name, limit=1000):
    """Get data from a table"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT {limit}")
        rows = cursor.fetchall()
        
        # Convert to list of dicts
        data = []
        for row in rows:
            data.append(dict(row))
        
        conn.close()
        return data
    except Exception as e:
        print(f"Error fetching data from {table_name}: {e}")
        return []

def get_tshark_statistics(tables):
    """Get comprehensive statistics for tshark data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Combine all tshark tables for analysis
        stats = {
            'total_packets': 0,
            'protocols': {},
            'top_sources': {},
            'top_destinations': {},
            'port_activity': {},
            'packet_sizes': {'small': 0, 'medium': 0, 'large': 0},
            'suspicious_activity': [],
            'http_hosts': {},
            'dns_queries': {},
            'tls_servers': {},
            'countries': {},
            'tcp_flags_distribution': {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0}
        }
        
        for table in tables:
            try:
                # Get protocol distribution
                cursor.execute(f"SELECT protocol, COUNT(*) as cnt FROM {table} WHERE protocol IS NOT NULL AND protocol != '' GROUP BY protocol")
                for row in cursor.fetchall():
                    proto = row[0]
                    count = row[1]
                    stats['protocols'][proto] = stats['protocols'].get(proto, 0) + count
                    stats['total_packets'] += count
                
                # Get top source IPs
                cursor.execute(f"SELECT src_ip, COUNT(*) as cnt FROM {table} WHERE src_ip IS NOT NULL AND src_ip != '' GROUP BY src_ip ORDER BY cnt DESC LIMIT 10")
                for row in cursor.fetchall():
                    ip = row[0]
                    count = row[1]
                    stats['top_sources'][ip] = stats['top_sources'].get(ip, 0) + count
                
                # Get top destination IPs
                cursor.execute(f"SELECT dest_ip, COUNT(*) as cnt FROM {table} WHERE dest_ip IS NOT NULL AND dest_ip != '' GROUP BY dest_ip ORDER BY cnt DESC LIMIT 10")
                for row in cursor.fetchall():
                    ip = row[0]
                    count = row[1]
                    stats['top_destinations'][ip] = stats['top_destinations'].get(ip, 0) + count
                
                # Get port activity
                cursor.execute(f"SELECT dest_port, COUNT(*) as cnt FROM {table} WHERE dest_port IS NOT NULL GROUP BY dest_port ORDER BY cnt DESC LIMIT 15")
                for row in cursor.fetchall():
                    port = row[0]
                    count = row[1]
                    stats['port_activity'][port] = stats['port_activity'].get(port, 0) + count
                
                # Analyze packet sizes
                cursor.execute(f"SELECT length FROM {table} WHERE length IS NOT NULL")
                for row in cursor.fetchall():
                    size = row[0]
                    if size <= 100:
                        stats['packet_sizes']['small'] += 1
                    elif size <= 500:
                        stats['packet_sizes']['medium'] += 1
                    else:
                        stats['packet_sizes']['large'] += 1
                
                # Collect HTTP hosts
                cursor.execute(f"SELECT http_host, COUNT(*) as cnt FROM {table} WHERE http_host IS NOT NULL AND http_host != '' GROUP BY http_host ORDER BY cnt DESC LIMIT 10")
                for row in cursor.fetchall():
                    host = row[0]
                    count = row[1]
                    stats['http_hosts'][host] = stats['http_hosts'].get(host, 0) + count
                
                # Collect DNS queries
                cursor.execute(f"SELECT dns_query, COUNT(*) as cnt FROM {table} WHERE dns_query IS NOT NULL AND dns_query != '' GROUP BY dns_query ORDER BY cnt DESC LIMIT 10")
                for row in cursor.fetchall():
                    query = row[0]
                    count = row[1]
                    stats['dns_queries'][query] = stats['dns_queries'].get(query, 0) + count
                
                # Collect TLS server names
                cursor.execute(f"SELECT tls_server_name, COUNT(*) as cnt FROM {table} WHERE tls_server_name IS NOT NULL AND tls_server_name != '' GROUP BY tls_server_name ORDER BY cnt DESC LIMIT 10")
                for row in cursor.fetchall():
                    server = row[0]
                    count = row[1]
                    stats['tls_servers'][server] = stats['tls_servers'].get(server, 0) + count
                
                # Collect country distribution
                cursor.execute(f"SELECT dest_country, COUNT(*) as cnt FROM {table} WHERE dest_country IS NOT NULL GROUP BY dest_country ORDER BY cnt DESC")
                for row in cursor.fetchall():
                    country = row[0]
                    count = row[1]
                    stats['countries'][country] = stats['countries'].get(country, 0) + count
                
                # TCP flags distribution
                cursor.execute(f"SELECT SUM(tcp_syn), SUM(tcp_ack), SUM(tcp_fin), SUM(tcp_rst) FROM {table}")
                flags = cursor.fetchone()
                if flags:
                    stats['tcp_flags_distribution']['SYN'] += flags[0] or 0
                    stats['tcp_flags_distribution']['ACK'] += flags[1] or 0
                    stats['tcp_flags_distribution']['FIN'] += flags[2] or 0
                    stats['tcp_flags_distribution']['RST'] += flags[3] or 0
                
                # Step 6: Enhanced anomaly detection patterns
                
                # 1. FIXED: High port backdoor detection - only flag INCOMING connections to same high port
                # Multiple external sources connecting to YOUR high port = backdoor
                cursor.execute(f"SELECT dest_port, COUNT(DISTINCT src_ip) as unique_sources, COUNT(*) as total FROM {table} WHERE dest_port > 50000 AND src_ip NOT LIKE '192.168.%' GROUP BY dest_port HAVING unique_sources > 3")
                for row in cursor.fetchall():
                    stats['suspicious_activity'].append({
                        'type': 'Potential Backdoor Detected',
                        'detail': f'Port {row[0]}: {row[1]} different external IPs connecting ({row[2]} total connections)',
                        'severity': 'high'
                    })
                
                # 2. FIXED: Port scan detection - outbound SYN to many different ports
                cursor.execute(f"SELECT src_ip, COUNT(DISTINCT dest_port) as unique_ports, COUNT(*) as total FROM {table} WHERE tcp_syn = 1 AND tcp_ack = 0 AND dest_ip NOT LIKE '192.168.%' GROUP BY src_ip HAVING unique_ports > 20")
                for row in cursor.fetchall():
                    stats['suspicious_activity'].append({
                        'type': 'Port Scan Detected',
                        'detail': f'Source {row[0]} scanning {row[1]} different ports ({row[2]} SYN attempts)',
                        'severity': 'high'
                    })
                
                # 3. DNS tunneling detection (very long queries)
                cursor.execute(f"SELECT dns_query, LENGTH(dns_query) as len FROM {table} WHERE dns_query IS NOT NULL AND LENGTH(dns_query) > 100 LIMIT 5")
                for row in cursor.fetchall():
                    if row[0]:
                        stats['suspicious_activity'].append({
                            'type': 'DNS Tunneling Suspected',
                            'detail': f'Abnormally long DNS query ({row[1]} chars): {row[0][:50]}...',
                            'severity': 'high'
                        })
                
                # 4. Connection resets (potential attacks or blocked connections)
                cursor.execute(f"SELECT COUNT(*) as rst_count FROM {table} WHERE tcp_rst = 1")
                rst_count = cursor.fetchone()[0]
                if rst_count > 100:
                    stats['suspicious_activity'].append({
                        'type': 'High RST Packet Count',
                        'detail': f'{rst_count} connection resets detected',
                        'severity': 'medium'
                    })
                
                # 5. Suspicious countries (customize based on your threat model)
                cursor.execute(f"SELECT dest_country, COUNT(*) as cnt FROM {table} WHERE dest_country IS NOT NULL AND dest_country NOT IN ('US', 'Local') GROUP BY dest_country HAVING cnt > 20")
                for row in cursor.fetchall():
                    stats['suspicious_activity'].append({
                        'type': 'Foreign Traffic Pattern',
                        'detail': f'High volume to {row[0]}: {row[1]} connections',
                        'severity': 'medium'
                    })
                
                # 6. Low TTL values (potential IP spoofing)
                cursor.execute(f"SELECT COUNT(*) as low_ttl FROM {table} WHERE ip_ttl < 32 AND ip_ttl > 0")
                low_ttl = cursor.fetchone()[0]
                if low_ttl > 10:
                    stats['suspicious_activity'].append({
                        'type': 'IP Spoofing Suspected',
                        'detail': f'{low_ttl} packets with abnormally low TTL (<32)',
                        'severity': 'high'
                    })
                
            except Exception as e:
                print(f"Error processing table {table}: {e}")
                continue
        
        # Sort and limit
        stats['protocols'] = dict(sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_sources'] = dict(sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_destinations'] = dict(sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        conn.close()
        return stats
    except Exception as e:
        print(f"Error getting tshark statistics: {e}")
        return None

@app.route('/')
def index():
    """Main dashboard with real-time data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all tables
        all_tables = get_all_tables()
        
        # === REAL DEVICE DATA ===
        total_devices = 0
        device_types = {}
        recent_devices = []
        
        try:
            cursor.execute("SELECT COUNT(*) as total FROM devices")
            total_devices = cursor.fetchone()['total']
            
            cursor.execute("""
                SELECT device_type, COUNT(*) as count 
                FROM devices 
                WHERE device_type IS NOT NULL
                GROUP BY device_type
            """)
            device_types = {row['device_type']: row['count'] for row in cursor.fetchall()}
            
            cursor.execute("""
                SELECT ip_address, hostname, device_type, vendor, security_score, last_seen
                FROM devices 
                ORDER BY last_seen DESC 
                LIMIT 10
            """)
            recent_devices = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Device data error: {e}")
        
        # === REAL TRAFFIC DATA ===
        total_packets = 0
        protocol_distribution = {}
        
        try:
            # Get latest tcpdump table
            tcpdump_tables = [t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]
            if tcpdump_tables:
                latest_tcpdump = sorted(tcpdump_tables)[-1]
                cursor.execute(f"SELECT COUNT(*) as count FROM {latest_tcpdump}")
                total_packets = cursor.fetchone()['count']
                
                cursor.execute(f"SELECT protocol, COUNT(*) as count FROM {latest_tcpdump} WHERE protocol IS NOT NULL GROUP BY protocol")
                protocol_distribution = {row['protocol']: row['count'] for row in cursor.fetchall()}
        except Exception as e:
            print(f"Traffic data error: {e}")
        
        # === REAL IoT DATA ===
        iot_vulns = 0
        try:
            cursor.execute("SELECT COUNT(*) as count FROM iot_vulnerabilities WHERE resolved=0")
            iot_vulns = cursor.fetchone()['count']
        except Exception as e:
            print(f"IoT vulnerabilities error: {e}")
        
        # === REAL AI ANALYSIS ===
        ai_data = {'threat_level': 'UNKNOWN', 'health_score': 0, 'last_analysis': 'Never'}
        try:
            cursor.execute("""
                SELECT threat_level, network_health_score, timestamp
                FROM ai_analysis 
                ORDER BY timestamp DESC 
                LIMIT 1
            """)
            ai_result = cursor.fetchone()
            if ai_result:
                ai_data = {
                    'threat_level': ai_result['threat_level'],
                    'health_score': ai_result['network_health_score'],
                    'last_analysis': ai_result['timestamp']
                }
        except Exception as e:
            print(f"AI analysis error: {e}")
        
        # === SERVICE STATUS ===
        services = {
            'p0f': len([t for t in all_tables if t.startswith('p0f_') and not t.endswith('_template')]),
            'tshark': len([t for t in all_tables if t.startswith('tshark_') and not t.endswith('_template')]),
            'tcpdump': len([t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]),
            'suricata': len([t for t in all_tables if t.startswith('suricata_') and not t.endswith('_template')]),
            'ngrep': len([t for t in all_tables if t.startswith('ngrep_') and not t.endswith('_template')]),
            'httpry': len([t for t in all_tables if t.startswith('httpry_') and not t.endswith('_template')]),
            'argus': len([t for t in all_tables if t.startswith('argus_') and not t.endswith('_template')]),
            'netsniff': len([t for t in all_tables if t.startswith('netsniff_') and not t.endswith('_template')]),
            'iftop': len([t for t in all_tables if t.startswith('iftop_') and not t.endswith('_template')]),
            'nethogs': len([t for t in all_tables if t.startswith('nethogs_') and not t.endswith('_template')])
        }
        
        active_services = sum(1 for count in services.values() if count > 0)
        
        # === TOP TALKERS ===
        top_talkers = []
        try:
            tcpdump_tables = [t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]
            if tcpdump_tables:
                latest_tcpdump = sorted(tcpdump_tables)[-1]
                cursor.execute(f"""
                    SELECT src_ip, COUNT(*) as packet_count
                    FROM {latest_tcpdump}
                    WHERE src_ip LIKE '192.168.%'
                    GROUP BY src_ip
                    ORDER BY packet_count DESC
                    LIMIT 5
                """)
                top_talkers = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Top talkers error: {e}")
        
        # === BANDWIDTH OVER TIME ===
        bandwidth_timeline = []
        try:
            tcpdump_tables = [t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]
            if len(tcpdump_tables) > 0:
                # Get last 10 tables for timeline
                recent_tables = sorted(tcpdump_tables)[-10:]
                for table in recent_tables:
                    # Extract timestamp from table name (tcpdump_YYYYMMDDHHMMSS)
                    try:
                        timestamp_str = table.replace('tcpdump_', '')
                        cursor.execute(f"SELECT COUNT(*) as count, SUM(frame_length) as bytes FROM {table}")
                        result = cursor.fetchone()
                        bandwidth_timeline.append({
                            'timestamp': timestamp_str,
                            'packets': result['count'] if result['count'] else 0,
                            'bytes': result['bytes'] if result['bytes'] else 0
                        })
                    except:
                        pass
        except Exception as e:
            print(f"Bandwidth timeline error: {e}")
        
        # === PORT ACTIVITY ===
        top_ports = []
        try:
            tcpdump_tables = [t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]
            if tcpdump_tables:
                latest_tcpdump = sorted(tcpdump_tables)[-1]
                cursor.execute(f"""
                    SELECT dest_port, COUNT(*) as count
                    FROM {latest_tcpdump}
                    WHERE dest_port IS NOT NULL AND dest_port != ''
                    GROUP BY dest_port
                    ORDER BY count DESC
                    LIMIT 10
                """)
                top_ports = [{'port': row['dest_port'], 'count': row['count']} for row in cursor.fetchall()]
        except Exception as e:
            print(f"Port activity error: {e}")
        
        # === THREAT TIMELINE (from Suricata) ===
        threat_timeline = []
        try:
            # Get Suricata alerts tables
            alert_tables = [t for t in all_tables if 'suricata' in t and 'alert' in t and not t.endswith('_template')]
            if alert_tables:
                latest_alerts = sorted(alert_tables)[-1]
                # Filter out false positives like "Ethertype unknown" and checksum errors
                cursor.execute(f"""
                    SELECT timestamp, severity, signature
                    FROM {latest_alerts}
                    WHERE signature NOT LIKE '%Ethertype unknown%'
                    AND signature NOT LIKE '%IPv4 checksum%'
                    AND signature NOT LIKE '%IPv6 checksum%'
                    AND signature NOT LIKE '%VLAN%'
                    ORDER BY timestamp DESC
                    LIMIT 20
                """)
                threat_timeline = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Threat timeline error: {e}")
        
        # === CONNECTION MATRIX (Top sources to destinations) ===
        connection_matrix = []
        try:
            tcpdump_tables = [t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]
            if tcpdump_tables:
                latest_tcpdump = sorted(tcpdump_tables)[-1]
                cursor.execute(f"""
                    SELECT src_ip, dest_ip, COUNT(*) as connection_count
                    FROM {latest_tcpdump}
                    WHERE src_ip LIKE '192.168.%' OR dest_ip LIKE '192.168.%'
                    GROUP BY src_ip, dest_ip
                    ORDER BY connection_count DESC
                    LIMIT 15
                """)
                connection_matrix = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Connection matrix error: {e}")
        
        # === HOURLY ACTIVITY HEATMAP ===
        hourly_activity = {}
        try:
            tcpdump_tables = [t for t in all_tables if t.startswith('tcpdump_') and not t.endswith('_template')]
            if len(tcpdump_tables) > 0:
                # Process last 5 tables
                for table in sorted(tcpdump_tables)[-5:]:
                    try:
                        # Extract hour from timestamp
                        timestamp_str = table.replace('tcpdump_', '')
                        hour = timestamp_str[8:10]  # HHMMSS -> HH
                        cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                        count = cursor.fetchone()['count']
                        if hour not in hourly_activity:
                            hourly_activity[hour] = 0
                        hourly_activity[hour] += count
                    except:
                        pass
        except Exception as e:
            print(f"Hourly activity error: {e}")
        
        conn.close()
        
        # Prepare data for template
        dashboard_data = {
            'total_devices': total_devices,
            'device_types': device_types,
            'recent_devices': recent_devices,
            'total_packets': total_packets,
            'protocol_distribution': protocol_distribution,
            'iot_vulnerabilities': iot_vulns,
            'ai_analysis': ai_data,
            'active_services': active_services,
            'total_services': 10,
            'services': services,
            'top_talkers': top_talkers,
            'bandwidth_timeline': bandwidth_timeline,
            'top_ports': top_ports,
            'threat_timeline': threat_timeline,
            'connection_matrix': connection_matrix,
            'hourly_activity': hourly_activity,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return render_template('index.html', data=dashboard_data)
    
    except Exception as e:
        print(f"Critical error in index route: {e}")
        import traceback
        traceback.print_exc()
        # Return a safe default
        return render_template('index.html', data={
            'total_devices': 0,
            'device_types': {},
            'recent_devices': [],
            'total_packets': 0,
            'protocol_distribution': {},
            'iot_vulnerabilities': 0,
            'ai_analysis': {'threat_level': 'UNKNOWN', 'health_score': 0, 'last_analysis': 'Never'},
            'active_services': 0,
            'total_services': 10,
            'services': {},
            'top_talkers': [],
            'bandwidth_timeline': [],
            'top_ports': [],
            'threat_timeline': [],
            'connection_matrix': [],
            'hourly_activity': {},
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

@app.route('/tcpdump')
def tcpdump():
    """tcpdump tables listing"""
    tables = get_tables_by_prefix('network_')
    
    # Get table info
    table_info = []
    for table in tables:
        count = get_table_count(table)
        # Extract timestamp from table name (network_YYYYMMDD_HHMMSS)
        timestamp_str = table.replace('network_', '')
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_time = timestamp_str
        
        table_info.append({
            'name': table,
            'timestamp': formatted_time,
            'count': count
        })
    
    # Sort by timestamp (descending)
    table_info.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('tcpdump.html', tables=table_info)

@app.route('/tcpdump/<table_name>')
def tcpdump_table(table_name):
    """View specific tcpdump table"""
    # Limit to 100 records for faster loading - DataTables handles pagination
    data = get_table_data(table_name, limit=100)
    return render_template('tcpdump_table.html', table_name=table_name, data=data)

@app.route('/suricata')
def suricata():
    """Suricata categories overview"""
    categories = ['alerts', 'http', 'dns', 'tls', 'files', 'flow', 'ssh', 'smtp', 'ftp', 'anomaly', 'stats']
    
    # Optimize: Use single connection and batch queries
    conn = get_db_connection()
    cursor = conn.cursor()
    
    category_info = []
    for category in categories:
        tables = get_tables_by_prefix(f'suricata_{category}_')
        
        # Optimize: Sample tables if too many, use UNION ALL
        total_events = 0
        if tables:
            try:
                # Sample first 10 tables for speed
                sample_tables = tables[:10] if len(tables) > 10 else tables
                if sample_tables:
                    union_query = " UNION ALL ".join([f"SELECT COUNT(*) as cnt FROM {t}" for t in sample_tables])
                    cursor.execute(union_query)
                    total_events = sum(row[0] for row in cursor.fetchall())
                    # Estimate if sampled
                    if len(tables) > 10:
                        total_events = int(total_events * (len(tables) / 10))
            except:
                total_events = 0
        
        category_info.append({
            'name': category,
            'display_name': category.capitalize(),
            'table_count': len(tables),
            'total_events': total_events
        })
    
    conn.close()
    return render_template('suricata.html', categories=category_info)

@app.route('/suricata/<category>')
def suricata_category(category):
    """View tables for specific Suricata category"""
    tables = get_tables_by_prefix(f'suricata_{category}_')
    
    # Optimize: Batch count queries
    conn = get_db_connection()
    cursor = conn.cursor()
    
    table_info = []
    
    # Get counts in batches of 50 for better performance
    batch_size = 50
    for i in range(0, len(tables), batch_size):
        batch_tables = tables[i:i+batch_size]
        
        try:
            if batch_tables:
                union_query = " UNION ALL ".join([f"SELECT '{t}' as tbl, COUNT(*) as cnt FROM {t}" for t in batch_tables])
                cursor.execute(union_query)
                counts = {row[0]: row[1] for row in cursor.fetchall()}
            else:
                counts = {}
        except:
            counts = {t: 0 for t in batch_tables}
        
        for table in batch_tables:
            count = counts.get(table, 0)
            # Extract timestamp
            timestamp_str = table.replace(f'suricata_{category}_', '')
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            except:
                formatted_time = timestamp_str
            
            table_info.append({
                'name': table,
                'timestamp': formatted_time,
                'count': count
            })
    
    conn.close()
    
    table_info.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('suricata_category.html', category=category, tables=table_info)

@app.route('/suricata/<category>/<table_name>')
def suricata_table(category, table_name):
    """View specific Suricata table"""
    # Limit to 100 records for faster loading
    if 'alert' in table_name.lower():
        # Filter out false positives for alert tables
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(f"""
                SELECT * FROM {table_name}
                WHERE signature NOT LIKE '%Ethertype unknown%'
                AND signature NOT LIKE '%IPv4 checksum%'
                AND signature NOT LIKE '%IPv6 checksum%'
                AND signature NOT LIKE '%VLAN%'
                ORDER BY timestamp DESC
                LIMIT 100
            """)
            data = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error filtering alerts: {e}")
            data = get_table_data(table_name, limit=100)
        finally:
            conn.close()
    else:
        data = get_table_data(table_name, limit=100)
    return render_template('suricata_table.html', category=category, table_name=table_name, data=data)

@app.route('/analysis')
def analysis():
    """Analysis tools overview"""
    tools = [
        {
            'name': 'tshark',
            'display_name': 'tshark',
            'description': 'Protocol Analysis',
            'interface': 'wlo1',
            'icon': '📊'
        },
        {
            'name': 'p0f',
            'display_name': 'p0f',
            'description': 'OS Fingerprinting',
            'interface': 'wlo1',
            'icon': '🔍'
        },
        {
            'name': 'argus',
            'display_name': 'argus',
            'description': 'Flow Analysis',
            'interface': 'wlo1',
            'icon': '🌊'
        },
        {
            'name': 'ngrep',
            'display_name': 'ngrep',
            'description': 'Pattern Matching',
            'interface': 'wlo1',
            'icon': '🔎'
        },
        {
            'name': 'netsniff',
            'display_name': 'netsniff-ng',
            'description': 'High-Performance Capture',
            'interface': 'wlx1cbfce6265ad',
            'icon': '⚡'
        },
        {
            'name': 'httpry',
            'display_name': 'httpry',
            'description': 'HTTP Logging',
            'interface': 'eno1',
            'icon': '🌐'
        },
        {
            'name': 'iftop',
            'display_name': 'iftop',
            'description': 'Bandwidth Monitoring',
            'interface': 'eno1',
            'icon': '📈'
        },
        {
            'name': 'nethogs',
            'display_name': 'nethogs',
            'description': 'Process Bandwidth',
            'interface': 'eno1',
            'icon': '💻'
        },
        {
            'name': 'tcpdump',
            'display_name': 'tcpdump',
            'description': 'Professional Packet Capture',
            'interface': 'wlo1',
            'icon': '📦'
        }
    ]
    
    # Add table counts
    # Optimize: Get counts in a single query per tool instead of per table
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for tool in tools:
        tables = get_tables_by_prefix(f"{tool['name']}_")
        tool['table_count'] = len(tables)
        
        # Get total records efficiently by querying all tables in one go
        total_records = 0
        if tables:
            # Use UNION ALL to count all tables in single query (much faster)
            try:
                # For tables with many entries, just sample first few tables
                sample_tables = tables[:10] if len(tables) > 10 else tables
                if sample_tables:
                    union_query = " UNION ALL ".join([f"SELECT COUNT(*) as cnt FROM {t}" for t in sample_tables])
                    cursor.execute(union_query)
                    total_records = sum(row[0] for row in cursor.fetchall())
                    # If we sampled, estimate total
                    if len(tables) > 10:
                        total_records = int(total_records * (len(tables) / 10))
            except:
                total_records = 0
        
        tool['total_records'] = total_records
    
    conn.close()
    return render_template('analysis.html', tools=tools)

@app.route('/analysis/<tool_name>')
def analysis_tool(tool_name):
    """View tables for specific analysis tool"""
    tables = get_tables_by_prefix(f'{tool_name}_')
    
    table_info = []
    for table in tables:
        count = get_table_count(table)
        # Extract timestamp
        timestamp_str = table.replace(f'{tool_name}_', '')
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
            formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        except:
            formatted_time = timestamp_str
        
        table_info.append({
            'name': table,
            'timestamp': formatted_time,
            'count': count
        })
    
    table_info.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get latest data preview - reduced to 50 for faster loading
    latest_data = []
    if table_info:
        latest_data = get_table_data(table_info[0]['name'], limit=50)
    
    # Enhanced statistics for tshark
    stats = None
    if tool_name == 'tshark' and tables:
        stats = get_tshark_statistics(tables)
    
    return render_template('analysis_tool.html', tool_name=tool_name, 
                         tables=table_info, latest_data=latest_data, stats=stats)

@app.route('/api/table/<table_name>')
def api_table_data(table_name):
    """API endpoint to get table data as JSON"""
    limit = request.args.get('limit', 1000, type=int)
    data = get_table_data(table_name, limit=limit)
    return jsonify(data)

@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics"""
    all_tables = get_all_tables()
    
    stats = {
        'total_tables': len(all_tables),
        'tcpdump_tables': len(get_tables_by_prefix('network_')),
        'suricata_tables': len([t for t in all_tables if t.startswith('suricata_') and not t.endswith('_template')]),
        'analysis_tables': len([t for t in all_tables if any(t.startswith(p) for p in 
                           ['tshark_', 'p0f_', 'argus_', 'ngrep_', 'netsniff_', 'httpry_', 'iftop_', 'nethogs_'])]),
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(stats)


@app.route('/ai-dashboard')
def ai_dashboard():
    """AI-powered threat detection dashboard - 5-minute intervals"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get latest AI analysis
    cursor.execute("""
        SELECT * FROM ai_analysis 
        ORDER BY timestamp DESC LIMIT 1
    """)
    latest_analysis = cursor.fetchone()
    
    # Parse JSON fields if analysis exists
    analysis_data = None
    chart_data = {
        'health_history': [],
        'threat_timeline': [],
        'protocol_distribution': {},
        'device_activity': []
    }
    
    if latest_analysis:
        analysis_data = dict(latest_analysis)
        try:
            analysis_data['threats_detected'] = json.loads(analysis_data.get('threats_detected', '[]'))
            analysis_data['network_insights'] = json.loads(analysis_data.get('network_insights', '{}'))
            analysis_data['device_analysis'] = json.loads(analysis_data.get('device_analysis', '{}'))
            analysis_data['http_analysis'] = json.loads(analysis_data.get('http_analysis', '{}'))
            analysis_data['iot_analysis'] = json.loads(analysis_data.get('iot_analysis', '{}'))
            analysis_data['recommendations'] = json.loads(analysis_data.get('recommendations', '[]'))
        except:
            pass
        
        # Get network summary from DEVICE TRACKER (accurate data)
        analysis_data['network_summary'] = {
            'tracked_devices': [],
            'total_tracked_devices': 0,
            'iot_devices': 0,
            'mobile_devices': 0,
            'computers': 0,
            'network_devices': 0,
            'os_distribution': {}
        }
        
        # Get real tracked devices from database
        try:
            cursor.execute("""
                SELECT ip_address, hostname, device_type, device_category, vendor,
                       mac_address, last_seen
                FROM devices
                ORDER BY last_seen DESC
                LIMIT 12
            """)
            tracked_devices = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute("""
                SELECT COUNT(*) as total,
                       COUNT(CASE WHEN device_type='IoT' THEN 1 END) as iot,
                       COUNT(CASE WHEN device_type='Mobile' THEN 1 END) as mobile,
                       COUNT(CASE WHEN device_type='Computer' THEN 1 END) as computer,
                       COUNT(CASE WHEN device_type='Network' THEN 1 END) as network
                FROM devices
            """)
            device_stats = cursor.fetchone()
            
            analysis_data['network_summary']['tracked_devices'] = tracked_devices
            analysis_data['network_summary']['total_tracked_devices'] = device_stats['total'] if device_stats else 0
            analysis_data['network_summary']['iot_devices'] = device_stats['iot'] if device_stats else 0
            analysis_data['network_summary']['mobile_devices'] = device_stats['mobile'] if device_stats else 0
            analysis_data['network_summary']['computers'] = device_stats['computer'] if device_stats else 0
            analysis_data['network_summary']['network_devices'] = device_stats['network'] if device_stats else 0
                
            # Get OS information from p0f
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE 'p0f_%' 
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            """)
            p0f_table = cursor.fetchone()
            
            if p0f_table:
                cursor.execute(f"""
                    SELECT DISTINCT src_ip, os_name, os_flavor 
                    FROM {p0f_table['name']} 
                    WHERE os_name != '' AND os_name IS NOT NULL
                    LIMIT 20
                """)
                os_data = cursor.fetchall()
                for row in os_data:
                    os_label = row['os_name']
                    if row['os_flavor']:
                        os_label = f"{row['os_name']} ({row['os_flavor']})"
                    if os_label not in analysis_data['network_summary']['os_distribution']:
                        analysis_data['network_summary']['os_distribution'][os_label] = 0
                    analysis_data['network_summary']['os_distribution'][os_label] += 1
                    
        except Exception as e:
            print(f"Error getting device IPs: {e}")
        
        # Get protocol distribution from network insights
        if analysis_data and analysis_data.get('network_insights'):
            protocols = analysis_data['network_insights'].get('most_active_protocols', [])
            for proto in protocols:
                chart_data['protocol_distribution'][proto] = 1
    
    # Get analysis history (last 12 = 1 hour at 5-min intervals)
    cursor.execute("""
        SELECT id, timestamp, threat_level, network_health_score, summary 
        FROM ai_analysis 
        ORDER BY timestamp DESC
        LIMIT 12
    """)
    analysis_history = [dict(row) for row in cursor.fetchall()]
    
    # Build chart data from history
    for item in reversed(analysis_history):
        chart_data['health_history'].append({
            'time': item['timestamp'].split(' ')[1][:5] if ' ' in item['timestamp'] else item['timestamp'][:5],
            'score': item['network_health_score']
        })
        chart_data['threat_timeline'].append({
            'time': item['timestamp'].split(' ')[1][:5] if ' ' in item['timestamp'] else item['timestamp'][:5],
            'level': item['threat_level']
        })
    
    # Get tool statistics
    tool_stats = {}
    try:
        cursor = conn.cursor()
        for tool in ['tshark', 'tcpdump', 'ngrep', 'httpry', 'argus', 'netsniff', 'iftop', 'nethogs']:
            cursor.execute(f"""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE '{tool}_%' 
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            """)
            table = cursor.fetchone()
            if table:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table['name']}")
                count_row = cursor.fetchone()
                tool_stats[tool] = count_row['count'] if count_row else 0
        
        # Suricata events
        suricata_total = 0
        for event_type in ['alerts', 'flow', 'http', 'dns', 'tls']:
            cursor.execute(f"""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE 'suricata_{event_type}_%' 
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            """)
            table = cursor.fetchone()
            if table:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table['name']}")
                count_row = cursor.fetchone()
                suricata_total += count_row['count'] if count_row else 0
        tool_stats['suricata'] = suricata_total
    except Exception as e:
        print(f"Error getting tool stats: {e}")
    
    conn.close()
    
    return render_template('ai_dashboard.html',
                         analysis=analysis_data,
                         history=analysis_history,
                         chart_data=json.dumps(chart_data),
                         tool_stats=tool_stats)


@app.route('/iot-devices')
def iot_devices():
    """IoT Devices Dashboard"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all IoT devices
    cursor.execute("""
        SELECT * FROM devices 
        WHERE device_type = 'IoT'
        ORDER BY last_seen DESC
    """)
    devices = [dict(row) for row in cursor.fetchall()]
    
    # Get vulnerabilities for each device
    cursor.execute("""
        SELECT device_ip, COUNT(*) as vuln_count, 
               MAX(CASE severity
                   WHEN 'CRITICAL' THEN 4
                   WHEN 'HIGH' THEN 3
                   WHEN 'MEDIUM' THEN 2
                   WHEN 'LOW' THEN 1
                   ELSE 0
               END) as max_severity
        FROM iot_vulnerabilities
        WHERE resolved = 0
        GROUP BY device_ip
    """)
    
    vuln_map = {}
    for row in cursor.fetchall():
        vuln_map[row['device_ip']] = {
            'count': row['vuln_count'],
            'max_severity': row['max_severity']
        }
    
    # Add vulnerability info to devices
    for device in devices:
        ip = device['ip_address']
        device['vulnerabilities'] = vuln_map.get(ip, {'count': 0, 'max_severity': 0})
    
    conn.close()
    
    return render_template('iot_devices.html', devices=devices)


@app.route('/iot-devices/<device_ip>/vulnerabilities')
def device_vulnerabilities(device_ip):
    """Get vulnerabilities for a specific device"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM iot_vulnerabilities
        WHERE device_ip = ? AND resolved = 0
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
    """, (device_ip,))
    
    vulnerabilities = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(vulnerabilities)


@app.route('/help')
def help_page():
    """Help and Documentation Page"""
    return render_template('help.html')


@app.route('/network-topology')
def network_topology():
    """Network Topology Visualization"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all devices
    cursor.execute("""
        SELECT ip_address, hostname, device_type, device_category, 
               vendor, mac_address, security_score, last_seen
        FROM devices
        ORDER BY last_seen DESC
    """)
    devices = [dict(row) for row in cursor.fetchall()]
    
    # Get recent connections (for topology links)
    connections = []
    try:
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND (name LIKE 'tcpdump_%' OR name LIKE 'tshark_%')
            AND name NOT LIKE '%_template'
            ORDER BY name DESC LIMIT 1
        """)
        table_result = cursor.fetchone()
        
        if table_result:
            table_name = table_result['name']
            cursor.execute(f"""
                SELECT DISTINCT src_ip, dest_ip, COUNT(*) as count
                FROM {table_name}
                WHERE src_ip LIKE '192.168.%' AND dest_ip LIKE '192.168.%'
                GROUP BY src_ip, dest_ip
                LIMIT 100
            """)
            connections = [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        print(f"Error getting connections: {e}")
    
    conn.close()
    
    return render_template('network_topology.html', devices=devices, connections=connections)


@app.route('/alerts')
def alerts_dashboard():
    """Security Alerts Dashboard"""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all active alerts
    cursor.execute("""
        SELECT * FROM security_alerts
        WHERE status = 'active'
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            created_at DESC
    """)
    active_alerts = [dict(row) for row in cursor.fetchall()]
    
    # Parse JSON fields
    for alert in active_alerts:
        if alert.get('affected_devices'):
            alert['affected_devices'] = json.loads(alert['affected_devices'])
        if alert.get('threat_indicators'):
            alert['threat_indicators'] = json.loads(alert['threat_indicators'])
        if alert.get('remediation_steps'):
            alert['remediation_steps'] = json.loads(alert['remediation_steps'])
    
    # Get alert statistics
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM security_alerts
        WHERE status = 'active'
        GROUP BY severity
    """)
    severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    # Recent alerts (last 24h)
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM security_alerts
        WHERE created_at > datetime('now', '-24 hours')
    """)
    recent_count = cursor.fetchone()['count']
    
    # Resolved count
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM security_alerts
        WHERE status = 'resolved'
    """)
    resolved_count = cursor.fetchone()['count']
    
    conn.close()
    
    statistics = {
        'severity_counts': severity_counts,
        'total_active': sum(severity_counts.values()),
        'recent_24h': recent_count,
        'total_resolved': resolved_count
    }
    
    return render_template('alerts.html', alerts=active_alerts, statistics=statistics)


@app.route('/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_security_alert(alert_id):
    """Resolve a security alert"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    data = request.get_json() or {}
    notes = data.get('notes', 'Alert resolved via dashboard')
    
    cursor.execute("""
        UPDATE security_alerts
        SET status = 'resolved',
            resolved_at = CURRENT_TIMESTAMP,
            resolved_by = 'user',
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
    """, (alert_id,))
    
    cursor.execute("""
        INSERT INTO alert_history (alert_id, action, action_by, notes)
        VALUES (?, 'resolved', 'user', ?)
    """, (alert_id, notes))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Alert resolved'})


@app.route('/alerts/<alert_id>/auto-remediate', methods=['POST'])
def auto_remediate_alert(alert_id):
    """Execute auto-remediation for an alert"""
    import subprocess
    
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT alert_id, auto_remediation_command
        FROM security_alerts
        WHERE alert_id = ? AND auto_remediation_available = 1
    """, (alert_id,))
    
    alert = cursor.fetchone()
    
    if not alert:
        return jsonify({'success': False, 'message': 'Alert not found or auto-remediation not available'})
    
    try:
        # Execute remediation command
        result = subprocess.run(
            alert['auto_remediation_command'],
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        success = result.returncode == 0
        
        # Log action
        cursor.execute("""
            INSERT INTO alert_history (alert_id, action, action_by, notes)
            VALUES (?, 'auto_remediation', 'user', ?)
        """, (alert_id, f"Executed: {alert['auto_remediation_command']}"))
        
        if success:
            # Mark as resolved
            cursor.execute("""
                UPDATE security_alerts
                SET status = 'resolved',
                    resolved_at = CURRENT_TIMESTAMP,
                    resolved_by = 'auto_remediation',
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = ?
            """, (alert_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': success,
            'message': 'Remediation executed successfully' if success else 'Remediation failed',
            'output': result.stdout or result.stderr
        })
        
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/alerts/<alert_id>/false-positive', methods=['POST'])
def mark_alert_false_positive(alert_id):
    """Mark alert as false positive"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE security_alerts
        SET false_positive = 1,
            status = 'false_positive',
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
    """, (alert_id,))
    
    cursor.execute("""
        INSERT INTO alert_history (alert_id, action, action_by, notes)
        VALUES (?, 'marked_false_positive', 'user', 'Marked as false positive')
    """, (alert_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Alert marked as false positive'})


@app.route('/ai-dashboard/alert/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE ai_alerts 
        SET resolved = 1, resolved_at = ?, resolved_by = 'user'
        WHERE alert_id = ?
    """, (datetime.now().isoformat(), alert_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


@app.route('/ai-dashboard/api/stats')
def ai_stats_api():
    """API endpoint for AI dashboard statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get counts
    cursor.execute("SELECT COUNT(*) as count FROM ai_alerts WHERE resolved = 0")
    active_alerts = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM ai_predictions")
    total_analyses = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM threat_patterns WHERE status = 'active'")
    active_patterns = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM url_classifications WHERE risk_score > 0.7")
    high_risk_urls = cursor.fetchone()['count']
    
    # Get latest threat level
    cursor.execute("SELECT threat_level, network_health_score FROM ai_predictions ORDER BY id DESC LIMIT 1")
    latest = cursor.fetchone()
    
    conn.close()
    
    return jsonify({
        'active_alerts': active_alerts,
        'total_analyses': total_analyses,
        'active_patterns': active_patterns,
        'high_risk_urls': high_risk_urls,
        'threat_level': latest['threat_level'] if latest else 'UNKNOWN',
        'health_score': latest['network_health_score'] if latest else 0
    })


@app.route('/flush-all-data', methods=['POST'])
def flush_all_data():
    """Flush all capture data from all tools - DROP tables completely"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        all_tables = [row['name'] for row in cursor.fetchall()]
        
        # Tools to flush
        tool_prefixes = [
            'tshark_', 'tcpdump_', 'p0f_', 'argus_', 'ngrep_', 
            'netsniff_', 'httpry_', 'iftop_', 'nethogs_',
            'suricata_alerts_', 'suricata_flow_', 'suricata_http_', 
            'suricata_dns_', 'suricata_tls_', 'suricata_files_',
            'suricata_ssh_', 'suricata_smtp_', 'suricata_ftp_',
            'suricata_anomaly_', 'suricata_stats_'
        ]
        
        # Tables to clear (delete all rows but keep structure)
        tables_to_clear = ['ai_analysis', 'devices', 'iot_vulnerabilities', 'security_alerts']
        
        dropped_tables = []
        cleared_tables = []
        kept_tables = []
        
        # Clear data tables (keep structure)
        for table in tables_to_clear:
            if table in all_tables:
                try:
                    cursor.execute(f"DELETE FROM {table}")
                    cleared_tables.append(table)
                except:
                    pass
        
        # Drop collector tables completely
        for table in all_tables:
            # Skip template tables
            if table.endswith('_template'):
                kept_tables.append(table)
                continue
            
            # Skip system tables
            if table in ['sqlite_sequence']:
                kept_tables.append(table)
                continue
            
            # Skip tables we already cleared
            if table in tables_to_clear:
                kept_tables.append(table)
                continue
            
            # Check if table matches any tool prefix
            should_drop = False
            for prefix in tool_prefixes:
                if table.startswith(prefix):
                    should_drop = True
                    break
            
            if should_drop:
                cursor.execute(f"DROP TABLE IF EXISTS {table}")
                dropped_tables.append(table)
            else:
                kept_tables.append(table)
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Successfully flushed all data! Dropped {len(dropped_tables)} tables, cleared {len(cleared_tables)} data tables.',
            'tables_dropped': len(dropped_tables),
            'tables_cleared': len(cleared_tables),
            'cleared_tables': cleared_tables,
            'dropped_tables_list': dropped_tables
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/system-status')
def system_status():
    """System status page showing all services and collectors"""
    import subprocess
    import os
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    all_tables = [row['name'] for row in cursor.fetchall()]
    
    # Network Collectors
    collectors = [
        {
            'name': 'Suricata IDS/IPS',
            'description': 'Intrusion Detection System - Real-time threat detection',
            'icon': '🛡️',
            'service': 'suricata',
            'tables': [t for t in all_tables if t.startswith('suricata_')]
        },
        {
            'name': 'tcpdump',
            'description': 'Professional packet capture with zero packet loss',
            'icon': '📦',
            'service': 'tcpdump',
            'tables': [t for t in all_tables if t.startswith('tcpdump_')]
        },
        {
            'name': 'tshark',
            'description': 'Protocol analysis and application layer parsing',
            'icon': '📊',
            'service': 'tshark',
            'tables': [t for t in all_tables if t.startswith('tshark_')]
        },
        {
            'name': 'p0f',
            'description': 'Passive OS fingerprinting and link detection',
            'icon': '🔍',
            'service': 'p0f',
            'tables': [t for t in all_tables if t.startswith('p0f_')]
        },
        {
            'name': 'ngrep',
            'description': 'Network pattern matching and content inspection',
            'icon': '🔎',
            'service': 'ngrep',
            'tables': [t for t in all_tables if t.startswith('ngrep_')]
        },
        {
            'name': 'httpry',
            'description': 'HTTP traffic capture and analysis',
            'icon': '🌐',
            'service': 'httpry',
            'tables': [t for t in all_tables if t.startswith('httpry_')]
        },
        {
            'name': 'argus',
            'description': 'Network flow monitoring and analysis',
            'icon': '🌊',
            'service': 'argus',
            'tables': [t for t in all_tables if t.startswith('argus_')]
        },
        {
            'name': 'netsniff-ng',
            'description': 'High-performance packet capture',
            'icon': '⚡',
            'service': 'netsniff-ng',
            'tables': [t for t in all_tables if t.startswith('netsniff_')]
        },
        {
            'name': 'iftop',
            'description': 'Real-time bandwidth monitoring per connection',
            'icon': '📈',
            'service': 'iftop',
            'tables': [t for t in all_tables if t.startswith('iftop_')]
        },
        {
            'name': 'nethogs',
            'description': 'Process-level bandwidth monitoring',
            'icon': '🐗',
            'service': 'nethogs',
            'tables': [t for t in all_tables if t.startswith('nethogs_')]
        }
    ]
    
    # Analysis & Processing Scripts
    scripts = [
        {
            'name': 'AI 5-Min Aggregator',
            'description': 'Collects data from all tools and sends to Gemini AI for analysis',
            'icon': '🤖',
            'script': 'ai_5min_aggregator.py',
            'service': 'ai-5min-aggregator'
        },
        {
            'name': 'Device Tracker',
            'description': 'MAC address tracking, vendor lookup, and device categorization',
            'icon': '📱',
            'script': 'device_tracker.py',
            'service': 'device-tracker'
        },
        {
            'name': 'Unified Device Processor',
            'description': 'Processes traffic data to identify unique devices',
            'icon': '🔄',
            'script': 'unified_device_processor.py',
            'service': 'unified-device-processor'
        },
        {
            'name': 'IoT Security Scanner',
            'description': 'Scans IoT devices for vulnerabilities and security issues',
            'icon': '🔐',
            'script': 'iot_security_scanner.py',
            'service': 'iot-security-scanner'
        },
        {
            'name': 'Device Scorer',
            'description': 'Calculates security scores (0-100) for all devices',
            'icon': '🎯',
            'script': 'device_scorer.py',
            'service': 'device-scorer'
        },
        {
            'name': 'Enhanced Alert System',
            'description': 'Advanced threat alerting with auto-remediation',
            'icon': '🚨',
            'script': 'enhanced_alert_system.py',
            'service': 'enhanced-alert-system'
        },
        {
            'name': 'Database Optimizer',
            'description': 'Adds indexes and runs VACUUM/ANALYZE for performance',
            'icon': '⚡',
            'script': 'optimize_database.py'
        }
    ]
    
    # Systemd Services
    systemd_services = [
        {
            'name': 'p0f-collector',
            'description': 'p0f OS fingerprinting collector service',
            'icon': '🔍',
            'service': 'p0f-collector'
        },
        {
            'name': 'tshark-collector',
            'description': 'tshark protocol analysis collector service',
            'icon': '📊',
            'service': 'tshark-collector'
        },
        {
            'name': 'tcpdump-collector',
            'description': 'tcpdump packet capture collector service',
            'icon': '📦',
            'service': 'tcpdump-collector'
        },
        {
            'name': 'ngrep-collector',
            'description': 'ngrep pattern matching collector service',
            'icon': '🔎',
            'service': 'ngrep-collector'
        },
        {
            'name': 'httpry-collector',
            'description': 'httpry HTTP traffic collector service',
            'icon': '🌐',
            'service': 'httpry-collector'
        },
        {
            'name': 'argus-collector',
            'description': 'argus flow monitoring collector service',
            'icon': '🌊',
            'service': 'argus-collector'
        },
        {
            'name': 'netsniff-collector',
            'description': 'netsniff-ng packet capture collector service',
            'icon': '⚡',
            'service': 'netsniff-collector'
        },
        {
            'name': 'iftop-collector',
            'description': 'iftop bandwidth monitoring collector service',
            'icon': '📈',
            'service': 'iftop-collector'
        },
        {
            'name': 'nethogs-collector',
            'description': 'nethogs process bandwidth collector service',
            'icon': '🐗',
            'service': 'nethogs-collector'
        },
        {
            'name': 'suricata-collector',
            'description': 'suricata IDS/IPS collector service',
            'icon': '🛡️',
            'service': 'suricata-collector'
        },
        {
            'name': 'ai-5min-aggregator',
            'description': 'AI data aggregation timer service',
            'icon': '🤖',
            'service': 'ai-5min-aggregator'
        },
        {
            'name': 'device-tracker',
            'description': 'Device tracking service',
            'icon': '📱',
            'service': 'device-tracker'
        },
        {
            'name': 'unified-device-processor',
            'description': 'Unified device processing service',
            'icon': '🔄',
            'service': 'unified-device-processor'
        },
        {
            'name': 'iot-security-scanner',
            'description': 'IoT security scanning service',
            'icon': '🔐',
            'service': 'iot-security-scanner'
        },
        {
            'name': 'device-scorer',
            'description': 'Device security scoring timer service',
            'icon': '🎯',
            'service': 'device-scorer'
        },
        {
            'name': 'enhanced-alert-system',
            'description': 'Enhanced alert system service',
            'icon': '🚨',
            'service': 'enhanced-alert-system'
        }
    ]
    
    # Web Services
    web_services = [
        {
            'name': 'Flask Dashboard',
            'description': 'Main web interface for NetGuard Pro',
            'icon': '🌐',
            'service': 'flask-dashboard',
            'port': 8080
        }
    ]
    
    # Check service status for all systemd services
    for service in systemd_services:
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service['service']],
                capture_output=True,
                text=True,
                timeout=2
            )
            service['status'] = 'running' if result.returncode == 0 else 'stopped'
        except:
            service['status'] = 'unknown'
    
    # Check service status
    for service in collectors + scripts + web_services:
        try:
            service['status'] = 'stopped'  # Default
            
            # Check if it's a systemd service
            if 'service' in service:
                result = subprocess.run(
                    ['systemctl', 'is-active', service['service']],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    service['status'] = 'running'
                else:
                    # If service check fails, try script check
                    if 'script' in service:
                        result = subprocess.run(
                            ['pgrep', '-f', service['script']],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        if result.returncode == 0:
                            service['status'] = 'running'
            
            # If no service defined, check if script is running
            elif 'script' in service:
                result = subprocess.run(
                    ['pgrep', '-f', service['script']],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    service['status'] = 'running'
            
            # For collectors, also check if tables exist (fallback indicator)
            if 'tables' in service:
                service['table_count'] = len([t for t in service['tables'] if not t.endswith('_template')])
                # If we have tables, collector has run at least once
                if service['table_count'] > 0 and service['status'] == 'stopped':
                    service['status'] = 'unknown'  # Was running, may be stopped now
        except Exception as e:
            service['status'] = 'unknown'
            service['error'] = str(e)
    
    # Database statistics
    database_stats = {
        'collector_tables': {},
        'data_tables': {}
    }
    
    # Count collector tables
    for prefix in ['tcpdump', 'tshark', 'p0f', 'suricata', 'ngrep', 'httpry', 'argus', 'netsniff', 'iftop', 'nethogs']:
        tables = [t for t in all_tables if t.startswith(f'{prefix}_') and not t.endswith('_template')]
        if tables:
            database_stats['collector_tables'][prefix] = len(tables)
    
    # Count data table records
    for table in ['devices', 'iot_vulnerabilities', 'security_alerts', 'ai_analysis']:
        if table in all_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                count = cursor.fetchone()['count']
                database_stats['data_tables'][table] = count
            except:
                database_stats['data_tables'][table] = 0
    
    conn.close()
    
    # Calculate summary
    all_services = collectors + scripts + web_services
    running = sum(1 for s in all_services if s.get('status') == 'running')
    stopped = sum(1 for s in all_services if s.get('status') == 'stopped')
    total = len(all_services)
    health = int((running / total * 100)) if total > 0 else 0
    
    status = {
        'collectors': collectors,
        'scripts': scripts,
        'web_services': web_services,
        'database': database_stats,
        'summary': {
            'running': running,
            'stopped': stopped,
            'total': total,
            'health': health
        }
    }
    
    return render_template('system_status.html', status=status)


if __name__ == '__main__':
    # Run on all interfaces, port 8080
    app.run(host='0.0.0.0', port=8080, debug=False)


#!/usr/bin/env python3
"""
Performance Benchmarking Script (Days 38-45)
Purpose: Measure system performance under various load conditions
Metrics: CPU, Memory, Disk I/O, Packet capture rates, Detection latency
"""

import psutil
import sqlite3
import time
import json
import subprocess
from datetime import datetime
from collections import defaultdict
import os

# Configuration
DATA_DIR = "/home/jarvis/thesis/data/performance"
LOG_FILE = "/home/jarvis/thesis/logs/performance_benchmark.log"
DB_PATH = "/home/jarvis/NetGuard/network.db"
DURATION_DAYS = 7  # Days 38-45

# Services to monitor
SERVICES = [
    'p0f-collector',
    'tshark-collector',
    'tcpdump-collector',
    'suricata-collector',
    'ngrep-collector',
    'argus-collector',
    'netsniff-collector',
    'httpry-collector',
    'iftop-collector',
    'nethogs-collector'
]

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log(message):
    """Log with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + '\n')

def get_system_metrics():
    """Collect overall system metrics"""
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    cpu_avg = psutil.cpu_percent(interval=1)
    
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    disk = psutil.disk_usage('/home/jarvis/NetGuard')
    disk_io = psutil.disk_io_counters()
    
    net_io = psutil.net_io_counters()
    
    return {
        'timestamp': datetime.now().isoformat(),
        'cpu': {
            'per_core': cpu_percent,
            'average': cpu_avg,
            'count': psutil.cpu_count(),
            'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
        },
        'memory': {
            'total_mb': memory.total / (1024**2),
            'available_mb': memory.available / (1024**2),
            'used_mb': memory.used / (1024**2),
            'percent': memory.percent,
            'cached_mb': memory.cached / (1024**2) if hasattr(memory, 'cached') else 0
        },
        'swap': {
            'total_mb': swap.total / (1024**2),
            'used_mb': swap.used / (1024**2),
            'percent': swap.percent
        },
        'disk': {
            'total_gb': disk.total / (1024**3),
            'used_gb': disk.used / (1024**3),
            'free_gb': disk.free / (1024**3),
            'percent': disk.percent
        },
        'disk_io': {
            'read_mb': disk_io.read_bytes / (1024**2),
            'write_mb': disk_io.write_bytes / (1024**2),
            'read_count': disk_io.read_count,
            'write_count': disk_io.write_count
        },
        'network_io': {
            'bytes_sent_mb': net_io.bytes_sent / (1024**2),
            'bytes_recv_mb': net_io.bytes_recv / (1024**2),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    }

def get_service_metrics():
    """Collect per-service metrics"""
    service_metrics = {}
    
    for service in SERVICES:
        try:
            # Get service status
            result = subprocess.run(
                ['systemctl', 'is-active', f'{service}.service'],
                capture_output=True,
                text=True
            )
            is_active = result.stdout.strip() == 'active'
            
            if not is_active:
                service_metrics[service] = {'status': 'inactive'}
                continue
            
            # Get PID
            result = subprocess.run(
                ['systemctl', 'show', f'{service}.service', '--property=MainPID'],
                capture_output=True,
                text=True
            )
            pid_line = result.stdout.strip()
            pid = int(pid_line.split('=')[1]) if '=' in pid_line else 0
            
            if pid == 0:
                service_metrics[service] = {'status': 'active', 'pid': 0}
                continue
            
            # Get process info
            try:
                process = psutil.Process(pid)
                
                with process.oneshot():
                    service_metrics[service] = {
                        'status': 'active',
                        'pid': pid,
                        'cpu_percent': process.cpu_percent(interval=0.1),
                        'memory_mb': process.memory_info().rss / (1024**2),
                        'memory_percent': process.memory_percent(),
                        'num_threads': process.num_threads(),
                        'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0,
                        'io_counters': process.io_counters()._asdict() if hasattr(process, 'io_counters') else {}
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                service_metrics[service] = {'status': 'active', 'pid': pid, 'error': 'access_denied'}
                
        except Exception as e:
            service_metrics[service] = {'error': str(e)}
    
    return service_metrics

def get_capture_statistics():
    """Get packet capture statistics from database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    stats = {}
    
    try:
        # Count tables for each tool
        tools = ['tshark', 'tcpdump', 'p0f', 'suricata', 'ngrep', 'argus', 'netsniff', 'httpry', 'iftop', 'nethogs']
        
        for tool in tools:
            cursor.execute(f"""
                SELECT COUNT(*) FROM sqlite_master 
                WHERE type='table' AND name LIKE '{tool}_%' 
                AND name NOT LIKE '%_template'
            """)
            table_count = cursor.fetchone()[0]
            
            # Get latest table size
            cursor.execute(f"""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name LIKE '{tool}_%' 
                AND name NOT LIKE '%_template'
                ORDER BY name DESC LIMIT 1
            """)
            latest_table = cursor.fetchone()
            
            record_count = 0
            if latest_table:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {latest_table[0]}")
                    record_count = cursor.fetchone()[0]
                except:
                    pass
            
            stats[tool] = {
                'tables': table_count,
                'latest_table_records': record_count
            }
        
        # Get total database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size = cursor.fetchone()[0] / (1024**2)  # MB
        
        stats['database'] = {
            'size_mb': db_size,
            'path': DB_PATH
        }
        
    finally:
        conn.close()
    
    return stats

def calculate_packet_rate():
    """Calculate current packet capture rate"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Get recent tshark records (last 5 minutes)
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name LIKE 'tshark_%' 
            AND name NOT LIKE '%_template'
            ORDER BY name DESC LIMIT 1
        """)
        latest_table = cursor.fetchone()
        
        if latest_table:
            five_min_ago = (datetime.now().timestamp() - 300) * 1000  # milliseconds
            cursor.execute(f"""
                SELECT COUNT(*) FROM {latest_table[0]}
                WHERE frame_time_epoch > {five_min_ago}
            """)
            count = cursor.fetchone()[0]
            packets_per_sec = count / 300.0
            return packets_per_sec
        
    except:
        pass
    finally:
        conn.close()
    
    return 0

def run_stress_test(intensity='low'):
    """Run network traffic stress test"""
    log(f"Running stress test: {intensity} intensity")
    
    if intensity == 'low':
        # Generate some HTTP traffic
        subprocess.Popen(['curl', '-s', 'http://example.com'], stdout=subprocess.DEVNULL)
        subprocess.Popen(['curl', '-s', 'https://google.com'], stdout=subprocess.DEVNULL)
    elif intensity == 'medium':
        # Multiple parallel connections
        for _ in range(10):
            subprocess.Popen(['curl', '-s', 'http://example.com'], stdout=subprocess.DEVNULL)
            subprocess.Popen(['ping', '-c', '10', '8.8.8.8'], stdout=subprocess.DEVNULL)
    elif intensity == 'high':
        # Heavy traffic generation
        for _ in range(50):
            subprocess.Popen(['curl', '-s', 'http://example.com'], stdout=subprocess.DEVNULL)

def benchmark_day(day, intensity='normal'):
    """Run benchmark for one day"""
    log(f"Starting benchmark for Day {day} (Intensity: {intensity})")
    
    day_data = {
        'day': day,
        'intensity': intensity,
        'samples': []
    }
    
    # Collect samples every 5 minutes for 24 hours
    samples_per_day = 288  # 24 hours * 12 samples per hour
    
    for sample in range(samples_per_day):
        sample_data = {
            'sample_number': sample,
            'timestamp': datetime.now().isoformat(),
            'system': get_system_metrics(),
            'services': get_service_metrics(),
            'capture_stats': get_capture_statistics(),
            'packet_rate_pps': calculate_packet_rate()
        }
        
        day_data['samples'].append(sample_data)
        
        # Every hour, log progress
        if sample % 12 == 0:
            log(f"Day {day}, Hour {sample // 12}/24 - CPU: {sample_data['system']['cpu']['average']:.1f}%, "
                f"Mem: {sample_data['system']['memory']['percent']:.1f}%, "
                f"Packets/sec: {sample_data['packet_rate_pps']:.0f}")
        
        # Apply stress test based on intensity
        if intensity == 'high' and sample % 6 == 0:  # Every 30 min
            run_stress_test('high')
        elif intensity == 'medium' and sample % 12 == 0:  # Every hour
            run_stress_test('medium')
        
        # Sleep until next sample (5 minutes)
        time.sleep(300)
    
    # Save day data
    output_file = os.path.join(DATA_DIR, f"day{day}_benchmark.json")
    with open(output_file, 'w') as f:
        json.dump(day_data, f, indent=2)
    
    log(f"Day {day} benchmark completed. Saved to {output_file}")
    
    # Generate summary
    avg_cpu = sum(s['system']['cpu']['average'] for s in day_data['samples']) / len(day_data['samples'])
    avg_mem = sum(s['system']['memory']['percent'] for s in day_data['samples']) / len(day_data['samples'])
    avg_pps = sum(s['packet_rate_pps'] for s in day_data['samples']) / len(day_data['samples'])
    
    log(f"Day {day} Summary - Avg CPU: {avg_cpu:.1f}%, Avg Mem: {avg_mem:.1f}%, Avg PPS: {avg_pps:.0f}")

def main():
    """Main benchmarking campaign"""
    log("="*70)
    log("PERFORMANCE BENCHMARKING CAMPAIGN STARTED")
    log(f"Duration: {DURATION_DAYS} days (Days 38-45)")
    log(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("="*70)
    
    # Day 38-39: Normal load
    benchmark_day(38, 'normal')
    benchmark_day(39, 'normal')
    
    # Day 40-41: Medium load
    benchmark_day(40, 'medium')
    benchmark_day(41, 'medium')
    
    # Day 42-43: High load
    benchmark_day(42, 'high')
    benchmark_day(43, 'high')
    
    # Day 44-45: Mixed load (validate consistency)
    benchmark_day(44, 'medium')
    benchmark_day(45, 'normal')
    
    log("="*70)
    log("PERFORMANCE BENCHMARKING COMPLETED")
    log(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Data location: {DATA_DIR}")
    log("="*70)

if __name__ == "__main__":
    main()


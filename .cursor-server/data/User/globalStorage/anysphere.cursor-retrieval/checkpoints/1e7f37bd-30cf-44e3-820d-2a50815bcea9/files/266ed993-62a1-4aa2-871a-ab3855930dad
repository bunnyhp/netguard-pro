#!/usr/bin/env python3
"""
NetGuard Pro - Analysis Tools Collector (Master Orchestrator)
Manages and coordinates all 8 analysis tool collectors
"""

import os
import sys
import subprocess
import logging
import time
import signal
from datetime import datetime

# Configuration
SCRIPTS_DIR = "/home/jarvis/NetGuard/scripts"
LOG_FILE = "/home/jarvis/NetGuard/logs/system/analysis-tools-collector.log"
CHECK_INTERVAL = 30  # Check collector status every 30 seconds

# Analysis tool collectors
COLLECTORS = {
    'tshark': {
        'script': os.path.join(SCRIPTS_DIR, 'tshark_collector.py'),
        'description': 'Protocol Analysis (wlo1)',
        'process': None
    },
    'p0f': {
        'script': os.path.join(SCRIPTS_DIR, 'p0f_collector.py'),
        'description': 'OS Fingerprinting (wlo1)',
        'process': None
    },
    'argus': {
        'script': os.path.join(SCRIPTS_DIR, 'argus_collector.py'),
        'description': 'Flow Analysis (wlo1)',
        'process': None
    },
    'ngrep': {
        'script': os.path.join(SCRIPTS_DIR, 'ngrep_collector.py'),
        'description': 'Pattern Matching (wlo1)',
        'process': None
    },
    'netsniff': {
        'script': os.path.join(SCRIPTS_DIR, 'netsniff_collector.py'),
        'description': 'High-Performance Capture (wlx1cbfce6265ad)',
        'process': None
    },
    'httpry': {
        'script': os.path.join(SCRIPTS_DIR, 'httpry_collector.py'),
        'description': 'HTTP Logging (eno1)',
        'process': None
    },
    'iftop': {
        'script': os.path.join(SCRIPTS_DIR, 'iftop_collector.py'),
        'description': 'Bandwidth Monitoring (eno1)',
        'process': None
    },
    'nethogs': {
        'script': os.path.join(SCRIPTS_DIR, 'nethogs_collector.py'),
        'description': 'Process Bandwidth (eno1)',
        'process': None
    }
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Graceful shutdown flag
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global shutdown_requested
    logging.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True

def start_collector(name, config):
    """Start a collector process"""
    try:
        script = config['script']
        
        if not os.path.exists(script):
            logging.error(f"✗ {name}: Script not found: {script}")
            return False
        
        logging.info(f"Starting {name} collector ({config['description']})...")
        
        process = subprocess.Popen(
            ['python3', script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # Create new process group
        )
        
        time.sleep(2)  # Give it time to start
        
        if process.poll() is None:
            config['process'] = process
            logging.info(f"✓ {name} started successfully (PID: {process.pid})")
            return True
        else:
            stderr_output = process.stderr.read().decode('utf-8', errors='ignore')
            logging.error(f"✗ {name} failed to start: {stderr_output[:200]}")
            return False
            
    except Exception as e:
        logging.error(f"✗ Error starting {name}: {e}")
        return False

def stop_collector(name, config):
    """Stop a collector process"""
    try:
        process = config['process']
        
        if process and process.poll() is None:
            logging.info(f"Stopping {name} collector...")
            
            # Try graceful shutdown first (SIGTERM)
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except:
                process.terminate()
            
            # Wait up to 5 seconds for graceful shutdown
            try:
                process.wait(timeout=5)
                logging.info(f"✓ {name} stopped gracefully")
            except subprocess.TimeoutExpired:
                # Force kill if needed
                logging.warning(f"{name} didn't stop gracefully, forcing...")
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    process.kill()
                process.wait()
                logging.info(f"✓ {name} stopped (forced)")
            
            config['process'] = None
            return True
            
    except Exception as e:
        logging.error(f"Error stopping {name}: {e}")
        return False

def check_collector_status(name, config):
    """Check if collector is running and restart if needed"""
    try:
        process = config['process']
        
        if process is None or process.poll() is not None:
            # Collector is not running
            if process is not None:
                # It was running but died
                return_code = process.returncode
                stderr_output = process.stderr.read().decode('utf-8', errors='ignore')
                logging.warning(f"⚠ {name} died (exit code: {return_code})")
                if stderr_output:
                    logging.debug(f"{name} stderr: {stderr_output[:200]}")
            
            # Restart collector
            logging.info(f"Restarting {name}...")
            return start_collector(name, config)
        else:
            # Collector is running
            return True
            
    except Exception as e:
        logging.error(f"Error checking {name} status: {e}")
        return False

def get_status_summary():
    """Get summary of all collector statuses"""
    running = 0
    stopped = 0
    
    for name, config in COLLECTORS.items():
        process = config['process']
        if process and process.poll() is None:
            running += 1
        else:
            stopped += 1
    
    return running, stopped

def main():
    """Main orchestrator loop"""
    global shutdown_requested
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logging.info("=" * 70)
    logging.info("NetGuard Pro - Analysis Tools Collector (Master Orchestrator)")
    logging.info("=" * 70)
    logging.info(f"Managing {len(COLLECTORS)} analysis tool collectors:")
    for name, config in COLLECTORS.items():
        logging.info(f"  • {name}: {config['description']}")
    logging.info(f"Check interval: {CHECK_INTERVAL} seconds")
    logging.info("=" * 70)
    
    # Create log directory
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    # Start all collectors
    logging.info("\nStarting all collectors...\n")
    for name, config in COLLECTORS.items():
        start_collector(name, config)
        time.sleep(1)  # Stagger starts
    
    # Get initial status
    running, stopped = get_status_summary()
    logging.info(f"\nInitial status: {running} running, {stopped} stopped\n")
    logging.info("=" * 70)
    logging.info("Monitoring collectors... (Press Ctrl+C to stop)")
    logging.info("=" * 70 + "\n")
    
    # Main monitoring loop
    iteration = 0
    try:
        while not shutdown_requested:
            time.sleep(CHECK_INTERVAL)
            iteration += 1
            
            # Check all collectors
            for name, config in COLLECTORS.items():
                check_collector_status(name, config)
            
            # Log status summary every 10 iterations (5 minutes)
            if iteration % 10 == 0:
                running, stopped = get_status_summary()
                logging.info(f"Status check: {running} running, {stopped} stopped")
                
    except KeyboardInterrupt:
        logging.info("\nShutdown requested via keyboard interrupt")
        shutdown_requested = True
    
    # Graceful shutdown
    logging.info("\n" + "=" * 70)
    logging.info("Shutting down all collectors...")
    logging.info("=" * 70)
    
    for name, config in COLLECTORS.items():
        stop_collector(name, config)
    
    logging.info("\n" + "=" * 70)
    logging.info("NetGuard Pro Analysis Tools Collector - Shutdown Complete")
    logging.info("=" * 70)

if __name__ == "__main__":
    main()


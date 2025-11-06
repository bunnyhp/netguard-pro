#!/usr/bin/env python3
import subprocess
import os

print("="*60)
print("P0F DIAGNOSTIC")
print("="*60)

# 1. Check if p0f is installed
try:
    result = subprocess.run(['which', 'p0f'], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"✓ p0f installed at: {result.stdout.strip()}")
    else:
        print("✗ p0f NOT installed")
        print("  Run: sudo apt-get install p0f")
except Exception as e:
    print(f"✗ Error checking p0f: {e}")

# 2. Check network interfaces
print("\nAvailable network interfaces:")
try:
    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if ':' in line and not line.startswith(' '):
            print(f"  {line}")
except:
    pass

# 3. Check if p0f process is running
print("\nRunning p0f processes:")
try:
    result = subprocess.run(['pgrep', '-a', 'p0f'], capture_output=True, text=True)
    if result.returncode == 0:
        print(result.stdout)
    else:
        print("  ✗ No p0f process running")
except:
    pass

# 4. Check p0f log file
print("\np0f log file:")
log_path = "/home/jarvis/NetGuard/captures/p0f/p0f.log"
if os.path.exists(log_path):
    size = os.path.getsize(log_path)
    print(f"  Exists: {log_path}")
    print(f"  Size: {size} bytes")
    if size > 0:
        with open(log_path, 'r') as f:
            print("  Last 5 lines:")
            lines = f.readlines()
            for line in lines[-5:]:
                print(f"    {line.strip()}")
    else:
        print("  ✗ File is EMPTY (p0f not capturing)")
else:
    print(f"  ✗ Does not exist: {log_path}")

# 5. Check p0f collector status
print("\np0f collector service:")
try:
    result = subprocess.run(['systemctl', 'is-active', 'p0f-collector'], capture_output=True, text=True)
    status = result.stdout.strip()
    print(f"  Status: {status}")
except:
    pass

# 6. Test p0f manually
print("\nTesting p0f on wlo1 (5 second capture)...")
print("  Command: sudo timeout 5 p0f -i wlo1")
try:
    result = subprocess.run(['sudo', 'timeout', '5', 'p0f', '-i', 'wlo1'], 
                          capture_output=True, text=True)
    if result.stdout:
        print("  ✓ p0f CAN capture on wlo1")
        print(f"  Sample output:\n{result.stdout[:500]}")
    else:
        print("  ✗ No output from p0f")
    if result.stderr:
        print(f"  Errors: {result.stderr}")
except Exception as e:
    print(f"  ✗ Error: {e}")

print("\n" + "="*60)
print("RECOMMENDATIONS:")
print("="*60)
print("1. If p0f not installed: sudo apt-get install p0f")
print("2. If wlo1 doesn't exist: Check 'ip link show' and use correct interface")
print("3. Restart service: sudo systemctl restart p0f-collector")
print("4. Check logs: tail -f /home/jarvis/NetGuard/logs/system/p0f-service-error.log")
print("="*60)


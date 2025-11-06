#!/usr/bin/env python3
"""
Script to remove IoT Security Status and AI Recommendations sections from AI dashboard
"""

file_path = "/home/jarvis/NetGuard/web/templates/ai_dashboard.html"

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
skip_mode = False
skip_section = None
brace_count = 0

for i, line in enumerate(lines):
    # Check if we're starting a section to remove
    if '<!-- IoT Security Status -->' in line:
        skip_mode = True
        skip_section = 'IoT'
        brace_count = 0
        print(f"Found IoT Security Status section at line {i+1}, removing...")
        continue
    
    if '<!-- AI Recommendations -->' in line:
        skip_mode = True
        skip_section = 'AI'
        brace_count = 0
        print(f"Found AI Recommendations section at line {i+1}, removing...")
        continue
    
    if skip_mode:
        # Count opening and closing div tags
        if '<div' in line:
            brace_count += line.count('<div')
        if '</div>' in line:
            brace_count -= line.count('</div>')
        
        # When we've closed all divs and hit a new comment or section, stop skipping
        if brace_count <= 0 and ('<!--' in line or '<div class="section-card"' in line):
            skip_mode = False
            skip_section = None
            new_lines.append(line)
            print(f"  Finished removing section at line {i+1}")
            continue
        
        continue  # Skip this line
    
    new_lines.append(line)

# Write back to file
with open(file_path, 'w') as f:
    f.writelines(new_lines)

print(f"\n✓ Successfully removed sections from {file_path}")
print(f"  Original lines: {len(lines)}")
print(f"  New lines: {len(new_lines)}")
print(f"  Removed: {len(lines) - len(new_lines)} lines")


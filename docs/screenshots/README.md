# Screenshots Directory

Place your dashboard screenshots in this directory:

## Required Screenshots

1. **`dashboard-main.png`** - Main dashboard overview
   - Shows network health, tracked devices, threats, packet counts
   - Device cards, network health history chart, protocol distribution

2. **`dashboard-ai.png`** - AI dashboard view
   - AI-powered threat analysis
   - Device type distribution, top talkers, bandwidth charts
   - Network activity metrics

3. **`network-topology.png`** - Network topology visualization
   - Interactive D3.js network map
   - Device connections and relationships
   - Filter options and device details

4. **`iot-devices.png`** - IoT devices monitoring
   - Device cards with security status
   - Threat detection panels
   - Network security assessment

5. **`suricata-dashboard.png`** - Suricata IDS/IPS categories
   - 11 event categories overview
   - Alert counts and event statistics
   - Category navigation buttons

6. **`tshark-data-dashboard.png`** - Tshark protocol dissection
   - Packet analysis view
   - Protocol breakdown
   - Deep packet inspection results

## Image Specifications

- **Format**: PNG (preferred) or JPG
- **Recommended Size**: 1920x1080 (Full HD) or 1280x720 (HD)
- **Optimization**: Compress images for web (use tools like TinyPNG or ImageOptim)
- **File Size**: Keep under 500KB per image for faster loading

## Adding Screenshots

1. Capture screenshots from your running dashboard
2. Save them with the exact filenames listed above
3. Place them in this `docs/screenshots/` directory
4. Commit and push to GitHub:
   ```bash
   git add docs/screenshots/*.png
   git commit -m "docs: Add dashboard screenshots"
   git push origin main
   ```

The README.md will automatically display these screenshots in the documentation.


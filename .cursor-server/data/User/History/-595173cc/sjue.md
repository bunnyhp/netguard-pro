# Application Layer Data Parsing - NetGuard Pro

## Overview
NetGuard Pro implements comprehensive application layer parsing to extract meaningful data from network traffic beyond basic packet information.

## Current Implementation

### 1. tshark Collector (`/home/jarvis/NetGuard/scripts/tshark_collector.py`)

The tshark collector provides the most comprehensive application layer parsing with the following capabilities:

#### HTTP/HTTPS Traffic
- **HTTP Host**: Extracted from HTTP headers (`http_host`)
- **HTTP URI**: Full request path (`http_uri`)
- **HTTP Method**: GET, POST, PUT, DELETE, etc. (`http_method`)
- **HTTP User Agent**: Browser/application identification (`http_user_agent`)
- **HTTP Response Code**: Status codes (200, 404, 500, etc.) (`http_response_code`)

**Use Cases:**
- Identify web browsing behavior
- Detect suspicious user agents (potential malware)
- Track API usage and REST calls
- Monitor HTTP-based IoT device communications

#### DNS Traffic
- **DNS Query**: Domain names being resolved (`dns_query`)
- **DNS Query Type**: A, AAAA, MX, TXT, etc. (`dns_query_type`)
- **DNS Response**: Resolved IP addresses (`dns_response`)

**Use Cases:**
- Detect DNS tunneling (long query names)
- Identify C2 communications via DGA domains
- Track domain resolution patterns
- Monitor DNS-over-HTTPS (DoH) usage

#### TLS/SSL Traffic
- **TLS Handshake Type**: Client Hello, Server Hello, etc. (`tls_handshake_type`)
- **TLS Server Name (SNI)**: Destination domain for HTTPS (`tls_server_name`)

**Use Cases:**
- Identify HTTPS destinations without decryption
- Detect suspicious TLS handshake patterns
- Monitor encrypted IoT device communications
- Track certificate validation behavior

### 2. HTTPry Collector (`/home/jarvis/NetGuard/scripts/httpry_collector.py`)

Specialized HTTP traffic logger capturing:
- HTTP methods and URIs
- Response codes and content types
- Request/response headers
- Cookie information
- Referer tracking

### 3. tcpdump Collector (`/home/jarvis/NetGuard/scripts/tcpdump_collector.py`)

While tcpdump provides raw packet data, it's enhanced with:
- **GeoIP Lookup**: Country and city for external IPs
- **Protocol Classification**: TCP, UDP, ICMP, etc.
- **TCP Flags**: SYN, ACK, FIN, RST for connection tracking
- **Packet Size Analysis**: For bandwidth monitoring

### 4. p0f Collector (`/home/jarvis/NetGuard/scripts/p0f_collector.py`)

OS Fingerprinting provides:
- **Operating System**: Windows, Linux, macOS, iOS, Android
- **OS Version**: Specific version numbers
- **Link Type**: Ethernet, WiFi detection
- **HTTP Signatures**: Additional application fingerprinting

## Data Enrichment Pipeline

### Stage 1: Raw Packet Capture
- tcpdump captures all packets with full headers
- tshark dissects packets into protocol layers
- p0f analyzes TCP/IP stack characteristics

### Stage 2: Protocol Parsing
- HTTP/HTTPS: Extract URLs, methods, user agents
- DNS: Parse queries and responses
- TLS: Extract SNI from Client Hello

### Stage 3: Behavioral Analysis
- Device identification from User-Agent strings
- Application fingerprinting from traffic patterns
- Protocol anomaly detection

### Stage 4: Threat Intelligence
- Compare domains against threat feeds
- Identify suspicious patterns (DNS tunneling, DGA)
- Detect IoT device compromises

## Advanced Features

### 1. User-Agent Analysis
Parse user agent strings to identify:
- Browser type and version
- Operating system
- Device type (mobile, desktop, tablet, IoT)
- Application frameworks

**Example:**
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```
Identifies: Windows 10, Chrome browser, 64-bit

### 2. Domain Categorization
Classify domains based on TLD and patterns:
- Legitimate services (.com, .org)
- Suspicious TLDs (.tk, .ml, .ga)
- DGA patterns (long random strings)
- Known malware C2 domains

### 3. Certificate Analysis
Extract information from TLS certificates:
- Issuer and subject
- Validity period
- Self-signed detection
- Certificate chain validation

## Threat Detection Use Cases

### 1. Malware C2 Detection
**Indicators:**
- DNS queries to DGA domains
- HTTP beaconing at regular intervals
- Unusual user agents (PowerShell, curl)
- Connections to suspicious TLDs

**Application Layer Signals:**
- `dns_query` with random patterns
- `http_user_agent` matching known malware
- `tls_server_name` to known C2 infrastructure

### 2. Data Exfiltration
**Indicators:**
- Large HTTP POST requests
- DNS queries with base64-encoded data
- HTTPS to cloud storage services
- FTP traffic to external IPs

**Application Layer Signals:**
- `http_method` = POST with large content
- `dns_query` with long subdomain strings
- `tls_server_name` to file sharing sites

### 3. IoT Device Compromise
**Indicators:**
- IoT device making DNS queries to unexpected domains
- HTTP requests from devices that should use HTTPS
- Telnet/SSH traffic from smart devices
- Unusual user agents from IoT devices

**Application Layer Signals:**
- `http_host` to known IoT botnet C2s
- `dns_query` from devices with suspicious patterns
- Missing or generic `http_user_agent` from IoT

### 4. Credential Theft
**Indicators:**
- HTTP authentication attempts
- Form submissions over unencrypted HTTP
- FTP/Telnet with plaintext passwords
- SMTP authentication failures

**Application Layer Signals:**
- `http_uri` containing /login or /auth
- `http_method` = POST to login pages
- Presence of authentication headers

## Database Schema

All parsed application layer data is stored in SQLite with the following structure:

```sql
-- tshark table (most comprehensive)
CREATE TABLE tshark_YYYYMMDDHHMMSS (
    -- HTTP Fields
    http_host TEXT,              -- e.g., 'www.example.com'
    http_uri TEXT,               -- e.g., '/api/v1/data'
    http_method TEXT,            -- e.g., 'GET', 'POST'
    http_user_agent TEXT,        -- Full UA string
    http_response_code INTEGER,  -- 200, 404, etc.
    
    -- DNS Fields
    dns_query TEXT,              -- e.g., 'malware.com'
    dns_query_type TEXT,         -- 'A', 'AAAA', 'MX'
    dns_response TEXT,           -- Resolved IP
    
    -- TLS Fields
    tls_handshake_type TEXT,     -- 'Client Hello'
    tls_server_name TEXT,        -- SNI hostname
    
    -- Analysis Fields
    is_suspicious INTEGER,       -- Boolean flag
    threat_score INTEGER,        -- 0-100 risk score
    
    -- Standard Fields
    timestamp TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    protocol TEXT,
    ...
);
```

## Query Examples

### Find All HTTP Traffic to Specific Domain
```sql
SELECT timestamp, src_ip, http_uri, http_method
FROM tshark_20251013000000
WHERE http_host LIKE '%example.com%'
ORDER BY timestamp DESC;
```

### Detect Potential DNS Tunneling
```sql
SELECT dns_query, COUNT(*) as query_count
FROM tshark_20251013000000
WHERE LENGTH(dns_query) > 63  -- Suspiciously long
GROUP BY dns_query
HAVING query_count > 10
ORDER BY query_count DESC;
```

### Identify Suspicious User Agents
```sql
SELECT DISTINCT http_user_agent, src_ip, COUNT(*) as requests
FROM tshark_20251013000000
WHERE http_user_agent LIKE '%PowerShell%'
   OR http_user_agent LIKE '%curl%'
   OR http_user_agent LIKE '%wget%'
GROUP BY http_user_agent, src_ip;
```

### Track TLS Connections by Device
```sql
SELECT src_ip, tls_server_name, COUNT(*) as connections
FROM tshark_20251013000000
WHERE tls_server_name IS NOT NULL
GROUP BY src_ip, tls_server_name
ORDER BY connections DESC;
```

## Performance Considerations

### 1. Parsing Overhead
- tshark is CPU-intensive for deep packet inspection
- Capture limited to 30-second windows to prevent lag
- Only parse essential fields to reduce processing time

### 2. Storage Optimization
- Application layer fields are TEXT (variable length)
- NULL values used for missing data (no storage waste)
- Indexes on timestamp and IP addresses for fast queries

### 3. Privacy & Compliance
- No payload data is stored (only metadata)
- URLs and domains captured, not content
- User agents stored for device identification only
- Can be disabled via configuration

## AI Integration

Application layer data is sent to Gemini AI for intelligent analysis:

### Data Sent to AI
```json
{
  "http_summary": {
    "total_requests": 1500,
    "top_domains": ["google.com", "facebook.com"],
    "user_agents": ["Chrome/118", "Firefox/119"],
    "suspicious_requests": []
  },
  "dns_summary": {
    "total_queries": 500,
    "top_queries": ["example.com", "test.com"],
    "dga_domains": [],
    "tunnel_attempts": 0
  },
  "tls_summary": {
    "encrypted_connections": 1200,
    "top_destinations": ["cdn.example.com"],
    "cert_warnings": []
  }
}
```

### AI Analysis Output
- Behavioral pattern recognition
- Anomaly detection in application usage
- Context-aware threat scoring
- Recommendations for security improvements

## Future Enhancements

### Planned Features
1. **Full HTTP Body Inspection** (optional, privacy-aware)
2. **JavaScript/WebSocket Analysis**
3. **API Endpoint Classification**
4. **OAuth/Authentication Flow Tracking**
5. **Mobile App Protocol Detection**
6. **Email Protocol Analysis (SMTP, IMAP)**
7. **Custom Protocol Decoders**

### Configuration Options
```json
{
  "parsing_depth": "full|metadata|minimal",
  "store_payloads": false,
  "privacy_mode": true,
  "custom_protocols": ["mqtt", "coap"]
}
```

## Conclusion

NetGuard Pro's application layer parsing provides deep visibility into network behavior without requiring payload inspection. This metadata-driven approach balances security insight with privacy protection, making it ideal for home network monitoring.

All parsing is done locally on the Raspberry Pi using standard Linux tools (tshark, httpry, p0f), with AI analysis enhancing detection through the Gemini API.


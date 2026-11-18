# Field Intelligence Methodology

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Purpose:** Systematic approach to physical/field security assessments using portable hardware

---

## Methodology Overview

This method covers physical sites and wireless devices with portable equipment.
The phases cover preparation, site survey, wireless discovery, target assessment, evidence, and reporting.
Use the location and time limits in the engagement scope.

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Prepare   │ → │   Survey    │ → │  Enumerate  │ → │   Assess    │ → │   Report    │
│             │    │             │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │                  │
 Equipment          Site intel         Target ID          Test/Validate      Document
 + authorization
```

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## Phase 1: Pre-Engagement Preparation

### 1.1 Authorization

**Required Documentation:**
- [ ] Written scope definition
- [ ] Physical location boundaries (addresses, coordinates)
- [ ] Time windows for testing
- [ ] Emergency contacts
- [ ] Identification badge/letter (when necessary)
- [ ] Legal sign-off

**Scope Boundaries:**
```markdown
## Authorized Scope

**Locations:**
- [Address 1] - [Building/Area]
- [Address 2] - [Building/Area]

**RF Bands:** (if applicable)
- [ ] WiFi (2.4GHz, 5GHz, 6GHz)
- [ ] BLE
- [ ] Sub-GHz ([specify frequencies])
- [ ] Other: [specify]

**Time Windows:**
- [Day 1]: [Start time] - [End time]
- [Day 2]: [Start time] - [End time]

**Excluded:**
- [Explicitly excluded areas/systems]
```

### 1.2 Equipment Preparation

**Core Equipment Checklist:**
| Item | Purpose | Charged | Tested |
|------|---------|---------|--------|
| Cardputer/Flipper | Multi-tool intel | [ ] | [ ] |
| Laptop | Analysis/logging | [ ] | [ ] |
| External battery | Extended operation | [ ] | [ ] |
| USB cables | Data transfer | [ ] | [ ] |
| SD cards | Data storage | [ ] | [ ] |
| WiFi adapter | Extended range | [ ] | [ ] |
| Directional antenna | Long-range capture | [ ] | [ ] |
| Camera | Visual documentation | [ ] | [ ] |
| Notepad | Manual notes | [ ] | [ ] |

**Firmware/Software Preparation:**
```bash
# Flash appropriate firmware
# Cardputer
pio run -e m5stack-stamps3
pio run -t upload

# Flipper Zero
qflipper --install firmware.dfu

# Verify tools are functional
# Test each capability before deployment
```

### 1.3 Baseline Data Collection

Before field work, collect the following information:
- Target organization public information
- Known WiFi networks (Wigle, etc.)
- Physical site imagery (satellite, street view)
- Known device types in scope
- Expected wireless protocols

### Deliverable
- [ ] `authorization.md` - Scope and authorization documents
- [ ] `equipment-checklist.md` - Prepared equipment list
- [ ] `baseline-intel.md` - Pre-engagement intelligence

---

## Phase 2: Site Survey

### 2.1 Physical Intelligence

**External Survey:**
- Building perimeter
- Entry/exit points
- Camera locations
- Antenna installations
- Cable runs (exposed conduit)
- Guard stations
- Parking areas

**Internal Survey (if authorized):**
- Network closets
- Server rooms
- Workstation areas
- Meeting rooms
- Common areas
- Access control points

### 2.2 Visual Documentation

```markdown
## Site Survey Photos

| Photo ID | Location | Description | GPS | Time |
|----------|----------|-------------|-----|------|
| P001 | Front entrance | Main entry door with HID reader | [coords] | [time] |
| P002 | North wall | Exposed cable tray | [coords] | [time] |
```

**Photography Guidelines:**
- Include reference points for scale
- Capture signage and labels
- Record visible equipment models
- Note camera/sensor coverage gaps

### 2.3 Access Control Observation

| Location | Control Type | Vendor | Notes |
|----------|--------------|--------|-------|
| Main entry | RFID card | HID | Prox, not iClass |
| Server room | Biometric + PIN | [Vendor] | Fingerprint scanner |
| Parking | License plate | [Vendor] | No validation observed |

### Deliverable
- [ ] `site-survey.md` - Physical survey notes
- [ ] `photos/` - Documented imagery
- [ ] `access-controls.md` - Access control inventory

---

## Phase 3: Wireless Enumeration

### 3.1 WiFi Survey

**Passive Scanning:**
```bash
# Cardputer/ESP32
# Boot → WiFi Mode → Scan

# Linux laptop
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon --output-format csv -w survey
```

**Data Collection:**
| SSID | BSSID | Channel | Security | Signal | Notes |
|------|-------|---------|----------|--------|-------|
| Corp-WiFi | AA:BB:CC:DD:EE:FF | 6 | WPA2-Enterprise | -45 | 802.1X |
| IoT-Network | AA:BB:CC:DD:EE:00 | 11 | WPA2-PSK | -52 | Weak? |
| Guest | AA:BB:CC:DD:EE:01 | 1 | Open | -60 | Captive portal |

**Hidden Network Detection:**
```bash
# Probe for hidden networks
airodump-ng wlan0mon | grep "<length:"

# Deauth to capture SSID (if authorized)
aireplay-ng -0 1 -a [BSSID] wlan0mon
```

### 3.2 BLE Survey

**Device Discovery:**
```cpp
// ESP32/Cardputer BLE scan
BLEScan* scan = BLEDevice::getScan();
scan->setActiveScan(true);
BLEScanResults results = scan->start(30);

for (int i = 0; i < results.getCount(); i++) {
    BLEAdvertisedDevice device = results.getDevice(i);
    // Log: MAC, name, RSSI, services
}
```

| MAC Address | Name | RSSI | Services | Notes |
|-------------|------|------|----------|-------|
| AA:BB:CC:DD:EE:02 | Lock-001 | -48 | GATT | Smart lock |
| AA:BB:CC:DD:EE:03 | Beacon-A | -55 | iBeacon | Location beacon |

### 3.3 Sub-GHz Survey (if in scope)

**Frequency Scanning:**
```
Flipper Zero → Sub-GHz → Read RAW

Target Frequencies:
- 315 MHz (US remotes)
- 433.92 MHz (EU remotes)
- 868 MHz (EU IoT)
- 915 MHz (US IoT)
```

| Frequency | Modulation | Signal Type | Notes |
|-----------|------------|-------------|-------|
| 433.92 MHz | OOK | Garage door | Rolling code |
| 315 MHz | ASK | Key fob | Fixed code |

### Deliverable
- [ ] `wifi-survey.csv` - WiFi enumeration results
- [ ] `ble-survey.csv` - BLE device inventory
- [ ] `rf-survey.csv` - Sub-GHz captures

---

## Phase 4: Target Assessment

### 4.1 Network Connection Testing

Use the following sequence for each accessible network:

```bash
# Connect and assess
# Note: Only if authorized

# DHCP lease
dhclient wlan0

# Network discovery
nmap -sn 192.168.1.0/24

# Service identification
nmap -sV -p- 192.168.1.1
```

### 4.2 Protocol-Specific Testing

**IoT Camera Assessment:**
```python
# ONVIF enumeration
from onvif import ONVIFCamera
cam = ONVIFCamera(host, port, user, passwd)
caps = cam.devicemgmt.GetCapabilities()

# RTSP probe
ffprobe rtsp://host:554/stream
```

**Access Control Testing:**
```bash
# RFID cloning (if authorized)
# Flipper Zero → RFID → Read

# BLE lock interaction
# Custom script for specific lock type
```

### 4.3 Signal Capture

**WiFi Handshake Capture:**
```bash
# Capture WPA handshake (if authorized)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Wait for client or send deauth
```

**RF Signal Capture:**
```
Flipper Zero → Sub-GHz → Read RAW → Save

File: signal_433mhz.sub
```

### 4.4 Vulnerability Identification

| Target | Finding | Severity | Evidence |
|--------|---------|----------|----------|
| IoT-Network | Default credentials | HIGH | admin/admin works |
| Camera-001 | Unauthenticated RTSP | HIGH | Stream accessible |
| Lock-003 | Replay attack possible | CRITICAL | Signal captured |

### Deliverable
- [ ] `network-assessment.md` - Network testing results
- [ ] `captures/` - Captured signals/traffic
- [ ] `vulnerabilities.md` - Identified issues

---

## Phase 5: Evidence Collection

### 5.1 Data Export

```bash
# Export from devices
# Cardputer SD card
cp /mnt/sdcard/data/* ./evidence/cardputer/

# Flipper Zero
qflipper --export-files ./evidence/flipper/

# Laptop captures
cp *.pcap *.csv *.sub ./evidence/captures/
```

### 5.2 Evidence Manifest

```markdown
## Evidence Manifest

| ID | Type | Source | Hash (SHA256) | Description |
|----|------|--------|---------------|-------------|
| E001 | pcap | Laptop | abc123... | WiFi capture |
| E002 | .sub | Flipper | def456... | RF signal |
| E003 | photo | Camera | ghi789... | Server room |
```

### 5.3 Chain of Custody

```markdown
## Chain of Custody

| Evidence ID | Collected By | Date/Time | Location | Notes |
|-------------|--------------|-----------|----------|-------|
| E001 | [Name] | 2026-01-23 14:30 | Site A | During survey |
```

### Deliverable
- [ ] `evidence/` - All collected evidence
- [ ] `evidence-manifest.md` - Evidence inventory
- [ ] `chain-of-custody.md` - Custody documentation

---

## Phase 6: Reporting

### Field Report Template

```markdown
# Field Intelligence Report

**Engagement:** [Name]
**Date(s):** [Start] - [End]
**Location(s):** [Addresses]
**Assessor(s):** [Names]

## Executive Summary
[One paragraph summary of key findings]

## Scope
[Authorized scope and boundaries]

## Methodology
[Brief methodology description]

## Findings

### Finding 1: [Title]
**Severity:** [Critical/High/Medium/Low]
**Location:** [Physical or logical location]
**Description:** [What was found]
**Evidence:** [Reference to evidence IDs]
**Impact:** [Potential impact]
**Recommendation:** [Remediation steps]

### Finding 2: [Title]
...

## Wireless Inventory
[Summary of discovered wireless assets]

## Recommendations
[Prioritized recommendations]

## Appendices
- A: Evidence Manifest
- B: WiFi Survey Results
- C: Photos
```

### Deliverable
- [ ] `field-report.md` - Complete assessment report
- [ ] `recommendations.md` - Prioritized remediation

---

## Quick Reference

### Equipment Quick Setup

```bash
# Cardputer boot sequence
1. Power on
2. Select mode (WiFi/BLE/IR)
3. Execute scan
4. Export to SD

# Flipper Zero
1. Power on
2. Select tool (Sub-GHz/RFID/NFC)
3. Read/Capture
4. Save to SD
```

### Common Issues

| Issue | Solution |
|-------|----------|
| No networks found | Check antenna, move location |
| Weak signal | Use directional antenna |
| Device not connecting | Check credentials, proximity |
| Capture empty | Verify frequency, modulation |

### Legal Reminders

- [ ] Only test authorized scope
- [ ] Do not interfere with non-target systems
- [ ] Respect physical boundaries
- [ ] Record all activities
- [ ] Report security incidents

---

## Checklist

### Pre-Engagement
- [ ] Authorization obtained
- [ ] Scope documented
- [ ] Equipment prepared
- [ ] Baseline intel collected

### During Assessment
- [ ] Site survey complete
- [ ] WiFi enumeration complete
- [ ] BLE enumeration complete
- [ ] RF survey complete (if in scope)
- [ ] Target assessment complete
- [ ] Evidence collected

### Post-Engagement
- [ ] Evidence secured
- [ ] Chain of custody documented
- [ ] Report drafted
- [ ] Findings presented

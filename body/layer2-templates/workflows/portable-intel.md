# Portable Hardware Intelligence Workflow

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Structured field intelligence using portable hardware platforms (M5Stack Cardputer, Flipper Zero, etc.)

Use this workflow to collect field evidence with portable hardware. Record the permitted targets, hardware, firmware version, and collection conditions.

Use command examples in an operator analysis workspace.
During governed agent work, use existing phase directories under `.bra/artifacts/`.
Store finding records in `layer3-engagement/NOTES/FINDINGS.md`.
Replace example targets with the approved scope values.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Prepare   │ → │    Scan     │ → │   Interact  │ → │   Document  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │
  Flash tools        Enumerate         Connect/Test        Export data
```

---

## Supported Platforms

### M5Stack Cardputer
- **CPU:** ESP32-S3 (240MHz dual-core)
- **Display:** 1.14" IPS (240x135)
- **Connectivity:** WiFi, BLE, IR
- **Input:** Full keyboard, GPIO
- **Use case:** WiFi intel, BLE scanning, IR replay

### Flipper Zero
- **CPU:** STM32WB55
- **Display:** 1.4" monochrome (128x64)
- **Connectivity:** Sub-GHz, NFC, RFID, IR, GPIO
- **Use case:** RF protocol analysis, access control testing

### ESP32 Generic
- **CPU:** ESP32/ESP32-S2/S3 variants
- **Connectivity:** WiFi, BLE
- **Use case:** Custom firmware, deauth testing, packet capture

---

## Stage 1: Preparation

### Hardware Setup
```bash
# M5Stack Cardputer - PlatformIO
pio run -e m5stack-stamps3

# Flipper Zero - qFlipper
qflipper --install <firmware.dfu>

# ESP32 Generic - esptool
esptool.py --chip esp32s3 --port /dev/ttyUSB0 write_flash 0 firmware.bin
```

### Firmware Selection

#### M5Stack Options
| Firmware | Purpose | Repository |
|----------|---------|------------|
| Bruce | Multi-tool (WiFi/BLE/IR) | github.com/pr3y/Bruce |
| Marauder | WiFi offensive | github.com/justcallmekoko/ESP32Marauder |
| Custom | Target-specific | Project repository |

#### Flipper Options
| Firmware | Purpose |
|----------|---------|
| Official | Stock, stable |
| Unleashed | Extended features |
| RogueMaster | Kitchen sink |

### Pre-Field Checklist
- [ ] Firmware flashed and tested
- [ ] Battery fully charged
- [ ] SD card inserted (if applicable)
- [ ] Target-specific tools loaded
- [ ] Backup firmware available
- [ ] Legal authorization documented

### Deliverable
- [ ] Configured device ready for deployment

---

## Stage 2: WiFi Intelligence

### Passive Scanning
```
Boot Device → WiFi Mode → Station → Scan Networks

Output:
┌─────────────────────────────────────────────────┐
│ # │ SSID                │ RSSI │ CH │ Auth      │
├───┼────────────────────┼──────┼────┼───────────┤
│ 1 │ TargetCorp-Guest   │ -45  │ 6  │ WPA2      │
│ 2 │ [CAMERA-SSID]  │ -52  │ 11 │ WPA2      │
│ 3 │ IoT-Sensor-Network │ -60  │ 1  │ Open      │
└───────────────────────────────────────────────┘
```

### Target Identification
```
Filter criteria:
- SSID patterns matching target (vendor names, device types)
- Signal strength (RSSI > -70 for reliable interaction)
- Channel clustering (indicates co-located devices)
- Auth mode (Open = immediate access, WPA2 = credential required)
```

### Hidden Network Detection
```cpp
// ESP32 hidden network detection
WiFi.scanNetworks(false, true);  // async=false, show_hidden=true

// For each result:
if (WiFi.SSID(i).length() == 0) {
    Serial.printf("Hidden network on channel %d\n", WiFi.channel(i));
}
```

### Deliverable
- [ ] `wifi-scan.csv` - All discovered networks
- [ ] `targets.md` - Prioritized target list

---

## Stage 3: BLE Intelligence

### BLE Scanning
```
M5Stack/ESP32 BLE Scan:

Device Discovery:
┌────────────────────────────────────────────────────────┐
│ MAC               │ Name           │ RSSI │ Services   │
├───────────────────┼───────────────┼──────┼────────────┤
│ AA:BB:CC:DD:EE:01 │ SmartLock-001 │ -48  │ GATT       │
│ AA:BB:CC:DD:EE:02 │ (unknown)     │ -55  │ iBeacon    │
│ AA:BB:CC:DD:EE:03 │ FitBand-XYZ   │ -62  │ HR Monitor │
└────────────────────────────────────────────────────────┘
```

### Service Enumeration
```cpp
// Connect and enumerate services
BLEClient* client = BLEDevice::createClient();
client->connect(targetDevice);

std::map<std::string, BLERemoteService*>* services = client->getServices();
for (auto& svc : *services) {
    Serial.printf("Service: %s\n", svc.first.c_str());
    // Enumerate characteristics
    auto chars = svc.second->getCharacteristics();
    for (auto& chr : *chars) {
        Serial.printf("  Char: %s Props: %02x\n",
            chr.first.c_str(), chr.second->getProperties());
    }
}
```

### Common BLE Attack Vectors
| Attack | Description | Tool |
|--------|-------------|------|
| Sniffing | Passive capture of BLE traffic | Ubertooth, nRF Sniffer |
| MITM | Relay between device and phone | GATTacker, BtleJuice |
| Fuzzing | Malformed GATT requests | BLE CTF tools |
| Replay | Capture and replay commands | Custom scripts |

### Deliverable
- [ ] `ble-scan.csv` - Discovered BLE devices
- [ ] `ble-services.json` - Enumerated services

---

## Stage 4: RF Intelligence (Sub-GHz)

### Frequency Scanning (Flipper Zero)
```
Sub-GHz → Read RAW

Common Target Frequencies:
┌──────────────────────────────────────────┐
│ Frequency   │ Use Case                   │
├─────────────┼────────────────────────────┤
│ 315 MHz     │ US garage doors, key fobs  │
│ 433.92 MHz  │ EU remotes, sensors        │
│ 868 MHz     │ EU smart home              │
│ 915 MHz     │ US/AU IoT, LoRa            │
└──────────────────────────────────────────┘
```

### Signal Capture
```
1. Set frequency range
2. Monitor for signals
3. Capture to SD card
4. Analyze modulation
5. Replay or decode
```

### Protocol Identification
| Protocol | Frequency | Modulation |
|----------|-----------|------------|
| Came | 433.92 | AM/OOK |
| Nice | 433.92 | AM/OOK |
| Princeton | 315/433 | ASK |
| LoRa | 868/915 | CSS |

### Deliverable
- [ ] `.sub` files - Captured signals
- [ ] `rf-inventory.md` - Identified transmitters

---

## Stage 5: Target Interaction

### WiFi Connection
```cpp
// M5Stack connection sequence
void connectToTarget(const char* ssid, const char* pass) {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (useStaticIP) {
        WiFi.config(localIP, gateway, subnet, dns);
    }

    WiFi.begin(ssid, pass);

    int timeout = 20000; // 20 seconds
    while (WiFi.status() != WL_CONNECTED && timeout > 0) {
        delay(500);
        timeout -= 500;
    }

    if (WiFi.status() == WL_CONNECTED) {
        // Success - note assigned IP
    }
}
```

### Protocol Testing
```bash
# From connected portable device (or tethered laptop)

# HTTP services
curl http://192.0.2.1/
curl http://192.0.2.1:8080/api/status

# RTSP streams
ffprobe rtsp://192.0.2.1:554/live

# Custom protocols
nc 192.0.2.1 1234
```

### Live Data Capture
```cpp
// MJPEG stream capture example (Cardputer)
void streamMjpeg() {
    WiFiClient client;
    if (client.connect(gatewayIP, streamPort)) {
        client.print("GET /mjpeg HTTP/1.1\r\n");
        client.print("Host: ");
        client.println(gatewayIP);
        client.println();

        // Parse and display frames
        while (client.connected()) {
            // Read boundary
            // Read JPEG data
            // Display on screen
            // Check for abort
        }
    }
}
```

### Deliverable
- [ ] `interaction-log.md` - Actions taken and responses
- [ ] Captured data (streams, responses, files)

---

## Stage 6: Data Exfiltration

### SD Card Export
```cpp
// Write findings to SD
File file = SD.open("/intel/findings.txt", FILE_APPEND);
file.printf("Target: %s\n", ssid);
file.printf("IP: %s\n", WiFi.localIP().toString().c_str());
file.printf("Timestamp: %lu\n", millis());
file.close();
```

### Serial Export
```cpp
// Dump to serial for laptop capture
Serial.println("--- BEGIN EXPORT ---");
Serial.println(jsonFindings);
Serial.println("--- END EXPORT ---");

// Capture with: pio device monitor > findings.txt
```

### BLE Exfil (if in hostile environment)
```cpp
// Broadcast findings via BLE advertising
BLEAdvertisementData advData;
advData.setName("EXFIL");
advData.setManufacturerData(findingsEncoded);
// Receive with BLE scanner on phone
```

### Deliverable
- [ ] All collected data exported
- [ ] Chain of custody maintained

---

## Stage 7: Reporting

### Field Notes Template
````markdown
## Field Intel Report

**Date:** YYYY-MM-DD
**Location:** [Description]
**Hardware:** [Device used]
**Authorization:** [Reference number]

### Targets Discovered

| Type | Identifier | Notes |
|------|------------|-------|
| WiFi | [SSID] | [Details] |
| BLE | [MAC] | [Details] |
| RF | [Freq] | [Details] |

### Interactions

1. [Target]: [Action taken] → [Result]
2. ...

### Captured Data

- [ ] `file1.bin` - Description
- [ ] `file2.json` - Description

### Findings

#### Finding 1: [Title]
**Severity:** [Rating]
**Details:** [Description]
**Evidence:** [Reference to captured data]

### Recommendations

1. [Recommendation]
2. [Recommendation]
````

### Deliverable
- [ ] `field-report.md` - Complete field report
- [ ] All evidence files organized and labeled

---

## Quick Reference

### Cardputer Key Bindings
| Key | Action |
|-----|--------|
| Fn+I/J/K/L | Navigation |
| Enter | Select |
| Q | Cancel/Abort |
| Ctrl+C | Force stop stream |

### Common Issues
| Issue | Solution |
|-------|----------|
| No networks found | Check antenna, move closer |
| Connection timeout | Verify password, check AP limits |
| Stream fails | Try port 1234, enable live view first |
| Low battery | Use serial passthrough from laptop |

### Legal Considerations
- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] No interference with non-target systems
- [ ] Data handling compliant with policy
- [ ] Report findings responsibly

---

## Checklist

- [ ] Hardware prepared and charged
- [ ] Firmware appropriate for targets
- [ ] Authorization documented
- [ ] WiFi scan completed
- [ ] BLE scan completed
- [ ] RF scan completed (if applicable)
- [ ] Target interaction documented
- [ ] Data exported
- [ ] Field report generated

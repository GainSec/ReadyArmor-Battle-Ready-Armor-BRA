# HAP (HomeKit Accessory Protocol) Fuzzing Methodology Template

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Target:** HomeKit accessories, HAP implementations, smart home devices

---

## Overview

This method covers HomeKit Accessory Protocol implementations.
HAP means HomeKit Accessory Protocol.
The phases cover discovery, fuzzing harnesses, TLV data, protocol states, cryptography, and crash analysis.
TLV means type, length, and value.

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## HAP Attack Surfaces

### 1. HAP IP Transport (Primary)

| Component | Port | Protocol | Attack Vector |
|-----------|------|----------|---------------|
| Accessory Server | 80 (default) | HTTP | Request parsing, TLV handling |
| Pair Setup | 80 | HTTP + SRP | Crypto implementation |
| Pair Verify | 80 | HTTP + Curve25519 | Session establishment |
| HAP Events | 80 | HTTP (EventSource) | Event injection |

### 2. Camera-Specific Surfaces

| Component | Protocol | Attack Vector |
|-----------|----------|---------------|
| RTP Streams | UDP | Media parsing |
| RTSP Control | TCP | Command injection |
| SRTP | UDP | Key negotiation |
| ICE/STUN | UDP | NAT traversal |

### 3. Radio/Privileged Services

| Component | Access | Attack Vector |
|-----------|--------|---------------|
| BLE HAP | Radio | Pairing, characteristics |
| Thread | Radio | Network layer |
| WiFi Setup | Radio | Provisioning |

### 4. Document/Data Ingestion

| Component | Format | Attack Vector |
|-----------|--------|---------------|
| Plist | Binary/XML | Parser bugs |
| Images | JPEG/PNG | Image processing |
| Firmware | Proprietary | Update mechanism |

---

## Phase 1: Target Identification

### Objectives
- Identify HAP implementation type
- Enumerate supported services
- Map characteristic tree
- Record pairing state

### HAP Discovery
```bash
# Bonjour/mDNS discovery
dns-sd -B _hap._tcp local

# Service details
dns-sd -L "<accessory_name>" _hap._tcp local

# Query TXT record fields:
# c# = Configuration number
# ff = Feature flags
# id = Device ID
# md = Model name
# pv = Protocol version
# s# = State number
# sf = Status flags
# ci = Category identifier
```

### Accessory Enumeration
```python
# Using HAP library (after pairing)
from homekit import HomeKit

hk = HomeKit()
pairing = hk.load_pairing('<pairing_data>')
accessories = pairing.list_accessories()

for acc in accessories:
    for service in acc.services:
        print(f"Service: {service.type}")
        for char in service.characteristics:
            print(f"  Char: {char.type} - {char.value}")
```

### Deliverables
- [ ] Accessory inventory
- [ ] Service/characteristic map
- [ ] Protocol version identification
- [ ] Pairing state documentation

---

## Phase 2: Fuzzing Harness Development

### Objectives
- Create AFL++-compatible harness
- Instrument target functions
- Prepare corpus management
- Configure sanitizers

### AFL++ with Frida Mode

#### Harness Template
```c
// hap_fuzz_harness.c
#include <stdint.h>
#include <stddef.h>

// Target function prototype
int hap_parse_tlv(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;  // Minimum TLV size

    hap_parse_tlv(data, size);
    return 0;
}
```

#### Frida Mode Setup
```bash
# Build with Frida mode
cd AFLplusplus
make FRIDA_MODE=1

# Run with Frida instrumentation
AFL_FRIDA_PERSISTENT_CNT=100000 \
AFL_FRIDA_PERSISTENT_ADDR=<target_func> \
afl-fuzz -i corpus/ -o findings/ -- ./hap_target
```

#### In-Process Fuzzing
```python
# Frida script for in-process fuzzing
import frida

session = frida.attach("<process_name>")
script = session.create_script("""
    // Hook target function
    Interceptor.attach(ptr("<target_addr>"), {
        onEnter: function(args) {
            // Inject fuzz data
            var fuzz_data = recv('fuzz', function(data) {
                Memory.writeByteArray(args[0], data.payload);
            });
            fuzz_data.wait();
        }
    });
""")
script.load()
```

### Corpus Management

#### Seed Collection
```bash
# Capture legitimate HAP traffic
tcpdump -i any -w hap_traffic.pcap port 80

# Extract TLV bodies
tshark -r hap_traffic.pcap -T fields -e http.file_data > corpus/

# Convert to binary corpus
for f in corpus/*; do
    xxd -r -p $f > corpus_bin/$(basename $f).bin
done
```

#### Corpus Minimization
```bash
afl-cmin -i corpus/ -o corpus_min/ -- ./hap_target @@
```

### Deliverables
- [ ] Fuzzing harness code
- [ ] Frida instrumentation scripts
- [ ] Initial corpus (minimized)
- [ ] Build instructions

---

## Phase 3: TLV Fuzzing

### Objectives
- Fuzz HAP TLV parsing
- Do tests of boundary conditions
- Identify parser crashes
- Record findings

### TLV Format
```
+------+--------+---------+
| Type | Length | Value   |
| 1b   | 1b     | 0-255b  |
+------+--------+---------+
```

### TLV Mutation Strategies

#### Structure Mutations
```python
def mutate_tlv_structure(tlv_data):
    mutations = []

    # Invalid length (length > remaining data)
    m1 = bytearray(tlv_data)
    m1[1] = 0xFF
    mutations.append(m1)

    # Zero length with type requiring data
    m2 = bytearray(tlv_data)
    m2[1] = 0x00
    mutations.append(m2)

    # Nested TLV corruption
    m3 = bytearray(tlv_data)
    if len(m3) > 10:
        m3[8] = 0xFF  # Corrupt nested length
    mutations.append(m3)

    return mutations
```

#### Type-Specific Mutations
| TLV Type | Test Cases |
|----------|------------|
| kTLVType_Method | Invalid method ID |
| kTLVType_Identifier | Oversized identifier |
| kTLVType_Salt | Wrong size salt |
| kTLVType_PublicKey | Malformed curve point |
| kTLVType_Proof | Invalid SRP proof |
| kTLVType_EncryptedData | Decrypt oracle |
| kTLVType_State | Out-of-sequence |
| kTLVType_Error | Error injection |

### Deliverables
- [ ] TLV fuzzer implementation
- [ ] Mutation dictionary
- [ ] Crash triage report
- [ ] PoC for reproducible crashes

---

## Phase 4: Protocol State Machine Fuzzing

### Objectives
- Map HAP state machine
- Fuzz state transitions
- Do tests of for state confusion
- Identify logic bugs

### HAP State Machine

```
[Unpaired] → Pair-Setup → [Paired]
                            ↓
[Paired] → Pair-Verify → [Verified/Session]
                            ↓
[Session] → Encrypted HAP requests
```

### State Transition Tests
| From State | To State | Test |
|------------|----------|------|
| Unpaired | Pair-Setup M1 | Valid start |
| Pair-Setup M1 | M2 | Valid response |
| Pair-Setup M1 | M4 | Skip M2/M3 |
| Pair-Setup M5 | M1 | Restart during |
| Paired | Pair-Verify | Normal flow |
| Verified | Unpaired | Force unpair |
| Session | Session | Request fuzzing |

### State Confusion Attacks
```python
def test_state_confusion(accessory):
    # Start pair-setup
    accessory.send_pair_setup_m1()

    # Don't complete, jump to pair-verify
    result = accessory.send_pair_verify_m1()

    # Check if accessory handles gracefully
    if result.error != "kTLVError_Authentication":
        print("Potential state confusion!")
```

### Deliverables
- [ ] State machine diagram
- [ ] State transition fuzzer
- [ ] State confusion findings
- [ ] Logic bug documentation

---

## Phase 5: Crypto Implementation Testing

### Objectives
- Do tests of SRP implementation
- Verify Curve25519 handling
- Check ChaCha20-Poly1305
- Identify timing side channels

### SRP Testing
```python
# Test weak password handling
def test_srp_weak_passwords():
    weak_passwords = ["000-00-000", "111-11-111", "123-45-678"]
    for pwd in weak_passwords:
        result = attempt_pair_setup(pwd)
        if result.success:
            print(f"Weak password accepted: {pwd}")

# Test SRP malleability
def test_srp_malleability():
    # Send A = 0 (should be rejected)
    m1 = build_pair_setup_m1(A=0)
    response = send_tlv(m1)
    # A = 0 leads to S = 0, trivial crack
```

### Curve25519 Testing
```python
# Low-order point injection
LOW_ORDER_POINTS = [
    bytes(32),  # Zero point
    bytes([0] * 31 + [1]),  # Point of order 8
]

for point in LOW_ORDER_POINTS:
    response = send_pair_verify_m1(public_key=point)
    if response.success:
        print("Low-order point accepted!")
```

### Timing Analysis
```python
import time

def measure_response_time(tlv_data):
    times = []
    for _ in range(1000):
        start = time.perf_counter()
        send_tlv(tlv_data)
        end = time.perf_counter()
        times.append(end - start)
    return statistics.mean(times), statistics.stdev(times)

# Compare timing for correct vs incorrect first byte
timing_correct = measure_response_time(correct_proof)
timing_wrong = measure_response_time(wrong_proof)
```

### Deliverables
- [ ] SRP implementation audit
- [ ] Curve25519 validation
- [ ] Timing analysis results
- [ ] Crypto vulnerability report

---

## Phase 6: Crash Analysis & Exploitation

### Objectives
- Triage fuzzer crashes
- Determine root cause
- Examine exploitability
- Develop PoC exploits

### Crash Triage Workflow
```bash
# Deduplicate crashes
afl-collect findings/ unique_crashes/

# Minimize crash inputs
for crash in unique_crashes/*; do
    afl-tmin -i "$crash" -o "min_$crash" -- ./hap_target @@
done

# Analyze with AddressSanitizer
ASAN_OPTIONS=detect_leaks=1 ./hap_target_asan min_crash
```

### Exploitability Assessment
| Crash Type | Exploitability | Next Steps |
|------------|----------------|------------|
| Stack BOF | High | ROP chain |
| Heap BOF | Medium-High | Heap spray |
| Use-After-Free | High | Object replacement |
| Null deref | Low | DoS only |
| Division by zero | Low | DoS only |
| Assertion fail | Low | DoS only |

### Deliverables
- [ ] Crash triage spreadsheet
- [ ] Root cause analysis
- [ ] Exploitability rating
- [ ] PoC exploits (if applicable)

---

## Tools Reference

| Category | Tools |
|----------|-------|
| Discovery | dns-sd, Bonjour Browser |
| Fuzzing | AFL++, libFuzzer, honggfuzz |
| Instrumentation | Frida, DynamoRIO |
| Crypto | cryptography (Python), mbedtls |
| Analysis | AddressSanitizer, Valgrind |
| HAP | homekit (Python), HAP-python |

---

## Checklist Summary

- [ ] Phase 1: Target identification complete
- [ ] Phase 2: Fuzzing harness ready
- [ ] Phase 3: TLV fuzzing complete
- [ ] Phase 4: State machine testing complete
- [ ] Phase 5: Crypto testing complete
- [ ] Phase 6: Crash analysis complete

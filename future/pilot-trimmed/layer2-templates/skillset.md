# Security Research Skillset Reference

> **Generated From:** Reusable assessment references
> **Purpose:** Comprehensive catalog of skills required for authorized security assessments

---

## Overview

Use this catalog to select assessment skills and identify training needs. Record the selected skills in `layer3-engagement/SKILLSUITES.md`.

---

## 1. Mobile Security

### Android Application Security
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| APK Reverse Engineering | Decompile, analyze, and understand Android apps | Can extract secrets, trace auth flows, identify vulns |
| Smali/Dalvik Bytecode | Read and modify low-level Android code | Can patch apps, bypass checks |
| Frida Scripting | Write runtime instrumentation scripts | Can bypass SSL pinning, hook methods, dump data |
| ADB Mastery | Advanced Android Debug Bridge usage | Can extract data, sideload, debug, capture logs |
| JDWP Exploitation | Exploit debuggable Android applications | Can achieve code execution via JDWP |
| SELinux Analysis | Understand and modify Android SELinux policies | Can identify policy gaps, inject rules |

### iOS Application Security
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| IPA Analysis | Analyze iOS application packages | Can extract, decrypt, analyze binaries |
| Objective-C/Swift RE | Reverse engineer iOS apps | Can trace flows, identify vulns in native code |
| iOS Jailbreak Knowledge | Understand iOS jailbreaks and their capabilities | Can set up test environment, use jailbreak tools |
| Keychain Analysis | Extract and analyze iOS keychain data | Can dump keychain, identify stored secrets |

---

## 2. Network Security

### Protocol Analysis
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| TCP/IP Fundamentals | Deep understanding of networking | Can analyze packets, identify anomalies |
| TLS/SSL Analysis | Assess TLS implementations | Can identify weak configs, perform MITM |
| HTTP/HTTPS Testing | Comprehensive web protocol testing | Can intercept, modify, replay requests |
| Custom Protocol RE | Reverse engineer proprietary protocols | Can document and fuzz unknown protocols |

### Wireless/RF
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| WiFi Security | Assess wireless network security | Can crack WPA, perform deauth, rogue AP |
| Bluetooth/BLE | Test Bluetooth implementations | Can sniff, MITM, fuzz BLE devices |
| SDR Fundamentals | Software-defined radio operation | Can capture, demodulate, replay signals |
| Protocol Reverse Engineering | Decode unknown RF protocols | Can identify modulation, decode frames |

---

## 3. IoT/Embedded Security

### Firmware Analysis
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Firmware Extraction | Extract firmware from devices/updates | Can binwalk, manual carve, flash dump |
| Filesystem Analysis | Navigate and analyze embedded filesystems | Can find secrets, analyze configs, identify vulns |
| Binary Analysis (ARM/MIPS) | Reverse engineer embedded binaries | Can disassemble, trace, identify vulnerabilities |
| Emulation | Run firmware in virtualized environment | Can set up QEMU, debug, test exploits |

### Hardware
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| UART/Serial | Interface with serial debug ports | Can identify pins, capture bootlogs |
| JTAG/SWD | Hardware debugging interfaces | Can connect, dump flash, debug |
| SPI/I2C | Communicate with flash/EEPROM | Can read/write storage chips |
| Logic Analysis | Capture and decode digital signals | Can use logic analyzer, identify protocols |

### Protocol-Specific
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| ONVIF/RTSP | IP camera protocols | Can enumerate, test auth, access streams |
| MQTT | IoT messaging protocol | Can subscribe, publish, find misconfigs |
| UPnP/SSDP | Device discovery protocols | Can enumerate, exploit exposed services |
| BACnet/Modbus | Industrial protocols | Can enumerate, read/write points |

---

## 4. Web Application Security

### OWASP Top 10
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Injection | SQL, command, LDAP, etc. | Can identify and exploit injection flaws |
| Broken Authentication | Auth/session vulnerabilities | Can bypass auth, hijack sessions |
| XSS | Cross-site scripting | Can identify and demonstrate XSS impact |
| CSRF | Cross-site request forgery | Can craft exploits, demonstrate impact |
| SSRF | Server-side request forgery | Can reach internal services, exfiltrate data |

### API Security
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| REST API Testing | Assess RESTful APIs | Can fuzz endpoints, test authz, find vulns |
| GraphQL Security | Assess GraphQL implementations | Can enumerate schema, test queries |
| OAuth/OIDC | Authentication protocol security | Can identify misconfigs, token theft |

---

## 5. Reverse Engineering

### Static Analysis
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| x86/x64 Assembly | Read Intel/AMD assembly | Can trace execution, identify vulns |
| ARM Assembly | Read ARM/ARM64 assembly | Can analyze mobile/embedded binaries |
| Decompilation | Use decompilers effectively | Can navigate Ghidra/IDA output |
| Control Flow Analysis | Understand program flow | Can trace from entry to vuln |

### Dynamic Analysis
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Debugging | Use debuggers effectively | Can set breakpoints, inspect memory |
| Tracing | Trace execution and syscalls | Can use strace/ltrace, identify behavior |
| Memory Analysis | Analyze process memory | Can dump, search, identify structures |

---

## 6. Exploitation

### Vulnerability Classes
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Buffer Overflows | Stack/heap overflow exploitation | Can craft exploits, bypass protections |
| Format Strings | Format string vulnerability exploitation | Can read/write memory via format bugs |
| Use-After-Free | Heap exploitation | Can trigger and exploit UAF |
| Type Confusion | Object type vulnerabilities | Can identify and exploit type confusion |

### Modern Mitigations
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| ASLR Bypass | Address space layout randomization bypass | Knows info leak techniques |
| DEP/NX Bypass | Data execution prevention bypass | Can use ROP/JOP techniques |
| Stack Canary Bypass | Stack protection bypass | Knows leak/brute techniques |
| CFI Bypass | Control flow integrity bypass | Understands modern CFI limitations |

---

## 7. Fuzzing

### Techniques
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Coverage-Guided | AFL++, libFuzzer | Can instrument, run, triage crashes |
| Grammar-Based | Structure-aware fuzzing | Can write grammars for protocols |
| Mutation-Based | Dumb fuzzing | Can set up and run effectively |
| In-Process | Persistent mode fuzzing | Can write harnesses, optimize throughput |

### Crash Analysis
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Triage | Categorize crashes | Can deduplicate, identify root cause |
| Exploitability | Assess crash exploitability | Can determine if crash is exploitable |
| Minimization | Reduce crash inputs | Can minimize for PoC development |

---

## 8. Reporting & Documentation

### Technical Writing
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Finding Reports | Document vulnerabilities clearly | Can write clear, reproducible findings |
| Executive Summaries | Communicate to non-technical audiences | Can distill technical issues for leadership |
| Attack Chains | Document multi-stage attacks | Can map attack flow, explain impact |

### Evidence Collection
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Screenshots | Capture proof of exploitation | Knows what to capture, how to annotate |
| Logs | Collect and present log evidence | Can extract relevant entries, correlate |
| Artifacts | Preserve and document artifacts | Maintains chain of custody |

---

## 9. OSINT & Intelligence

### Passive
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| Search Engine Dorking | Advanced search techniques | Can find exposed data, configs |
| Social Media Intel | Gather info from social platforms | Can map org structure, find targets |
| Breach Data Analysis | Use leaked data ethically | Can correlate identities, find creds |

### Active
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| DNS Enumeration | Map DNS infrastructure | Can enumerate subdomains, records |
| Network Scanning | Identify live hosts and services | Can scan without detection |
| Fingerprinting | Identify technologies | Can version services, identify stack |

---

## 10. Specialized Domains

### Automotive
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| CAN Bus | Controller Area Network | Can sniff, inject, fuzz CAN |
| OBD-II | On-board diagnostics | Can extract data, identify vulns |
| Infotainment | In-vehicle systems | Can analyze head units, find vulns |

### HomeKit/Smart Home
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| HAP Protocol | HomeKit Accessory Protocol | Can analyze pairing, fuzz TLV |
| Matter | New smart home standard | Can test Matter devices |
| Zigbee/Z-Wave | Mesh protocols | Can sniff, inject, analyze |

### ALPR/Surveillance
| Skill | Description | Proficiency Indicators |
|-------|-------------|------------------------|
| ALPR Systems | License plate recognition | Can assess accuracy, identify bypasses |
| Camera Systems | IP camera security | Can test ONVIF, RTSP, web interfaces |
| Video Analytics | AI-based surveillance | Can assess evasion, find vulns |

---

## Skill Development Paths

### Entry Level (0-2 years)
Focus Areas:
1. Network fundamentals (TCP/IP, HTTP, TLS)
2. Web application testing (OWASP Top 10)
3. Basic scripting (Python, Bash)
4. Tool proficiency (Burp, nmap, Wireshark)

### Mid Level (2-5 years)
Focus Areas:
1. Mobile application security (Android/iOS)
2. Basic reverse engineering
3. IoT/embedded fundamentals
4. Fuzzing basics

### Senior Level (5+ years)
Focus Areas:
1. Advanced exploitation techniques
2. Custom tool development
3. Protocol reverse engineering
4. Vulnerability research

---

## Skill Assessment Matrix

Use this matrix to assess team skills for engagement staffing:

| Domain | Skill | None | Basic | Proficient | Expert |
|--------|-------|------|-------|------------|--------|
| Mobile | Android RE | [ ] | [ ] | [ ] | [ ] |
| Mobile | iOS RE | [ ] | [ ] | [ ] | [ ] |
| Network | Protocol Analysis | [ ] | [ ] | [ ] | [ ] |
| Web | OWASP Testing | [ ] | [ ] | [ ] | [ ] |
| RE | x86/x64 | [ ] | [ ] | [ ] | [ ] |
| RE | ARM | [ ] | [ ] | [ ] | [ ] |
| IoT | Firmware Analysis | [ ] | [ ] | [ ] | [ ] |
| IoT | Hardware | [ ] | [ ] | [ ] | [ ] |
| Fuzzing | Coverage-Guided | [ ] | [ ] | [ ] | [ ] |
| Reporting | Technical Writing | [ ] | [ ] | [ ] | [ ] |

---

## Learning Resources

### Certifications
- OSCP - Offensive Security Certified Professional
- OSCE - Offensive Security Certified Expert
- GWAPT - GIAC Web Application Penetration Tester
- GMOB - GIAC Mobile Device Security Analyst

### Training Platforms
- Offensive Security (offsec.com)
- SANS (sans.org)
- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe

### Books
- "The Web Application Hacker's Handbook"
- "The Mobile Application Hacker's Handbook"
- "Practical Reverse Engineering"
- "The IoT Hacker's Handbook"
- "Fuzzing: Brute Force Vulnerability Discovery"

---

## Engagement-Derived Skills

Skills discovered and documented from security engagements.

| Skill | Description | Source |
|-------|-------------|--------|
| `- [x] Review raw findings with /brainblast to identify skills` |  | Pitch promotion |

# Security Research Toolset Reference

> **Generated From:** Reusable assessment references
> **Purpose:** Comprehensive catalog of tools for authorized security assessments

---

## Overview

Use this catalog to select analysis tools. Record the permitted tools and versions in `layer3-engagement/TOOLSUITES.md`.

---

## Android/Mobile Security

### Static Analysis
| Tool | Purpose | Installation |
|------|---------|--------------|
| jadx | APK decompilation to Java | `brew install jadx` |
| apktool | APK decode/rebuild | `brew install apktool` |
| dex2jar | DEX to JAR conversion | `brew install dex2jar` |
| androguard | Python APK analysis | `pip install androguard` |
| MobSF | Automated mobile analysis | Docker: `opensecurity/mobile-security-framework-mobsf` |
| APKiD | APK identifier/packer detect | `pip install apkid` |

### Dynamic Analysis
| Tool | Purpose | Installation |
|------|---------|--------------|
| Frida | Runtime instrumentation | `pip install frida-tools` |
| Objection | Mobile exploration | `pip install objection` |
| drozer | Android security assessment | `pip install drozer` |
| jdwp-shellifier | JDWP exploitation | `git clone github.com/IOActive/jdwp-shellifier` |

### Debugging
| Tool | Purpose | Installation |
|------|---------|--------------|
| adb | Android Debug Bridge | Android SDK |
| scrcpy | Screen mirroring | `brew install scrcpy` |
| logcat | Log capture | Part of adb |

### Root/Exploit
| Tool | Purpose | Installation |
|------|---------|--------------|
| Magisk | Systemless root | magiskmanager.com |
| sepolicy-inject | SELinux policy modification | github.com/nickel1996/sepolicy-inject |
| magiskpolicy | Runtime policy patching | Included with Magisk |

---

## Network Analysis

### Scanning
| Tool | Purpose | Installation |
|------|---------|--------------|
| nmap | Port/service scanning | `brew install nmap` |
| masscan | Fast port scanning | `brew install masscan` |
| httpx | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |

### Traffic Analysis
| Tool | Purpose | Installation |
|------|---------|--------------|
| Wireshark | Packet analysis GUI | `brew install wireshark` |
| tcpdump | Command-line capture | Built-in (macOS/Linux) |
| tshark | CLI Wireshark | Part of Wireshark |
| mitmproxy | HTTP(S) interception | `brew install mitmproxy` |
| Burp Suite | Web security testing | portswigger.net |

### Protocol-Specific
| Tool | Purpose | Installation |
|------|---------|--------------|
| onvif-cli | ONVIF device testing | `pip install onvif-cli` |
| ffmpeg/ffprobe | RTSP stream testing | `brew install ffmpeg` |
| mosquitto-clients | MQTT testing | `brew install mosquitto` |
| rtsp-simple-server | RTSP server/proxy | github.com/aler9/rtsp-simple-server |

---

## IoT/Embedded

### Firmware Analysis
| Tool | Purpose | Installation |
|------|---------|--------------|
| binwalk | Firmware extraction | `pip install binwalk` |
| jefferson | JFFS2 extraction | `pip install jefferson` |
| sasquatch | SquashFS (non-standard) | github.com/devttys0/sasquatch |
| firmwalker | Automated firmware analysis | github.com/craigz28/firmwalker |
| FACT | Firmware Analysis Toolkit | github.com/fkie-cad/FACT_core |

### Hardware
| Tool | Purpose | Installation |
|------|---------|--------------|
| flashrom | SPI flash read/write | `brew install flashrom` |
| OpenOCD | JTAG debugging | `brew install openocd` |
| sigrok/PulseView | Logic analysis | `brew install sigrok` |

### Emulation
| Tool | Purpose | Installation |
|------|---------|--------------|
| QEMU | System emulation | `brew install qemu` |
| Firmadyne | Firmware emulation | github.com/firmadyne/firmadyne |
| unicorn | CPU emulation | `pip install unicorn` |

---

## Radio/Wireless

### Bluetooth
| Tool | Purpose | Installation |
|------|---------|--------------|
| Ubertooth | BT Classic/BLE sniffing | greatscottgadgets.com |
| btlejack | BLE hijacking | github.com/virtualabs/btlejack |
| gatttool | BLE GATT interaction | BlueZ package |
| bettercap | Network/BLE attacks | `brew install bettercap` |
| bleak | Python BLE library | `pip install bleak` |

### SDR
| Tool | Purpose | Installation |
|------|---------|--------------|
| GNU Radio | SDR framework | `brew install gnuradio` |
| rtl_sdr | RTL-SDR tools | `brew install librtlsdr` |
| hackrf | HackRF tools | `brew install hackrf` |
| gqrx | SDR receiver GUI | `brew install gqrx` |
| inspectrum | Signal analysis | `brew install inspectrum` |
| rtl_433 | ISM band decoder | `brew install rtl_433` |

---

## Fuzzing

### General Purpose
| Tool | Purpose | Installation |
|------|---------|--------------|
| AFL++ | Coverage-guided fuzzing | github.com/AFLplusplus/AFLplusplus |
| libFuzzer | In-process fuzzing | Part of LLVM |
| honggfuzz | Feedback-driven fuzzer | `brew install honggfuzz` |
| Radamsa | Mutation-based fuzzer | `brew install radamsa` |

### Protocol-Specific
| Tool | Purpose | Installation |
|------|---------|--------------|
| Boofuzz | Network protocol fuzzing | `pip install boofuzz` |
| Sulley | Protocol fuzzing framework | github.com/OpenRCE/sulley |

---

## Reverse Engineering

### Disassembly/Decompilation
| Tool | Purpose | Installation |
|------|---------|--------------|
| Ghidra | NSA reverse engineering | ghidra-sre.org |
| IDA Pro | Industry standard RE | hex-rays.com (commercial) |
| radare2 | CLI reverse engineering | `brew install radare2` |
| Binary Ninja | Modern RE platform | binary.ninja (commercial) |
| Hopper | macOS/iOS disassembler | hopperapp.com |

### Debugging
| Tool | Purpose | Installation |
|------|---------|--------------|
| gdb | GNU debugger | `brew install gdb` |
| lldb | LLVM debugger | Part of Xcode |
| x64dbg | Windows debugger | x64dbg.com |

### Memory Analysis
| Tool | Purpose | Installation |
|------|---------|--------------|
| Volatility | Memory forensics | `pip install volatility3` |
| Rekall | Memory analysis | github.com/google/rekall |

---

## Web Security

### Scanners
| Tool | Purpose | Installation |
|------|---------|--------------|
| Burp Suite | Web proxy/scanner | portswigger.net |
| OWASP ZAP | Open source web scanner | zaproxy.org |
| nikto | Web server scanner | `brew install nikto` |
| sqlmap | SQL injection testing | `brew install sqlmap` |

### Fuzzing/Discovery
| Tool | Purpose | Installation |
|------|---------|--------------|
| ffuf | Fast web fuzzer | `go install github.com/ffuf/ffuf@latest` |
| gobuster | Directory brute-forcing | `brew install gobuster` |
| feroxbuster | Content discovery | `brew install feroxbuster` |

---

## OSINT/Intelligence

### Passive
| Tool | Purpose | Installation |
|------|---------|--------------|
| Shodan | Internet-wide scanning DB | shodan.io, `pip install shodan` |
| Censys | Internet scanning | censys.io |
| subfinder | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| theHarvester | OSINT gathering | `brew install theharvester` |

### Active
| Tool | Purpose | Installation |
|------|---------|--------------|
| Amass | Attack surface mapping | `brew install amass` |
| dnsrecon | DNS enumeration | `pip install dnsrecon` |
| dig | DNS queries | Built-in |

---

## Exploitation Frameworks

| Tool | Purpose | Installation |
|------|---------|--------------|
| Metasploit | Exploitation framework | `brew install metasploit` |
| Cobalt Strike | Adversary simulation | cobaltstrike.com (commercial) |
| Empire | Post-exploitation | github.com/BC-SECURITY/Empire |
| Sliver | Open source C2 | github.com/BishopFox/sliver |

---

## Utility/Support

### Encoding/Crypto
| Tool | Purpose | Installation |
|------|---------|--------------|
| CyberChef | Data transformation | gchq.github.io/CyberChef |
| hashcat | Password cracking | `brew install hashcat` |
| john | Password cracking | `brew install john` |

### Documentation
| Tool | Purpose | Installation |
|------|---------|--------------|
| CherryTree | Hierarchical notes | `brew install cherrytree` |
| Obsidian | Knowledge management | obsidian.md |
| Notion | Collaborative docs | notion.so |

---

## Custom Tools (From Ingested Projects)

### sepolicy-inject
**Purpose:** Modify compiled Android SELinux policies at runtime
**Source:** github.com/nickel1996/sepolicy-inject
**Key Commands:**
```bash
./sepolicy-inject -Z shell -P sepolicy  # Make permissive
./sepolicy-inject -s shell -t su_exec -c file -p execute -P sepolicy  # Add rule
```

### simdump
**Purpose:** SIM card data extraction and analysis
**Source:** Ingested from research project
**Usage:** Requires physical SIM reader hardware

### jdwp-shellifier
**Purpose:** JDWP exploitation for Android debuggable apps
**Source:** github.com/IOActive/jdwp-shellifier
**Key Commands:**
```bash
python3 jdwp-shellifier.py -t 127.0.0.1 -p 8700 --break-on "java.net.ServerSocket.accept" -c "id"
```

### quark-engine
**Purpose:** Android malware scoring system
**Source:** github.com/quark-engine/quark-engine
**Installation:** `pip install quark-engine`

---

## Tool Selection Guidelines

### By Engagement Type

| Engagement | Primary Tools |
|------------|---------------|
| Mobile App Assessment | jadx, Frida, Burp Suite, adb |
| IoT Device Testing | binwalk, nmap, Wireshark, QEMU |
| Web Application | Burp Suite, sqlmap, ffuf |
| Thick Client | x64dbg/gdb, Wireshark, Process Monitor |
| Wireless/RF | Ubertooth, GNU Radio, bettercap |
| Firmware Analysis | binwalk, Ghidra, QEMU |

### By Phase

| Phase | Tools |
|-------|-------|
| Intelligence | Shodan, nmap, subfinder, httpx |
| Vulnerability Scanning | nuclei, nikto, Burp Scanner |
| Exploitation | Metasploit, custom scripts, Frida |
| Post-Exploitation | Mimikatz, BloodHound, Empire |
| Reporting | CherryTree, Obsidian, screenshots |

---

## Version Management

Record the installed tool versions for repeatable results:
```bash
# Example: Pin Frida version for consistency
pip install frida-tools==12.0.0

# Document versions in engagement notes
frida --version > tool_versions.txt
```

# Thick Client Security Testing Methodology Template

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Target:** Windows/Linux desktop applications, native clients, installed software

---

## Overview

This method covers installed desktop applications on Windows and Linux.
The phases cover files, configuration, binaries, network traffic, interprocess communication, and privileges.
IPC means interprocess communication.

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## Phase 1: Inventory

### Objectives
- Enumerate all application components
- Map file system footprint
- Identify configuration files
- Record installation artifacts

### Techniques

#### File System Enumeration (Windows)
```powershell
# Installation directory
Get-ChildItem -Path "C:\Program Files\<AppName>" -Recurse |
    Select-Object FullName, Length, LastWriteTime

# AppData locations
Get-ChildItem -Path "$env:LOCALAPPDATA\<AppName>" -Recurse
Get-ChildItem -Path "$env:APPDATA\<AppName>" -Recurse

# Registry entries
Get-ChildItem -Path "HKLM:\SOFTWARE\<Vendor>" -Recurse
Get-ChildItem -Path "HKCU:\SOFTWARE\<Vendor>" -Recurse
```

#### File System Enumeration (Linux)
```bash
# Installation locations
find /opt/<appname> -type f -ls
find /usr/share/<appname> -type f -ls

# User config
find ~/.config/<appname> -type f -ls
find ~/.local/share/<appname> -type f -ls

# System config
find /etc/<appname> -type f -ls
```

#### Component Classification
| Type | Extensions | Priority |
|------|------------|----------|
| Executables | .exe, .dll, .so | High |
| Scripts | .ps1, .bat, .sh, .py | High |
| Configuration | .ini, .xml, .json, .conf | High |
| Data | .db, .sqlite, .dat | Medium |
| Resources | .dll (resources), images | Low |

### Deliverables
- [ ] Complete file inventory
- [ ] Registry/configuration location map
- [ ] Component classification
- [ ] Dependency list

---

## Phase 2: Configuration Review

### Objectives
- Identify sensitive data in configuration files
- Find hardcoded credentials
- Detect insecure settings
- Map external connections

### Techniques

#### Sensitive Data Patterns
```bash
# Credentials
grep -riE "(password|passwd|pwd|secret|apikey|api_key|token)" ./config/

# Connection strings
grep -riE "(jdbc:|mongodb://|mysql://|postgres://|redis://)" ./config/

# Encryption keys
grep -riE "(-----BEGIN|AES|DES|RSA|private_key)" ./config/

# URLs and endpoints
grep -riE "(https?://|wss?://|ftp://)" ./config/
```

#### Windows Registry Analysis
```powershell
# Export relevant keys
reg export "HKLM\SOFTWARE\<Vendor>" vendor_hklm.reg
reg export "HKCU\SOFTWARE\<Vendor>" vendor_hkcu.reg

# Search for sensitive values
Select-String -Path *.reg -Pattern "password|secret|key|token" -CaseSensitive:$false
```

#### Configuration Risk Matrix
| Finding | Risk | Impact |
|---------|------|--------|
| Plaintext credentials | Critical | Account compromise |
| Hardcoded API keys | High | Service abuse |
| Debug mode enabled | Medium | Information disclosure |
| Verbose logging | Medium | Sensitive data in logs |
| World-readable configs | Medium | Local privilege escalation |

### Deliverables
- [ ] Sensitive data inventory
- [ ] Configuration risk assessment
- [ ] External connection map
- [ ] Recommendations

---

## Phase 3: Binary Analysis

### Objectives
- Identify vulnerable functions
- Detect insecure coding patterns
- Find hardcoded strings
- Examine compiler protections

### Techniques

#### Static Analysis (Windows PE)
```powershell
# PE header analysis
dumpbin /headers app.exe

# Imports (vulnerable functions)
dumpbin /imports app.exe | Select-String "strcpy|strcat|sprintf|gets"

# Strings extraction
strings app.exe > strings.txt

# Check protections
winchecksec app.exe  # ASLR, DEP, CFG, etc.
```

#### Static Analysis (Linux ELF)
```bash
# ELF info
readelf -h app
readelf -d app  # Dynamic section

# Dangerous functions
objdump -T app | grep -E "strcpy|strcat|sprintf|gets|system"

# Strings
strings -a app > strings.txt

# Security features
checksec --file=app  # RELRO, Stack Canary, NX, PIE
```

#### .NET Analysis
```powershell
# Decompile with dnSpy or ILSpy
# Check for:
# - Hardcoded credentials
# - SQL string concatenation
# - Insecure deserialization
# - Debug symbols present
```

### Compiler Protection Checklist
- [ ] ASLR/PIE enabled
- [ ] DEP/NX enabled
- [ ] Stack canaries present
- [ ] CFG enabled (Windows)
- [ ] RELRO enabled (Linux)
- [ ] Debug symbols stripped

### Deliverables
- [ ] Binary inventory with protections
- [ ] Vulnerable function list
- [ ] Hardcoded string findings
- [ ] Decompiled source (if .NET/Java)

---

## Phase 4: Network Analysis

### Objectives
- Capture and examine traffic
- Identify plaintext protocols
- Examine TLS implementation
- Map external communications

### Techniques

#### Traffic Capture
```bash
# Wireshark filter for app
tcp.port == <port> or udp.port == <port>

# tcpdump capture
tcpdump -i any -w capture.pcap port <port>

# Windows netsh trace
netsh trace start capture=yes tracefile=capture.etl
```

#### TLS Analysis
```bash
# Test TLS configuration
testssl.sh <host>:<port>

# Certificate inspection
openssl s_client -connect <host>:<port> -showcerts

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p <port> <host>
```

#### Protocol Analysis Checklist
- [ ] Authentication mechanism
- [ ] Session management
- [ ] Data encryption in transit
- [ ] Certificate validation
- [ ] API security

### Deliverables
- [ ] Network traffic summary
- [ ] Protocol documentation
- [ ] TLS assessment
- [ ] Sensitive data in transit findings

---

## Phase 5: IPC Analysis

### Objectives
- Enumerate IPC mechanisms
- Do tests of for injection vulnerabilities
- Examine access controls
- Identify privilege boundaries

### Techniques

#### Named Pipes (Windows)
```powershell
# List named pipes
Get-ChildItem \\.\pipe\ | Select-Object Name

# Pipe permissions
accesschk.exe -w \\.\pipe\<pipename>

# Monitor pipe activity
pipelist.exe
```

#### D-Bus (Linux)
```bash
# List services
dbus-send --system --print-reply --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# Introspect service
dbus-send --system --print-reply --dest=<service> \
    / org.freedesktop.DBus.Introspectable.Introspect
```

#### Shared Memory
```bash
# List shared memory segments
ipcs -m

# Windows
# Use Process Explorer or handle.exe
```

#### COM Objects (Windows)
```powershell
# Enumerate registered COM objects
Get-ChildItem HKLM:\SOFTWARE\Classes\CLSID |
    Where-Object { $_.GetValue("") -like "*<AppName>*" }
```

### IPC Security Checklist
- [ ] Proper ACLs on named pipes
- [ ] Input validation on IPC endpoints
- [ ] Authenticated IPC channels
- [ ] No sensitive data in shared memory

### Deliverables
- [ ] IPC mechanism inventory
- [ ] Access control assessment
- [ ] Injection test results
- [ ] Privilege boundary map

---

## Phase 6: Privilege Analysis

### Objectives
- Record running context
- Identify elevation paths
- Do tests of for privilege escalation
- Examine service configurations

### Techniques

#### Running Context (Windows)
```powershell
# Process privileges
whoami /priv
whoami /groups

# Service account
sc qc <ServiceName>
sc query <ServiceName>

# Check for unquoted paths
wmic service get name,displayname,pathname,startmode |
    findstr /i "auto" | findstr /i /v "c:\windows"
```

#### Running Context (Linux)
```bash
# Process user
ps aux | grep <app>

# Service user
systemctl show <service> -p User

# SUID binaries
find /opt/<app> -perm -4000 -ls

# Capabilities
getcap -r /opt/<app>
```

#### Privilege Escalation Vectors
| Vector | Windows | Linux |
|--------|---------|-------|
| Unquoted service path | Yes | N/A |
| Weak service permissions | Yes | Yes |
| DLL hijacking | Yes | N/A |
| Library injection | Yes | Yes (LD_PRELOAD) |
| SUID/SGID abuse | N/A | Yes |
| Capability abuse | N/A | Yes |

### Deliverables
- [ ] Running context documentation
- [ ] Privilege escalation findings
- [ ] Service hardening recommendations
- [ ] Risk assessment

---

## Tools Reference

| Category | Windows | Linux |
|----------|---------|-------|
| File Analysis | PE-bear, PEStudio | readelf, objdump |
| Strings | strings, FLOSS | strings |
| Debugging | x64dbg, WinDbg | gdb, radare2 |
| Network | Wireshark, Fiddler | Wireshark, tcpdump |
| .NET | dnSpy, ILSpy | - |
| Privilege | accesschk, Process Explorer | linpeas, pspy |

---

## Checklist Summary

- [ ] Phase 1: Inventory complete
- [ ] Phase 2: Configuration review complete
- [ ] Phase 3: Binary analysis complete
- [ ] Phase 4: Network analysis complete
- [ ] Phase 5: IPC analysis complete
- [ ] Phase 6: Privilege analysis complete

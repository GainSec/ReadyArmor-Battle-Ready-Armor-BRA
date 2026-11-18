# Android/Mobile Security Assessment Methodology Template

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Target:** Android devices, mobile applications, embedded Android systems

---

## Overview

This method covers Android devices, mobile applications, and embedded Android systems.
The seven phases cover device information, code, runtime behavior, vulnerabilities, impact, and reporting.
APK means Android application package.

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## Phase 1: Intelligence

### Objectives
- Enumerate physical device characteristics
- Collect system properties and build information
- Map running processes and services
- Identify attack surface

### Techniques

#### Device Enumeration
```bash
# Basic device info
adb shell getprop ro.product.model
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.sdk

# System properties dump
adb shell getprop > device_properties.txt

# CPU architecture
adb shell getprop ro.product.cpu.abi
```

#### Process Enumeration
```bash
# Running processes
adb shell ps -A

# Services
adb shell service list

# Packages with debuggable flag
adb shell "pm list packages -f" | while read pkg; do
    path=$(echo $pkg | cut -d: -f2 | cut -d= -f1)
    name=$(echo $pkg | cut -d= -f2)
    debuggable=$(adb shell "run-as $name id" 2>&1)
    if [[ ! "$debuggable" =~ "not debuggable" ]]; then
        echo "DEBUGGABLE: $name"
    fi
done
```

#### Network Services
```bash
# Open ports
adb shell netstat -tlnp

# Network interfaces
adb shell ip addr
```

### Deliverables
- [ ] Device property dump
- [ ] Process list with UIDs
- [ ] Service enumeration
- [ ] Network configuration
- [ ] Initial attack surface map

---

## Phase 2: Static Analysis

### Objectives
- Decompile and examine APK structure
- Review AndroidManifest.xml for misconfigurations
- Examine smali/Java code for vulnerabilities
- Identify hardcoded secrets

### Techniques

#### APK Extraction
```bash
# Pull APK from device
adb shell pm path <package_name>
adb pull <apk_path> ./

# Extract APK contents
apktool d <app>.apk -o ./extracted/

# Decompile to Java (jadx)
jadx -d ./decompiled <app>.apk
```

#### Manifest Analysis
Examine these manifest items:
- `android:debuggable="true"` - Enables JDWP debugging
- `android:allowBackup="true"` - Data extraction risk
- `android:exported="true"` on components - Unprotected entry points
- `android:permission` - Custom permission definitions
- `<uses-permission>` - Requested permissions
- Intent filters on activities/services/receivers

#### Code Analysis Patterns
- Hardcoded API keys: `grep -r "api[_-]?key" ./decompiled/`
- Hardcoded credentials: `grep -rE "(password|passwd|secret)" ./decompiled/`
- Insecure crypto: Find `DES`, `MD5`, `ECB` mode
- SQL injection: `rawQuery`, `execSQL` with concatenation
- WebView issues: `setJavaScriptEnabled(true)`, `addJavascriptInterface`

### Deliverables
- [ ] Decompiled source code
- [ ] Manifest analysis report
- [ ] Hardcoded secrets inventory
- [ ] Component exposure map

---

## Phase 3: Dynamic Analysis

### Objectives
- Monitor runtime behavior via ADB
- Capture and examine logcat output
- Hook methods with Frida/Objection
- Intercept network traffic

### Techniques

#### Logcat Monitoring
```bash
# Clear and start fresh log
adb logcat -c
adb logcat -v time > logcat_capture.txt

# Filter by package
adb logcat --pid=$(adb shell pidof <package_name>)

# Filter for sensitive data
adb logcat | grep -iE "(password|token|key|secret|auth)"
```

#### Frida Hooking
```javascript
// Hook example: SSL pinning bypass
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkServerTrusted.implementation = function(chain, authType, session) {
        console.log('[*] SSL pinning bypassed');
        return;
    };
});
```

#### Network Interception
```bash
# Set up proxy
adb shell settings put global http_proxy <proxy_ip>:<port>

# For HTTPS, install CA cert
adb push burp_cacert.der /sdcard/
adb shell "su -c 'cp /sdcard/burp_cacert.der /system/etc/security/cacerts/'"
```

### Deliverables
- [ ] Logcat capture with sensitive data findings
- [ ] Frida script library for target app
- [ ] Network traffic capture (sanitized)
- [ ] Runtime behavior documentation

---

## Phase 4: Reverse Engineering

### Objectives
- Trace control flow and data flow
- Identify authentication/authorization logic
- Map cryptographic implementations
- Record proprietary protocols

### Techniques

#### JDWP Debugging (if debuggable)
```bash
# Find JDWP-enabled processes
adb jdwp

# Forward JDWP port
adb forward tcp:8700 jdwp:<pid>

# Connect with jdb
jdb -attach localhost:8700

# Set breakpoints
stop in com.target.app.AuthManager.validateToken
```

#### Control Flow Analysis
- Use jadx-gui for interactive navigation
- Trace entry points from exported components
- Follow authentication flows
- Map data storage locations

### Deliverables
- [ ] Authentication flow diagram
- [ ] Cryptographic implementation notes
- [ ] Protocol documentation
- [ ] Key code paths annotated

---

## Phase 5: Vulnerability Identification

### Objectives
- Map findings to CWE identifiers
- Calculate CVSS scores
- Set priorities by exploitability
- Record proof-of-concept

### Common Android Vulnerabilities

| CWE | Vulnerability | Detection Method |
|-----|--------------|------------------|
| CWE-312 | Cleartext Storage | Static + file system analysis |
| CWE-319 | Cleartext Transmission | Network capture |
| CWE-489 | Active Debug Code | Manifest analysis |
| CWE-926 | Improper Export | Manifest + component testing |
| CWE-927 | Sensitive Broadcast | Intent sniffing |
| CWE-939 | Improper Auth | Dynamic testing |

### Deliverables
- [ ] Vulnerability findings with CWE mapping
- [ ] CVSS scores for each finding
- [ ] Proof-of-concept code/steps
- [ ] Prioritized finding list

---

## Phase 6: Impact Assessment

### Objectives
- Build attack chains from individual findings
- Examine operational impact
- Evaluate likelihood of exploitation
- Determine business risk

### Attack Chain Template
```
[Initial Access] → [Privilege Escalation] → [Data Access] → [Impact]

Example:
Exported Activity → JDWP Debug → Code Execution → Data Exfiltration
```

### Deliverables
- [ ] Attack chain diagrams
- [ ] Impact assessment per chain
- [ ] Risk ratings
- [ ] Remediation priority

---

## Phase 7: Documentation

### Objectives
- Prepare the complete report
- Provide remediation guidance
- Archive evidence properly
- Prepare disclosure materials

### Report Structure
1. Executive Summary
2. Scope and Methodology
3. Findings (prioritized)
4. Attack Chains
5. Remediation Recommendations
6. Appendices (evidence, logs, scripts)

### Evidence Handling
- Hash all evidence files
- Maintain chain of custody
- Sanitize sensitive data in reports
- Secure storage of raw captures

### Deliverables
- [ ] Final assessment report
- [ ] Remediation guidance record
- [ ] Evidence archive (encrypted)
- [ ] Disclosure timeline

---

## Tools Reference

| Category | Tools |
|----------|-------|
| APK Analysis | apktool, jadx, dex2jar, androguard |
| Dynamic | Frida, Objection, drozer |
| Debugging | jdb, Android Studio debugger |
| Network | Burp Suite, mitmproxy, tcpdump |
| Automation | adb, scrcpy |

---

## Checklist Summary

- [ ] Phase 1: Intelligence complete
- [ ] Phase 2: Static analysis complete
- [ ] Phase 3: Dynamic analysis complete
- [ ] Phase 4: Reverse engineering complete
- [ ] Phase 5: Vulnerabilities identified
- [ ] Phase 6: Impact assessed
- [ ] Phase 7: Documentation complete

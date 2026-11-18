# APK Decompilation & Analysis Pipeline

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Structured Android application reverse engineering

Use this workflow to inspect an Android application package (APK). Collect metadata, review decompiled code, and connect findings to evidence.

Use command examples in an operator analysis workspace.
During governed agent work, use existing phase directories under `.bra/artifacts/`.
Store finding records in `layer3-engagement/NOTES/FINDINGS.md`.
Replace example targets with the approved scope values.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Acquisition │ → │  Extraction  │ → │  Analysis   │ → │  Reporting  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │
   adb pull          jadx/apktool      grep patterns       findings.md
```

---

## Stage 1: APK Acquisition

### From Device
```bash
# List installed packages
adb shell pm list packages | grep -i <vendor>

# Get APK path
adb shell pm path <package_name>

# Pull APK(s)
adb pull <path> ./apks/

# Verify integrity
sha256sum ./apks/*.apk | tee checksums.txt
```

### From Store/Third-Party
```bash
# Use apkpure, apkmirror, or similar
# Verify signature matches PlayStore version
apksigner verify --verbose app.apk
```

### From Firmware
```bash
# Mount system image
sudo mount -o ro,loop system.img /mnt/system/

# Copy APKs
find /mnt/system -name "*.apk" -exec cp {} ./apks/ \;

# Unmount
sudo umount /mnt/system
```

### Deliverable
- [ ] `./apks/` directory with all target APKs
- [ ] `checksums.txt` with SHA256 hashes

---

## Stage 2: Static Extraction

### JADX Decompilation (Preferred)
```bash
# Full decompilation to Java source
jadx -d ./jadx-output <app>.apk

# With debugging info
jadx -d ./jadx-output --show-bad-code --deobf <app>.apk

# Export Gradle project
jadx -e ./jadx-project <app>.apk
```

### APKTool Extraction
```bash
# Decode APK resources
apktool d <app>.apk -o ./apktool-output

# Decode without sources (resources only)
apktool d -s <app>.apk -o ./resources-only

# Key files:
# - AndroidManifest.xml (decoded)
# - res/ (resources)
# - smali/ (bytecode)
# - assets/ (raw assets)
```

### dex2jar + JD-GUI (Alternative)
```bash
# Convert to JAR
d2j-dex2jar <app>.apk -o app.jar

# Open in JD-GUI for browsing
jd-gui app.jar
```

### Deliverables
- [ ] `./jadx-output/` - Decompiled Java sources
- [ ] `./apktool-output/` - Decoded resources and smali
- [ ] `AndroidManifest.xml` - Decoded manifest

---

## Stage 3: Manifest Analysis

### Security-Critical Elements
```bash
# Extract key manifest data
cat apktool-output/AndroidManifest.xml | grep -E \
    "debuggable|allowBackup|exported|permission|uses-permission"

# Check for dangerous patterns
MANIFEST="./apktool-output/AndroidManifest.xml"

# Debuggable check
grep -i "debuggable.*true" $MANIFEST && echo "[!] DEBUGGABLE"

# Backup check
grep -i "allowBackup.*true" $MANIFEST && echo "[!] BACKUP ENABLED"

# Exported components
grep -B5 "exported.*true" $MANIFEST
```

### Component Inventory
```bash
# Activities
grep -E "<activity\s" $MANIFEST | wc -l

# Services
grep -E "<service\s" $MANIFEST | wc -l

# Receivers
grep -E "<receiver\s" $MANIFEST | wc -l

# Providers
grep -E "<provider\s" $MANIFEST | wc -l

# Content provider URIs
grep -E "authorities=" $MANIFEST
```

### Permissions Analysis
```bash
# Custom permissions
grep "<permission " $MANIFEST

# Requested permissions
grep "uses-permission" $MANIFEST | sort -u

# Dangerous permissions
grep "uses-permission" $MANIFEST | grep -E \
    "CAMERA|LOCATION|CONTACTS|RECORD_AUDIO|READ_SMS|CALL_LOG"
```

### Deliverable
- [ ] `manifest-analysis.md` - Manifest findings

---

## Stage 4: Code Pattern Analysis

### Sensitive Data Patterns
```bash
# Credentials/Secrets
grep -riE "(password|passwd|pwd|secret|api[_-]?key)" ./jadx-output/ \
    --include="*.java" | tee secrets.txt

# Hardcoded URLs
grep -riE "https?://[a-zA-Z0-9.-]+" ./jadx-output/ \
    --include="*.java" | tee urls.txt

# IP addresses
grep -riE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" ./jadx-output/ \
    --include="*.java" | tee ips.txt

# Base64 strings (potential encoded secrets)
grep -riE "[A-Za-z0-9+/]{40,}={0,2}" ./jadx-output/ \
    --include="*.java" | tee base64.txt
```

### Vulnerability Patterns
```bash
# SQL Injection (raw queries)
grep -riE "rawQuery|execSQL" ./jadx-output/ --include="*.java"

# Command Injection
grep -riE "Runtime\.exec|ProcessBuilder" ./jadx-output/ --include="*.java"

# Insecure WebView
grep -riE "setJavaScriptEnabled|addJavascriptInterface" ./jadx-output/ --include="*.java"

# Insecure Crypto
grep -riE "DES|MD5|ECB|SHA1withRSA" ./jadx-output/ --include="*.java"

# Insecure Random
grep -riE "java\.util\.Random" ./jadx-output/ --include="*.java"

# Log leaks
grep -riE "Log\.[dievw]\(" ./jadx-output/ --include="*.java"
```

### Entry Point Analysis
```bash
# Exported activity handlers
grep -riE "public void on[A-Z][a-zA-Z]*\(" ./jadx-output/ --include="*.java"

# Intent handlers
grep -riE "getIntent\(\)|getExtras\(\)" ./jadx-output/ --include="*.java"

# Content provider queries
grep -riE "query\(|insert\(|update\(|delete\(" ./jadx-output/ --include="*.java"
```

### Deliverable
- [ ] `code-patterns.md` - Vulnerability pattern findings

---

## Stage 5: Network Analysis

### API Endpoint Discovery
```bash
# REST endpoints
grep -riE "(GET|POST|PUT|DELETE|PATCH).*/" ./jadx-output/ --include="*.java"

# Retrofit annotations
grep -riE "@(GET|POST|PUT|DELETE|PATCH)" ./jadx-output/ --include="*.java"

# OkHttp calls
grep -riE "OkHttpClient|Request\.Builder" ./jadx-output/ --include="*.java"
```

### Certificate Pinning
```bash
# Pinning implementations
grep -riE "certificatePinner|TrustManager|X509TrustManager" ./jadx-output/ --include="*.java"

# Network security config
cat ./apktool-output/res/xml/network_security_config.xml 2>/dev/null

# OkHttp pinning
grep -riE "sha256/" ./jadx-output/ --include="*.java"
```

### Deliverable
- [ ] `api-endpoints.md` - Discovered APIs
- [ ] `network-security.md` - Pinning/TLS analysis

---

## Stage 6: Automated Scanning

### MobSF Analysis
```bash
# Run MobSF (Docker)
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Upload APK via web interface at http://localhost:8000
# Export PDF report
```

### androguard Analysis
```python
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

apk = APK("app.apk")
print(f"Package: {apk.get_package()}")
print(f"Main Activity: {apk.get_main_activity()}")
print(f"Permissions: {apk.get_permissions()}")

# Get classes
dex = DalvikVMFormat(apk.get_dex())
for cls in dex.get_classes():
    print(cls.get_name())
```

### Deliverable
- [ ] `mobsf-report.pdf` - Automated scan results
- [ ] `androguard-analysis.txt` - Programmatic analysis

---

## Stage 7: Reporting

### Finding Template
````markdown
## Finding: [TITLE]

**Severity:** Critical/High/Medium/Low/Info
**CWE:** CWE-XXX
**Location:** `path/to/File.java:line`

### Description
[What is the vulnerability]

### Evidence
```java
// Code snippet showing the issue
```

### Impact
[What an attacker could achieve]

### Remediation
[How to fix it]
````

### Report Structure
1. Executive Summary
2. Scope & Methodology
3. Findings (prioritized by severity)
4. Appendix: Full code excerpts
5. Appendix: Tool outputs

### Deliverable
- [ ] `apk-analysis-report.md` - Complete analysis report

---

## Quick Reference

### Command Cheatsheet
```bash
# Full pipeline (one-liner)
adb pull $(adb shell pm path com.app | cut -d: -f2) app.apk && \
jadx -d out/ app.apk && \
grep -riE "password|secret|api_key" out/
```

### Tool Versions
| Tool | Minimum Version |
|------|-----------------|
| jadx | 1.4.0+ |
| apktool | 2.7.0+ |
| MobSF | 3.0+ |
| androguard | 3.4.0+ |

---

## Checklist

- [ ] APK(s) acquired and verified
- [ ] Decompilation complete
- [ ] Manifest analyzed
- [ ] Code patterns searched
- [ ] Network analysis done
- [ ] Automated scan complete
- [ ] Report generated

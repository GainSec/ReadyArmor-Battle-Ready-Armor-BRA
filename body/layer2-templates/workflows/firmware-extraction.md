# Firmware Extraction & Analysis Workflow

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Systematic firmware extraction and security analysis

Use this workflow to identify firmware formats, extract filesystems, and inspect components. Record the original image hash before analysis.

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
   download          binwalk           grep secrets        findings.md
```

---

## Phase 1: Firmware Acquisition

### From Vendor
```bash
# Check vendor support page
# Download update packages

# Verify integrity
sha256sum firmware.bin
md5sum firmware.bin

# Document version
strings firmware.bin | grep -iE "version|v[0-9]+\.[0-9]+"
```

### From Device (OTA Capture)
```bash
# Proxy device traffic during update
mitmproxy -p 8080

# Look for firmware download URLs in captured traffic
grep -E "\.bin|\.img|firmware" traffic.log
```

### From Flash (Hardware)
```bash
# SPI flash read (with flashrom)
flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin

# NAND read (with nanddump)
nanddump -f firmware.bin /dev/mtd0

# JTAG read (with OpenOCD)
openocd -f interface/ftdi/... -f target/...
> dump_image firmware.bin 0x0 0x800000
```

### From Update Traffic
```bash
# Intercept OTA update
# Many devices use HTTP for updates

# MITM the update server
bettercap -eval "set net.probe on; net.probe.mdns on; http.proxy on"
```

### Deliverable
- [ ] `firmware.bin` - Raw firmware image
- [ ] `checksums.txt` - Integrity hashes
- [ ] `acquisition_notes.md` - Source and method

---

## Phase 2: Initial Analysis

### File Identification
```bash
# Basic file type
file firmware.bin

# Entropy analysis (detect encryption/compression)
binwalk -E firmware.bin

# Magic bytes
xxd firmware.bin | head -50

# Strings overview
strings -n 8 firmware.bin | head -100
```

### Structure Identification
```bash
# Binwalk signature scan
binwalk firmware.bin

# Common structures:
# - Header (vendor-specific)
# - Bootloader (U-Boot, etc.)
# - Kernel (Linux, RTOS)
# - Root filesystem (SquashFS, JFFS2, etc.)
# - Configuration/data partitions
```

### Encryption Detection
```bash
# High entropy = encrypted or compressed
binwalk -E firmware.bin | grep "entropy"
# Entropy > 0.9 suggests encryption

# Look for crypto headers
binwalk -R "\x00AES" firmware.bin
binwalk -R "RSA" firmware.bin
```

### Deliverable
- [ ] `initial_analysis.md` - File structure documentation

---

## Phase 3: Extraction

### Binwalk Extraction
```bash
# Automated extraction
binwalk -e firmware.bin

# Extract with Matryoshka (recursive)
binwalk -Me firmware.bin

# Output in _firmware.bin.extracted/
ls -la _firmware.bin.extracted/
```

### Manual Extraction
```bash
# If binwalk fails, manual carving

# Find offset (e.g., SquashFS magic)
binwalk firmware.bin | grep "Squashfs"
# Offset: 0x180000

# Extract manually
dd if=firmware.bin of=squashfs.img bs=1 skip=$((0x180000))

# Mount/extract
unsquashfs squashfs.img
```

### Filesystem-Specific Tools

#### SquashFS
```bash
# Unsquash
unsquashfs -d rootfs/ squashfs-root

# List without extracting
unsquashfs -l squashfs-root
```

#### JFFS2
```bash
# Using jefferson
jefferson jffs2.img -d rootfs/

# Or jffs2dump
jffs2dump -c jffs2.img
```

#### UBIFS
```bash
# Extract UBI image
ubireader_extract_images firmware.ubi

# Mount (requires UBI support)
sudo modprobe ubi
sudo ubiattach -p /dev/mtd0
sudo mount -t ubifs /dev/ubi0_0 /mnt
```

#### YAFFS2
```bash
# Using unyaffs
unyaffs yaffs2.img rootfs/
```

### Deliverable
- [ ] `rootfs/` - Extracted filesystem
- [ ] `extraction_log.txt` - Extraction commands and notes

---

## Phase 4: Filesystem Analysis

### Directory Structure
```bash
# Standard Linux filesystem
ls -la rootfs/
# /bin, /etc, /lib, /usr, /var, /home, /root

# Find interesting directories
find rootfs/ -type d -name "*config*"
find rootfs/ -type d -name "*web*"
find rootfs/ -type d -name "*cgi*"
```

### Credential Hunting
```bash
# Password files
cat rootfs/etc/passwd
cat rootfs/etc/shadow

# Hardcoded credentials
grep -riE "(password|passwd|pwd|secret)" rootfs/etc/
grep -riE "(password|passwd|pwd|secret)" rootfs/usr/
grep -riE "(password|passwd|pwd|secret)" rootfs/var/

# SSH keys
find rootfs/ -name "id_rsa*" -o -name "authorized_keys"

# API keys
grep -riE "(api[_-]?key|token|secret)" rootfs/
```

### Configuration Analysis
```bash
# Network configuration
cat rootfs/etc/network/interfaces
cat rootfs/etc/hosts
cat rootfs/etc/resolv.conf

# Service configuration
ls rootfs/etc/init.d/
cat rootfs/etc/inittab

# Web server config
cat rootfs/etc/lighttpd/lighttpd.conf
cat rootfs/etc/nginx/nginx.conf
cat rootfs/etc/httpd.conf
```

### Binary Analysis
```bash
# Find executables
find rootfs/ -type f -executable

# Check for debugging symbols
file rootfs/usr/bin/*

# Identify architecture
readelf -h rootfs/bin/busybox

# Look for vulnerable functions
for bin in $(find rootfs/ -type f -executable); do
    strings "$bin" | grep -E "strcpy|strcat|sprintf|gets" && echo ">>> $bin"
done
```

### Web Application Analysis
```bash
# Find web files
find rootfs/ -name "*.php" -o -name "*.cgi" -o -name "*.lua"

# Analyze CGI scripts
grep -riE "system\(|exec\(|popen\(" rootfs/www/cgi-bin/

# Find hardcoded creds in web files
grep -riE "password|admin" rootfs/www/
```

### Deliverable
- [ ] `filesystem_analysis.md` - Analysis findings

---

## Phase 5: Vulnerability Identification

### Known Vulnerability Check
```bash
# Check software versions
cat rootfs/etc/version
strings rootfs/bin/* | grep -iE "version|v[0-9]"

# Search CVE database
# Manual: search.mitre.org
# Automated: cve-search tools
```

### Common IoT Vulnerabilities

| Category | What to Look For |
|----------|------------------|
| Hardcoded Creds | /etc/passwd, /etc/shadow, config files |
| Command Injection | CGI scripts with system(), exec() |
| Buffer Overflow | strcpy, strcat in binaries |
| Backdoors | Telnetd enabled, debug accounts |
| Weak Crypto | MD5, DES, static keys |
| Info Disclosure | Debug endpoints, verbose logs |

### Backdoor Detection
```bash
# Suspicious listeners
grep -riE "telnetd|ftpd|sshd" rootfs/etc/init.d/
grep -riE "nc -l|netcat" rootfs/

# Hidden accounts
awk -F: '$3 == 0 {print $1}' rootfs/etc/passwd

# Suspicious scripts
find rootfs/ -name "*.sh" -exec grep -l "curl\|wget\|nc " {} \;
```

### Deliverable
- [ ] `vulnerabilities.md` - Identified vulnerabilities

---

## Phase 6: Emulation (Optional)

### QEMU Emulation
```bash
# Identify architecture
file rootfs/bin/busybox
# ARM, MIPS, x86, etc.

# Copy QEMU static binary
cp /usr/bin/qemu-arm-static rootfs/usr/bin/

# Chroot emulation
sudo chroot rootfs/ /bin/sh

# Full system emulation (if kernel available)
qemu-system-arm -M vexpress-a9 \
    -kernel zImage \
    -dtb vexpress-v2p-ca9.dtb \
    -drive file=rootfs.ext4,format=raw \
    -append "root=/dev/mmcblk0"
```

### Firmadyne (Automated)
```bash
# Using Firmadyne for full emulation
./fat.py firmware.bin

# Or Firmwalker for analysis
./firmwalker.sh rootfs/
```

### Deliverable
- [ ] `emulation_notes.md` - Emulation setup and findings

---

## Phase 7: Reporting

### Finding Template
````markdown
## Finding: [Title]

**Severity:** Critical/High/Medium/Low
**Category:** Hardcoded Creds / Command Injection / etc.
**File:** `path/to/file`

### Description
[What the vulnerability is]

### Evidence
```
[Code snippet or file content]
```

### Impact
[What an attacker could achieve]

### Remediation
[How to fix]
````

### Report Structure
1. Executive Summary
2. Methodology
3. Findings (prioritized)
4. Firmware Composition
5. Appendices

### Deliverable
- [ ] `firmware_analysis_report.md` - Complete report

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| binwalk | Signature scanning, extraction |
| unsquashfs | SquashFS extraction |
| jefferson | JFFS2 extraction |
| firmwalker | Automated analysis |
| FACT | Firmware Analysis Toolkit |
| Firmadyne | Emulation framework |

---

## Checklist

- [ ] Firmware acquired and verified
- [ ] Initial analysis complete
- [ ] Filesystem extracted
- [ ] Credentials hunted
- [ ] Configuration analyzed
- [ ] Binaries checked
- [ ] Vulnerabilities identified
- [ ] Report generated

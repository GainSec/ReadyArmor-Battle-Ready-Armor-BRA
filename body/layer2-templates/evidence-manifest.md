# Evidence Manifest Template

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Chain of custody and evidence tracking for security assessments

Use this manifest to connect evidence files to hashes, collection details, and custody records. Complete each applicable table.

---

## Manifest Header

| Field | Value |
|-------|-------|
| **Engagement ID** | [Unique engagement identifier] |
| **Engagement Name** | [Descriptive name] |
| **Start Date** | [YYYY-MM-DD] |
| **End Date** | [YYYY-MM-DD] |
| **Lead Assessor** | [Name] |
| **Evidence Custodian** | [Name] |
| **Storage Location** | [Path or physical location] |
| **Classification** | [Public/Confidential/Restricted] |

---

## Evidence Integrity

### Hash Algorithm
Calculate a **SHA-256** hash for each evidence file. Record a different algorithm if the engagement requires one.

### Verification Command
```bash
# Verify single file
sha256sum -c <evidence_id>.sha256

# Verify all evidence
sha256sum -c manifest.sha256
```

---

## Evidence Index

### Artifacts

| Evidence ID | Filename | Type | SHA-256 Hash | Size | Collected | Source |
|-------------|----------|------|--------------|------|-----------|--------|
| A001 | app.apk | APK | [64-char hash] | 15.2 MB | 2026-01-23 10:30 | Device extract |
| A002 | config.xml | Config | [64-char hash] | 2.1 KB | 2026-01-23 10:35 | File system |
| A003 | firmware.bin | Binary | [64-char hash] | 8.4 MB | 2026-01-23 11:00 | Device dump |

### Network Captures

| Evidence ID | Filename | Type | SHA-256 Hash | Size | Collected | Duration |
|-------------|----------|------|--------------|------|-----------|----------|
| N001 | http_traffic.pcap | PCAP | [64-char hash] | 45.6 MB | 2026-01-23 14:00 | 2 hours |
| N002 | auth_handshake.pcap | PCAP | [64-char hash] | 1.2 MB | 2026-01-23 16:30 | 5 minutes |

### Screenshots/Media

| Evidence ID | Filename | Type | SHA-256 Hash | Size | Collected | Description |
|-------------|----------|------|--------------|------|-----------|-------------|
| S001 | vuln_disclosure.png | Image | [64-char hash] | 245 KB | 2026-01-23 15:00 | Information disclosure |
| S002 | auth_bypass.mp4 | Video | [64-char hash] | 12.3 MB | 2026-01-23 15:30 | Authentication bypass demo |

### Logs

| Evidence ID | Filename | Type | SHA-256 Hash | Size | Collected | Source |
|-------------|----------|------|--------------|------|-----------|--------|
| L001 | system.log | Log | [64-char hash] | 890 KB | 2026-01-23 12:00 | Target system |
| L002 | proxy.log | Log | [64-char hash] | 2.4 MB | 2026-01-23 18:00 | Burp Suite |

### Proof of Concept Files

| Evidence ID | Filename | Type | SHA-256 Hash | Size | Created | Finding Reference |
|-------------|----------|------|--------------|------|---------|-------------------|
| P001 | sqli_poc.py | PoC | [64-char hash] | 1.8 KB | 2026-01-23 17:00 | F001 |
| P002 | deser_payload.bin | Payload | [64-char hash] | 512 B | 2026-01-23 17:30 | F002 |

### RF/Signal Captures

| Evidence ID | Filename | Type | SHA-256 Hash | Size | Collected | Frequency |
|-------------|----------|------|--------------|------|-----------|-----------|
| R001 | garage_signal.sub | Sub-GHz | [64-char hash] | 24 KB | 2026-01-23 09:00 | 433.92 MHz |
| R002 | ble_capture.btsnoop | BLE | [64-char hash] | 890 KB | 2026-01-23 10:00 | 2.4 GHz |

---

## Chain of Custody Log

| Evidence ID | Action | Performed By | Date/Time | Location | Notes |
|-------------|--------|--------------|-----------|----------|-------|
| A001 | Collected | [Name] | 2026-01-23 10:30 | Lab | Extracted via adb |
| A001 | Hashed | [Name] | 2026-01-23 10:35 | Lab | SHA-256 verified |
| A001 | Stored | [Name] | 2026-01-23 10:40 | Evidence server | Encrypted storage |
| A001 | Accessed | [Name] | 2026-01-24 09:00 | Lab | Analysis |
| A001 | Returned | [Name] | 2026-01-24 17:00 | Evidence server | Analysis complete |

---

## Finding-Evidence Cross Reference

| Finding ID | Finding Title | Evidence IDs | Notes |
|------------|---------------|--------------|-------|
| F001 | SQL Injection in login | A001, N001, P001, S001 | Full chain documented |
| F002 | Insecure deserialization | A002, P002 | PoC generated |
| F003 | Default credentials | L001, S002 | Video demonstration |

---

## Evidence Collection Procedures

### Digital Artifacts

```bash
# 1. Calculate hash before collection
sha256sum /path/to/artifact > original_hash.txt

# 2. Collect with read-only mount (if possible)
mount -o ro /dev/sda1 /mnt/evidence

# 3. Copy with preservation
cp -p /mnt/evidence/file ./evidence/

# 4. Verify hash after collection
sha256sum ./evidence/file > collected_hash.txt
diff original_hash.txt collected_hash.txt
```

### Network Captures

```bash
# 1. Start capture with timestamp
tcpdump -i eth0 -w capture_$(date +%Y%m%d_%H%M%S).pcap

# 2. Document capture parameters
echo "Interface: eth0, Filter: [filter], Duration: [time]" > capture_metadata.txt

# 3. Hash immediately after capture
sha256sum capture_*.pcap > capture_hashes.txt
```

### Screenshots/Video

```bash
# 1. Use consistent naming
screenshot_YYYYMMDD_HHMMSS_description.png

# 2. Include metadata
exiftool -Comment="Finding F001 - SQL Injection demonstration" screenshot.png

# 3. Hash all media
sha256sum *.png *.mp4 > media_hashes.txt
```

---

## Evidence Storage Requirements

### Security Controls

| Control | Requirement |
|---------|-------------|
| Encryption | AES-256 at rest |
| Access Control | Role-based, logged |
| Backup | Daily, off-site |
| Retention | Per engagement agreement |
| Destruction | Secure wipe after retention |

### Directory Structure

```
evidence/
├── manifest.md              # This file
├── manifest.sha256          # Hash of all evidence
├── artifacts/               # Collected artifacts
│   ├── A001_app.apk
│   └── A002_config.xml
├── captures/                # Network captures
│   ├── N001_http_traffic.pcap
│   └── N002_auth_handshake.pcap
├── media/                   # Screenshots/video
│   ├── S001_vuln_disclosure.png
│   └── S002_auth_bypass.mp4
├── logs/                    # Log files
│   ├── L001_system.log
│   └── L002_proxy.log
├── poc/                     # Proof of concept files
│   ├── P001_sqli_poc.py
│   └── P002_deser_payload.bin
└── rf/                      # RF/Signal captures
    └── R001_garage_signal.sub
```

---

## Verification Checklist

### Collection Phase
- [ ] Evidence collected from authorized sources only
- [ ] Hash calculated before any processing
- [ ] Original preserved (read-only)
- [ ] Collection metadata documented
- [ ] Chain of custody entry created

### Storage Phase
- [ ] Evidence stored in designated location
- [ ] Access controls verified
- [ ] Encryption enabled
- [ ] Backup completed
- [ ] Hash verified after storage

### Analysis Phase
- [ ] Working copy created (not original)
- [ ] Analysis tools documented
- [ ] Findings linked to evidence
- [ ] Chain of custody updated

### Handoff Phase
- [ ] All evidence accounted for
- [ ] Final hash verification
- [ ] Recipient acknowledged
- [ ] Chain of custody transferred
- [ ] Retention policy confirmed

---

## Manifest Signature

```
Manifest Generated: [YYYY-MM-DD HH:MM:SS UTC]
Generated By: [Name]
Manifest Hash (SHA-256): [Hash of this manifest file]

Verified By: [Name]
Verification Date: [YYYY-MM-DD]
Verification Hash: [Recalculated hash - must match above]
```

---

## Quick Reference

### Hash Commands

```bash
# Generate hash
sha256sum file.bin > file.sha256

# Verify hash
sha256sum -c file.sha256

# Generate manifest hash
find evidence/ -type f -exec sha256sum {} \; | sort > manifest.sha256
sha256sum manifest.sha256 >> manifest.sha256
```

### Evidence Naming Convention

```
<TYPE><NUMBER>_<DESCRIPTION>.<EXT>

Examples:
A001_target_app.apk
N002_auth_traffic.pcap
S003_sqli_error.png
P004_rce_exploit.py
```

### Required Metadata

| Evidence Type | Required Fields |
|---------------|-----------------|
| All | ID, Hash, Size, Collected, Source |
| Captures | Duration, Filter, Interface |
| Media | Description, Related Finding |
| PoC | Finding Reference, Language |
| RF | Frequency, Modulation |

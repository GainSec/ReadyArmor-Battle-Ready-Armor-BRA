# Tool Optimization Quick Reference

> **Template Version:** 1.0
> **Purpose:** Parameter recommendations by target type and operational mode
> **Layer:** Layer 2 Template

Select parameters for the target and approved operating mode. Record rate limits and scan permissions before network activity.

---

## Operational Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Stealth** | Slow, low-profile, evades detection | Production systems, IDS/IPS present |
| **Normal** | Balanced speed and noise | Standard assessments |
| **Aggressive** | Fast, high parallelism, noisy | Lab environments, time-constrained |

---

## Network Intelligence

### nmap

| Target Type | Recommended Parameters |
|-------------|----------------------|
| Web Application | `-sV -sC -p 80,443,8080,8443,8000,9000` |
| Network Host | `-sS -O --top-ports 1000` |
| Full Port Scan | `-sS -p-` |
| Service Version | `-sV --version-intensity 5` |
| Vulnerability Scan | `-sV --script=vuln` |

**Operational Mode Adjustments:**

| Mode | Timing | Additional Flags |
|------|--------|------------------|
| Stealth | `-T2` | `--scan-delay 1s --max-retries 2` |
| Normal | `-T3` | (default) |
| Aggressive | `-T4` | `--min-rate 1000` |

**Examples:**
```bash
# Stealth web scan
nmap -sV -sC -T2 --scan-delay 1s -p 80,443,8080,8443 target.com

# Aggressive full scan
nmap -sS -T4 --min-rate 1000 -p- target.com

# Normal service detection
nmap -sV -sC -T3 --top-ports 1000 target.com
```

---

### masscan

| Mode | Rate | Flags |
|------|------|-------|
| Stealth | `--rate 100` | `--wait 5` |
| Normal | `--rate 1000` | `--wait 3` |
| Aggressive | `--rate 10000` | `--wait 1` |

**Examples:**
```bash
# Stealth scan
masscan -p1-65535 --rate 100 --wait 5 -oJ results.json target.com

# Aggressive scan
masscan -p1-65535 --rate 10000 --wait 1 -oJ results.json target.com
```

---

### rustscan

| Mode | Batch Size | Timeout |
|------|------------|---------|
| Stealth | `-b 100` | `-t 2000` |
| Normal | `-b 500` | `-t 1500` |
| Aggressive | `-b 2000` | `-t 1000` |

**Examples:**
```bash
# Stealth with nmap handoff
rustscan -a target.com -b 100 -t 2000 -- -sV -sC

# Aggressive
rustscan -a target.com -b 2000 -t 1000 -- -sV
```

---

## Web Assessment

### ffuf / gobuster

**Extension Selection by Technology:**

| Stack | Extensions |
|-------|------------|
| PHP | `-e php,html,txt,xml,inc,bak` |
| ASP.NET | `-e asp,aspx,ashx,asmx,html,txt,config` |
| Java | `-e jsp,jsf,do,action,html,xml` |
| Python | `-e py,html,txt,json` |
| Node.js | `-e js,json,html,txt` |
| Generic | `-e html,php,txt,js,json` |

**Thread/Rate Adjustments:**

| Mode | ffuf | gobuster |
|------|------|----------|
| Stealth | `-rate 10 -t 5` | `-t 5 --delay 500ms` |
| Normal | `-rate 50 -t 20` | `-t 20` |
| Aggressive | `-rate 200 -t 50` | `-t 50` |

**Examples:**
```bash
# ffuf - Stealth PHP scan
ffuf -u https://target.com/FUZZ -w wordlist.txt -e php,html,txt -rate 10 -t 5

# gobuster - Aggressive .NET scan
gobuster dir -u https://target.com -w wordlist.txt -x asp,aspx,config -t 50

# ffuf - API endpoint discovery
ffuf -u https://api.target.com/FUZZ -w api-wordlist.txt -rate 50 -mc 200,201,301,302,401,403
```

---

### nuclei

**Severity Filters:**

| Scan Type | Severity Flag |
|-----------|---------------|
| Critical only | `-s critical` |
| High+ | `-s critical,high` |
| All findings | `-s critical,high,medium,low,info` |
| Quick triage | `-s critical,high -rl 50` |

**Technology Tags:**

| Target | Tags |
|--------|------|
| WordPress | `-tags wordpress,wp-plugin` |
| Joomla | `-tags joomla` |
| Drupal | `-tags drupal` |
| Generic CMS | `-tags cms` |
| API | `-tags api,graphql` |
| Cloud | `-tags aws,azure,gcp` |

**Rate Adjustments:**

| Mode | Flags |
|------|-------|
| Stealth | `-rl 5 -c 2` |
| Normal | `-rl 50 -c 10` |
| Aggressive | `-rl 150 -c 25` |

**Examples:**
```bash
# Stealth critical-only scan
nuclei -u https://target.com -s critical,high -rl 5 -c 2

# Aggressive WordPress scan
nuclei -u https://target.com -tags wordpress -rl 150 -c 25

# Normal API assessment
nuclei -u https://api.target.com -tags api -s critical,high,medium -rl 50
```

---

### sqlmap

**Database-Specific Optimization:**

| Database | DBMS Flag | Additional |
|----------|-----------|------------|
| MySQL | `--dbms=mysql` | `--technique=BEUSTQ` |
| PostgreSQL | `--dbms=postgresql` | `--technique=BEUSTQ` |
| MSSQL | `--dbms=mssql` | `--technique=BEUSTQ` |
| Oracle | `--dbms=oracle` | `--technique=BEUST` |
| SQLite | `--dbms=sqlite` | `--technique=BEUST` |

**Aggression Levels:**

| Mode | Flags |
|------|-------|
| Stealth | `--level=1 --risk=1 --delay=2 --random-agent` |
| Normal | `--level=2 --risk=2 --random-agent` |
| Aggressive | `--level=5 --risk=3 --threads=10` |

**Examples:**
```bash
# Stealth MySQL test
sqlmap -u "https://target.com/page?id=1" --dbms=mysql --level=1 --risk=1 --delay=2 --random-agent

# Aggressive full test
sqlmap -u "https://target.com/page?id=1" --level=5 --risk=3 --threads=10 --batch

# Normal with specific technique
sqlmap -u "https://target.com/page?id=1" --level=2 --risk=2 --technique=BEU --random-agent
```

---

## Credential Testing

### hydra

**Service-Specific Parameters:**

| Service | Protocol Flag | Common Ports |
|---------|---------------|--------------|
| SSH | `ssh` | 22 |
| FTP | `ftp` | 21 |
| HTTP Basic | `http-get` | 80, 443 |
| HTTP Form | `http-post-form` | 80, 443 |
| SMB | `smb` | 445 |
| RDP | `rdp` | 3389 |
| MySQL | `mysql` | 3306 |

**Rate Adjustments:**

| Mode | Flags |
|------|-------|
| Stealth | `-t 1 -W 5` |
| Normal | `-t 4 -W 3` |
| Aggressive | `-t 16 -W 1` |

**Examples:**
```bash
# Stealth SSH
hydra -L users.txt -P passwords.txt -t 1 -W 5 ssh://target.com

# Normal HTTP form
hydra -L users.txt -P passwords.txt -t 4 target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Aggressive with verbose
hydra -L users.txt -P passwords.txt -t 16 -W 1 -vV ssh://target.com
```

---

## Static Analysis

### semgrep

| Scan Type | Flags |
|-----------|-------|
| Security-focused | `--config=p/security-audit` |
| OWASP Top 10 | `--config=p/owasp-top-ten` |
| Language-specific | `--config=p/python` or `p/javascript` |
| CI mode | `--json --quiet` |

**Examples:**
```bash
# Full security audit
semgrep --config=p/security-audit --config=p/owasp-top-ten /path/to/code

# Quick Python check
semgrep --config=p/python /path/to/code --json
```

---

### CodeQL

| Query Suite | Use Case |
|-------------|----------|
| `security-extended` | Comprehensive security |
| `security-and-quality` | Security + code quality |
| `security-experimental` | Bleeding edge rules |

**Examples:**
```bash
# Create database
codeql database create codeql-db --language=javascript --source-root=/path/to/code

# Run security queries
codeql database analyze codeql-db codeql/javascript-queries:codeql-suites/javascript-security-extended.qls --format=sarif-latest --output=results.sarif
```

---

## Quick Decision Matrix

### By Target Type

| Target | Primary Tools | Recommended Mode |
|--------|---------------|------------------|
| Production web app | nuclei, ffuf | Stealth |
| Internal network | nmap, masscan | Normal |
| Lab/CTF | rustscan, aggressive nuclei | Aggressive |
| API endpoint | ffuf, nuclei (api tags) | Normal |
| Login form | hydra, sqlmap | Stealth |

### By Time Constraint

| Time Available | Strategy |
|----------------|----------|
| < 1 hour | Aggressive mode, critical findings only |
| 1-4 hours | Normal mode, high+ severity |
| Full day+ | Normal/Stealth, comprehensive |

### By Detection Risk

| Risk Level | Recommended Mode | Notes |
|------------|------------------|-------|
| High (IDS/IPS active) | Stealth | Accept slower results |
| Medium (logging only) | Normal | Balanced approach |
| Low (lab environment) | Aggressive | Maximize coverage |

---

## ROE Integration

When documenting operational mode in `layer3-engagement/ROE.md`:

```markdown
## Operational Mode

**Selected Mode:** [Stealth | Normal | Aggressive]

**Justification:** [Why this mode was chosen]

**Constraints:**
- Maximum threads/rate: [Value]
- Timing restrictions: [If any]
- Detection tolerance: [High | Medium | Low]
```

---

## References

- `layer2-templates/toolset.md` — Full tool catalog
- `layer2-templates/skillset.md` — Skill-tool mappings
- `layer3-engagement/ROE.md` — Engagement-specific constraints
- `layer3-engagement/TOOLSUITES.md` — Approved tools for engagement

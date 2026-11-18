# Scope Intake (Agent Prompt + Recording Guide)


Create an engagement copy at `layer3-engagement/SCOPE.md`. Collect the fields below. Keep this reusable template unchanged during intake.

## Questions & Destinations

- Ethics: "Do you have authorization for the activities in this engagement?"
  - YES → record in `layer3-engagement/README-PROJECTOVERVIEW.md` and `layer3-engagement/SCOPE.md`. An affirmative answer records authorization within scope.

- Target Type: What type of target is this engagement focused on?
  - Options:
    - **android** - Android mobile apps (APK/AAB)
    - **ios** - iOS mobile apps (IPA)
    - **iot** - IoT/embedded devices, cameras
    - **bluetooth** - Bluetooth/BLE devices
    - **thick-client** - Desktop apps (Windows exe/dll)
    - **dotnet** - .NET assemblies
    - **firmware** - Binary firmware images
    - **selinux** - SELinux policy analysis
    - **homekit** - HomeKit/HAP devices
    - **network** - Network-only (IPs, domains)
    - **field** - Field intelligence
  - Record in `layer3-engagement/SCOPE.md` as `Target Type: <type>`
  - The target type selects the method through `layer1/lib/target_type_detector.py`

- Targets: app/device/version/build/URLs/IPs/CIDRs, ports/protocols; in-scope vs out-of-scope.
  - Record in `layer3-engagement/SCOPE.md`; also note in `layer3-engagement/TOOLSUITES.md` and `layer3-engagement/SKILLSUITES.md` if it affects tool/skill selection.
- Auth: roles/accounts/creds/TOTP, SSO scopes, session limits.  
  - Record in `layer3-engagement/SCOPE.md` and `layer3-engagement/SKILLSUITES.md`.
- Network: allowed egress/ingress, proxy/Burp/CDP/headless allowances.  
  - Record in `layer3-engagement/TOOLSUITES.md` and `layer3-engagement/SKILLSUITES.md`.
- Data handling: allowed data classes, secret handling/storage/encryption rules.  
  - Record in `layer3-engagement/SKILLSUITES.md` and `layer3-engagement/README-PROJECTOVERVIEW.md`.
- Tooling: allowed tools/versions, bans, rate limits.  
  - Record in `layer3-engagement/TOOLSUITES.md` and `layer3-engagement/SKILLSUITES.md`; if specific tools are out-of-scope, also note in `layer3-engagement/SCOPE.md`.
- Time window: start/end, blackout periods.  
  - Record in `layer3-engagement/README-PROJECTOVERVIEW.md`.
- External research: Record permitted internet use, research purposes, and domains.
  - Include source code, installation, documentation, and open-source intelligence limits.
  - Record cache requirements.  
  - Record in `layer3-engagement/TOOLSUITES.md` and `layer3-engagement/SKILLSUITES.md`.
- Tokens: which are set (NEGATIVE-RESULTS, ARTIFACTS override, DESTRUCTIVE-APPROVAL, IGNORE-BACKUP, WATCH, TRACK, etc.).
  - Record in `layer3-engagement/ROE.md` and `layer3-engagement/README-PROJECTOVERVIEW.md`.
- Active Testing: Do you want to allow active/network-based testing against the target(s)?
  - Options:
    - **YES** - Network-based testing allowed (port scanning, fuzzing live targets, etc.)
    - **NO** - Only static analysis + local VMs. Any network activity is BLOCKED.
    - **ASK** - Prompt before any network-based testing activity (default)
  - Active network assessment includes port scans, remote fuzzing, exploitation, and commands that send traffic to external hosts.
  - Static and local work includes offline binary analysis, local virtual machines, loopback checks, and tools such as Ghidra or Semgrep.
  - Record in `layer3-engagement/SCOPE.md` (Active Testing section), `layer3-engagement/ROE.md` (Token table), and `.bra/approvals/ACTIVE-TESTING-APPROVAL` (if YES).
- Outputs: where layer3-engagement/NOTES/PoCs/evidence/reports must live; push/publish constraints.  
  - Record in `layer3-engagement/README-PROJECTOVERVIEW.md` and `layer3-engagement/SKILLSUITES.md`.
- Other: any questions, concerns, notes, or guidance.  
  - Record case-by-case in the most relevant file (SCOPE, ROE, TOOLSUITES, SKILLSUITES, or README-PROJECTOVERVIEW).
- Backups: any unique steps during recurring backups for this project.  
  - Record in `layer3-engagement/README-PROJECTOVERVIEW.md` and `layer3-engagement/SCOPE.md` if it affects handling.

## Recording Guidance
- Instantiate from this template per engagement to `layer3-engagement/SCOPE.md` (or PLAN). Keep templates untouched.
- After intake, summarize the scope in `layer3-engagement/ROE.md`.
- Keep commands and skills within the recorded limits.
- Set token-dependent behavior from the recorded answers.
- Use `NEGATIVE-RESULTS` when negative coverage records are required.

## Post-Intake
- Run `./layer1/scripts/precheck.py` to verify environment readiness and create any missing directories/files.
- Review the precheck report at `.bra/PRECHECK_REPORT.md` before proceeding.

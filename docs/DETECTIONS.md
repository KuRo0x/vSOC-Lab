# Detection Engineering

This document describes the active detections implemented in the vSOC lab.  
Each detection is based on **observable behavior**, mapped to telemetry sources, and designed to reflect real SOC alerting practices.

All detections are validated against live data flowing through the Logstash pipeline.

---

## 1. Detection Philosophy

The lab prioritizes:
- **Behavioral detections** over static indicators
- **Cross-source correlation**
- **Explainability** for analysts

Detections focus on:
- Living-off-the-Land techniques (LOLBins)
- Execution abuse
- Persistence mechanisms
- Policy violations

---

## 2. Active Detections

| Detection | MITRE | Data Source | Confidence |
| :--- | :--- | :--- | :--- |
| Suspicious Encoded PowerShell | T1059.001 | Sysmon (EID 1) | High |
| LOLBin Abuse: Certutil Ingress | T1105 | Sysmon (EID 1) | High |
| Persistence: Registry Run Key | T1547.001 | Sysmon (EID 13) | High |
| Local Account Creation (Sigma) | T1136.001 | Windows Security | High |
| Post-Exploitation Discovery | T1033 | Windows Security | Medium |
| Unauthorized DNS Egress | T1071.004 | pfSense Logs | High |

---

### 2.1 Suspicious PowerShell Execution  
**MITRE Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell

**Data Source:**  
- Windows Sysmon (Process Creation)

**Behavior Detected:**  
- Encoded PowerShell commands  
- Download-and-execute patterns  
- In-memory execution indicators

**Detection Logic (High-Level):**
- Process name: `powershell.exe`
- Command-line contains:
  - `-enc`
  - `IEX`
  - `Invoke-Expression`
  - Remote content retrieval

**Why It Matters:**  
PowerShell is frequently abused for initial access, execution, and post-exploitation while blending in with legitimate administration activity.

**Validation / Reproduction (Lab):**
1. On the Windows endpoint, run a harmless encoded command:
   - `powershell.exe -NoP -enc VwByAGkAdABlAC0ASABvAHMAdAAgAFYAUwBPAEMALQBMAGEAYgA=`
2. Confirm a Sysmon process creation event shows `-enc`.
3. Validate the detection alert in Kibana with the full command-line context.

---

### 2.2 LOLBin Abuse: Certutil  
**MITRE Technique:** T1105 – Ingress Tool Transfer

**Data Source:**  
- Windows Sysmon (Process Creation)

**Behavior Detected:**  
- Use of `certutil.exe` to retrieve remote files
- File download via built-in Windows utilities

**Detection Logic (High-Level):**
- Process name: `certutil.exe`
- Command-line flags:
  - `-urlcache`
  - `-split`
  - Remote URL usage

**Why It Matters:**  
Attackers abuse trusted binaries to bypass application allowlisting and reduce detection surface.

**Validation / Reproduction (Lab):**
1. On the Windows endpoint, run:
   - `certutil.exe -urlcache -split -f https://example.com/`
2. Confirm Sysmon logs the process execution and URL in the command line.
3. Validate the detection alert in Kibana.

---

### 2.3 Registry-Based Persistence  
**MITRE Technique:** T1547.001 – Registry Run Keys / Startup Folder

**Data Source:**  
- Windows Sysmon (Registry Event)

**Behavior Detected:**  
- Modification of autorun registry keys
- Persistence mechanisms executed at user logon

**Detection Logic (High-Level):**
- Registry path monitoring:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

**Why It Matters:**  
Persistence ensures attacker access across reboots and user sessions.

**Validation / Reproduction (Lab):**
1. On the Windows endpoint, set a test Run key:
   - `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v VSOC-Lab-Test /t REG_SZ /d "C:\\Windows\\System32\\notepad.exe" /f`
2. Confirm Sysmon logs the registry modification event.
3. Validate the detection alert in Kibana.

---

### 2.4 Host & User Discovery Commands  
**MITRE Technique:** T1033 – System Owner/User Discovery

**Data Source:**  
- Windows Sysmon (Process Creation)

**Behavior Detected:**  
- Enumeration commands such as:
  - `whoami`
  - `hostname`
  - `echo %USERNAME%`

**Detection Logic (High-Level):**
- Command-line matching known discovery utilities
- Correlation with suspicious parent processes

**Why It Matters:**  
Discovery often precedes lateral movement or privilege escalation.

**Validation / Reproduction (Lab):**
1. On the Windows endpoint, run:
   - `whoami`
   - `hostname`
2. Confirm Sysmon process creation events for these commands.
3. Validate the detection alert in Kibana.

---

### 2.5 DNS Policy Violation  
**MITRE Technique:** T1071.004 – Application Layer Protocol: DNS

**Data Source:**  
- pfSense firewall logs

**Behavior Detected:**  
- Endpoint attempts to bypass enforced DNS path
- Direct external DNS resolution attempts

**Detection Logic (High-Level):**
- Blocked outbound DNS traffic not destined for pfSense
- Firewall rule violations logged and forwarded

**Why It Matters:**  
DNS is commonly used for command-and-control and data exfiltration.

**Validation / Reproduction (Lab):**
1. On the Windows endpoint, attempt direct DNS resolution:
   - `nslookup example.com 8.8.8.8`
2. Confirm pfSense logs a blocked outbound DNS attempt.
3. Validate the detection alert in Kibana.

---

### 2.6 Unauthorized Local User Creation (Sigma-Based)  
**MITRE Technique:** T1136.001 – Create Account: Local Account

**Data Source:**  
- Windows Security Event Logs

**Detection Type:**  
- Translated Sigma rule

**Behavior Detected:**  
- Creation of new local user accounts

**Detection Logic (High-Level):**
- Event ID indicating user creation
- Account creation outside expected administrative workflows

**Why It Matters:**  
Unauthorized account creation enables long-term persistence and privilege escalation.

**Validation / Reproduction (Lab):**
1. On the Windows endpoint (admin context), create a test user:
   - `net user vsoc-test-user P@ssw0rd! /add`
2. Confirm Windows Security logs the account creation event.
3. Validate the detection alert in Kibana.

---

## 3. Detection Coverage Summary

| Category | Coverage |
|-------|--------|
| Execution | PowerShell, LOLBins |
| Persistence | Registry Run Keys |
| Discovery | Host/User Enumeration |
| Network | DNS Policy Violations |
| Account Abuse | Local User Creation |

---

## 4. Analyst Workflow

For each alert:
1. Identify detection type and MITRE technique
2. Review command-line or network context
3. Correlate with recent endpoint or network activity
4. Assess intent (administrative vs malicious)
5. Escalate or close with justification

---

## 5. Design Notes

- Detections favor **clarity over volume**
- False positives are expected and documented
- Logic is intentionally transparent for analyst training

---

## 6. Scope Notes

- No automated blocking is performed
- Alerts are informational and investigative
- The lab focuses on **detection engineering**, not response automation

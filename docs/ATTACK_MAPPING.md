# MITRE ATT&CK Mapping

This document explains how each detection in the vSOC lab maps to specific MITRE ATT&CK techniques.  
Mappings are based on **observed behavior**, not tool names or assumptions.

Only techniques that are **directly evidenced by telemetry** are mapped.

---

## 1. Mapping Methodology

### 1.1 Principles

A detection is mapped to a MITRE ATT&CK technique only if:

- The observed behavior **matches the technique definition**
- The required telemetry is **explicitly captured**
- The detection logic would remain valid regardless of the specific tool used

This avoids:
- Over-mapping
- Tool-based assumptions
- Inflated coverage claims

---

### 1.2 Telemetry Sources Used

- Windows Sysmon (process, registry activity)
- Windows Security Event Logs
- pfSense firewall and DNS logs
- Suricata IDS alerts

---

## 2. Technique Mappings

---

### 2.1 T1059.001 — Command and Scripting Interpreter: PowerShell

**Detection:** Suspicious PowerShell Execution

**Observed Behavior:**
- PowerShell execution with encoded commands
- In-memory execution indicators
- Download-and-execute patterns

**Justification:**
The detection observes direct use of the PowerShell interpreter to execute commands.  
Encoded and expression-based execution aligns precisely with the PowerShell sub-technique.

**Why This Mapping Is Valid:**
- Telemetry captures full command-line arguments
- Execution context is observable
- No assumption about payload content is required

---

### 2.2 T1105 — Ingress Tool Transfer

**Detection:** LOLBin Abuse: Certutil

**Observed Behavior:**
- File retrieval from remote locations using `certutil.exe`
- Use of native Windows utilities for payload transfer

**Justification:**
The technique explicitly covers transferring tools or payloads from external systems.  
The method of transfer (LOLBin vs custom downloader) does not affect the technique classification.

**Why This Mapping Is Valid:**
- Network destination and command-line arguments are visible
- Behavior matches ATT&CK definition regardless of intent

---

### 2.3 T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**Detection:** Registry-Based Persistence

**Observed Behavior:**
- Modification of Run and RunOnce registry keys
- Persistence established at user logon

**Justification:**
The detection observes registry paths that ATT&CK defines as autorun execution points.

**Why This Mapping Is Valid:**
- Registry object modification is directly captured
- No inference is required
- Persistence mechanism is explicit

---

### 2.4 T1033 — System Owner/User Discovery

**Detection:** Host & User Discovery Commands

**Observed Behavior:**
- Execution of commands that enumerate current user and host identity
- Discovery activity following initial execution

**Justification:**
The technique describes attempts to identify user context and system ownership.

**Why This Mapping Is Valid:**
- Commands executed are unambiguous
- Behavior matches technique intent exactly
- Often observed early in attack chains

---

### 2.5 T1071.004 — Application Layer Protocol: DNS

**Detection:** DNS Policy Violation

**Observed Behavior:**
- Endpoint attempts to bypass enforced DNS resolver
- Blocked outbound DNS traffic

**Justification:**
The technique covers DNS usage for application-layer communication, including command-and-control.

**Why This Mapping Is Valid:**
- DNS protocol usage is explicitly observed
- Policy enforcement reveals attempted misuse
- Mapping does not assume malicious payloads

---

### 2.6 T1136.001 — Create Account: Local Account

**Detection:** Unauthorized Local User Creation (Sigma-Based)

**Observed Behavior:**
- Creation of new local user accounts
- Account creation events captured in security logs

**Justification:**
ATT&CK defines this technique as the creation of local accounts for persistence or privilege escalation.

**Why This Mapping Is Valid:**
- Account creation is directly logged
- No behavioral inference required
- Detection logic aligns with Sigma standards

---

## 3. Coverage Summary

| ATT&CK Tactic | Techniques Covered |
|-------------|------------------|
| Execution | T1059.001 |
| Persistence | T1547.001, T1136.001 |
| Discovery | T1033 |
| Command and Control | T1071.004 |
| Initial Access / Transfer | T1105 |

---

## 4. Limitations & Intentional Gaps

The lab does **not** claim coverage for:
- Exploitation techniques
- Credential dumping
- Lateral movement
- Privilege escalation beyond account creation

These are intentionally out of scope to:
- Maintain clarity
- Avoid simulated exploit noise
- Focus on detection engineering fundamentals

---

## 5. Analyst Value

This mapping enables:
- Technique-based triage
- Detection gap analysis
- ATT&CK Navigator visualization
- Strategic understanding of detection coverage

Mappings are designed to be **defensible under questioning** and explainable to both technical and non-technical audiences.

---

## 6. Scope Notes

- All mappings are derived from live lab telemetry
- No simulated or assumed behaviors are included
- The mapping reflects detection capability, not adversary intent

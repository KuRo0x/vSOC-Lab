# SOC Runbook (Analyst Playbooks)

This runbook documents the investigation workflow for alerts generated in the vSOC lab.
It is written as an analyst-facing guide: what to check first, what evidence to collect, how to decide severity, and how to close or escalate.

Scope:
- Defensive monitoring only
- No automated response actions
- Lab environment (non-production)

---

## 1. Common Analyst Workflow (All Alerts)

### 1.1 Triage Checklist (60–120 seconds)
1. Confirm **alert type** and **MITRE technique**
2. Identify:
   - Hostname / endpoint IP (Windows)
   - User (if present)
   - Process name + command line (endpoint alerts)
   - Source/destination IP/port (network alerts)
3. Determine if it is:
   - Expected administrative activity
   - Lab validation activity
   - Suspicious / potentially malicious behavior
4. Decide initial severity (Low / Medium / High)

### 1.2 Evidence to Capture (Minimum)
- Kibana screenshot of the alert event
- Query used (copy/paste or screenshot)
- Timestamp range used for investigation
- Related events (process parent, network connections, registry writes, account events)
- Conclusion and reasoning (why closed or escalated)

### 1.3 Time Window Guidance
- Start with **± 10 minutes** around the alert timestamp
- Expand to **± 60 minutes** if you suspect a chain of activity

---

## 2. Data Sources and Where to Look

### 2.1 Windows Endpoint Telemetry
Primary:
- Sysmon process creation (command line context)
- Sysmon network connections (destination and port)
Secondary:
- Windows Security logs (account changes)

What you look for:
- Parent/child process relationships
- Encoded or obfuscated command lines
- Connections to external IPs or unusual internal targets
- Persistence indicators (autoruns, Run keys)

### 2.2 pfSense Gateway Telemetry
- Firewall allow/deny logs
- DNS enforcement rule hits (policy violations)

What you look for:
- Which host attempted the traffic
- Destination IP and port 53 attempts
- Repeat attempts (persistence / beaconing behavior)

### 2.3 Suricata IDS
- JSON alerts from Suricata

What you look for:
- Signature metadata (category, severity)
- Traffic tuple (src/dst/port/proto)
- Timing correlation with endpoint events

---

## 3. Alert Playbooks (Per Detection)

### 3.1 Suspicious PowerShell Execution (T1059.001)

**Goal:** Decide if PowerShell usage is normal admin work or suspicious execution.

#### Triage Questions
- Is the command line encoded (`-enc`) or using expression execution (`IEX`, `Invoke-Expression`)?
- Is PowerShell launched by a suspicious parent (Office, browser, temp directory executables)?
- Are there immediate outbound connections after execution?

#### Investigation Steps
1. Locate the Sysmon process event:
   - Process: `powershell.exe`
   - Capture full command line
2. Check **parent process** and **user context**
3. Look for follow-on events within ±10 minutes:
   - Network connection events (Sysmon network)
   - File creation events (if collected)
4. If encoded/obfuscated:
   - Note indicator strings (`-enc`, `IEX`) and the execution pattern

#### Close Conditions (Benign)
- Clear administrative script path
- Known admin parent process
- No suspicious network connections or follow-on behavior

#### Escalate Conditions (Suspicious)
- Encoded command + external network activity
- Suspicious parent process (Office → PowerShell, browser → PowerShell)
- Repeated execution attempts

**Recommended Severity**
- Low: plain PowerShell usage, no suspicious context
- Medium: obfuscated indicators, unclear parent
- High: obfuscated + external callbacks/download behavior

---

### 3.2 LOLBin Abuse: Certutil (T1105)

**Goal:** Validate if `certutil.exe` is used to download content (common attacker technique).

#### Triage Questions
- Are flags present: `-urlcache`, `-split`?
- Is a remote URL present?
- Where is the output file written (Temp, Downloads, user profile)?

#### Investigation Steps
1. Find Sysmon process event for `certutil.exe`
2. Capture command line, including URL and output path (if present)
3. Correlate with:
   - Network connections near the same time
   - Any subsequent execution of downloaded file

#### Close Conditions (Benign)
- No remote URL
- Legitimate certificate operations, expected paths

#### Escalate Conditions (Suspicious)
- Remote URL + file written to Temp/user directories
- Follow-on execution of the downloaded artifact

**Recommended Severity**
- Medium by default (certutil downloads are rarely normal)
- High if followed by execution or persistence

---

### 3.3 Registry Run Key Persistence (T1547.001)

**Goal:** Determine whether a Run key modification is legitimate startup configuration or persistence.

#### Triage Questions
- Which key was modified (HKCU vs HKLM)?
- What executable/path is being persisted?
- Is the path suspicious (Temp, AppData\Roaming, random name)?

#### Investigation Steps
1. Find Sysmon registry event (Run/RunOnce paths)
2. Record:
   - Registry path
   - Value name
   - Value data (the persisted command/path)
3. Look for the creating process around the same time:
   - What process wrote the registry value?
4. Check if the persisted file exists and whether it was recently created

#### Close Conditions (Benign)
- Known software installer updating autoruns
- Signed/expected application paths

#### Escalate Conditions (Suspicious)
- Unknown executable in AppData/Temp
- Run key written by suspicious process chain
- Persistence shortly after PowerShell/certutil activity

**Recommended Severity**
- Medium (persistence attempt)
- High if correlated with other suspicious activity

---

### 3.4 Host & User Discovery Commands (T1033)

**Goal:** Decide whether discovery is normal user/admin behavior or part of attack chain.

#### Triage Questions
- Are commands executed from an unusual parent process?
- Is discovery clustered (many discovery commands in a short time)?
- Does it follow suspicious execution (PowerShell/certutil)?

#### Investigation Steps
1. Identify process creation events for:
   - `whoami`, `hostname`, related commands
2. Confirm user context and parent process
3. Correlate with other suspicious activity in ±30 minutes

#### Close Conditions (Benign)
- Launched from cmd/PowerShell by expected user
- Single command, no suspicious follow-on

#### Escalate Conditions (Suspicious)
- Multiple discovery commands in sequence
- Discovery launched by suspicious parent process
- Discovery following a known execution alert

**Recommended Severity**
- Low standalone
- Medium when chained with other alerts

---

### 3.5 DNS Policy Violation (T1071.004)

**Goal:** Confirm endpoint attempted to bypass enforced DNS path (possible C2 or misconfiguration).

#### Triage Questions
- Which host attempted outbound DNS?
- What destination DNS server was attempted (public resolver)?
- Is this repeated (beaconing pattern)?

#### Investigation Steps
1. Locate pfSense firewall deny events for port 53
2. Record:
   - Source IP (endpoint)
   - Destination IP
   - Timestamp + count of attempts
3. Check endpoint events near the same time:
   - Any processes making network connections
   - Any suspicious execution prior to the DNS attempt

#### Close Conditions (Benign)
- Misconfiguration test, single attempt, known admin action

#### Escalate Conditions (Suspicious)
- Repeated attempts over time
- DNS attempts correlated with PowerShell/certutil or unknown processes

**Recommended Severity**
- Medium by default
- High if repeated and correlated with execution alerts

---

### 3.6 Unauthorized Local User Creation (T1136.001)

**Goal:** Confirm whether account creation is expected admin work or persistence.

#### Triage Questions
- Which account was created?
- Who created it (actor account)?
- Was the account added to privileged groups?

#### Investigation Steps
1. Find Windows Security event for user creation (record event ID, user, target account)
2. Check surrounding events:
   - Group membership changes (if available)
   - Logon events for the new user
3. Correlate with endpoint suspicious activity near the time

#### Close Conditions (Benign)
- Known admin maintenance (expected naming convention)
- Documented test activity

#### Escalate Conditions (Suspicious)
- Unknown account created by non-admin context
- Account created after suspicious execution/persistence activity
- Privileged group membership added

**Recommended Severity**
- High if unapproved account creation
- Medium if likely lab/test but not confirmed

---

## 4. Reporting Format (How to Write the Case)

Use this structure in your notes:

- Alert Type:
- MITRE Technique:
- Time Range Investigated:
- Affected Host / User:
- Key Evidence:
- Correlated Events:
- Analyst Conclusion:
- Severity:
- Closure Reason (or Escalation Reason):

---

## 5. Scope Notes

- This runbook is for investigation and analyst training
- No auto-blocking or response automation is implemented
- The goal is defensible triage decisions based on visible telemetry

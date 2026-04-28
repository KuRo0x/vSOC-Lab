# INC-005 – Improvements & Lessons Learned


## Detection Gaps Analysis

> This section answers the key question: **what would NOT have caught this scan, and why?**

| # | Gap | What It Misses | Root Cause | Fix |
|---|---|---|---|---|
| 1 | No Suricata deployed in this lab at time of scan | Entire network IDS layer absent — primary detection vector unavailable | Lab configuration gap | Deploy Suricata on pfSense or as inline sensor; configure EVE JSON → Logstash → Elastic |
| 2 | No SYN rate baseline established before incident | Alert threshold (200 SYN/min) set without baseline — could be too high or too low for this environment | No baseline measurement | Run 7-day passive collection of Sysmon Event ID 3 rates; set threshold at mean + 3σ |
| 3 | Sysmon Event ID 3 was present but no alert rule existed for burst detection | 20 inbound connections logged at 03:06 — visible in hindsight but no automated alert fired | No detection rule on Sysmon Event ID 3 volume | Create Elastic threshold rule: >10 unique destination ports from one source in 60 seconds (see detection.md) |
| 4 | Suricata ET SCAN misses slow-and-low scans (`--scan-delay 5s`) | An evasion-aware attacker spreading 10,000 probes over 13 hours would not trigger any current rule | Rate-based signatures only | Add long-window aggregation rule: >50 unique destination ports from one source over 10 minutes |
| 5 | No automated IP block on alert trigger | Manual response added ~2 minutes of exposure after alert fired | No SOAR/response action configured | Integrate pfSense REST API with Elastic response actions to push block rule automatically |
| 6 | RDP (3389) and SMB (445) found exposed through this scan, not through proactive auditing | High-value services were reachable externally with no prior awareness | No scheduled firewall audit | Monthly `nmap -sS --open` audit from WAN-side VM; restrict 3389/445 to RFC1918 alias only |
| 7 | No GeoIP / ASN enrichment on firewall logs | Source IP context (country, ISP, ASN) not immediately visible in Kibana alert | Logstash pipeline not enriched | Enable MaxMind GeoLite2 filter in Logstash for pfSense syslog events |


## Impact Assessment

> **What would have happened if this recon preceded real exploitation?**

This scan confirmed two critical findings:

### Finding 1 — RDP (3389) Exposed
- **Microsoft Terminal Services** confirmed open and responding (Nmap `-sV` + Sysmon Event ID 3 at 03:06:50)
- An attacker with valid credentials could achieve **full interactive remote access** to `DESKTOP-DPU3CDQ`
- RDP brute force tools (Hydra, CrackMapExec) would immediately target this port after the recon
- **Blast radius:** Complete host compromise — file access, credential dumping, lateral movement, ransomware deployment
- **Real-world precedent:** The majority of ransomware attacks in 2023–2025 began with exposed RDP (Sophos State of Ransomware 2024)

### Finding 2 — SMB (445) Exposed → Direct Link to INC-004
- SMB is open and responding on `DESKTOP-DPU3CDQ`
- **INC-004 documents an actual brute force against this exact service** — the kill chain is confirmed:
  ```
  INC-005 (Recon) → INC-004 (SMB Brute Force) → Potential Remote Access
  ```
- A successful SMB authentication would allow: file share enumeration, credential relay (Pass-the-Hash), remote code execution via PsExec/WMI
- **Blast radius:** Lateral movement to all hosts trusting the same credentials; domain-wide if NTLM relay succeeds

### Risk Rating

| Service | Exposure | Confidentiality | Integrity | Availability | Combined Risk |
|---|---|---|---|---|---|
| RDP (3389) | External | 🔴 Critical | 🔴 Critical | 🔴 Critical | **CRITICAL** |
| SMB (445) | External | 🔴 Critical | 🔴 Critical | 🔴 Critical | **CRITICAL** |
| NetBIOS (139) | External | 🟠 High | 🟡 Medium | 🟡 Medium | **HIGH** |
| MSRPC (135) | External | 🟡 Medium | 🟡 Medium | 🟡 Medium | **MEDIUM** |

> **Bottom line:** If this scan had been conducted by a real external attacker, the two open services (RDP + SMB) provide a complete exploitation path to full host compromise with no additional tooling beyond what any attacker already carries.


## IOC Enrichment

> Standard procedure: every source IP involved in an incident is checked against threat intelligence sources before being written off as benign.

### Source IP: 172.16.0.11 (Kali Attacker VM)

| Source | Query | Result | Notes |
|---|---|---|---|
| **AbuseIPDB** | `172.16.0.11` | ❌ No results | RFC1918 private address — not indexed in public threat intel |
| **VirusTotal** | `172.16.0.11` | ❌ No results | RFC1918 private address — not indexed |
| **Shodan** | `172.16.0.11` | ❌ No results | RFC1918 private address — not internet-routable |
| **Internal asset inventory** | MAC `00:0C:29:E3:CC:CD` | ✅ Known lab host | VMware OUI confirmed — this is the designated attacker VM in the vSOC-Lab environment |
| **AbuseIPDB confidence** | N/A | N/A | Private IPs return no data — expected and documented |

**Enrichment conclusion:** `172.16.0.11` is a known internal lab asset (Kali Linux attacker VM). No public threat intel applies to RFC1918 addresses. In a real engagement, this IP would be an external address and would be checked against:
- [AbuseIPDB](https://www.abuseipdb.com/) — reported abuse history
- [VirusTotal](https://www.virustotal.com/gui/home/search) — malicious activity associations
- [Shodan](https://www.shodan.io/) — what services this IP exposes publicly
- [ipinfo.io](https://ipinfo.io/) — ASN, organization, country
- Internal CMDB / asset inventory — is this a known corporate asset?

> **Analyst habit documented:** Even for an internal lab IP that will return no results, the enrichment check must be performed and documented. Showing this habit in a portfolio case demonstrates real SOC discipline — the process is the same regardless of the expected outcome.

### Target IP: 172.16.0.10 (DESKTOP-DPU3CDQ)

| Field | Value |
|---|---|
| **Hostname** | DESKTOP-DPU3CDQ |
| **MAC OUI** | VMware Inc. (00:0C:29:E3:CC:CD) — confirmed VM |
| **OS** | Windows 10 1803 (97% Nmap confidence) |
| **Asset classification** | Lab victim VM — known, managed |
| **Criticality** | Low (lab) / Would be High in production (Windows workstation with RDP + SMB) |


## Containment Actions

> What was done in the lab vs. what would be done in a real environment.

### Immediate Response (0–15 minutes)

| Action | Lab (what was done) | Real Environment (what should be done) |
|---|---|---|
| **Block source IP** | Added `172.16.0.11` to `ATTACKER_RECON_BLOCK` alias in pfSense manually | Automated via Elastic response action → pfSense REST API push within 30 seconds of alert |
| **Preserve evidence** | Nmap outputs saved to `evidence/`; Kibana screenshots taken | Packet capture (`.pcap`) preserved; Sysmon logs exported and hashed (SHA256) for chain of custody |
| **Notify SOC** | N/A (solo lab) | Alert escalated to Tier 2 analyst; ticket opened in ITSM system (ServiceNow/Jira) |
| **Asset isolation** | N/A (lab — no business impact) | Isolate affected host from network if follow-on exploitation detected; preserve memory image (WinPMEM) |

### Short-Term Remediation (15 minutes – 24 hours)

1. **Restrict RDP (3389):** Add pfSense firewall rule to allow 3389 only from `RFC1918_INTERNAL` alias. Deny all other sources.
2. **Restrict SMB (445):** Same as above — allow 445 only from trusted internal subnets. Block at perimeter.
3. **Restrict NetBIOS (139):** Block entirely unless legacy application dependency confirmed.
4. **Enable SYN cookies** on pfSense: `System → Advanced → Firewall & NAT → Enable SYN cookies` — mitigates SYN flood follow-up attacks.
5. **Add rate-limiting rule** in pfSense: `Firewall → Rules → Floating → Advanced Options → Max new connections: 100/s` per source IP.
6. **Review authentication logs** on `DESKTOP-DPU3CDQ` for any login attempts from `172.16.0.11` in the 48h window post-scan.

### Long-Term Hardening (24–72 hours)

1. **Network segmentation:** Move RDP and SMB to a dedicated management VLAN accessible only via jump host / VPN.
2. **Deploy Sysmon on all Windows hosts** with the SwiftOnSecurity baseline config — Event ID 3 detection is only possible because Sysmon was already deployed.
3. **Deploy Suricata** on pfSense or as a dedicated sensor — the primary network IDS gap in this incident.
4. **Enable NLA on RDP** (Network Level Authentication) — requires credentials before establishing RDP session, blocking unauthenticated probes.
5. **Implement account lockout** on Windows: 5 failed attempts → 15 min lockout → mitigates brute force follow-on (INC-004 pattern).
6. **Deploy Elastic SOAR response action:** When a port scan alert fires, automatically push the source IP to pfSense block alias via API.

### Post-Incident Monitoring (48-hour watch)

- [ ] Check `winlogbeat-*` for any Event ID 4624/4625 (logon success/fail) from `172.16.0.11`
- [ ] Check `winlogbeat-*` for any Event ID 7045 (new service installed) — possible persistence
- [ ] Check `winlogbeat-*` for any Event ID 4688 (new process) spawned from network-facing services
- [ ] Verify no new scheduled tasks or Run key entries on `DESKTOP-DPU3CDQ`
- [ ] Confirm firewall block rule is still active and has logged at least 0 hits (no retry attempts)


## What Worked

- Sysmon Event ID 3 on the victim corroborated the attacker-side scan — cross-source correlation confirmed the scan from two independent data sources.
- The Sysmon RDP probe log (03:06:50) provided exact timestamp alignment with Nmap Stage 3, proving victim-side visibility even without Suricata.
- MITRE ATT&CK tagging (T1595.001 / T1595.002) correctly applied and aligned with all three scan phases.
- Kill chain link to INC-004 was identified through port correlation — SMB found open here was brute-forced there.


## What Failed / Needs Improvement

- Suricata was not deployed in the lab at time of incident — the planned primary IDS had no data. Detection relied entirely on Sysmon (victim-side) and Nmap output (attacker-side).
- No automated alert rule existed for Sysmon Event ID 3 burst — the spike was visible in Kibana but required manual discovery, not automated alerting.
- The IP block was applied manually ~2 minutes after detection. In a real environment this is too slow.
- No formal post-scan monitoring checklist existed — monitoring was ad-hoc rather than procedural.


## Lessons Learned

### One-liner for the portfolio
> A fast Nmap scan is loud and easy to catch. The real detection challenge is the slow scan that takes 10 minutes instead of 45 seconds — and the real detection gap is the missing alert rule that should have fired automatically on the Sysmon spike.

### References

- [MITRE ATT&CK T1595.001 – Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001/)
- [MITRE ATT&CK T1595.002 – Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
- [Nmap – Firewall/IDS Evasion Techniques](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [Suricata ET SCAN Ruleset](https://rules.emergingthreats.net/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Sophos State of Ransomware 2024](https://www.sophos.com/en-us/content/state-of-ransomware)
- Internal Runbook: **Does not yet exist** ← tracked remediation action

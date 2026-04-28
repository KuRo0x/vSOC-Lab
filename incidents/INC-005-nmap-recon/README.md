# INC-005 – Nmap Port Scan & Network Recon Detection (T1595.001 / T1595.002)


## Summary

This incident simulates an external attacker performing active network reconnaissance against a Windows 10 host using Nmap. The attack generates a high-volume burst of TCP SYN packets across 1,000+ ports (half-open / stealth scan), followed by OS fingerprinting and service version detection probes. The activity is captured by pfSense firewall logs, Suricata IDS alerts, and Sysmon Event ID 3 (Network Connection), then surfaced in Elastic (Kibana) via a custom detection rule.

The goal of this case is to validate that the lab can (1) capture the SYN sweep at the perimeter, (2) detect Nmap probe signatures in Suricata, (3) surface and correlate the events in Kibana, and (4) measure the timing of the scan to distinguish aggressive versus slow-and-low reconnaissance.


## Environment

- **Attacker:** Kali Linux running `nmap` (SYN scan, OS detection, service version probing)
- **Victim:** Windows 10 endpoint (`DESKTOP-DPU3CDQ`, `172.16.0.10`)
- **Perimeter:** pfSense firewall (WAN-facing interface, logging all blocked/allowed traffic)
- **IDS:** Suricata (on pfSense or inline Ubuntu sensor) — ET SCAN ruleset enabled
- **Logging pipeline:** Sysmon Event ID 3 + pfSense syslog + Suricata EVE JSON → Logstash → Elasticsearch → Kibana (`winlogbeat-*`, `suricata-*`, `pfsense-*` indices)
- **Detection:** Elastic Security rule **"Nmap Port Scan – SYN Sweep Detected"** (threshold rule on Suricata `alert.signature` + pfSense SYN count)
- **Network control (lab-only):** pfSense `ATTACKER_RECON_BLOCK` alias


## Attack Overview

1. The attacker runs a staged Nmap reconnaissance sequence from Kali against the victim subnet:
   ```
   # Stage 1 — Stealth SYN scan (1,000+ ports)
   sudo nmap -sS -p 1-10000 172.16.0.10 -oN stage1_syn.txt

   # Stage 2 — OS fingerprinting
   sudo nmap -O 172.16.0.10 -oN stage2_os.txt

   # Stage 3 — Service version detection on discovered open ports
   sudo nmap -sV -p 80,443,3389,445 172.16.0.10 -oN stage3_versions.txt
   ```
2. pfSense logs a burst of inbound SYN packets with no corresponding SYN-ACK completion (half-open connections), all sourced from `172.16.0.11`.
3. Suricata fires ET SCAN signatures: `ET SCAN NMAP -sS window 1024`, `ET SCAN NMAP OS Detection Probe`, and `ET SCAN Nmap Scripting Engine User-Agent Detected`.
4. Sysmon Event ID 3 (Network Connection) on the victim records inbound connection attempts from `172.16.0.11` across sequential destination ports.
5. The Elastic Security rule **"Nmap Port Scan – SYN Sweep Detected"** runs every minute over `suricata-*` and `pfsense-*`, triggers when Suricata alert count from a single source IP exceeds the threshold, and generates a high-severity alert.
6. Kibana (Discover + Alerts view) surfaces both the raw Suricata EVE events and the correlated alert for the scan window.


## Key Evidence

- **Kibana Discover screenshot** showing a time-based spike of Suricata `ET SCAN` alerts from `172.16.0.11` targeting `172.16.0.10` across the scan window.
- **Elastic Alerts screenshot** showing the triggered rule **"Nmap Port Scan – SYN Sweep Detected"** with:
  - `source.ip: 172.16.0.11`
  - `destination.ip: 172.16.0.10`
  - `rule.name: ET SCAN NMAP -sS window 1024`
  - Alert severity: High
- **pfSense firewall log excerpt** showing 1,000+ sequential SYN-only packets from `172.16.0.11` to `172.16.0.10` with no ACK follow-up.
- **Suricata EVE JSON snippet** showing signature matches for Nmap SYN scan and OS probe patterns.
- **Nmap terminal output** from Kali showing discovered open ports, OS guess, and service versions.
- **Timing analysis:** scan duration, total packets, and calculated SYN/min rate confirming aggressive classification.

(Place these PNG/JPG/TXT files under `incidents/INC-005-nmap-recon/evidence/` and reference them from the investigation and improvements files.)


## Detection Goals

- Identify high-rate SYN bursts from a single external source targeting sequential ports.
- Detect Nmap-specific probe signatures (OS fingerprinting, service version probing, NSE User-Agent).
- Correlate pfSense perimeter block logs with Suricata IDS alerts to confirm the scan origin and scope.
- Generate a high-severity Elastic alert mapped to MITRE ATT&CK:
  - Technique: **T1595.001 – Active Scanning: Scanning IP Blocks**
  - Technique: **T1595.002 – Active Scanning: Vulnerability Scanning**
  - Tactic: **TA0043 – Reconnaissance**
- Measure scan timing (packets/second, total duration) to classify the scan as aggressive vs. slow-and-low.
- Identify which ports responded and cross-reference against expected exposure (flag any unexpected open services).


## Gap Analysis (High-Level)

- Suricata ET SCAN ruleset detects common Nmap signatures but misses slow/distributed scans (e.g., `--scan-delay 5s` or decoy scans with `-D`).
- No SYN rate baseline was established prior to the incident; alerts fired only after Suricata matched a known signature, not on raw packet rate alone.
- The Elastic rule is currently scoped to Suricata signature matches; a complementary pfSense-only rule based on SYN count per source per minute would catch scans that evade IDS signatures.
- No automated response action (IP block via pfSense API or firewall rule push) is attached to the alert; the block was applied manually using the `ATTACKER_RECON_BLOCK` alias.
- Port 3389 (RDP) responded to the scan — this is an unintended lab exposure and a standalone finding requiring remediation.

These gaps are expanded in `detection.md`, `investigation.md`, and `improvements.md`.


## Next Steps

- Add a complementary pfSense-based SYN rate threshold rule in Elastic (>200 SYN/min from a single source) to catch evasive scans that bypass Suricata signature matching.
- Attach an automated response action to the detection rule: push a temporary block rule to pfSense via its REST API when the alert fires.
- Remediate the unintended RDP exposure on `172.16.0.10` — restrict port 3389 to VPN/internal traffic only.
- Extend the detection pattern to cover slow-and-low scans (`--scan-delay`) using long-window aggregations (e.g., >50 unique destination ports from one source over 10 minutes).
- Document a formal response playbook:
  - Confirm alert in Elastic.
  - Validate SYN burst in pfSense logs and Suricata EVE.
  - Check if any scanned port responded (cross-reference with Sysmon Event ID 3).
  - Block source IP at pfSense using `ATTACKER_RECON_BLOCK` alias.
  - Monitor for 48 hours for follow-on exploitation attempts (auth events, exploit payloads).

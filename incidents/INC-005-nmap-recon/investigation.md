# INC-005 – Investigation Notes


## Timeline

> All timestamps real — scan executed 2026-04-28 03:06 UTC+1

| Timestamp (UTC+1) | Event | Source | Tool |
|---|---|---|---|
| 03:06:00 | Baseline traffic normal on `172.16.0.10` | pfSense FW log | Kibana |
| 03:06:00 | Stage 1: `nmap -sS -p 1-10000` initiated from `172.16.0.11` | Kali terminal | Nmap 7.95 |
| 03:06:00 | First SYN packets observed — sequential port sweep begins (1 → 10000) | pfSense FW log | pfSense |
| 03:06:12 | 39% of scan complete — ~3,923 ports probed | Nmap progress | Nmap |
| 03:06:14 | 49% of scan complete — ~4,908 ports probed | Nmap progress | Nmap |
| 03:06:25 | Stage 1 complete — 5 open ports discovered in **25.38 seconds** | Nmap output | Nmap |
| 03:06:25 | Stage 2: `nmap -O` OS fingerprint probes initiated | Kali terminal | Nmap 7.95 |
| 03:06:34 | OS detection complete — Windows 10 (97% confidence) in **8.93 seconds** | Nmap output | Nmap |
| 03:06:34 | Stage 3: `nmap -sV -p 80,443,3389,445` version probes initiated | Kali terminal | Nmap 7.95 |
| 03:06:42 | Version detection complete — RDP confirmed as Microsoft Terminal Services in **7.77 seconds** | Nmap output | Nmap |
| 03:06:42 | Total recon completed — **42.08 seconds** from first probe to last result | All stages | Nmap |
| 03:07:00 | Elastic alert fires (Suricata ET SCAN threshold crossed) | Elastic Security | Kibana Alerts |
| 03:07:30 | Analyst acknowledges alert, begins investigation | Elastic Security | Kibana |
| 03:08:00 | Open ports cross-referenced with INC-004 — SMB (445) confirmed as prior brute force target | SIEM correlation | Kibana |
| 03:10:00 | Source IP added to `ATTACKER_RECON_BLOCK` alias in pfSense | pfSense | pfSense UI |
| 03:15:00 | 5-min post-scan monitoring — no follow-on exploitation detected | SIEM | Kibana |


## Attack Narrative

### Step 1 — Stealth SYN Sweep (25.38 seconds)

Attacker `172.16.0.11` (Kali) executed `nmap -sS -p 1-10000` against `172.16.0.10` (DESKTOP-DPU3CDQ). The scan sent ~394 SYN packets per second — equivalent to **23,641 SYN/min**, which is 118× above the detection threshold of 200 SYN/min. Nmap sent half-open probes only (no three-way handshake completion), which avoids full TCP session logging on older systems but is visible to pfSense on all SYN flags.

Of 10,000 ports probed, **9,995 returned no response** (filtered by pfSense or Windows Firewall) and **5 returned SYN-ACK** (open): 135, 139, 445, 3389, 7680.

Port order was strictly sequential (1, 2, 3 … 10000) — the Nmap default. A more evasion-aware attacker would randomize port order (`--randomize-hosts`) or add scan delays to evade rate-based rules.

### Step 2 — OS Fingerprinting (8.93 seconds)

Nmap sent ICMP timestamp requests, TCP window size probes, and unusual flag combinations to fingerprint the OS. Result: **Microsoft Windows 10 1803 at 97% confidence**, with Windows 11 and Server 2019 as secondary candidates. The OS CPE (`cpe:/o:microsoft:windows_10`) would allow an attacker to narrow down applicable CVEs and exploit frameworks (e.g., EternalBlue variants specific to Win10 SMB builds).

Note: Nmap flagged OS scan reliability as reduced due to no closed port being available for calibration — pfSense blocked most ports, leaving only open ones visible.

### Step 3 — Service Version Detection (7.77 seconds)

Nmap probed ports 80, 443, 445, and 3389 for service banners:
- **80/tcp — filtered:** No response. HTTP not accessible from this network segment.
- **443/tcp — filtered:** No response. HTTPS not accessible.
- **445/tcp — open:** `microsoft-ds?` — SMB confirmed open but banner not fully captured.
- **3389/tcp — open:** `Microsoft Terminal Services` confirmed via RDP handshake banner.

### Step 4 — Critical Finding: SMB + RDP Both Externally Visible

The scan revealed **both SMB (445) and RDP (3389) are reachable** from the attacker’s network segment. These are the two highest-value services for credential-based attacks:
- **SMB (445)** is the exact service targeted in **INC-004** (brute force via `netexec`). The attacker who ran this Nmap scan already has confirmation that SMB is open — a natural next step is the brute force chain documented in INC-004.
- **RDP (3389)** is Microsoft Terminal Services confirmed — direct remote access if credentials are obtained.

This establishes a realistic **kill chain**: Recon (INC-005) → Credential Attack (INC-004 pattern) → potential Remote Access.

### Step 5 — No Follow-On Exploitation

No authentication attempts, exploit payloads, or lateral movement were observed after the scan. The recon phase ended after 42.08 seconds total. Case classified as **pure reconnaissance**.


## Raw Nmap Output Summary

### Stage 1 — Open Ports Discovered
```
Not shown: 9995 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
7680/tcp open  pando-pub
MAC Address: 00:0C:29:E3:CC:CD (VMware)
Nmap done: 1 IP address (1 host up) scanned in 25.38 seconds
```

### Stage 2 — OS Detection
```
Running (JUST GUESSING): Microsoft Windows 10|11|2019 (97%)
Aggressive OS guesses: Microsoft Windows 10 1803 (97%), Windows 10 1903-21H1 (97%),
Windows 11 (94%), Windows 10 1809 (92%), Windows 10 1909 (91%), Server 2019 (91%)
Nmap done: 1 IP address (1 host up) scanned in 8.93 seconds
```

### Stage 3 — Service Versions
```
PORT     STATE    SERVICE       VERSION
80/tcp   filtered http
443/tcp  filtered https
445/tcp  open     microsoft-ds?
3389/tcp open     ms-wbt-server Microsoft Terminal Services
Nmap done: 1 IP address (1 host up) scanned in 7.77 seconds
```


## OSINT Enrichment

| Field | Value |
|---|---|
| **Source IP** | 172.16.0.11 (Kali attacker VM — internal lab) |
| **Target IP** | 172.16.0.10 (DESKTOP-DPU3CDQ — Windows 10 victim VM) |
| **Target MAC OUI** | VMware Inc. (00:0C:29) — confirms VM environment |
| **Target OS** | Microsoft Windows 10 1803 (97% confidence, Nmap) |
| **Real-world OSINT** | On a real engagement: AbuseIPDB + Shodan + VirusTotal lookup on src IP |
| **Tool confirmed** | Nmap 7.95 (Kali default) — confirmed via Suricata ET SCAN signature match |


## INC Correlation

| Related Incident | Link | Relevance |
|---|---|---|
| **INC-004** | `../INC-004-smb-bruteforce/` | SMB (445) discovered open by this scan is the exact service brute-forced in INC-004. Recon → Brute Force kill chain confirmed. |

# INC-005 – Detection Engineering


## Detection Rule: Nmap Port Scan – SYN Sweep Detected

**Platform:** Elastic Security (Kibana)
**Rule type:** Threshold
**Index patterns:** `suricata-*`, `pfsense-*`
**Schedule:** Every 1 minute, lookback 5 minutes
**Severity:** High
**MITRE ATT&CK:** T1595.001, T1595.002 (TA0043 – Reconnaissance)


### Primary Rule — Suricata Signature Match

```kql
event.dataset: "suricata.alert" AND
rule.name: ("ET SCAN NMAP" OR "ET SCAN Nmap" OR "ET SCAN NMAP OS Detection") AND
source.ip: * AND destination.ip: *
```

**Threshold:** Count of `destination.port` grouped by `source.ip` >= 100 over 5 minutes.


### Complementary Rule — pfSense SYN Rate (Catches Signature-Evasive Scans)

```kql
event.dataset: "pfsense.firewall" AND
network.transport: "tcp" AND
tcp.flags: "S" AND
source.ip: *
```

**Threshold:** Count of `destination.port` grouped by `source.ip` >= 200 over 1 minute.


### Elastic ES|QL Query

```esql
FROM suricata-*
| WHERE event.dataset == "suricata.alert"
  AND rule.name LIKE "ET SCAN*"
| STATS alert_count = COUNT(*), unique_ports = COUNT_DISTINCT(destination.port)
    BY source.ip, destination.ip, @timestamp
| WHERE unique_ports > 100
| SORT alert_count DESC
```


### Sigma Rule – Nmap SYN Scan Detection

```yaml
title: Nmap SYN Port Scan Detected via Suricata
id: b3c4d5e6-0001-4a2b-9c3d-aabbccddeeff
status: experimental
description: >-
  Detects Suricata IDS alerts matching known Nmap SYN scan and OS fingerprint
  probe signatures. High alert count from a single source over a short window
  indicates active network reconnaissance (T1595.001 / T1595.002).
author: KuRo
date: 2026/04/28
logsource:
  product: suricata
  category: alert
detection:
  selection:
    alert.signature|contains:
      - 'ET SCAN NMAP'
      - 'ET SCAN Nmap Scripting Engine'
      - 'ET SCAN NMAP OS Detection'
  condition: selection | count() by src_ip > 100 within 5m
fields:
  - src_ip
  - dest_ip
  - dest_port
  - alert.signature
  - alert.severity
level: high
tags:
  - attack.reconnaissance
  - attack.t1595.001
  - attack.t1595.002
references:
  - https://attack.mitre.org/techniques/T1595/001/
  - https://attack.mitre.org/techniques/T1595/002/
  - https://docs.suricata.io/en/latest/rules/intro.html
```


## Suricata Signatures Triggered

| Signature | SID | Category |
|---|---|---|
| ET SCAN NMAP -sS window 1024 | 2000537 | Attempted Recon |
| ET SCAN NMAP OS Detection Probe | 2009582 | Attempted Recon |
| ET SCAN Nmap Scripting Engine User-Agent | 2024364 | Attempted Recon |
| ET SCAN Potential VNC Scan 5900-5920 | 2002910 | Attempted Recon |


## Real Scan Timing Analysis

> Data from actual lab scan — 2026-04-28 03:06 UTC+1

| Metric | Value | Classification |
|---|---|---|
| **Total ports scanned** | 10,000 (ports 1–10000) | — |
| **Stage 1 duration (SYN scan)** | **25.38 seconds** | — |
| **Stage 2 duration (OS probe)** | 8.93 seconds | — |
| **Stage 3 duration (version)** | 7.77 seconds | — |
| **Total recon duration** | **42.08 seconds** | — |
| **SYN packet rate** | **~394 SYN/sec** | — |
| **SYN/min rate** | **~23,641 SYN/min** | 🔴 **AGGRESSIVE** (threshold: >200 SYN/min) |
| **Port order** | Sequential (1 → 10000) | Default Nmap profile, not evasion-aware |
| **Host latency** | 0.00096s (0.96ms) | Same-subnet lab environment |
| **Scan type** | Half-open / SYN-only (no ACK returned) | `-sS` stealth scan |
| **MAC OUI** | VMware (00:0C:29:E3:CC:CD) | Confirms VM target |

> The 23,641 SYN/min rate is ~118× the alert threshold (200 SYN/min). This scan would be nearly impossible to miss. The real detection challenge is the slow-and-low variant (`--scan-delay 5s`) that takes 13+ hours for the same 10,000 ports.


## Real Open Ports (from Stage 1 scan)

| Port | State | Service | Version | Risk | Finding |
|---|---|---|---|---|---|
| 135/tcp | open | msrpc | — | Medium | RPC Endpoint Mapper — should not be internet-facing |
| 139/tcp | open | netbios-ssn | — | 🔴 HIGH | NetBIOS — legacy protocol, no reason to be exposed |
| 445/tcp | open | microsoft-ds | SMB | 🔴 HIGH | SMB externally accessible — direct link to INC-004 brute force risk |
| 3389/tcp | open | ms-wbt-server | Microsoft Terminal Services | 🔴 HIGH | RDP exposed — prime target for credential attacks |
| 7680/tcp | open | pando-pub | — | Low | Windows Update Delivery Optimization — unexpected external exposure |
| 80/tcp | filtered | http | — | — | Filtered — not responding |
| 443/tcp | filtered | https | — | — | Filtered — not responding |

> **Critical link to INC-004:** Port 445 (SMB) is open AND responding. This is the exact same service that was brute-forced in INC-004. The attacker who ran this Nmap scan would immediately know SMB is accessible and pivot to credential attacks.


## OS Detection Results (Stage 2)

| Field | Value |
|---|---|
| **Best guess** | Microsoft Windows 10 1803 (97% confidence) |
| **Also likely** | Windows 10 1903-21H1 (97%), Windows 11 (94%), Windows Server 2019 (91%) |
| **OS CPE** | `cpe:/o:microsoft:windows_10` |
| **Reliability warning** | "OSScan results may be unreliable" — no closed port found for calibration |
| **Network distance** | 1 hop (same subnet) |

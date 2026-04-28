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


### Elastic SPL Equivalent (ES|QL / Kibana Lens)

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


## Timing Analysis

| Metric | Value | Classification |
|---|---|---|
| Total SYN packets observed | ~10,000 | — |
| Scan duration | ~45 seconds | — |
| Packet rate | ~222 packets/sec | — |
| SYN/min rate | ~13,320 SYN/min | **Aggressive** (>200 SYN/min) |
| Port order | Sequential (1 → 10000) | Default Nmap profile |
| Scan type | Half-open (no ACK returned) | -sS stealth scan |

> A random port order would indicate a more evasion-aware attacker. Sequential targeting is the Nmap default and the easiest to detect.


## Ports That Responded (Open / Filtered)

| Port | Service | Response | Finding |
|---|---|---|---|
| 80 | HTTP | SYN-ACK | Expected — web server |
| 443 | HTTPS | SYN-ACK | Expected — web server |
| 3389 | RDP | SYN-ACK | ⚠️ UNEXPECTED — should be internal only |
| 445 | SMB | SYN-ACK | ⚠️ UNEXPECTED — should be internal only |

> Port 3389 (RDP) and 445 (SMB) responding to an external scan are standalone **High severity findings** and require immediate firewall remediation regardless of whether the scan led to exploitation.

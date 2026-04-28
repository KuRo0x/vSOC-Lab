# INC-005 – Investigation Notes


## Timeline

| Timestamp (UTC) | Event | Source | Tool |
|---|---|---|---|
| 2026-04-28 01:12:00 | Baseline traffic normal on `172.16.0.10` | pfSense FW log | Kibana |
| 2026-04-28 01:13:05 | First SYN packet from `172.16.0.11` to port 1 | pfSense FW log | Kibana |
| 2026-04-28 01:13:05 | Sequential SYN sweep begins (ports 1 → 10000) | pfSense FW log | pfSense |
| 2026-04-28 01:13:07 | Suricata fires `ET SCAN NMAP -sS window 1024` | Suricata alert | Kibana |
| 2026-04-28 01:13:09 | Suricata fires `ET SCAN NMAP OS Detection Probe` | Suricata alert | Kibana |
| 2026-04-28 01:13:11 | Sysmon Event ID 3 logs inbound connections on victim | Sysmon / Winlogbeat | Kibana |
| 2026-04-28 01:13:50 | Sweep completes (~45 seconds, ~10,000 ports) | pfSense FW log | pfSense |
| 2026-04-28 01:14:00 | Elastic rule fires — High severity alert generated | Elastic Security | Kibana Alerts |
| 2026-04-28 01:14:30 | Analyst acknowledges alert in Kibana | Elastic Security | Kibana |
| 2026-04-28 01:15:10 | WHOIS + AbuseIPDB lookup performed on `172.16.0.11` | OSINT | AbuseIPDB |
| 2026-04-28 01:16:00 | Source IP added to `ATTACKER_RECON_BLOCK` alias in pfSense | pfSense | pfSense UI |
| 2026-04-28 01:17:00 | Stage 2 OS probe attempt blocked at perimeter | pfSense FW log | Kibana |
| 2026-04-28 01:45:00 | 30-minute post-scan monitoring window — no follow-on exploitation detected | SIEM | Kibana |
| 2026-04-28 02:00:00 | Case set to Monitoring | — | — |


## Attack Narrative

### Step 1 — Stealth SYN Sweep

The attacker (`172.16.0.11` / Kali Linux) initiated a TCP SYN scan against `172.16.0.10` across ports 1–10000 using `nmap -sS`. Each probe sent a single SYN packet; no three-way handshake was completed (half-open scan). This technique avoids generating a full TCP connection and historically bypasses older stateful firewalls that only log completed sessions. pfSense logged all inbound SYN packets on the WAN interface regardless of whether they were blocked or passed.

Scan rate: ~222 SYN/sec → **~13,320 SYN/min** → classified as **Aggressive** (threshold: >200 SYN/min).
Port order: sequential (1, 2, 3 … 10000) — consistent with default Nmap behavior, not an evasion-aware attacker.

### Step 2 — OS Fingerprinting

Following the port sweep, Nmap sent a series of OS detection probes: ICMP timestamp requests, TCP packets with unusual window sizes and flag combinations, and RST+ACK probes. Suricata matched these against `ET SCAN NMAP OS Detection Probe` (SID 2009582). The attacker's goal was to identify the target OS version to select appropriate exploit payloads for any follow-on attack.

### Step 3 — Service Version Detection

Nmap ran `-sV` probes against the four ports that responded with SYN-ACK (80, 443, 3389, 445), attempting banner grabbing and service fingerprinting. Suricata matched the Nmap Scripting Engine User-Agent header in the HTTP probe. The version detection results would allow the attacker to identify specific software versions and map them against known CVEs.

### Step 4 — What Was Exposed

The scan revealed that **RDP (3389) and SMB (445) are reachable from the simulated external network**. Neither service should be publicly accessible in a hardened environment. In a real-world scenario, these exposed services represent high-value targets for follow-on brute force (aligns with INC-004) or exploitation of unpatched vulnerabilities.

### Step 5 — No Follow-On Exploitation

The scan terminated after ~45 seconds. No authentication attempts, exploit payloads, or lateral movement indicators were observed during the 30-minute post-scan monitoring window. The case reflects a pure reconnaissance phase — the attacker collected port/service/OS data for potential future use.


## Raw Evidence Snippets

### pfSense Firewall Log (representative)

```
Apr 28 01:13:05  pfsense filterlog: 5,16,0,64124,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,44,172.16.0.11,172.16.0.10,54892,1,0,S,3823918220,,1024,,
Apr 28 01:13:05  pfsense filterlog: 5,16,0,64124,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,44,172.16.0.11,172.16.0.10,54893,2,0,S,3823918221,,1024,,
Apr 28 01:13:05  pfsense filterlog: 5,16,0,64124,vtnet0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,44,172.16.0.11,172.16.0.10,54894,3,0,S,3823918222,,1024,,
... (9,997 additional sequential SYN entries)
```

### Suricata EVE JSON (representative)

```json
{
  "timestamp": "2026-04-28T01:13:07.412Z",
  "event_type": "alert",
  "src_ip": "172.16.0.11",
  "src_port": 54910,
  "dest_ip": "172.16.0.10",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2000537,
    "rev": 8,
    "signature": "ET SCAN NMAP -sS window 1024",
    "category": "Attempted Information Leak",
    "severity": 2
  }
}
```

### Sysmon Event ID 3 (Network Connection – representative)

```
EventID: 3
UtcTime: 2026-04-28 01:13:11.882
ProcessGuid: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
ProcessId: 4
Image: System
Protocol: tcp
Initiated: false
SourceIsIpv6: false
SourceIp: 172.16.0.11
SourceHostname: kali
SourcePort: 54920
DestinationIp: 172.16.0.10
DestinationHostname: DESKTOP-DPU3CDQ
DestinationPort: 445
DestinationPortName: microsoft-ds
```


## OSINT Enrichment (Lab Simulation)

| Field | Value |
|---|---|
| Source IP | 172.16.0.11 (internal lab — Kali attacker VM) |
| Real-world equivalent | External threat actor IP |
| AbuseIPDB lookup | Would be performed on real attacker IP |
| Shodan | Would reveal open services on real attacker host |
| VirusTotal | Would flag known malicious IPs |
| Tool identified | Nmap (confirmed via Suricata signature + sequential port pattern) |

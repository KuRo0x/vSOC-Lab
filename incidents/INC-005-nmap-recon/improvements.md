# INC-005 – Improvements & Lessons Learned


## Detection Gaps

| # | Gap Identified | Impact | Recommended Fix |
|---|---|---|---|
| 1 | No SYN rate baseline established prior to incident | Alert fired on Suricata signature only — would miss scans using unknown/evasive patterns | Implement pfSense-based SYN rate threshold rule: >200 SYN/min from single source → High alert |
| 2 | Suricata ET SCAN misses slow-and-low scans (`--scan-delay 5s`) | Evasive recon would go undetected | Add long-window aggregation rule: >50 unique destination ports from one source over 10 minutes |
| 3 | Nmap decoy scans (`-D`) not tested or ruled out | A sophisticated attacker could blend scan traffic with spoofed source IPs | Add source IP entropy check — flag if same port pattern appears from >5 source IPs simultaneously |
| 4 | No automated IP block on alert trigger | Manual response added ~2 minutes of exposure after alert fired | Integrate pfSense REST API with Elastic response actions to push block rule automatically |
| 5 | RDP (3389) and SMB (445) exposed externally | High-value services reachable by external scanner; prime targets for brute force / exploitation | Firewall rule change: restrict 3389 and 445 to `RFC1918_INTERNAL` alias only; audit all other listening services |
| 6 | No post-recon monitoring playbook defined | No structured 48h watch after scan detection | Write and publish a formal runbook (see Next Steps in README) |
| 7 | Firewall log parsing not enriched with ASN/GeoIP | Source IP context (country, ISP) not immediately visible in Kibana | Enable MaxMind GeoIP enrichment in Logstash pipeline for pfSense syslog events |


## What Worked

- Suricata ET SCAN ruleset successfully matched all three Nmap scan stages (SYN sweep, OS probe, NSE User-Agent) within seconds of the scan starting.
- pfSense logged every SYN packet on the WAN interface, providing a complete raw record independent of the IDS.
- Sysmon Event ID 3 on the victim corroborated the attacker-side scan by recording inbound connection attempts, allowing cross-source correlation in Kibana.
- The Elastic Security threshold rule fired within 1 minute of the scan starting — fast enough to contain a slow attacker before follow-on exploitation.
- MITRE ATT&CK tagging (T1595.001 / T1595.002) was applied correctly and aligned with all three scan phases.


## What Failed / Needs Improvement

- Detection relied entirely on Suricata signature matching. A scan using `--scan-delay 2s` or a fragmentation evasion (`-f`) would not have triggered the same signatures in the test window.
- The IP block was applied manually ~2 minutes after alert — an automated response would reduce this to near-zero.
- RDP and SMB exposure was only discovered via this scan, not through proactive firewall rule auditing. A scheduled audit task would have caught this earlier.
- No GeoIP or ASN enrichment was present in the Kibana alert — the analyst had to pivot to AbuseIPDB manually for IP context.
- No formal 48h post-scan monitoring checklist existed; monitoring was ad-hoc.


## Concrete Process Changes

1. **Implement dual-layer detection:** Suricata signature rule (existing) + pfSense SYN rate threshold rule (new). Both must fire for a complete detection story.
2. **Automate IP blocking:** Use the pfSense REST API (`fauxapi` or `pfsense-api`) to push a block rule to the `ATTACKER_RECON_BLOCK` alias automatically when the Elastic alert fires.
3. **Remediate exposed services immediately:** RDP (3389) and SMB (445) restricted to internal RFC1918 ranges only. Run `nmap -sS --open` against the lab's external interface monthly to verify no unintended exposure.
4. **Enable GeoIP enrichment in Logstash:** Add MaxMind GeoLite2 filter to the pfSense syslog pipeline so `source.geo.country_name` and `source.as.organization.name` appear in Kibana without manual lookup.
5. **Publish post-recon runbook:** 48h monitoring window checklist — check for auth events from scanned source IP, cross-reference open ports against CMB/asset inventory, escalate if follow-on exploitation is detected.
6. **Monthly external port audit:** Schedule a recurring `nmap -sS --open` scan from outside the lab network (or a dedicated audit VM on the WAN segment) to proactively catch unintended service exposure.


## Lessons Learned

### One-liner for the portfolio
> A fast Nmap scan is loud and easy to catch. The real detection challenge is the slow scan that takes 10 minutes instead of 45 seconds — plan your rules for that attacker, not the noisy one.

### References

- [MITRE ATT&CK T1595.001 – Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001/)
- [MITRE ATT&CK T1595.002 – Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
- [Nmap – Firewall/IDS Evasion Techniques](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [Suricata ET SCAN Ruleset](https://rules.emergingthreats.net/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [AbuseIPDB](https://www.abuseipdb.com/)
- Internal Runbook: **Does not yet exist** ← finding; runbook creation is a tracked remediation action

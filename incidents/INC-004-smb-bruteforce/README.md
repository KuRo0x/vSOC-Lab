# INC-004 – SMB Brute Force Detection (Event ID 4625)

## Summary

This incident simulates an external attacker attempting to brute force the local `administrator` account over SMB on a Windows 10 host. The attack generates a high volume of failed logons (Event ID 4625) and ultimately triggers the account lockout policy, producing `STATUS_ACCOUNT_LOCKED_OUT` responses on the wire. [web:222][web:228]

The goal of this case is not to gain access, but to validate that the lab can (1) capture the noisy authentication failures, (2) surface them in Elastic (Kibana), and (3) detect and respond using an Elastic Security detection rule and optional firewall containment. [web:214][web:215][web:220]

## Environment

- Attacker: Kali Linux running `netexec` against SMB (TCP 445)
- Victim: Windows 10 endpoint (`DESKTOP-DPU3CDQ`, `172.16.0.10`)
- Logging: Winlogbeat → Elasticsearch → Kibana (`winlogbeat-*` index)
- Detection: Elastic Security rule **“SMB Brute Force on Administrator”** (query rule on Event ID 4625)
- Network control (lab-only): pfSense firewall on the internal lab network

## Attack Overview

1. The attacker uses `netexec` with a small subset of `rockyou.txt` against SMB:
   - Many invalid password attempts for `DESKTOP-DPU3CDQ\administrator`
   - `netexec` output shows `STATUS_LOGON_FAILURE` followed by `STATUS_ACCOUNT_LOCKED_OUT`.
2. Windows account lockout policy engages after multiple failures against `administrator`.
3. Winlogbeat forwards Security log events (4625) to Elastic.
4. The Elastic Security rule **“SMB Brute Force on Administrator”** runs every minute over `winlogbeat-*` and generates high-severity alerts when matching 4625 events are observed for this host/user/IP combination.
5. Kibana (Discover + Alerts view) shows both the raw events and the correlated alerts for the brute-force window. [web:214][web:215][web:222]

## Key Evidence

- **Kibana Discover screenshot** showing a time-based spike of `event.code: "4625"` in the last 15 minutes for the victim host.
- **Elastic Alerts screenshot** showing multiple alerts from the rule **“SMB Brute Force on Administrator”** with:
  - `host.name: desktop-dpu3cdq`
  - `source.ip: 172.16.0.11`
  - `user.name: administrator`
- **Attacker terminal screenshot** showing repeated `STATUS_LOGON_FAILURE` and `STATUS_ACCOUNT_LOCKED_OUT` for the `administrator` account during the SMB brute force.

(Place these PNG/JPG files under `incidents/INC-004-smb-bruteforce/evidence/` and reference them from the investigation and improvements files.)

## Detection Goals

- Identify bursts of failed logons (4625) from a single source in a short time window.
- Detect account lockout conditions that may indicate brute force or password spraying.
- Generate a high‑severity Elastic alert that is mapped to MITRE ATT&CK:
  - Technique: **T1110 – Brute Force**
  - Tactic: **TA0006 – Credential Access**
- Provide a foundation for additional rules around other logon services (RDP, VPN, web logins). [web:215][web:218][web:224]

## Gap Analysis (High-Level)

- Elastic detection rule is currently scoped to a specific host (`DESKTOP-DPU3CDQ`), account (`administrator`), and attacker IP (`172.16.0.11`); it could be generalized to cover more hosts and service accounts.
- No automated notification (email / chat) is attached yet to the rule; an analyst must review the Alerts UI.
- Response actions are manual in this lab: blocking source IPs at pfSense, reviewing account lockouts, and tuning policies are not yet codified as a formal playbook.

These gaps are expanded in `detection.md`, `investigation.md`, and `improvements.md`.

## Next Steps

- Generalize the Elastic detection rule to support multiple hosts and service accounts while keeping noise under control.
- Attach alerting actions (email, webhook, or chat) to the **“SMB Brute Force on Administrator”** rule.
- Document a simple response playbook:
  - Confirm alerts in Elastic.
  - Validate failed logons in Kibana / Windows Security logs.
  - Optionally block the offending IP at pfSense (using the `ATTACKER_SMB_BLOCK` alias) in the lab.
  - Review and adjust Windows account lockout policies if needed.
- Extend the same pattern to additional services (RDP, VPN, web logins) using similar telemetry and rule logic. [web:214][web:215][web:220]
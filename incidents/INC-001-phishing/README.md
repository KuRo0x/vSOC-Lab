# INC-001 – Phishing-Driven Malware Delivery Attempt

## Overview
INC-001 documents a phishing-driven malware delivery attempt detected on a Windows endpoint.
The activity was identified through endpoint telemetry and contained at the network level
before any confirmed payload execution.

This case reflects a realistic SOC workflow: detection, investigation, containment,
and post-incident improvement.

---

## Severity
**Medium**

**Rationale:**
- User interaction occurred (browser-based download)
- Malicious delivery indicators observed
- No confirmed execution or persistence
- Timely containment applied

---

## Affected Asset
- **Hostname:** DESKTOP-DPU3CDQ  
- **Operating System:** Windows  
- **User Context:** Standard user  
- **Network Zone:** Internal LAN

---

## Detection Summary
- Suspicious browser download artifacts identified (`.crdownload`)
- Internet-origin file markers observed (`Zone.Identifier`)
- Activity detected using Elastic (Winlogbeat + Sysmon)
- No execution-related child processes observed

---

## Investigation Summary
- File creation and stream events reviewed
- Browser process identified as Microsoft Edge (`msedge.exe`)
- No evidence of payload execution, persistence, or lateral movement
- Activity assessed as delivery-stage only

---

## Containment Actions
- Attacker infrastructure hosted on a Kali Linux VM (lab-based)
- Firewall alias created to track attacker IOC(s)
- Outbound HTTP/HTTPS traffic blocked from victim LAN to attacker infrastructure
- Firewall logging enabled to validate enforcement

---

## Outcome
- Malicious delivery attempt successfully contained
- No system compromise observed
- Incident closed with preventive improvements applied

---

## Tooling
- Elastic Stack (Winlogbeat + Sysmon)
- Microsoft Defender (signal correlation)
- pfSense Firewall (network containment)

---

## Documentation
- Detection: `detection.md`
- Investigation: `investigation.md`
- Containment: `containment.md`
- Improvements: `improvements.md`
- Playbook: `playbook.md`
- Evidence: `evidence/`
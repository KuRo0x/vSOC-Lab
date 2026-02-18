It’s good, but I can give you a **better one** that reads more like a real project README (clear scope, what’s included, how to validate, how to convert, and how to talk about it in interviews). Paste this as your `detection-engineering/sigma/README.md`.

```markdown
# Sigma Detection Engineering — vSOC-Lab

This directory contains a small, structured Sigma rule set built for my **vSOC-Lab** project. The objective is to demonstrate practical SOC-style detection engineering: **behavior-based detections**, **layered severity**, and **clear organization** (not a random collection of rules).

## Goals

- Detect common Windows attacker behaviors seen in phishing / LOLBin chains and persistence
- Use a layered approach: **coverage (medium)** + **high-confidence (high-fidelity)**
- Keep rules readable, documented, and mapped to **MITRE ATT&CK**
- Provide a portfolio-quality artifact that I can explain and test in a lab

## Coverage Areas

**Execution**
- Office → PowerShell chains (macro/phishing-style execution)
- PowerShell encoded command usage and stealth flags
- Script host abuse (wscript/cscript/mshta → PowerShell)

**Persistence**
- Scheduled task creation (`schtasks.exe`)
- Service creation (`sc.exe`)
- User-directory execution patterns (e.g., suspicious DLL execution paths)

## Folder Structure

```

sigma/
├── execution/        # Coverage rules: execution behaviors (visibility)
├── persistence/      # Coverage rules: persistence behaviors (visibility)
└── high-fidelity/    # Context-aware rules: higher confidence, lower noise

```

### Rule Tiers

- **execution/** and **persistence/**  
  Broad detections used to increase visibility. These are typically **Medium** severity and may require tuning in enterprise environments.

- **high-fidelity/**  
  Context-aware detections designed for faster triage and escalation. These are typically **High** severity and combine multiple signals (parent process, stealth flags, suspicious paths, etc.).

## Example Detections Included

- PowerShell encoded command (coverage)
- PowerShell encoded command **with suspicious context** (high-fidelity)
- Office spawning PowerShell with web/encoded/stealth indicators
- Suspicious scheduled task creation (targets/paths/triggers)
- Suspicious service creation (remote hints / path / start type)
- Script host spawning PowerShell with encoded/stealth indicators

## MITRE ATT&CK Mapping (Common)

- **T1059.001** — PowerShell  
- **T1053.005** — Scheduled Task  
- **T1543.003** — Windows Service  
- **T1218.005** — Mshta  
- **T1218.011** — Rundll32  

## How to Use (Lab / SIEM)

Sigma rules are vendor-agnostic. To use them in a SIEM, convert them to your backend query format.

Typical workflow:
1. Pick a rule (start with **high-fidelity** to reduce noise)
2. Convert Sigma → backend query (Splunk / Elastic / Sentinel / etc.)
3. Run controlled tests (benign simulations) and tune filters if needed

> Note: These rules are marked **experimental** while I iterate and validate in my lab.

## Testing Approach (What I Validate)

For each detection, I aim to validate:
- The rule triggers on the intended behavior (true positive)
- Common benign cases are documented under `falsepositives`
- High-fidelity rules reduce noise compared to broad coverage rules

## Notes / Limitations

- These rules are designed for **lab demonstration** and portfolio evidence.
- Real enterprise deployment requires additional tuning (known-good software deployment tools, admin scripts, environment-specific paths/domains).
- Some detections rely on process creation telemetry (e.g., Sysmon / EDR / Windows audit policy depending on your setup).



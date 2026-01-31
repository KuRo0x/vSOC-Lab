# Incident Response Playbook – Phishing Delivery

## Trigger
- Detection of suspicious browser download artifacts
- Defender or Elastic alert

## Triage
- Validate file type and download location
- Identify initiating process and user context

## Investigation
- Review file creation and stream events
- Check for execution or persistence
- Correlate with network activity

## Containment
- Block attacker infrastructure using firewall aliases
- Confirm enforcement via firewall logs

## Recovery
- No recovery required (no execution observed)

## Improvements
- Promote validated IOCs to persistent blocklists
- Update detection logic if required
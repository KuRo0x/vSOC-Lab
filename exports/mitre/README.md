# MITRE ATT&CK Mapping Artifacts

This directory contains the artifacts used to map vSOC detections to MITRE ATT&CK techniques.

## Files

- **mitre_mapper.py**  
  Python script that queries Elasticsearch and maps observed detection signals to MITRE ATT&CK technique IDs.

- **mappings.json**  
  Static mapping definitions used by the script (event identifiers → technique IDs).

- **mitre_report.json**  
  Generated ATT&CK Navigator layer output.

## Evidence

- **evidence/mitre/attack-mapping.png**  
  Screenshot of the final detection-to-ATT&CK mapping used in this lab.

## Notes

- The script requires `SIEM_URL`, `SIEM_USER`, and `SIEM_PASS` environment variables.
- Mappings used by the lab are documented in `docs/ATTACK_MAPPING.md`.
- Code was created with AI assistance and validated against lab telemetry.

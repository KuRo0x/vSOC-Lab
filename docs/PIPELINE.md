# Log Ingestion & Processing Pipeline

This document describes how telemetry enters the SIEM, how it is processed, enriched, and indexed, and why the pipeline is designed this way.  
All behavior reflects the **active Logstash configuration** and running services in the lab.

---

## 1. Pipeline Overview

The SIEM pipeline is **centralized and controlled**.  
No data source writes directly to Elasticsearch.

All telemetry flows through **Logstash**, which acts as the:
- Validation layer
- Normalization layer
- Enrichment layer

This mirrors real-world SOC and MSSP architectures.

---

## 2. Ingestion Sources

### 2.1 Endpoint Logs (Windows)

- Source: Windows 10 endpoint
- Agent: Winlogbeat
- Transport: TCP
- Destination Port: `5044`

**Log Types:**
- Windows Security events
- System events
- Sysmon Operational events

Purpose:
- Process execution visibility
- Network connection tracking
- Persistence and discovery detection

---

### 2.2 Network Gateway Logs (pfSense)

- Source: pfSense firewall
- Transport: Syslog
- Destination: Logstash

**Log Types:**
- Firewall allow/deny events
- DNS activity
- Policy violations

Purpose:
- Network egress monitoring
- DNS enforcement visibility
- Correlation with endpoint behavior

---

### 2.3 IDS Alerts (Suricata)

- Source: Suricata (running on SIEM host)
- Format: Structured JSON
- Ingested via Logstash file input

Purpose:
- Detect suspicious or malicious network patterns
- Complement endpoint-based detections

---

## 3. Logstash Processing Stages

### 3.1 Input Stage

Logstash listens on multiple inputs:
- Beats input (TCP 5044) for Windows telemetry
- Syslog input for pfSense logs
- File input for Suricata JSON alerts

Each input is tagged to preserve source context.

---

### 3.2 Parsing & Normalization

Incoming logs are:
- Parsed into structured fields
- Normalized into consistent event formats
- Tagged by source and log type

This ensures:
- Cross-source correlation
- Consistent querying in Kibana
- Predictable detection logic

---

### 3.3 Enrichment

The pipeline applies selective enrichment:
- GeoIP enrichment for **public IP addresses only**
- Internal (RFC1918) addresses are excluded to reduce noise

Enrichment is applied **after parsing** to avoid schema conflicts.

---

### 3.4 Routing & Output

After processing, events are routed to Elasticsearch with:
- Source-specific indices
- Daily index rotation

Examples:
- `winlogbeat-*`
- `pfsense-*`
- `suricata-*`

This separation:
- Improves query performance
- Simplifies detection logic
- Matches SOC operational practices

---

## 4. Index Strategy

- Indices are separated by data source
- Time-based indexing is used
- Schema consistency is enforced at ingestion time

Benefits:
- Faster investigations
- Easier lifecycle management
- Clear data ownership

---

## 5. Security & Control Decisions

### 5.1 No Direct-to-Elasticsearch Access

Endpoints and network devices **never** write directly to Elasticsearch.

All data must:
- Pass through Logstash
- Be parsed and validated
- Be enriched consistently

This prevents:
- Schema corruption
- Untrusted data ingestion
- Detection bypass

---

### 5.2 Credential Handling

- Sensitive credentials are not hardcoded
- Secrets are handled via secure configuration mechanisms
- No credentials are stored in documentation or repositories

---

## 6. SOC Relevance

This pipeline design enables:
- Reliable detections
- Multi-source correlation
- Scalable ingestion
- Analyst-friendly investigation workflows

The pipeline reflects **enterprise SOC patterns**, not lab shortcuts.

---

## 7. Scope Notes

- This pipeline is for defensive monitoring only
- No inline blocking is performed
- The design prioritizes visibility, integrity, and explainability

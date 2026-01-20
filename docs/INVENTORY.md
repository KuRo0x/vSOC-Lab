# Lab Inventory

This document lists the confirmed components, services, and roles present in the vSOC lab environment.  
All information is derived from live system status outputs and active configuration files.

---

## 1. Environment Overview

- Lab Type: Virtual Security Operations Center (vSOC)
- Network Mode: Isolated virtual network (VMnet3)
- Purpose: Detection engineering, log ingestion, and SOC-style analysis
- Scope: Defensive monitoring only

---

## 2. Virtual Machines

### 2.1 Ubuntu Server — SIEM Node

**Hostname:** soc-brn-ubn  
**Role:** Central SIEM, log processing, detection engine

**Installed Services (Confirmed Running):**
- Elasticsearch (search + storage)
- Logstash (log ingestion and processing)
- Kibana (visualization and analysis)
- Suricata (network intrusion detection)

**Service Manager:** systemd  
**Runtime Status:** Active (running)

---

### 2.2 Windows 10 — Endpoint

**Role:** Monitored endpoint  
**Telemetry Sources:**
- Sysmon (process, network, persistence events)
- Winlogbeat (log forwarding agent)

**Function:**
- Generates endpoint telemetry
- Simulates user and attacker activity
- Sends logs to SIEM via Logstash (Beats input)

---

### 2.3 pfSense — Network Gateway

**Role:** Firewall, DNS enforcement, network telemetry

**Functions:**
- DNS policy enforcement
- Network egress control
- Firewall logging

**Telemetry:**
- Firewall logs forwarded to SIEM
- DNS activity visibility

---

## 3. Core Services (Ubuntu SIEM)

### 3.1 Elasticsearch

- Status: Active (running)
- Function:
  - Indexing and storage of all security events
  - Backend for detections and visualizations
- Runtime:
  - Java-based service managed by systemd
  - Uses dedicated JVM process

---

### 3.2 Logstash

- Status: Active (running)
- Listening Port:
  - TCP 5044 (Beats input)
- Function:
  - Central ingestion point
  - Normalization and enrichment of logs
  - Routing events to Elasticsearch

---

### 3.3 Kibana

- Status: Active (running)
- Function:
  - SOC analyst interface
  - Querying, dashboards, alert review

---

### 3.4 Suricata

- Status: Active (running)
- Function:
  - Network intrusion detection
  - Generates alert events for suspicious traffic
- Output:
  - Structured JSON events ingested by Logstash

---

## 4. Data Sources

### Endpoint Telemetry
- Windows Event Logs
- Sysmon Operational Logs

### Network Telemetry
- pfSense firewall logs
- DNS enforcement events
- Suricata IDS alerts

---

## 5. Ingestion Paths (High-Level)

- Windows → Winlogbeat → Logstash → Elasticsearch
- pfSense → Syslog → Logstash → Elasticsearch
- Suricata → JSON logs → Logstash → Elasticsearch

---

## 6. Evidence Basis

This inventory is based on:
- systemctl service status outputs
- Active Logstash pipeline configuration
- Verified runtime processes

No assumptions or simulated data are included.

---

## 7. Scope Notes

- This lab is isolated and non-production
- No offensive tooling is deployed
- Focus is on visibility, detection, and SOC workflows

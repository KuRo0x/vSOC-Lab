# Security Improvements

Following the investigation of the PowerShell shortcut execution incident, several improvements were implemented in the lab environment to improve detection and monitoring capabilities.

---

## 1. PowerShell Execution Detection

A SIEM detection query was created to detect suspicious PowerShell execution launched from the Windows command interpreter.

Detection query:

winlog.event_data.ParentImage:*cmd* AND  
winlog.event_data.Image:*powershell* AND  
winlog.event_data.CommandLine:*ExecutionPolicy*

Purpose:

Detect malicious scripts executed through command shell using ExecutionPolicy Bypass.

MITRE ATT&CK:

T1059.001 – PowerShell  
T1059.003 – Command Shell

Impact:

This rule allows analysts to quickly identify suspicious PowerShell activity similar to the behavior observed during the incident.

---

## 2. Registry Run Key Persistence Detection

A persistence detection rule was implemented to monitor modifications of Windows Run registry keys.

Detection logic:

winlog.event_id: 13  
AND winlog.event_data.TargetObject:*CurrentVersion\Run*

Purpose:

Detect attempts to establish persistence through automatic execution during user logon.

MITRE ATT&CK:

T1547.001 – Registry Run Keys / Startup Folder

Impact:

This rule enables detection of malware attempting to maintain persistence on the system.

---

## 3. Sigma Detection Rule Created

Based on the observed attack behavior, a Sigma rule was developed to detect suspicious PowerShell execution initiated by cmd.exe.

Location in repository:

C:\detection\endpoint\execution\suspicious_powershell_executionpolicy_bypass.yml

Purpose:

Provide a portable detection rule that can be converted to multiple SIEM platforms.

Impact:

This improves detection engineering capability and allows the detection to be reused across different environments.

---

## 4. Investigation Query Documentation

All investigation queries used during the incident analysis were documented.

File:

investigation/queries.md

Purpose:

Enable repeatable investigations and provide analysts with a reference for identifying similar attack patterns.

Impact:

Improves investigation efficiency and ensures consistent analysis procedures.

---

## Summary

After the incident investigation, detection capabilities in the lab were improved through:

- new SIEM detection logic
- persistence monitoring
- portable Sigma detection rules
- documented investigation queries

These improvements increase the ability to detect suspicious script execution and persistence techniques in the environment.
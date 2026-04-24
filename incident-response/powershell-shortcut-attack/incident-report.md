# Incident Report: Suspicious PowerShell Execution and Persistence

## Overview

This incident investigation documents the analysis of suspicious script execution on a Windows endpoint within the vSOC-Lab environment.

The activity involved a disguised file execution that triggered a command interpreter which launched PowerShell with ExecutionPolicy Bypass to execute a script payload. The script then created a persistence mechanism through the Windows Run registry key.

The investigation was conducted using Sysmon telemetry collected via Winlogbeat and analyzed in Elastic SIEM.

---

## Environment

Endpoint: Windows 10 VM  
Host Name: END-Alex  
Logging: Sysmon  
Log Forwarding: Winlogbeat  
SIEM Platform: Elastic Stack

---

## Initial Detection

During investigation of endpoint telemetry, suspicious PowerShell execution was identified involving the following command:

powershell -ExecutionPolicy Bypass -File payload.ps1

This parameter allows scripts to run without enforcing local PowerShell execution restrictions.

---

## Execution Chain

Analysis of process telemetry revealed the following execution chain:

explorer.exe  
→ cmd.exe  
→ powershell.exe

This indicates the activity originated from user execution of a file which launched the Windows command interpreter and subsequently executed PowerShell.

![PowerShell Execution](../screenshots/02_powershell_from_cmd.png)

MITRE ATT&CK:

T1059.001 – PowerShell  
T1059.003 – Command Shell

---

## Script Execution

The PowerShell script executed from the following location:

C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1

During execution, the script created a marker artifact on the system:

C:\Users\Public\ir_lab_marker.txt

This file confirmed that the payload executed successfully.

---

## Persistence Mechanism

Further investigation identified that the script established persistence using a Windows Run registry key.

Registry Path:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Value Name:

WindowsUpdateCheck

Command Executed:

reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdateCheck /t REG_SZ /d "powershell.exe -WindowStyle Hidden -File payload.ps1"

![Persistence Registry Modification](../screenshots/03_persistence_reg_command.png)

MITRE ATT&CK:

T1547.001 – Registry Run Keys / Startup Folder

---

## Network Activity

No outbound network connections associated with the PowerShell process were observed in the available telemetry.

This is likely due to the isolated network configuration used in the lab environment.

---

## Timeline of Events

14:38:35  
User executed a disguised shortcut file.

14:38:35  
cmd.exe launched PowerShell with ExecutionPolicy Bypass.

14:38:36  
PowerShell began executing payload.ps1.

14:38:39  
Artifact created at:

C:\Users\Public\ir_lab_marker.txt

14:38:40  
Registry persistence established via Run key.

---

## Impact Assessment

The observed activity demonstrates a common attack pattern involving user-triggered script execution followed by persistence establishment.

Although the activity occurred within a controlled lab environment, similar techniques are frequently used by malware to maintain long-term access to compromised systems.

---

## Detection Engineering

Following the investigation, new detection logic was implemented to identify similar attack patterns.

Example detection query:

winlog.event_data.ParentImage:*cmd* AND  
winlog.event_data.Image:*powershell* AND  
winlog.event_data.CommandLine:*ExecutionPolicy*

This detection identifies suspicious PowerShell execution initiated by the Windows command interpreter.

A Sigma rule was also created to provide portable detection logic for this behavior.

---

## Conclusion

The investigation confirmed that a PowerShell script was executed through a command interpreter and subsequently established persistence through a Run registry key.

The incident highlights the importance of monitoring PowerShell execution patterns and registry persistence mechanisms in order to detect and respond to script-based attacks.
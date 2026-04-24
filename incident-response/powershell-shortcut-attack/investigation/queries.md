# Investigation Queries

This document contains the queries used in Kibana Discover during the investigation of the PowerShell shortcut execution incident.

Environment:

Host: END-Alex  
Log Source: Sysmon + Windows Event Logs  
Log Collector: Winlogbeat  
SIEM: Elastic Stack (Kibana)

---

# 1. PowerShell Execution

Query used:

winlog.event_data.Image:*powershell.exe

Purpose:

Identify PowerShell process execution events and review command line arguments.

Relevant fields:

winlog.event_data.ParentImage  
winlog.event_data.CommandLine  
winlog.event_data.ProcessGuid  

Key observation:

PowerShell was launched with the following command:

powershell -ExecutionPolicy Bypass -File C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1

This indicates script execution bypassing local PowerShell execution policies.

MITRE Technique:

T1059.001 – PowerShell

---

# 2. Command Interpreter Execution

Query used:

winlog.event_data.Image:*cmd.exe

Purpose:

Identify command interpreter activity and determine which process launched PowerShell.

Relevant fields:

winlog.event_data.ParentImage  
winlog.event_data.CommandLine  

Observed process chain:

explorer.exe → cmd.exe → powershell.exe

The command executed by cmd.exe was:

cmd.exe /c powershell -ExecutionPolicy Bypass -File C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1

This confirms that the shortcut execution triggered a command interpreter which subsequently launched PowerShell.

MITRE Technique:

T1059.003 – Command Shell

---

# 3. Registry Persistence Activity

Query used:

winlog.event_data.Image:*reg.exe

Purpose:

Identify registry modification commands that may indicate persistence mechanisms.

Relevant fields:

winlog.event_data.ParentImage  
winlog.event_data.CommandLine  

Observed command:

reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdateCheck /t REG_SZ /d "powershell.exe -WindowStyle Hidden -File C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1" /f

Parent process:

powershell.exe

This command created a Run key persistence mechanism allowing the payload to execute automatically when the user logs in.

MITRE Technique:

T1547.001 – Registry Run Keys / Startup Folder

---

# 4. Network Activity Investigation

Query used:

winlog.event_id:3 AND winlog.event_data.Image:*powershell.exe

Purpose:

Identify potential outbound network connections initiated by PowerShell.

Result:

No outbound connections from powershell.exe were observed in the available telemetry.

Possible explanations:

- Lab environment network isolation
- Web request failure due to lack of internet connectivity
- Network logging limitations in the environment

---

# Summary of Key Observations

Execution chain identified:

explorer.exe  
→ cmd.exe  
→ powershell.exe  
→ reg.exe

Indicators identified:

- PowerShell executed with ExecutionPolicy Bypass
- Script execution from user Downloads directory
- Registry Run key persistence created
- Script artifact created on the host

Artifacts observed on host:

C:\Users\Public\ir_lab_marker.txt

Registry persistence:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run  
Value: WindowsUpdateCheck
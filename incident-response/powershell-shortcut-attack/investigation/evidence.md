# Evidence Summary

## Host Information

Host: END-Alex  
Environment: Windows 10 VM  
Logging: Sysmon + Winlogbeat  
SIEM: Elastic Stack (Kibana Discover)

---

## Initial Execution

Evidence shows user execution of a disguised shortcut file which launched the command interpreter.

Process chain observed:

explorer.exe → cmd.exe → powershell.exe

Timestamp:
2026-03-07 14:38:35

Command executed:

cmd.exe /c powershell -ExecutionPolicy Bypass -File C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1

---

## PowerShell Execution

PowerShell executed a script located in the user Downloads directory.

Command:

powershell -ExecutionPolicy Bypass -File C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1

Suspicious indicators:

- ExecutionPolicy Bypass
- Script execution from user directory
- PowerShell launched from cmd.exe

MITRE Technique:

T1059.001 – PowerShell

---

## Payload Artifact

The script created a file artifact on the host.

File:

C:\Users\Public\ir_lab_marker.txt

Creation Time:

2026-03-07 14:38:39

This artifact confirms successful execution of the script payload.

---

## Persistence Mechanism

Registry persistence was established via the Run key.

Registry Path:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Value Name:

WindowsUpdateCheck

Command:

powershell.exe -WindowStyle Hidden -File C:\Users\END-Alex\Downloads\IR-Lab\payload.ps1

MITRE Technique:

T1547.001 – Registry Run Keys / Startup Folder

---

## Network Activity

No outbound network activity from powershell.exe was observed in available telemetry.

Possible reasons:

- Lab environment isolated network
- Web request failed due to no internet connectivity
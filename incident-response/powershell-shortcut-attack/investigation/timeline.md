## Incident Timeline

Date: 2026-03-07  
Host: END-Alex  
Analyst: Walid Ait Zaouit  

14:38:35  
User executed a disguised shortcut file.  
Process chain observed: explorer.exe → cmd.exe  

14:38:35  
cmd.exe launched PowerShell with ExecutionPolicy Bypass.  
Command observed:
powershell -ExecutionPolicy Bypass -File payload.ps1

14:38:36  
PowerShell began execution of payload.ps1 located in the user Downloads directory.

14:38:39  
Script created artifact:
C:\Users\Public\ir_lab_marker.txt

14:38:40  
Registry persistence established via:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: WindowsUpdateCheck
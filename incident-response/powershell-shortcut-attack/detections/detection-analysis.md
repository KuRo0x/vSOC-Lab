# Detection Analysis

## Attack Behavior

The incident involved a disguised shortcut file that executed a command interpreter which subsequently launched PowerShell.

Observed process chain:

explorer.exe → cmd.exe → powershell.exe

PowerShell was executed with the following argument:

ExecutionPolicy Bypass

This parameter allows PowerShell scripts to run without enforcement of local execution policies.

---

## Detection Opportunity

Security monitoring systems should detect the following behaviors:

- PowerShell execution from cmd.exe
- Use of ExecutionPolicy Bypass
- Script execution from user directories

These indicators commonly appear in malicious script-based attacks.

---

## Recommended Detection Logic

Trigger alert when:

Parent process = cmd.exe  
Child process = powershell.exe  
CommandLine contains = ExecutionPolicy Bypass

---

## MITRE ATT&CK Mapping

Execution

T1059.001 – PowerShell  
T1059.003 – Command Shell
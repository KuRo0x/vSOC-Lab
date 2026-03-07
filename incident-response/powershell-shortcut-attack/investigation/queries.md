
```markdown
# Investigation Queries

The following queries were used in Kibana Discover to investigate the incident.

---

## 1. PowerShell Execution

Search for PowerShell process creation.

Query:

```

winlog.event_data.Image:*powershell.exe

```

Purpose:

Identify suspicious PowerShell executions and inspect command-line arguments.

Relevant fields:

- winlog.event_data.ParentImage
- winlog.event_data.CommandLine
- winlog.event_data.ProcessGuid

---

## 2. CMD Execution

Search for command interpreter activity.

Query:

```

winlog.event_data.Image:*cmd.exe

```

Purpose:

Identify parent process responsible for launching PowerShell.

Relevant fields:

- winlog.event_data.ParentImage
- winlog.event_data.CommandLine

Observed process chain:

explorer.exe → cmd.exe → powershell.exe

---

## 3. Registry Persistence

Search for registry modifications related to Run keys.

Query:

```

winlog.event_id:13 AND winlog.event_data.TargetObject:*CurrentVersion\Run*

```

Purpose:

Detect persistence mechanisms using Windows Run registry keys.

Technique:

MITRE ATT&CK T1547.001

---

## 4. Network Activity

Search for network connections initiated by PowerShell.

Query:

```

winlog.event_id:3 AND winlog.event_data.Image:*powershell.exe

```

Purpose:

Identify potential command-and-control communication or external downloads.

Result:

No outbound network connections observed in available telemetry.
```

---

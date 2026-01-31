# Detection

## Detection Source
Elastic (Winlogbeat with Sysmon telemetry)

## Detection Logic
Suspicious browser download activity was identified by searching for incomplete
or interrupted download artifacts commonly associated with phishing payload delivery.

### Query Used
```kql
event.original:*crdownload*
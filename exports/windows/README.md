# Windows Telemetry Exports

This directory contains exported configuration and status files from the Windows 10 endpoint used in the vSOC lab.

## Contents

- sysmon-config.xml  
  Full Sysmon configuration used to generate endpoint telemetry.

- winlogbeat.yml  
  Active Winlogbeat configuration forwarding logs to Logstash.

- status_sysmon.txt  
  Service status output verifying Sysmon is installed and running.

- status_winlogbeat.txt  
  Service status output verifying Winlogbeat is installed and running.

These files are provided as evidence of real telemetry generation and forwarding.

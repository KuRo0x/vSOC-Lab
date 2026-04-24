# Improvements – INC-004 SMB Brute Force

## 1. Detection Rule in Elastic Security

- Created an Elastic Security detection rule **“SMB Brute Force on Administrator”** to continuously monitor for failed SMB logons against the Windows host `DESKTOP-DPU3CDQ` (`172.16.0.10`). [web:214][web:215]
- Rule configuration:
  - Rule type: **Query**
  - Data view / index: `winlogbeat-*`
  - KQL query:  
    `event.code: "4625" AND host.name: "DESKTOP-DPU3CDQ" AND winlog.event_data.TargetUserName: "administrator" AND winlog.event_data.IpAddress: "172.16.0.11"`
  - Schedule: runs **every 1 minute** with **1 minute look-back**, ensuring short detection delay.
  - Severity: **High**
  - Risk score: **73**
  - MITRE ATT&CK mapping: **Credential Access (TA0006) – Brute Force (T1110)**. [web:215][web:217]
- Verified that the rule successfully generated multiple alerts during the simulated `netexec` attack, with alerts clearly tied to:
  - `host.name: desktop-dpu3cdq`
  - `source.ip: 172.16.0.11`
  - `user.name: administrator`

## 2. Response / Containment (Lab Validation)

- Created a pfSense IP alias `ATTACKER_SMB_BLOCK` to group malicious or suspected attacker IPs (initially `172.16.0.11`), so the same rule can be reused for additional sources.
- Added a LAN firewall rule to **block TCP/445** from `ATTACKER_SMB_BLOCK` to `172.16.0.10`.
- When enabled during testing, this rule prevented new SMB connections from the attacker VM and no additional 4625 events from `172.16.0.11` were observed in Kibana during the attack window, demonstrating a practical containment action that could be taken after the Elastic alert fires. [web:216][web:221]

## 3. Future Hardening Ideas

- Attach a notification action (e.g. email, Slack, or webhook) to the **“SMB Brute Force on Administrator”** rule so analysts are alerted immediately when a brute-force pattern is detected, instead of relying only on the Alerts UI. 
- Review and tune Windows password and account lockout policies for privileged accounts (such as `administrator`) to reduce the effectiveness of brute-force attempts while maintaining operational usability. [web:222][web:228]
- In future iterations of the lab, consider limiting SMB access on `DESKTOP-DPU3CDQ` to a small set of administrative or management hosts, while keeping the current broader access for demo and training purposes. 
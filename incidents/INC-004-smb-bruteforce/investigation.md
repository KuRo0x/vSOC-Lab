# Investigation – INC-004 SMB Brute Force

## 1. Initial Observation

- During the lab exercise, a brute-force / password-spraying attempt was launched from the Kali attacker VM against the Windows host `DESKTOP-DPU3CDQ` (`172.16.0.10`) over SMB (TCP 445) using `netexec`.
- The attacker used a small wordlist (`test_passwords.txt`) against the local `administrator` account.
- On the attacker side, `netexec` showed repeated authentication failures followed by `STATUS_ACCOUNT_LOCKED_OUT`, indicating that the account lockout policy had been triggered.

## 2. Log Source Identification

- The Windows victim is configured with Winlogbeat to forward Security logs into Elasticsearch.
- Relevant telemetry for failed logons:
  - Event ID: `4625` — An account failed to log on.
  - Index: `winlogbeat-*`.

## 3. Pivot into Kibana

Steps performed in Kibana:

1. Open **Discover** and select the `winlogbeat-*` data view.
2. Set the time range to **Last 15 minutes** to cover the attack window.
3. Run the following query:

   `event.code: "4625" AND host.name: "DESKTOP-DPU3CDQ" AND winlog.event_data.TargetUserName: "administrator"`

4. Review the results and observe:
   - A clear spike of `4625` events around the time `netexec` was executed.
   - Multiple documents with the same target user (`administrator`) from the attacker source IP.

## 4. Event Detail Review

For several `4625` events, the following fields were verified:

- `host.name` = `DESKTOP-DPU3CDQ`
- `winlog.event_data.TargetUserName` = `administrator`
- `winlog.event_data.IpAddress` = `172.16.0.11`
- `winlog.event_data.Status` / `SubStatus` consistent with failed logon and lockout behavior

The timestamps matched the `netexec` output, confirming the attack sequence and the transition from repeated failures to `STATUS_ACCOUNT_LOCKED_OUT`.

## 5. Assessment

- The activity is consistent with a brute-force / password-spraying attempt against a privileged local account.
- The Windows account lockout policy successfully prevented further authentication attempts after the threshold was reached.
- The logging pipeline functioned as expected:
  - Windows Security logs → Winlogbeat → Elasticsearch → Kibana

## 6. Screenshots Collected
 `evidence/kibana-4625-admin-172.16.0.10-attack-172.16.0.11.png` – Discover view showing the `4625` spike and event list.
- `evidence/netexec-smb-status-account-locked-out.png` – Attacker terminal showing repeated `STATUS_ACCOUNT_LOCKED_OUT` responses.

These artifacts can be referenced in the main incident README and used in a portfolio or interview to demonstrate the full investigation workflow.
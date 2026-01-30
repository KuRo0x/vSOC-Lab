# Training Design — Phishing Awareness Exercise

## 1. Training Approach

This phishing awareness exercise was designed to replicate how organizations conduct **controlled phishing simulations** to evaluate user awareness and defensive controls.

The training prioritizes:

* Natural user behavior
* Safety and containment
* Evidence-based validation
* Clear separation between training and incident response

---

## 2. Pre-Training Conditions

Before execution, the following conditions were ensured:

* The environment was isolated and controlled
* Endpoint protection (Microsoft Defender) was enabled
* Browser security features were active
* Centralized logging (Sysmon + Winlogbeat) was operational
* SIEM visibility was verified

No prior warning was given to the test user to avoid biasing behavior.

---

## 3. Simulation Phase (Baseline Test)

### Step 1 — Phishing Email Delivery

* A phishing-style email was sent to the test user
* The email contained an embedded hyperlink
* The theme mimicked a common business scenario (invoice / internal request)

### Step 2 — User Interaction

* The user opened the email
* The user clicked the embedded link
* The browser initiated a download attempt

User behavior was not interrupted during this phase.

---

## 4. Monitoring Phase (SOC Observation)

During and after user interaction:

* Endpoint telemetry was collected
* Browser activity was logged
* File creation events were monitored
* Security controls operated normally
* No artificial alerts were triggered

The SOC focused on **observing**, not interfering.

---

## 5. Investigation Phase

After the simulation:

* Endpoint logs were reviewed
* A timeline was reconstructed
* Evidence was correlated in the SIEM
* The scope and impact were assessed

Key questions addressed:

* Did the user interact?
* Did protections activate?
* Did execution occur?
* Was there any persistence or impact?

---

## 6. Classification Phase

The outcome was classified as a **training result**, not a security breach.

* User awareness: Failed (clicked link)
* Endpoint protection: Successful
* Impact: None

This classification aligns with enterprise phishing awareness practices.

---

## 7. Post-Training Feedback

After classification:

* The user was informed of the simulation
* The phishing indicators were explained
* Correct handling procedures were reviewed
* Emphasis was placed on reporting suspicious emails

No disciplinary action was taken.

---

## 8. Training Integrity

At no point were:

* Malware payloads executed
* Credentials harvested
* Systems destabilized
* Protections disabled

This ensures the exercise remains safe, ethical, and repeatable.

---

## 9. Design Summary

This training design demonstrates how phishing awareness can be:

* Measured realistically
* Validated through SOC evidence
* Closed professionally without escalation

---


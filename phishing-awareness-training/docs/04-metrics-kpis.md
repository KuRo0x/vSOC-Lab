# Metrics & KPIs — Phishing Awareness Training

## 1. Purpose of Metrics

Metrics are used to objectively evaluate:

* User awareness
* Control effectiveness
* SOC visibility

This program avoids subjective judgments and relies on **observable, measurable outcomes**.

---

## 2. Key Metrics Tracked

### 2.1 Email Delivery

* **Metric:** Phishing email delivered
* **Result:** Yes
* **Purpose:** Confirms training execution

---

### 2.2 User Interaction

* **Metric:** Link clicked
* **Result:** Yes
* **Purpose:** Measures user susceptibility

---

### 2.3 Download Attempt

* **Metric:** Browser-initiated file download
* **Result:** Yes
* **Evidence:** `.crdownload` file creation
* **Purpose:** Confirms depth of interaction

---

### 2.4 Malware Execution

* **Metric:** File execution
* **Result:** No
* **Purpose:** Confirms containment

---

### 2.5 Endpoint Protection Effectiveness

* **Metric:** Endpoint prevention triggered
* **Result:** Yes
* **Purpose:** Validates defensive controls

---

### 2.6 Network Impact

* **Metric:** Successful outbound connection
* **Result:** No confirmed evidence
* **Purpose:** Confirms no data exchange

---

### 2.7 SOC Visibility

* **Metric:** Relevant telemetry ingested into SIEM
* **Result:** Yes
* **Purpose:** Confirms monitoring coverage

---

## 3. KPI Summary Table

| KPI                        | Result | Status |
| -------------------------- | ------ | ------ |
| Phishing email delivered   | Yes    | ✔      |
| User clicked link          | Yes    | ❌      |
| Download attempt           | Yes    | ❌      |
| Malware execution          | No     | ✔      |
| Endpoint protection worked | Yes    | ✔      |
| SOC visibility             | Yes    | ✔      |
| Business impact            | None   | ✔      |

---

## 4. KPI Interpretation

* The user failed the awareness test by clicking the link.
* Technical controls prevented escalation.
* SOC monitoring functioned as intended.
* No operational or data impact occurred.

This represents a **controlled awareness failure with safe outcome**, which is an acceptable and valuable training result.

---

## 5. Benchmarking Context

In real organizations:

* Initial phishing click rates are often non-zero.
* Success is measured by **reduction over time**, not perfection.

This training establishes a **baseline** for future improvement.

---

## 6. Metrics Limitations

* Single-user scope
* Single scenario
* No long-term trend analysis

These limitations are acknowledged and documented.

---

## 7. Metrics Conclusion

The metrics demonstrate:

* Measurable user behavior
* Effective defensive controls
* Actionable awareness insight

These results justify targeted awareness reinforcement rather than technical remediation.

---


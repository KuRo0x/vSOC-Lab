Good.
Now **Step 4 — `docs/02-threat-model.md`**.

This file defines phishing **formally**, the way SOCs, auditors, and blue teams expect.
Copy-paste **exactly** into `docs/02-threat-model.md`.

---

# Threat Model — Phishing Awareness Training

## 1. Threat Description

Phishing is a social engineering attack in which an adversary attempts to trick a user into interacting with malicious content, typically delivered via email.

The primary objective of phishing is **initial access**, which may lead to:

* Credential theft
* Malware delivery
* Persistence
* Lateral movement

This training focuses on **link-based phishing**, one of the most common real-world techniques.

---

## 2. Adversary Goals

In this scenario, the simulated adversary aims to:

* Deliver a convincing phishing email
* Induce user interaction (link click)
* Initiate contact with attacker-controlled infrastructure
* Deliver secondary payloads if defenses fail

No advanced adversary techniques are simulated.

---

## 3. Attack Vector

**Primary Vector:**

* Email-based phishing with embedded hyperlink

**Delivery Characteristics:**

* Legitimate-looking sender context
* Social engineering theme (invoice / internal request)
* Urgency-based messaging

No exploit-based delivery is used.

---

## 4. Assumed Threat Capabilities

The simulated adversary is assumed to have:

* Ability to send phishing emails
* Basic infrastructure hosting capability
* No zero-day exploits
* No insider access

This reflects a **low-to-moderate sophistication attacker**, which aligns with the majority of real phishing incidents.

---

## 5. Defender Assumptions

The environment is assumed to have:

* Endpoint protection enabled
* Browser security features active
* Centralized log collection
* SOC monitoring in place

The purpose of the training is to validate these assumptions using evidence.

---

## 6. Relevant ATT&CK Techniques

This training maps to the following ATT&CK technique:

* **T1566 — Phishing**

Only the **initial access phase** is in scope.
No post-compromise techniques are evaluated.

---

## 7. Risk Statement

If phishing is successful and unmitigated, the organization faces risk of:

* Credential compromise
* Malware infection
* Data loss
* Operational disruption

This training evaluates how early controls and awareness reduce this risk **before impact**.

---

## 8. Control Objectives

The following controls are evaluated indirectly:

* User awareness
* Endpoint security controls
* SOC detection and investigation capability

The goal is **risk reduction**, not attack completion.

---

## 9. Threat Model Summary

This threat model represents a **realistic and common phishing scenario** appropriate for awareness training and SOC validation.

It intentionally avoids advanced or destructive techniques in favor of:

* Safety
* Repeatability
* Measurable outcomes

---


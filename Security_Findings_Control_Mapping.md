# Security Findings — Control & Risk Mapping

**Author:** Pasin Visuttipinate
**Frameworks referenced:** ISO/IEC 27001:2022 (Annex A) · OWASP Top 10:2025 · OWASP ASVS v5.0 · NIST Cybersecurity Framework (CSF) 2.0

---

## 1. Purpose

This document takes the findings from three hands-on security exercises — two web-application penetration tests and one malware / incident analysis — and maps each finding to recognised security-control frameworks. Each technical issue is restated as a **control gap** and a **business risk**, with prioritised, control-level recommendations.

The intent is to demonstrate the **assurance and advisory perspective**: taking offensive, technical findings and translating them into the language a security function, an IT auditor, or a regulator works in. The underlying penetration-test and analysis reports contain the full exploitation detail; this document is the governance layer that sits on top of them.

> All testing was performed in **authorised, isolated lab environments** as part of university coursework.
---

## 2. Sources & Scope

| Ref | Exercise | Type |
|----|----------|------|
| **A** | Support Ticket System | Black-box web-application penetration test |
| **B** | SecureBank Customer Portal | Black-box web-application / API penetration test |
| **C** | Ransomware incident (CryptoLocker family) | Static malware analysis + incident review |

---

## 3. Methodology

- Each finding is restated as a control gap and mapped to **ISO/IEC 27001:2022 Annex A** controls, the relevant **OWASP Top 10:2025** risk category (web findings only), and the applicable **NIST CSF 2.0** function.
- Verification-level guidance follows the themes of the **OWASP ASVS v5.0** (the testable companion to the Top 10): input validation / sanitisation / encoding, authentication, authorisation, and configuration.
- Severity uses the **CVSS** ratings recorded in the original assessments.
- This is a control-mapping / assurance view, **not a re-test**.

A note on framework currency: the original assessments classified findings against the **OWASP Top 10 2021** list. OWASP published the **2025** edition on 6 November 2025, which is now current, so the mappings below use the 2025 categories (for example, Cross-Site Scripting and SQL Injection both fall under **A05:2025 – Injection**, where they were **A03:2021 – Injection** previously).

---

## 4. Finding-to-Control Mapping

### Exercise A — Support Ticket System

| # | Finding | Severity | OWASP Top 10:2025 | ISO/IEC 27001:2022 Annex A | NIST CSF 2.0 |
|---|---------|----------|-------------------|----------------------------|--------------|
| A1 | Stored Cross-Site Scripting (XSS) in the ticket *Description* field; unsanitised input executed in the admin context and used to exfiltrate restricted page content | **Critical (CVSS 8.6)** | A05 – Injection | A.8.28 Secure coding; A.8.26 Application security requirements; A.8.29 Security testing in development & acceptance | Protect (PR.PS) |
| A2 | Information disclosure — sensitive internal paths (`/admin/dashboard`, `/report`) revealed in an HTML comment | Medium | A02 – Security Misconfiguration | A.8.28 Secure coding; A.8.9 Configuration management | Protect (PR.PS) |
| A3 | Missing Content Security Policy (CSP); no defence-in-depth against script injection or unexpected outbound connections | Medium | A02 – Security Misconfiguration | A.8.9 Configuration management; A.8.28 Secure coding | Protect (PR.PS) |
| A4 | Insufficient sandboxing of the privileged "admin bot" that renders user-submitted content (excessive trust + network egress) | Medium | A02 – Security Misconfiguration | A.8.22 Segregation of networks; A.8.9 Configuration management | Protect (PR.PS) |

**Key remediations (A):**
- Apply **context-aware output encoding** and **server-side input sanitisation** (allowlist), with framework auto-escaping enabled — directly addresses A.8.28 / A.8.26.
- Deploy a **strict CSP** (`script-src 'self'; connect-src 'self'; img-src 'self'`), which would have blocked both the script execution and the data exfiltration.
- **Remove sensitive information from source/comments** and add a pre-deployment code-review check for information leakage.
- **Constrain the admin bot**: restrict outbound network access and enforce CSP in its rendering environment.

---

### Exercise B — SecureBank Customer Portal

| # | Finding | Severity | OWASP Top 10:2025 | ISO/IEC 27001:2022 Annex A | NIST CSF 2.0 |
|---|---------|----------|-------------------|----------------------------|--------------|
| B1 | UNION-based **SQL Injection** in an undocumented API endpoint (`/api/v2/customers?id=`); string-concatenated query enabled full read of the SQLite database, including a `secrets` table | **Critical (CVSS 9.8)** | A05 – Injection | A.8.28 Secure coding; A.8.26 Application security requirements; A.8.29 Security testing in development & acceptance | Protect (PR.PS) |
| B2 | Information disclosure — internal API endpoint advertised in an HTML comment | Medium | A02 – Security Misconfiguration | A.8.28 Secure coding; A.8.9 Configuration management | Protect (PR.PS) |
| B3 | **Missing authentication / authorisation** on a data-bearing API endpoint; reachable anonymously | Medium | A07 – Authentication Failures (with A01 – Broken Access Control) | A.8.5 Secure authentication; A.8.3 Information access restriction; A.5.15 Access control | Protect (PR.AA) |
| B4 | Latent control gaps — over-privileged application DB account and sensitive values (`secrets`) stored unencrypted at rest | Medium | A01 – Broken Access Control; A04 – Cryptographic Failures | A.8.2 Privileged access rights; A.8.3 Information access restriction; A.8.24 Use of cryptography | Protect (PR.AA / PR.DS) |

**Key remediations (B):**
- Use **parameterised queries / prepared statements** and **strict integer input validation** on the `id` parameter — the primary fix (A.8.28).
- **Require authentication and authorisation** on all API endpoints; restrict "internal" endpoints to internal networks; deny-by-default (A.8.5 / A.8.3 / A.5.15).
- Apply **least privilege** to the application's database account and **encrypt sensitive data at rest** (A.8.2 / A.8.24).
- Add **generic error handling** and consider a **WAF** as a compensating, not primary, control.

---

### Exercise C — Ransomware Incident (CryptoLocker family)

*Web Top 10 categories do not apply to host-based malware; mappings use ISO 27001 and NIST CSF.*

| # | Control gap highlighted by the incident | ISO/IEC 27001:2022 Annex A | NIST CSF 2.0 |
|---|------------------------------------------|----------------------------|--------------|
| C1 | Malicious executable delivered by email and run by multiple users (initial access via phishing) | A.8.7 Protection against malware; A.8.23 Web filtering; A.6.3 Information security awareness, education & training | Protect (PR.PS); Detect (DE.CM) |
| C2 | Endpoint compromise — registry "Run" key persistence, command-and-control traffic, and keylogging went undetected | A.8.7 Protection against malware; A.8.16 Monitoring activities; A.8.15 Logging | Detect (DE.CM); Protect (PR.PS) |
| C3 | File encryption with recovery dependent on backups | A.8.13 Information backup | Recover (RC.RP) |
| C4 | Incident handling — containment, eradication, and recovery | A.5.24 Incident management planning & preparation; A.5.26 Response to incidents; A.5.27 Learning from incidents | Respond (RS); Recover (RC.RP) |

**Key remediations (C):**
- **Block / quarantine executable email attachments**, enable phishing detection and attachment sandboxing (A.8.7 / A.8.23).
- Deploy **EDR** for behavioural detection and blocking; **monitor autoruns and outbound C2**; apply network egress filtering (A.8.7 / A.8.16 / A.8.15).
- Maintain **tested, offline / immutable backups** with periodic restore testing (A.8.13).
- Operate a **documented incident-response plan** — isolate, eradicate, rebuild from a known-good image, and run a post-incident review (A.5.24 / A.5.26 / A.5.27).
- Deliver recurring **phishing-awareness training** to staff (A.6.3).

---

## 5. Cross-Cutting Risk Themes

Read together, the three exercises point to five systemic themes rather than isolated bugs:

1. **Insecure development lifecycle.** The injection flaws (XSS, SQLi) and the leaked internal paths trace back to missing secure-coding and security-testing practices across the build process — ISO 27001 Annex A 8.25–8.29.
2. **Broken access control and weak authentication.** Sensitive functionality and a data-bearing API were reachable without proper authentication or authorisation — OWASP A01 / A07; ISO A.8.3, A.8.5.
3. **Security misconfiguration.** Absent CSP, sensitive comments, and an over-trusted automation component widened the blast radius — OWASP A02; ISO A.8.9.
4. **Insufficient detection and response.** The ransomware case shows the need for endpoint detection (EDR), logging and monitoring, and a practised incident-response capability — ISO A.8.7, A.8.15–A.8.16, A.5.24–A.5.27; CSF Detect / Respond / Recover.
5. **The human layer.** Phishing-borne malware succeeds where security-awareness training is weak — ISO A.6.3.

---

## 6. Regulatory Context of Thailand

In a Thai financial-services setting, the data exposure that the SecureBank SQL-injection finding would cause in production engages obligations under Thailand's **Personal Data Protection Act B.E. 2562 (PDPA)** — including duties around protecting personal data and handling and notifying qualifying data breaches. The control themes above also align with the **Bank of Thailand's IT-risk-management expectations** for financial institutions. Mapping findings to recognised controls is part of how an organisation evidences due diligence to regulators and auditors.

*(This section reflects a foundational understanding of the relevant regimes and is not legal advice.)*

---

## 7. Notes & Limitations

- All work was conducted in **authorised, isolated lab environments** for academic coursework; no production or third-party systems were involved.
- The control mappings reflect the author's study of the named frameworks and are intended to demonstrate risk-translation skill, not to serve as a certified audit opinion.

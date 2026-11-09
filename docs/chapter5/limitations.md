# Chapter 5: System Limitations & Future Work

This document critically evaluates the design trade-offs, theoretical boundaries, and operational constraints of the SecureSDLC Framework, aligning with CLAUDE.md §5.2, §5.4, §5.5, and academic dissertation requirements.

---

## 1. ZAP Risk-to-CVSS Mapping Approximation (§5.2)

### Description & Rationale
Automated DAST tools like OWASP ZAP categorize discovered alerts using four coarse categorical risk bands (*High*, *Medium*, *Low*, *Informational*). However, the SecureSDLC Framework calculates vulnerability metrics and enforces gate thresholds using CVSS v3.1 vector strings and numeric base scores. Because ZAP's REST API does not emit full CVSS vectors, the framework synthesizes a deterministic default vector based on the alert's risk level upon automated import:

| ZAP Risk Level | Default Synthesized CVSS:3.1 Vector | Base Score | Derived Severity |
|---|---|:---:|:---:|
| **High** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| **Medium** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | **5.3** | Medium |
| **Low** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N` | **3.5** | Low |
| **Informational** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | **0.0** | Info |

### Limitation
This synthetic mapping provides a consistent approximation, but it lacks environmental and contextual granularity. For example, a "High" risk alert on an unauthenticated external endpoint and a "High" risk alert on an internal debugging interface are assigned identical vectors and scores (7.5). It does not reflect user interaction requirements (UI), privileges required (PR), or attack complexity (AC) specific to the vulnerable endpoint.

### Future Work
Implement a triage workflow where imported findings are initially flagged as provisional. Pentesters can then adjust individual vector metrics (e.g., modifying privileges required from None to High) before the score is finalized and incorporated into the gate evaluation.

---

## 2. Risk Score Formulation (§5.4)

### Description & Rationale
The overall project risk score is derived using an additive formula:
$$\text{Raw Risk} = \sum (\text{Critical} \times 10 + \text{High} \times 5 + \text{Medium} \times 2 + \text{Low} \times 1 + \text{Info} \times 0)$$
$$\text{Project Risk Score} = \min(100, \text{Raw Risk})$$
Findings in `OPEN` or `FIXED` statuses contribute to risk; findings in `VERIFIED` or `CLOSED` statuses are excluded.

### Limitation
While deliberately simple, transparent, and easy to explain during academic evaluation, the metric treats all software assets uniformly. It does not differentiate between vulnerabilities in mission-critical payment services versus static marketing pages. Additionally, the score saturates at 100: a project with 10 Critical vulnerabilities receives a score of 100, which is mathematically indistinguishable from a project with 50 Critical vulnerabilities, obscuring catastrophic defect accumulation.

### Future Work
Introduce asset criticality multipliers (e.g., Crown Jewels, Internal, Deprecated) and dynamic risk modeling such as OWASP Risk Rating Methodology, incorporating business impact and likelihood factors.

---

## 3. Dynamic Application Security Testing (DAST) Coverage Limits

### Description & Rationale
DAST analyzes running web applications from the outside in without access to source code. In this framework, OWASP ZAP is leveraged to spider target routes and execute active attack payloads.

### Limitation
DAST cannot inspect underlying code constructs, unreferenced API endpoints, business logic flaws (e.g., transferring negative amounts in a bank ledger), or multi-step authenticated workflows requiring multi-factor authentication. In modern Single Page Applications (SPAs) like OWASP Juice Shop, client-side JavaScript rendering can hinder basic spidering unless headless browser integration (AJAX Spider) is actively configured.

### Future Work
Combine DAST with Static Application Security Testing (SAST) and Software Composition Analysis (SCA) tools (e.g., Semgrep, Bandit, pip-audit) to achieve hybrid application security verification across both code and runtime.

---

## 4. Dependence on Honest Evidence in the Phase Gate

### Description & Rationale
The core phase gate rule (`phases.services::can_advance`) requires every mandatory checklist item to be marked `done=True` with non-empty text in the `evidence` field.

### Limitation
The application enforces that evidence must be non-empty and verifies that gate requirements are fulfilled, but it cannot programmatically validate the substantive accuracy or quality of human-entered text. A malicious or pressured team member could theoretically enter placeholder text (e.g., "reviewed and approved") to satisfy the non-empty string check and bypass the intent of the control.

### Future Work
Introduce structured evidence attachments (e.g., cryptographically hashed document uploads, links to signed pull requests, or automated CI/CD pipeline artifact verification) and require dual-sign-off from both the PM and the Security Lead.

---

## 5. Single-Target Scanning Model

### Description & Rationale
`ScanTarget` records represent individual URLs (e.g., `http://localhost:3000`) associated with a single project environment.

### Limitation
Modern microservice architectures rarely consist of a single standalone web host. Complex enterprise applications span multiple microservices, container networks, API gateways, and cloud functions. Scanning one target URL at a time does not simulate cross-service attacks, token replay across microservices, or ingress/egress network pivots.

### Future Work
Expand the data model to support Target Groups or Environments, allowing coordinated multi-target scans that sweep across interconnected project services.

---

## 6. `DevAutoAuthMiddleware` Development-Only Risk

### Description & Rationale
The `DevAutoAuthMiddleware` class allows simulated authentication by passing a `?__as_user=<username>` query parameter, created specifically to facilitate automated headless browser screenshot capture for documentation without external browser drivers.

### Limitation
If improperly deployed to a production environment, this middleware would represent a catastrophic authentication bypass vulnerability (CWE-306). 

### Mitigation & Hardening Verification
The implementation mitigates this risk through defense-in-depth:
1. **Settings Separation:** The middleware is registered **only** in `config/settings/dev.py`. It is absent from `base.py` and `prod.py`.
2. **Runtime Guard:** The middleware code explicitly checks `if settings.DEBUG and "__as_user" in request.GET:`. When `DEBUG = False`, the branch is unreachable and returns immediately.
3. **Deployment Audit:** `python manage.py check --deploy --settings=config.settings.prod` enforces `DEBUG = False` and verifies that secure production settings are applied.

### Future Work
Completely decouple automated screenshot generation from application middleware by using authenticated session cookies injected directly into the headless browser context via the test client or Playwright/Selenium CLI wrappers.


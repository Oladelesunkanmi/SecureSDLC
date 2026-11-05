# Chapter 4: Security Hardening & Audit Verification

This document provides evidence of security controls, automated configuration checks, permission enforcement, and transport hardening implemented in the SecureSDLC Framework.

---

## 1. Production Deployment Audit (`check --deploy`)

The Django production settings (`config.settings.prod`) were validated using Django's deployment verification command:

```powershell
$env:DJANGO_SECRET_KEY="<production-50+-character-high-entropy-secret-key>"
$env:DJANGO_ALLOWED_HOSTS="example.com,securesdlc.local"
.venv\Scripts\python.exe manage.py check --deploy --settings=config.settings.prod
```

### Verification Result
```text
System check identified no issues (0 silenced).
```

### Configured Security Directives

| Security Directive | Setting Value | Purpose / Standard |
|---|---|---|
| `DEBUG` | `False` | Disables interactive debuggers, stack trace leaks, and technical 500 error pages. |
| `ALLOWED_HOSTS` | Explicit host list | Prevents HTTP Host header poisoning attacks. |
| `SECURE_SSL_REDIRECT` | `True` | Automatically redirects all unencrypted HTTP traffic to HTTPS. |
| `SECURE_HSTS_SECONDS` | `31536000` (1 year) | Instructs browsers to communicate exclusively over HTTPS via HTTP Strict Transport Security. |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `True` | Extends HSTS policy to all subdomains. |
| `SECURE_HSTS_PRELOAD` | `True` | Qualifies domain for browser HSTS preload list. |
| `SESSION_COOKIE_SECURE` | `True` | Ensures session cookies are transmitted solely over HTTPS connections. |
| `SESSION_COOKIE_HTTPONLY` | `True` | Prevents client-side scripts from accessing session tokens (XSS mitigation). |
| `SESSION_COOKIE_SAMESITE` | `"Lax"` | Protects session tokens from Cross-Site Request Forgery in top-level navigations. |
| `CSRF_COOKIE_SECURE` | `True` | Prevents transmission of CSRF cookies over insecure channels. |
| `CSRF_COOKIE_SAMESITE` | `"Lax"` | Enforces SameSite policy for CSRF prevention. |
| `SECURE_CONTENT_TYPE_NOSNIFF` | `True` | Sets `X-Content-Type-Options: nosniff` to prevent MIME-type confusion attacks. |
| `SECURE_REFERRER_POLICY` | `"same-origin"` | Prevents leaking sensitive URL paths in Referer headers to external sites. |
| `X_FRAME_OPTIONS` | `"DENY"` | Completely prevents clickjacking by forbidding embedding in iframes. |

---

## 2. Permission Matrix Enforcement

Role-Based Access Control (RBAC) is implemented according to CLAUDE.md §3 across four distinct roles:
1. **Admin (`ADMIN`)**: Global system administrator with superuser management capabilities.
2. **Project Manager (`PM`)**: Project coordinator responsible for checklists, project members, and phase gate transitions.
3. **Developer (`DEVELOPER`)**: Project contributor responsible for technical checklist evidence and implementing remediation fixes.
4. **Pentester (`PENTESTER`)**: Security tester responsible for vulnerability logging, re-testing/verification, scan target registration, and scan execution.

### Verification of Negative Permission Cells ("No" Tests)

The test module `accounts.tests_permission_matrix.PermissionMatrixNoCellTests` executes 27 dedicated tests verifying that every capability marked as "No" in the specification is rejected:

1. **Administration Access:** PM, Developer, and Pentester users cannot access Django administration (`/admin/`).
2. **Project Creation:** Developer and Pentester users receive `HTTP 403 Forbidden` on project creation endpoints.
3. **Membership Management:** Developer and Pentester users receive `HTTP 403 Forbidden` when attempting to add or remove project members.
4. **Phase Gate Advancement:** Developer and Pentester users receive `HTTP 403 Forbidden` when attempting to advance or reopen phases.
5. **Scan Target Registration:** Developer users receive `HTTP 403 Forbidden` when attempting to register scan targets.
6. **Vulnerability Creation:** PM and Developer users receive `HTTP 403 Forbidden` on finding creation endpoints.
7. **Transition to Fixed:** PM and Pentester users receive `HTTP 403 Forbidden`; only Developers and Admins can move a finding to `FIXED`.
8. **Transition to Verified / Closed / Re-open:** PM and Developer users receive `HTTP 403 Forbidden`; only Pentesters and Admins can verify or close findings.
9. **Scanner Execution:** PM and Developer users receive `HTTP 403 Forbidden`; only Pentesters and Admins can trigger DAST scans.
10. **Report Generation:** Developer users receive `HTTP 403 Forbidden` when attempting to generate or download assessment reports.
11. **Global Security Dashboard:** PM, Developer, and Pentester users receive `HTTP 403 Forbidden`; global dashboard is restricted strictly to Admins.

### Information Hiding (Non-Member 404 Policy)

To prevent unauthorized users from discovering the existence of projects or resources:
- Project views inherit `ProjectMemberRequiredMixin`.
- When an authenticated user requests a project URL for a project they are not a member of, the system returns `HTTP 404 Not Found` rather than `403 Forbidden`.
- Verified across projects, phases, vulnerabilities, scans, and dashboard routes.

---

## 3. CSRF & Form Protection

1. **Middleware Enforcement:** Django's `CsrfViewMiddleware` is globally active.
2. **Exemption Audit:** An audit of all view modules confirmed zero instances of `@csrf_exempt`.
3. **Template Verification:** Every state-modifying `<form method="post">` across all apps includes `{% csrf_token %}`. Read-only search and filter forms use GET and do not modify database state.

---

## 4. Scan Safety & Boundary Controls

In accordance with CLAUDE.md §5.5, scanning safety is non-negotiable:
1. **Target Registration Validation:** `ScanTarget.clean()` validates that target URLs belong to the allowlist configured in `settings.SCAN_ALLOWED_HOSTS` (default: `localhost`, `127.0.0.1`, `host.docker.internal`, `juice-shop`). Any production or external host is rejected.
2. **Mandatory Authorization:** A target cannot be saved without `authorization_confirmed=True` and a recorded authorized party.
3. **Worker-Side Re-validation:** Before initiating an active scan or spider, the asynchronous worker task `run_zap_scan` re-verifies target authorization and the host allowlist to defend against race conditions or direct database modifications.
4. **Execution Timeout:** All scans are capped by `SCAN_TIMEOUT_SECONDS` (default: 900 seconds).

---

## 5. Repository Secret Sanitization

The entire Git commit history was inspected for leaked secrets:

```powershell
git log -p | Select-String -Pattern "DJANGO_SECRET_KEY|SECRET_KEY"
```

### Result
- No real secret keys, API tokens, passwords, or credentials have ever been committed to the repository.
- Development uses `.env.example` containing obvious placeholder strings.
- Production settings strictly read secrets from environment variables and fail loudly if `DJANGO_SECRET_KEY` is missing.

---

## 6. Custom Error Handling

Custom templates (`templates/404.html`, `templates/403.html`, and `templates/500.html`) ensure that when `DEBUG = False`:
- Stack traces, Python exception types, file paths, and SQL queries are completely suppressed.
- Standardized, user-friendly security notices are presented to the user.


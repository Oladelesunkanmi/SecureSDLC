# CLAUDE.md: SecureSDLC Framework

Final-year project. A web application that puts penetration testing into every stage of the software development lifecycle (SDLC), enforced by a phase-gate system. Claude Code reads this file at the start of every session. Keep it current: when a decision changes, update this file first, then the code.

---

## 1. Project summary

**Problem.** Developers usually run security testing at the end of a project, when fixing vulnerabilities is expensive and late. Security checks are optional, so they get skipped under deadline pressure.

**Solution.** A Django web dashboard in which a project moves through six SDLC phases. Each phase has a security checklist and specific security activities. A phase cannot advance until its required checks pass. The app integrates existing security tools (OWASP ZAP) rather than implementing scanners itself.

**Out of scope for this build.** Building our own scanner, Nmap and Nikto integration, live continuous monitoring, SAST tooling, a full re-test scheduler (a due-date field only), mobile apps, multi-tenant SaaS hosting, and email notifications.

---

## 2. Technology stack

| Layer | Choice | Reason |
|---|---|---|
| Language | Python 3.11+ | One language across app and security tooling |
| Web framework | Django 5.x | Built-in auth, permissions, ORM, migrations, admin panel |
| Database | SQLite (development), PostgreSQL (demo and deployment settings) | SQLite needs no setup; Postgres is the realistic target |
| Frontend | Django templates, Bootstrap 5, Chart.js | No build step, no separate API layer |
| Background jobs | Django-Q2 with the ORM broker | Runs ZAP scans without blocking requests; no Redis needed |
| Security scanner | OWASP ZAP (Docker image `zaproxy/zap-stable`) via `zapv2` client | Real, documented, free scanner with a REST API |
| Scan targets | OWASP Juice Shop (`bkimminich/juice-shop`), optionally DVWA | Deliberately vulnerable apps; ethical test targets |
| CVSS | `cvss` Python package (CVSS v3.1) | Severity derived from the vector, not typed by hand |
| PDF reports | WeasyPrint (Linux/macOS) or xhtml2pdf (Windows) | Reports written as HTML templates |
| Testing | Django `TestCase`, `unittest.mock` | Standard, no extra framework |
| Containers | Docker Desktop (already installed) | Runs ZAP and Juice Shop reproducibly |
| Version control | Git, GitHub | Commit history as evidence of process |

Do not add libraries outside this table without recording the reason in `docs/decisions.md`.

---

## 3. Roles and permissions

Four roles, stored as a `role` field on a custom `User` model.

| Capability | Admin | Project Manager | Developer | Pentester |
|---|:-:|:-:|:-:|:-:|
| Manage users and roles | Yes | No | No | No |
| Create project | Yes | Yes | No | No |
| Add or remove project members | Yes | Yes (own projects) | No | No |
| View projects they belong to | Yes | Yes | Yes | Yes |
| Choose SDLC model (Waterfall / Agile) | Yes | Yes | No | No |
| Complete checklist items and add evidence | Yes | Yes | Yes | Yes |
| Advance a phase (through the phase gate) | Yes | Yes | No | No |
| Register scan targets (with authorization) | Yes | Yes | No | Yes |
| Create a vulnerability finding | Yes | No | No | Yes |
| Move finding to Fixed | Yes | No | Yes | No |
| Move finding to Verified or Closed | Yes | No | No | Yes |
| Trigger a ZAP scan | Yes | No | No | Yes |
| Generate PDF report | Yes | Yes | No | Yes |
| View dashboard | Yes | Yes | Yes | Yes |

Enforcement rules:
- Every project view checks membership. A user who is not a member gets a 404, not a 403, so project existence is not revealed.
- Permission checks live in `accounts/permissions.py` as functions (`can_advance_phase(user, project)`, `can_create_vuln(user, project)`, `can_register_target(user, project)`, `can_trigger_scan(user, project)`, `can_generate_report(user, project)`, and so on), while vulnerability status transition authorization (`can_transition(user, vuln, new_status)`) lives in `vulns/services.py` alongside `transition()` and the status workflow rules (§5.3). Views call these functions. Templates use them only to hide buttons, never as the only protection.
- Admin is a Django superuser-equivalent for the app, but it must still pass through the same checks.

---

## 4. Data model

All models have `created_at` and `updated_at` timestamps.

**User** (extends `AbstractUser`)
- `role`: choices `ADMIN`, `PM`, `DEVELOPER`, `PENTESTER`

**Project**
- `name` (char 150), `description` (text)
- `sdlc_model`: `WATERFALL` or `AGILE`
- `created_by` (FK User)
- `current_phase` (FK Phase, nullable until phases are created)

**ProjectMember**
- `project` (FK), `user` (FK), `project_role` (choice: PM, DEVELOPER, PENTESTER)
- unique together (`project`, `user`)

The project role is separate from the global role so a user can be a Developer on one project and a Pentester on another. Permissions combine both: a user acts with their project role inside a project, and the global role only grants site-wide powers (Admin, creating projects).

**Phase**
- `project` (FK), `kind`: REQUIREMENTS, DESIGN, CODING, TESTING, DEPLOYMENT, MAINTENANCE
- `order` (int 1–6), `status`: NOT_STARTED, IN_PROGRESS, COMPLETED
- unique together (`project`, `kind`)

**ChecklistItem** (seeded from fixture; global templates)
- `phase_kind`, `code` (e.g. `REQ-01`), `text`, `guidance`, `required` (bool), `owasp_ref` (nullable, e.g. `A01:2021`)

**ChecklistResponse** (one per project × checklist item)
- `project` (FK), `item` (FK ChecklistItem), `done` (bool), `evidence` (text), `completed_by` (FK User, nullable), `completed_at`
- unique together (`project`, `item`)

**Vulnerability**
- `project` (FK), `phase` (FK Phase, nullable)
- `title`, `description`, `affected_component`
- `cvss_vector` (char, CVSS:3.1/... format), `cvss_score` (decimal, computed), `severity`: CRITICAL, HIGH, MEDIUM, LOW, INFO (computed)
- `owasp_category` (choice from OWASP Top 10 2021: A01 to A10)
- `status`: OPEN, FIXED, VERIFIED, CLOSED
- `source`: MANUAL or ZAP
- `reporter` (FK User), `assignee` (FK User, nullable)
- `scan` (FK Scan, nullable), `zap_alert_id` (char, nullable)
- `due_date` (date, nullable): stands in for re-test scheduling

**VulnerabilityEvent** (audit trail for status changes)
- `vulnerability` (FK), `from_status`, `to_status`, `actor` (FK User), `note`, `created_at`

**ScanTarget**
- `project` (FK), `url` (URL), `environment`: STAGING or LOCAL_TEST (production is rejected by validation)
- `authorization_confirmed` (bool, must be True to save)
- `authorized_by` (char), `authorized_at` (datetime)

**Scan**
- `project` (FK), `target` (FK ScanTarget), `tool`: ZAP
- `status`: QUEUED, RUNNING, DONE, FAILED
- `started_at`, `finished_at`, `requested_by` (FK User)
- `raw_result` (JSON), `error_message` (text)

**Report**
- `project` (FK), `generated_by` (FK User), `generated_at`, `file` (FileField under `media/reports/`)

---

## 5. Business rules

### 5.1 Phase gate (the core rule)

Implemented in exactly one function: `phases/services.py::can_advance(project, phase) -> GateResult`. `GateResult` holds `allowed: bool` and `reasons: list[str]` so the UI can explain a block.

A phase can advance only when all of these hold:
1. Every `ChecklistItem` with `required=True` for that phase has a `ChecklistResponse` with `done=True` and non-empty `evidence`.
2. No Vulnerability with `phase=this phase` has status OPEN or FIXED and severity CRITICAL or HIGH. (A FIXED finding is not verified yet, so it still blocks.)
3. The phase is not already COMPLETED.

Waterfall projects: phases advance strictly in order. Advancing is only forward. Completing phase N makes phase N+1 IN_PROGRESS.

Agile projects: the same gate applies to each phase, but a PM may reopen an earlier phase (for a new iteration). Reopening sets the phase back to IN_PROGRESS and is recorded as an event.

Every gate decision (allowed or blocked) is written to an audit log so the decision can be shown in Chapter 4.

### 5.2 Severity from CVSS v3.1

- The user enters a CVSS v3.1 vector string. The app computes the base score with the `cvss` library and stores it.
- Severity mapping (NVD scale), applied at the boundaries:
  - 0.0 → INFO
  - 0.1–3.9 → LOW
  - 4.0–6.9 → MEDIUM
  - 7.0–8.9 → HIGH
  - 9.0–10.0 → CRITICAL
- Invalid vectors are rejected with a form error. Severity is never accepted from the form.
- ZAP alerts have a risk level (High, Medium, Low, Informational) but no vector. For ZAP-imported findings, map the ZAP risk to a default vector stored with the finding and mark `source=ZAP`. Document this approximation in Chapter 3 and Chapter 5. It is an honest limitation to state, not hide.

### 5.3 Status workflow

Allowed transitions only:
- OPEN → FIXED (Developer, Admin)
- FIXED → VERIFIED (Pentester, Admin)
- VERIFIED → CLOSED (Pentester, Admin)
- FIXED → OPEN (Pentester, Admin: fix rejected on re-test)
- VERIFIED → OPEN (Pentester, Admin: regression)

Every transition creates a `VulnerabilityEvent`. Illegal transitions raise `InvalidTransition`. Transition logic lives in `vulns/services.py::transition(vuln, new_status, actor, note)`. Nothing else changes `status`.

### 5.4 Risk score

Defined once in `dashboard/services.py` with a docstring. Weights: Critical 10, High 5, Medium 2, Low 1, Info 0. Raw risk = sum of weights for all findings in status OPEN or FIXED. Project risk score = min(100, raw risk). Verified and Closed findings do not count.

The formula is deliberately simple so it can be explained in the viva. Its limitations (for example, it does not weight by asset value) go in Chapter 5.

### 5.5 Scan safety (non-negotiable)

- A scan can only target a `ScanTarget` belonging to the project, with `authorization_confirmed=True`.
- `ScanTarget.clean()` rejects any URL whose host is not on the allowlist in settings (`SCAN_ALLOWED_HOSTS`, default `localhost`, `127.0.0.1`, `host.docker.internal`, and the Juice Shop container name).
- The scan task re-checks these conditions before starting. A check at save time is not enough, because a target could be edited later.
- Only ZAP runs scans. Scans cannot be started from arbitrary shell input. No user-supplied strings are passed to a shell.
- Scan duration is capped (default 15 minutes, set in settings). On timeout the scan is marked FAILED with a clear message.

### 5.6 Checklist content (seeded)

Write these fixtures in `phases/fixtures/checklists.json`. Each item needs `code`, `text`, `guidance`, `required`, and `owasp_ref` where relevant.

- **Requirements:** threat model drafted (STRIDE); security requirements documented; data classification defined; authentication requirements stated; compliance needs identified (required: all except compliance).
- **Design:** architecture diagram reviewed; trust boundaries identified; attack surface listed; authentication and session design reviewed; input validation strategy defined; secrets management approach chosen.
- **Coding:** input validation on all user-controlled data; output encoding in templates; parameterized queries or ORM only; no hardcoded secrets (checked); dependencies scanned for known vulnerabilities; error messages do not leak stack traces; access control checked on every endpoint.
- **Testing:** DAST scan run against a registered target; OWASP Top 10 checklist completed; manual test cases for authentication and authorization; findings triaged and logged; regression tests for fixed issues.
- **Deployment:** `python manage.py check --deploy` passes; DEBUG disabled; secrets in environment variables; HTTPS enforced in production settings; security headers configured; least-privilege database user; backups configured.
- **Maintenance:** monitoring and logging enabled; re-test scheduled (due date set on open findings); patch process documented; incident response contact recorded.

Mark `required=True` for the core items in each phase. Keep 5–7 items per phase so the list is manageable to demonstrate.

---

## 6. URL structure

```
/accounts/login/ , /accounts/logout/
/                                  dashboard home (project list)
/projects/                         list
/projects/new/                     create (Admin, PM)
/projects/<id>/                    detail: phases, members, summary
/projects/<id>/members/            add / remove (Admin, PM)
/projects/<id>/phases/<kind>/      checklist view and evidence form
/projects/<id>/phases/<kind>/advance/   POST, phase gate
/projects/<id>/vulns/              list with filters
/projects/<id>/vulns/new/          create finding (Pentester)
/projects/<id>/vulns/<vid>/        detail with event history
/projects/<id>/vulns/<vid>/transition/  POST status change
/projects/<id>/targets/            register scan target
/projects/<id>/scans/              list and status
/projects/<id>/scans/new/          start ZAP scan (Pentester)
/projects/<id>/scans/<sid>/        results and imported findings
/projects/<id>/dashboard/          metrics and charts
/projects/<id>/report/             generate and download PDF
/admin/                            Django admin
```

All POST endpoints use Django's CSRF protection. No GET request changes state.

---

## 7. Build phases

Each phase below has goals, tasks, and a definition of done. Do not start a phase until the previous one's definition of done is met and committed.

### Phase 0: Environment and repository (Week 1)

**Goals.** A working development environment and a repository ready for disciplined work.

**Tasks.**
- Create the repository `secure-sdlc` with `git init`. Add `.gitignore` for Python, Django, `.venv`, `media/`, `*.sqlite3`, `.env`.
- Create a virtual environment and install: `django`, `django-q2`, `zapv2`, `cvss`, `weasyprint` (or `xhtml2pdf` on Windows), `python-dotenv`, `pytest-django` (optional, if used consistently).
- Create the project with `django-admin startproject config .`
- Split settings into `config/settings/base.py`, `dev.py`, `prod.py`. Read secrets from environment variables through `python-dotenv`.
- Add `CLAUDE.md`, `docs/decisions.md` (empty table: date, decision, reason), and `README.md` with setup steps.
- Pull Docker images: `docker pull zaproxy/zap-stable` and `docker pull bkimminich/juice-shop`.
- Start Juice Shop and confirm it loads in a browser at `http://localhost:3000`.
- Start ZAP in daemon mode and confirm the API responds at `http://localhost:8080`.

**Definition of done.** `python manage.py runserver` starts with no errors. Juice Shop and ZAP both respond locally. The first commit is made: `P0: project setup`.

### Phase 1: Accounts and authentication (Weeks 1–2)

**Goals.** Users can log in, and each user has a role.

**Tasks.**
- Create the `accounts` app. Add a custom `User` model with `role` and set `AUTH_USER_MODEL` before the first migration.
- Implement login, logout, and password change using Django's built-in views with custom templates.
- Create `accounts/permissions.py` with a global role helper, `has_global_role(user, *roles)`.
- Create a management command `seed_demo_users` that creates one user per role with known demo passwords (for testing and Chapter 4 screenshots only; documented as such).
- Base template with navigation, showing the logged-in user and role.
- Admin site registration of User with role editing.

**Tests.**
- Unauthenticated access to `/projects/` redirects to login.
- Each role is created correctly and `has_global_role` returns the expected result.

**Definition of done.** A user logs in and sees the base layout with their role. Tests pass. Commit: `P1: accounts and roles`.

### Phase 2: Projects and membership (Weeks 3–4)

**Goals.** Projects can be created, given a SDLC model, and staffed with members.

**Tasks.**
- Create the `projects` app with `Project` and `ProjectMember` models and migrations.
- On project creation, automatically create six `Phase` rows (status NOT_STARTED) and set the first phase IN_PROGRESS for Waterfall. Set current_phase accordingly.
- Views: list (only projects the user belongs to, or all for Admin), create (Admin and PM), detail.
- Member management: add a user with a project role, remove a member. Enforce that a project always keeps at least one PM.
- Project membership check as a reusable mixin or decorator, `ProjectMemberRequiredMixin`, used by every project-scoped view. Non-members receive 404.
- Forms with validation: name required, SDLC model required.

**Tests.**
- Creating a project creates six phases in the correct order.
- A Developer cannot create a project (403).
- A non-member requesting a project detail gets 404.
- Removing the last PM is refused.
- Adding the same user twice to a project is refused.

**Definition of done.** All project tests pass. Manual check: create a project, add a Developer and a Pentester, log in as each, and confirm each sees only their projects.

### Phase 3: Phases, checklists, and the phase gate (Weeks 5–6)

**Goals.** Each phase has a checklist, and advancement is gated by the rules in section 5.1.

**Tasks.**
- Create the `phases` app with `ChecklistItem` and `ChecklistResponse` models.
- Write `phases/fixtures/checklists.json` using the content in section 5.6. Load it with a data migration or the `loaddata` command, and document which one in README.
- Phase detail view: lists checklist items, shows done state and evidence, and allows members (Developer, Pentester, PM) to tick items and add evidence. Evidence is required before an item can be marked done.
- Implement `phases/services.py::can_advance()` returning `GateResult`. It must check the required items and the open Critical or High findings. The vulnerability check depends on the Vulnerability model, so implement the Vulnerability model in this phase (fields only) to avoid circular work; its workflow comes in Phase 4.
- Advance view (POST only): calls `can_advance()`. If allowed, marks the phase COMPLETED and the next phase IN_PROGRESS (Waterfall) or leaves ordering open (Agile). If blocked, shows each reason in a message.
- Gate audit log: a `GateDecision` model storing project, phase, allowed, reasons (JSON), actor, timestamp.
- Waterfall strict ordering and Agile reopen action, PM-only, recorded as a GateDecision.

**Tests.**
- Advance is allowed when all required items are done with evidence and no blocking findings exist.
- Advance is blocked when a required item is not done.
- Marking an item done without evidence is refused.
- Advance is blocked by an open High finding in that phase.
- Advance is not blocked by a High finding in a different phase.
- A FIXED Critical finding still blocks (not yet verified).
- A Developer cannot call the advance endpoint (403).
- Waterfall cannot skip a phase.
- Every attempt writes a GateDecision.

**Definition of done.** All gate tests pass, and the rule is documented in `docs/decisions.md`. Commit: `P3: phases, checklists, phase gate`.

### Phase 4: Vulnerability management (Weeks 7–8)

**Goals.** Findings are recorded with CVSS-derived severity and move through a controlled workflow.

**Tasks.**
- Complete the Vulnerability model and create `VulnerabilityEvent`.
- Create `vulns/cvss.py`: parse and validate a CVSS:3.1 vector, compute the base score via the `cvss` library, map score to severity (section 5.2).
- Vulnerability create form (Pentester only): title, description, affected component, CVSS vector (with a help link to the FIRST calculator), OWASP category, linked phase, optional assignee and due date. The form computes and shows the score and severity on submit.
- `vulns/services.py::transition()` enforcing section 5.3. Every transition creates a VulnerabilityEvent.
- Vulnerability list with filters for severity, status, and phase. Detail page shows the event timeline.
- Transition buttons shown only when the current user is allowed to make that transition.

**Tests.**
- Score-to-severity boundaries: 0.0 INFO, 3.9 LOW, 4.0 MEDIUM, 6.9 MEDIUM, 7.0 HIGH, 8.9 HIGH, 9.0 CRITICAL, 10.0 CRITICAL.
- An invalid vector is rejected.
- Severity cannot be set through the form (posted value is ignored).
- Each allowed transition succeeds for the correct role.
- Illegal transitions (for example OPEN → VERIFIED, or Developer making FIXED → VERIFIED) are rejected.
- Each transition writes one VulnerabilityEvent.

**Definition of done.** Vulnerability tests pass. A manual walkthrough from Pentester creating a finding to Developer fixing it to Pentester verifying and closing it works end to end. Commit: `P4: vulnerabilities and status workflow`.

### Phase 5: Scanner integration with OWASP ZAP (Weeks 9–10)

**Goals.** A registered target can be scanned with ZAP and the results are imported as findings.

**Tasks.**
- Create the `scans` app with `ScanTarget` and `Scan` models.
- `ScanTarget` form with the authorization checkbox (required) and environment choice. `clean()` enforces the allowlist and rejects production-looking URLs (section 5.5).
- Create `scans/zap_client.py`: a wrapper around `zapv2.ZAPv2` with methods `start_spider(url)`, `wait_for_spider()`, `start_active_scan(url)`, `wait_for_ascan()`, `get_alerts(url)`. Read the ZAP address from settings. Include a timeout on every wait.
- Create `scans/tasks.py::run_zap_scan(scan_id)` as a Django-Q task. It re-checks authorization and the allowlist, marks the scan RUNNING, runs the wrapper, stores raw alerts in `raw_result`, creates Vulnerability records, and marks the scan DONE or FAILED.
- Mapping from ZAP alerts to Vulnerability: title from `alert`, description from `description`, affected component from `url`, severity from ZAP `risk` mapped to a default CVSS vector (documented approximation, section 5.2), OWASP category from ZAP's CWE or tag where possible, `source=ZAP`, `zap_alert_id` set. Deduplicate on (scan target, zap_alert_id, url).
- Scan start view (Pentester): queues the task. Scan list and detail pages show status and imported findings. Pages poll the status every few seconds with a small JavaScript fetch.
- Settings: `ZAP_API_URL`, `ZAP_API_KEY` (disabled in dev, read from env in prod), `SCAN_TIMEOUT_SECONDS`, `SCAN_ALLOWED_HOSTS`.
- Start the worker with `python manage.py qcluster` and document it in README.

**Tests (with the ZAP client mocked).**
- A scan on an unregistered or unauthorized target is refused before the task is queued.
- A target not on the allowlist is refused by `clean()`.
- The task re-checks authorization and refuses if it has been revoked.
- Alerts are converted to Vulnerability records correctly.
- Duplicate alerts are not imported twice.
- A ZAP connection failure marks the scan FAILED with a readable message.
- A timeout marks the scan FAILED.

**Integration check (manual, not in CI).** Start Juice Shop in Docker, register `http://localhost:3000` as a target with authorization, run a scan, and confirm that findings appear. Save the scan result and screenshots for Chapter 4.

**Definition of done.** Mocked tests pass. The manual integration check succeeds once and is recorded. Commit: `P5: ZAP integration and background scans`.

### Phase 6: Dashboard (Week 11)

**Goals.** A project's security status is visible at a glance.

**Tasks.**
- `dashboard/services.py`: functions `count_by_severity(project)`, `count_by_status(project)`, `risk_score(project)` (section 5.4, with docstring), `phase_progress(project)` (checklist completion percentage per phase).
- Dashboard view and template: summary cards (total findings, open Critical/High, risk score, current phase), Chart.js charts (severity doughnut, status bar, phase progress bar).
- Chart data passed as JSON from the view, no inline computation in templates.
- Global dashboard for Admin showing all projects with their risk scores.

**Tests.**
- Counts and risk score match a hand-calculated fixture with known findings.
- Verified and Closed findings are excluded from the risk score.
- A user who is not a member cannot see a project's dashboard.

**Definition of done.** Tests pass. The numbers on screen match the fixture. Commit: `P6: dashboard and metrics`.

### Phase 7: PDF reporting (Week 12, first half)

**Goals.** One click produces a PDF report suitable for a client or examiner.

**Tasks.**
- Create the `reports` app with the `Report` model.
- HTML template `reports/templates/reports/report.html` with sections:
  1. Cover page: project name, date, SDLC model, generated by
  2. Executive summary: findings count, risk score, phase status, plain-language overall assessment generated from the numbers
  3. Technical findings: each finding with severity, CVSS vector and score, affected component, description, status, and event history
  4. OWASP Top 10 (2021) compliance table: each category with finding count and status
  5. Phase gate record: each phase, its status, and gate decisions
  6. Appendix: scan summaries (target, tool, date, alert count)
- `reports/services.py::generate_report(project, user)` renders the template and writes the PDF with WeasyPrint or xhtml2pdf, saves to `MEDIA_ROOT/reports/`, and creates a Report record.
- Download view, restricted to project members with the Pentester or PM role.

**Tests.**
- The generated file exists, is non-empty, and begins with the `%PDF` header.
- The rendered HTML contains every finding title for the project (test the HTML before PDF conversion for speed).

**Definition of done.** A PDF for a seeded project opens and contains all findings. Commit: `P7: PDF reports`.

### Phase 8: Hardening, testing, and documentation (Week 12, second half)

**Goals.** The system is secure by its own standards, tested, and documented for Chapter 4.

**Tasks.**
- Run `python manage.py check --deploy` and resolve every warning, or document why it does not apply.
- Walk the permission matrix (section 3) against the actual app. Write a test for each cell that is "No".
- Check every POST endpoint for CSRF and every project view for membership checks. Use a small script or grep to list views without the membership mixin and justify each.
- Confirm secrets are not in the repository (`git log -p | grep -i secret` returns nothing meaningful).
- Confirm error pages do not show stack traces when DEBUG is False.
- Run the full test suite and record the result for Chapter 4.
- Produce the test case table (ID, description, input, expected, actual, pass/fail) from the test suite.
- Capture screenshots: login, project list, phase gate blocked and allowed, vulnerability workflow, ZAP scan results, dashboard, PDF report.
- Update README with setup, demo accounts, how to run ZAP and the worker, and how to reproduce the demo.

**Definition of done.** `check --deploy` is clean or justified. Test suite passes. Screenshots and test table are saved in `docs/chapter4/`. Commit: `P8: hardening and documentation`.

---

## 8. Testing strategy

- **Unit tests** for services: `can_advance`, CVSS mapping, `transition`, risk score, scan safety checks. These are the examiner-facing logic and must have the most coverage.
- **View tests** for permissions: each role against each protected endpoint, expecting 200, 302, 403, or 404 as specified.
- **Mocked integration tests** for the ZAP wrapper. The real ZAP is never called from automated tests.
- **Manual end-to-end test** against Juice Shop, documented once in Phase 5 and again in Phase 8.
- Run `python manage.py test` before every commit. Do not commit with failing tests.

---

## 9. Coding standards

- Follow PEP 8. Use type hints on service functions.
- Business logic goes in `services.py` modules. Views only handle request parsing, permission checks, calling services, and rendering.
- No raw SQL. Use the ORM.
- No `eval`, `exec`, `shell=True`, or string-built shell commands anywhere.
- User input is never placed in a URL or command without validation.
- Templates auto-escape. Do not use `|safe` on user-supplied content.
- Every model has a `__str__`. Every service function has a docstring that states its rule.
- Migrations are committed. Do not edit an applied migration; create a new one.
- Keep functions short. If a function needs a comment to explain what it does, split it.

---

## 10. Git conventions

- Branch per phase: `phase/0-setup`, `phase/1-accounts`, and so on. Merge to `main` after the phase's definition of done is met.
- Commit messages: `P<n>: <short description>` for milestones, and normal imperative messages for smaller commits within a phase.
- Never commit `.env`, `*.sqlite3`, `media/`, or `.venv/`.

---

## 11. Working rules for Claude Code

- At the start of each session, read this file and `docs/decisions.md`. State which phase you are working on before changing any file.
- Use plan mode for any phase larger than a single model or view. Show the plan and wait for approval before writing code.
- Write tests for a feature before or alongside its implementation, not after the phase is finished.
- Do not change the phase-gate rule, the status workflow, the permission matrix, or the scan safety rules without first updating this file and recording the change in `docs/decisions.md`.
- Do not add features outside the current phase. If something useful occurs to you, add it to a "Future work" list in `docs/decisions.md` instead.
- When a choice is not covered by this file, pick the simplest option that satisfies the rules, and record it in `docs/decisions.md`.
- Ask before deleting files, dropping data, or running any command that touches a system outside this project folder.
- Never scan a target that is not registered in the app with authorization confirmed. Never suggest scanning production or any third-party site.

---

## 12. Open decisions for supervisor review

These are assumptions made in this specification. Confirm or change each one before Phase 0 begins.

1. Agile projects allow reopening earlier phases (section 5.1). Alternative: Agile uses the same strict ordering as Waterfall.
2. Only Juice Shop and DVWA are allowed as scan targets, plus anything on localhost. Alternative: allow registered staging URLs of the student's own applications.
3. ZAP-imported findings use a default CVSS vector derived from ZAP risk level. Alternative: require a manual CVSS score for each imported finding before it counts toward risk.
4. The risk score uses fixed weights (10, 5, 2, 1, 0). Alternative: weights configurable by Admin.
5. Report generation is available to Pentesters and PMs only. Developers are excluded.
6. Operating system: WeasyPrint is chosen for Linux and macOS; xhtml2pdf for Windows. Confirm the OS before Phase 0 so the correct install line is used.

---

## 13. Definition of done for the whole project

- All eight phases complete, with their commits merged to `main`.
- Test suite passes.
- Demo runs end to end: create a project, complete checklists, pass a gate, register Juice Shop as a target, run a ZAP scan, triage and verify findings, view the dashboard, and download a PDF report.
- `docs/decisions.md`, README, and `docs/chapter4/` are complete and match the built system.
- Chapter 3 diagrams (use case, DFD, ERD, framework) match sections 3, 4, and 5 of this file.

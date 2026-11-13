# SecureSDLC Framework

A Django web dashboard that puts penetration testing into every stage of the software
development lifecycle, enforced by a phase-gate system.

A project moves through six SDLC phases (Requirements, Design, Coding, Testing,
Deployment, Maintenance). Each phase has a security checklist; a phase cannot advance
until its required checklist items are complete with evidence and no unverified
Critical or High findings remain open. OWASP ZAP is integrated rather than
reimplemented.


Decisions that the specification does not cover are recorded in
[docs/decisions.md](docs/decisions.md).

---

## Requirements

| Tool | Version | Notes |
|---|---|---|
| Python | 3.13 | Installed on this machine as the `py -3.13` launcher. CLAUDE.md requires 3.11+. |
| Git | any recent | |
| Docker Desktop | running | Needed for OWASP ZAP and Juice Shop. The daemon must be started, not just the app. |

> **Windows note.** `python` and `python3` are not on PATH on the build machine. Use
> the launcher (`py -3.13`) to create the virtual environment, and the venv's own
> interpreter (`.venv/Scripts/python.exe`) for everything after that. Every command
> below is written that way so it works as-is.

---

## Setup

### 1. Clone and create the environment

```bash
git clone https://github.com/Oladelesunkanmi/SecureSDLC.git
cd secure-sdlc
py -3.13 -m venv .venv
```

### 2. Install dependencies


```bash
.venv/Scripts/python.exe -m pip install --upgrade pip
```

```bash
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

### 3. Configure the environment

```bash
cp .env.example .env
```

`.env` is git-ignored. For local development the defaults work unchanged; leave
`DJANGO_SECRET_KEY` as the placeholder or generate a real one:

```bash
.venv/Scripts/python.exe -c "from django.core.management.utils import get_random_secret_key as k; print(k())"
```

### 4. Migrate and run

```bash
.venv/Scripts/python.exe manage.py migrate
```

```bash
.venv/Scripts/python.exe manage.py runserver
```

The app is at <http://localhost:8000/>. `manage.py` defaults to
`config.settings.dev` (DEBUG on, SQLite). Production uses
`DJANGO_SETTINGS_MODULE=config.settings.prod`.

### 5. Create demo accounts or an admin user

To create standard accounts for each role:

```bash
.venv/Scripts/python.exe manage.py seed_demo_users
```

Or seed an entire end-to-end demonstration project with checklists, vulnerabilities, scan targets, and reports:

```bash
.venv/Scripts/python.exe manage.py seed_demo_project
```

Or create a manual superuser:

```bash
.venv/Scripts/python.exe manage.py createsuperuser
```

---

## Demo Accounts

All demo accounts share the password `demo123`:

| Username | Global Role | Allowed Actions |
|---|---|---|
| `admin` | Admin | Full platform administrative access, user management, global risk dashboard |
| `pm` | Project Manager | Project creation, member management, phase gate advancement and reopening |
| `dev` | Developer | Complete checklist items with evidence, transition findings to `FIXED` |
| `pentester` | Pentester | Log findings, re-test/verify (`VERIFIED`, `CLOSED`), register targets, run ZAP scans |

---

## End-to-End Demo Reproduction

Follow these steps to demonstrate the framework end-to-end:

1. **Seed Demo Project:**
   ```bash
   .venv/Scripts/python.exe manage.py seed_demo_project
   ```
2. **Phase Gate Evaluation:**
   - Log in as `pm` (<http://localhost:8000/accounts/login/>).
   - Navigate to the Requirements phase: all items are complete with evidence, and the gate was successfully advanced.
   - Navigate to the Design phase: the gate is **blocked** with clear violation notices because required items are pending and an open Critical vulnerability exists.
3. **Vulnerability Remediation Workflow:**
   - Log in as `dev`: open the Critical finding. Notice the developer can click **Mark as Fixed** and add remediation notes.
   - Log in as `pentester`: open the Fixed finding. Notice the pentester can click **Verify Fix** (after re-testing) or **Reject & Re-open**.
4. **DAST Scanning (Juice Shop & ZAP):**
   - Start Docker targets (`juice-shop` on port 3000, `zap` on port 8080).
   - Start background worker: `.venv/Scripts/python.exe manage.py qcluster`.
   - As `pentester`, navigate to **Scan Targets**, confirm authorization for `http://localhost:3000`, and trigger a scan.
   - Monitor real-time status polling; upon completion, inspect alerts and click **Import Finding** to convert an alert into a tracked defect in the Testing phase.
5. **Security Risk Dashboard:**
   - View real-time risk scores (calculated per §5.4), severity doughnut chart, status bar chart, and phase progress bars.
   - Log in as `admin` and visit `/dashboard/` to view cross-project risk rankings.
6. **Executive PDF Report:**
   - As `pm` or `pentester`, click **Export PDF Report** to download the comprehensive 6-section assessment report.

---

## Security tooling (Docker)

Start Docker Desktop first — the daemon does not start with the app.

### Pull the images

```bash
docker pull zaproxy/zap-stable
```

```bash
docker pull bkimminich/juice-shop
```

### Juice Shop (the scan target)

```bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

Open <http://localhost:3000> — the Juice Shop storefront should load. It is
deliberately vulnerable and must never be exposed outside localhost.

### OWASP ZAP (the scanner)

```bash
docker run -d --name zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

Check the API responds:

```bash
curl "http://localhost:8080/JSON/core/view/version/"
```

This returns a JSON object containing the ZAP version. The API key is disabled for
local development only; a production deployment must set `ZAP_API_KEY` and start ZAP
without `api.disablekey=true`.

### Background worker (from Phase 5)

ZAP scans run in a Django-Q2 worker so a scan does not block a request:

```bash
.venv/Scripts/python.exe manage.py qcluster
```

Keep it running in its own terminal whenever scans are needed.

---

## Running the tests

```bash
.venv/Scripts/python.exe manage.py test
```

The suite must pass before every commit (CLAUDE.md section 8).

---

## Project layout

```
config/                 Django project: settings split into base / dev / prod
  settings/base.py        shared settings, env loading, Django-Q, ZAP and scan safety
  settings/dev.py         DEBUG on, SQLite, console email
  settings/prod.py        DEBUG off, HTTPS and cookie hardening, fails on missing secret
docs/decisions.md       every decision the specification does not cover, with reasons
CLAUDE.md               the specification: rules, data model, build phases
```

Apps are added per phase: `accounts`, `projects`, `phases`, `vulns`, `scans`,
`dashboard`, `reports`.

---

## Build progress

| Phase | Scope | Status |
|---|---|---|
| 0 | Environment and repository | Completed |
| 1 | Accounts and authentication | Completed |
| 2 | Projects and membership | Completed |
| 3 | Phases, checklists, phase gate | Completed |
| 4 | Vulnerability management | Completed |
| 5 | ZAP scanner integration | Completed |
| 6 | Dashboard | Completed |
| 7 | PDF reporting | Completed |
| 8 | Hardening and documentation | Completed |

---

## Ethical use

Scanning is restricted to targets registered in the app with authorization confirmed,
and only to hosts on the `SCAN_ALLOWED_HOSTS` allowlist (localhost, the Juice Shop
container, and host.docker.internal by default). Never point the scanner at production
systems or third-party sites.

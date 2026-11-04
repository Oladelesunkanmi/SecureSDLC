# Decisions Log

Every decision that CLAUDE.md does not already cover is recorded here with its reason.
Changes to the phase-gate rule, the status workflow, the permission matrix, or the scan
safety rules must be recorded here **before** the code changes.

| Date | Decision | Reason |
|---|---|---|
| 2026-11-04 | Python 3.13.14 used instead of 3.11, via the `py -3.13` launcher into `.venv`. | It is the interpreter installed on the build machine. CLAUDE.md requires 3.11+; Django 5.x supports 3.13. The venv is pinned so the exact interpreter is reproducible. Note that bare `python`/`python3` are not on PATH on this machine — always use the venv. |
| 2026-11-04 | PDF generation uses `xhtml2pdf`, not WeasyPrint. | Resolves open decision 6 in CLAUDE.md §12: the build machine runs Windows 10, and WeasyPrint needs GTK libraries that are not present on Windows. `xhtml2pdf` is pure Python and needs no system dependencies. |
| 2026-11-04 | `pytest-django` is **not** installed. All tests use Django's own `TestCase`. | CLAUDE.md §8 lists `TestCase` and `unittest.mock` as the testing tools. Installing pytest as well would give two ways to run the suite for no benefit at this scale. Keeps `manage.py test` as the single command in §8 that must pass before every commit. |
| 2026-11-04 | Settings are split into `config/settings/{base,dev,prod}.py`, with `DJANGO_SETTINGS_MODULE` defaulting to `config.settings.dev` in `manage.py`. | CLAUDE.md §7 Phase 0 requires the split. Defaulting to `dev` means `manage.py runserver` works with no environment variable set, while `prod.py` must be selected explicitly. |
| 2026-11-04 | Secrets are read from environment variables via `python-dotenv`, which loads a git-ignored `.env` from the project root. A committed `.env.example` lists every variable with a safe placeholder. | CLAUDE.md §7 Phase 0 and §8 Phase 8 both require secrets outside the repository. The example file makes setup reproducible without leaking real values. |
| 2026-11-04 | The ZAP Python client is installed from PyPI as **`zaproxy`**, not `zapv2`. The module is still imported as `import zapv2`; the distribution and the module have different names. | CLAUDE.md §7 Phase 0 lists `zapv2` in the install line, but no package by that name exists on PyPI — `pip` reports `from versions: none` and aborts the entire resolution, so **nothing** installs. `zaproxy` is the official distribution that provides the `zapv2` module. Its upper version bound is left open deliberately: a guessed bound is what caused this failure, so the exact version is pinned after install instead. |
| 2026-11-04 | Open decisions 1–5 in CLAUDE.md §12 (Agile reopen, scan target allowlist, ZAP default CVSS vectors, risk weights, report access) remain **unconfirmed** pending supervisor review. | They affect Phases 3 and 5–7, not Phase 0. Implementing them provisionally and recording the change later is cheaper than blocking setup. Each will be logged here when confirmed. |
| 2026-11-04 | Phase 3 Phase Gate and Checklist Implementation: Phase gate enforced strictly in `phases/services.py::can_advance()` returning `GateResult`. Checklists seeded via `phases/fixtures/checklists.json` containing 34 items across 6 SDLC phases. Minimal `vulns.Vulnerability` model created in Phase 3 to allow gate checks for OPEN/FIXED CRITICAL/HIGH findings without circular dependency. | Adheres to CLAUDE.md §5.1, §5.6, and §7 (Phase 3). Every evaluation is persisted to `GateDecision` audit log. Agile phase reopen is supported for Agile projects only. |
| 2026-11-05 | Phase 4 Vulnerability Management and Status Workflow: CVSS:3.1 base score calculated and validated using `cvss.CVSS3`. Severity derived strictly via NVD scale boundaries (0.0 INFO, 0.1-3.9 LOW, 4.0-6.9 MEDIUM, 7.0-8.9 HIGH, 9.0-10.0 CRITICAL). User-posted severity values are ignored. Status transitions enforced exclusively in `vulns/services.py::transition()` (OPEN -> FIXED by Developer/Admin, FIXED -> VERIFIED/OPEN and VERIFIED -> CLOSED/OPEN by Pentester/Admin), with each transition logging a `VulnerabilityEvent` audit entry. | Enforces CLAUDE.md §5.2, §5.3, and §7 (Phase 4). |

## Future work

Ideas raised while building that are outside the current phase. Not implemented.

- (none yet)

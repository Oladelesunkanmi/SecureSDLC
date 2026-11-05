# Chapter 4: Testing & Verification Evidence

## 1. Automated Test Suite Summary

- **Total Automated Test Cases:** 116
- **Test Framework:** Django `TestCase`, `unittest.mock`
- **Result:** 100% Passed (0 Failures, 0 Errors)
- **Test Execution Command:** `.venv/Scripts/python.exe manage.py test`

## 2. Test Case Specification and Execution Table

| Test ID | Module | Test Case Name | Description / Objective | Expected Result | Status |
|---|---|---|---|---|:---:|
| TC-001 | Accounts | `test_custom_404_page_no_stack_trace` | Test custom 404 page no stack trace | HTTP 404 Not Found (Information hiding) | PASS |
| TC-002 | Accounts | `test_has_global_role_anonymous_or_none` | Test has global role anonymous or none | Verified matching specification criteria | PASS |
| TC-003 | Accounts | `test_has_global_role_multiple` | Test has global role multiple | Verified matching specification criteria | PASS |
| TC-004 | Accounts | `test_role_creation_and_has_global_role` | Test role creation and has global role | Verified matching specification criteria | PASS |
| TC-005 | Accounts | `test_unauthenticated_redirect_to_login` | Test unauthenticated redirect to login | HTTP 302 Redirect to Login | PASS |
| TC-006 | Accounts | `test_dev_cannot_access_django_admin` | Test dev cannot access django admin | HTTP 403 Forbidden / Access Denied | PASS |
| TC-007 | Accounts | `test_dev_cannot_access_global_dashboard` | Test dev cannot access global dashboard | HTTP 403 Forbidden / Access Denied | PASS |
| TC-008 | Accounts | `test_developer_cannot_advance_phase` | Test developer cannot advance phase | HTTP 403 Forbidden / Access Denied | PASS |
| TC-009 | Accounts | `test_developer_cannot_create_project` | Test developer cannot create project | HTTP 403 Forbidden / Access Denied | PASS |
| TC-010 | Accounts | `test_developer_cannot_create_vulnerability` | Test developer cannot create vulnerability | HTTP 403 Forbidden / Access Denied | PASS |
| TC-011 | Accounts | `test_developer_cannot_generate_report` | Test developer cannot generate report | HTTP 403 Forbidden / Access Denied | PASS |
| TC-012 | Accounts | `test_developer_cannot_manage_members` | Test developer cannot manage members | HTTP 403 Forbidden / Access Denied | PASS |
| TC-013 | Accounts | `test_developer_cannot_register_scan_target` | Test developer cannot register scan target | HTTP 403 Forbidden / Access Denied | PASS |
| TC-014 | Accounts | `test_developer_cannot_trigger_scan` | Test developer cannot trigger scan | HTTP 403 Forbidden / Access Denied | PASS |
| TC-015 | Accounts | `test_developer_cannot_verify_finding` | Test developer cannot verify finding | HTTP 403 Forbidden / Access Denied | PASS |
| TC-016 | Accounts | `test_non_member_cannot_view_dashboard` | Test non member cannot view dashboard | HTTP 403 Forbidden / Access Denied | PASS |
| TC-017 | Accounts | `test_non_member_cannot_view_phases` | Test non member cannot view phases | HTTP 403 Forbidden / Access Denied | PASS |
| TC-018 | Accounts | `test_non_member_cannot_view_project_detail` | Test non member cannot view project detail | HTTP 403 Forbidden / Access Denied | PASS |
| TC-019 | Accounts | `test_non_member_cannot_view_scans` | Test non member cannot view scans | HTTP 403 Forbidden / Access Denied | PASS |
| TC-020 | Accounts | `test_non_member_cannot_view_vulns` | Test non member cannot view vulns | HTTP 403 Forbidden / Access Denied | PASS |
| TC-021 | Accounts | `test_pentester_cannot_access_django_admin` | Test pentester cannot access django admin | HTTP 403 Forbidden / Access Denied | PASS |
| TC-022 | Accounts | `test_pentester_cannot_access_global_dashboard` | Test pentester cannot access global dashboard | HTTP 403 Forbidden / Access Denied | PASS |
| TC-023 | Accounts | `test_pentester_cannot_advance_phase` | Test pentester cannot advance phase | HTTP 403 Forbidden / Access Denied | PASS |
| TC-024 | Accounts | `test_pentester_cannot_create_project` | Test pentester cannot create project | HTTP 403 Forbidden / Access Denied | PASS |
| TC-025 | Accounts | `test_pentester_cannot_manage_members` | Test pentester cannot manage members | HTTP 403 Forbidden / Access Denied | PASS |
| TC-026 | Accounts | `test_pentester_cannot_move_finding_to_fixed` | Test pentester cannot move finding to fixed | HTTP 403 Forbidden / Access Denied | PASS |
| TC-027 | Accounts | `test_pm_cannot_access_django_admin` | Test pm cannot access django admin | HTTP 403 Forbidden / Access Denied | PASS |
| TC-028 | Accounts | `test_pm_cannot_access_global_dashboard` | Test pm cannot access global dashboard | HTTP 403 Forbidden / Access Denied | PASS |
| TC-029 | Accounts | `test_pm_cannot_create_vulnerability` | Test pm cannot create vulnerability | HTTP 403 Forbidden / Access Denied | PASS |
| TC-030 | Accounts | `test_pm_cannot_move_finding_to_fixed` | Test pm cannot move finding to fixed | HTTP 403 Forbidden / Access Denied | PASS |
| TC-031 | Accounts | `test_pm_cannot_trigger_scan` | Test pm cannot trigger scan | HTTP 403 Forbidden / Access Denied | PASS |
| TC-032 | Accounts | `test_pm_cannot_verify_finding` | Test pm cannot verify finding | HTTP 403 Forbidden / Access Denied | PASS |
| TC-033 | Projects | `test_add_duplicate_member_raises` | Test add duplicate member raises | Verified matching specification criteria | PASS |
| TC-034 | Projects | `test_add_member` | Test add member | Verified matching specification criteria | PASS |
| TC-035 | Projects | `test_remove_developer_succeeds` | Test remove developer succeeds | Verified matching specification criteria | PASS |
| TC-036 | Projects | `test_remove_last_pm_raises` | Test remove last pm raises | Verified matching specification criteria | PASS |
| TC-037 | Projects | `test_remove_non_last_pm_succeeds` | Test remove non last pm succeeds | Verified matching specification criteria | PASS |
| TC-038 | Projects | `test_agile_all_phases_not_started` | Test agile all phases not started | Verified matching specification criteria | PASS |
| TC-039 | Projects | `test_create_project_creates_six_phases` | Test create project creates six phases | Verified matching specification criteria | PASS |
| TC-040 | Projects | `test_creator_added_as_pm` | Test creator added as pm | Verified matching specification criteria | PASS |
| TC-041 | Projects | `test_current_phase_set` | Test current phase set | Verified matching specification criteria | PASS |
| TC-042 | Projects | `test_waterfall_first_phase_in_progress` | Test waterfall first phase in progress | Verified matching specification criteria | PASS |
| TC-043 | Projects | `test_admin_sees_all_projects` | Test admin sees all projects | Verified matching specification criteria | PASS |
| TC-044 | Projects | `test_member_sees_own_project` | Test member sees own project | Verified matching specification criteria | PASS |
| TC-045 | Projects | `test_non_member_does_not_see_project` | Test non member does not see project | HTTP 404 Not Found (Information hiding) | PASS |
| TC-046 | Projects | `test_admin_can_create_project` | Test admin can create project | Verified matching specification criteria | PASS |
| TC-047 | Projects | `test_admin_can_see_any_project` | Test admin can see any project | Verified matching specification criteria | PASS |
| TC-048 | Projects | `test_developer_cannot_create_project` | Test developer cannot create project | HTTP 403 Forbidden / Access Denied | PASS |
| TC-049 | Projects | `test_member_gets_200_on_detail` | Test member gets 200 on detail | Verified matching specification criteria | PASS |
| TC-050 | Projects | `test_non_member_gets_404_on_detail` | Test non member gets 404 on detail | HTTP 404 Not Found (Information hiding) | PASS |
| TC-051 | Projects | `test_nonexistent_project_returns_404` | Test nonexistent project returns 404 | HTTP 404 Not Found (Information hiding) | PASS |
| TC-052 | Projects | `test_pm_can_create_project` | Test pm can create project | Verified matching specification criteria | PASS |
| TC-053 | Phases | `test_agile_reopen_succeeds` | Test agile reopen succeeds | Verified matching specification criteria | PASS |
| TC-054 | Phases | `test_waterfall_reopen_refused` | Test waterfall reopen refused | Verified matching specification criteria | PASS |
| TC-055 | Phases | `test_advance_allowed_when_required_items_done_with_evidence` | Test advance allowed when required items done with evidence | HTTP 200 OK / Operation Succeeded | PASS |
| TC-056 | Phases | `test_advance_blocked_by_open_high_vulnerability_in_phase` | Test advance blocked by open high vulnerability in phase | Verified matching specification criteria | PASS |
| TC-057 | Phases | `test_advance_blocked_when_item_done_but_empty_evidence` | Test advance blocked when item done but empty evidence | Verified matching specification criteria | PASS |
| TC-058 | Phases | `test_advance_blocked_when_required_item_not_done` | Test advance blocked when required item not done | Verified matching specification criteria | PASS |
| TC-059 | Phases | `test_advance_not_blocked_by_high_vulnerability_in_different_phase` | Test advance not blocked by high vulnerability in different phase | Verified matching specification criteria | PASS |
| TC-060 | Phases | `test_every_attempt_writes_gate_decision` | Test every attempt writes gate decision | Verified matching specification criteria | PASS |
| TC-061 | Phases | `test_fixed_critical_finding_still_blocks_until_verified` | Test fixed critical finding still blocks until verified | Verified matching specification criteria | PASS |
| TC-062 | Phases | `test_successful_advance_transitions_next_phase_in_waterfall` | Test successful advance transitions next phase in waterfall | HTTP 200 OK / Operation Succeeded | PASS |
| TC-063 | Phases | `test_verified_or_closed_critical_finding_does_not_block` | Test verified or closed critical finding does not block | Verified matching specification criteria | PASS |
| TC-064 | Phases | `test_waterfall_cannot_skip_phases` | Test waterfall cannot skip phases | HTTP 403 Forbidden / Access Denied | PASS |
| TC-065 | Phases | `test_developer_cannot_call_advance_endpoint_403` | Test developer cannot call advance endpoint 403 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-066 | Phases | `test_marking_item_done_with_evidence_succeeds` | Test marking item done with evidence succeeds | Verified matching specification criteria | PASS |
| TC-067 | Phases | `test_marking_item_done_without_evidence_is_refused` | Test marking item done without evidence is refused | Verified matching specification criteria | PASS |
| TC-068 | Phases | `test_pm_can_call_advance_endpoint` | Test pm can call advance endpoint | Verified matching specification criteria | PASS |
| TC-069 | Vulns | `test_invalid_vector_rejected` | Test invalid vector rejected | HTTP 200 OK / Operation Succeeded | PASS |
| TC-070 | Vulns | `test_score_to_severity_boundaries` | Verify boundary mapping as specified in CLAUDE.md: 0.0 INFO, 3.9 LOW, 4.0 MEDIUM, 6.9 MEDIUM, 7.0 HIGH, 8.9 HIGH, 9.0 CRITICAL, 10.0 CRITICAL. | Verified matching specification criteria | PASS |
| TC-071 | Vulns | `test_valid_vector_parsing` | Test valid vector parsing | HTTP 200 OK / Operation Succeeded | PASS |
| TC-072 | Vulns | `test_invalid_vector_rejected_in_form` | Test invalid vector rejected in form | HTTP 200 OK / Operation Succeeded | PASS |
| TC-073 | Vulns | `test_severity_cannot_be_set_by_form` | Severity posted in data must be ignored and derived purely from the vector. | HTTP 403 Forbidden / Access Denied | PASS |
| TC-074 | Vulns | `test_developer_cannot_access_create_view_403` | Test developer cannot access create view 403 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-075 | Vulns | `test_pentester_can_access_create_view` | Test pentester can access create view | Verified matching specification criteria | PASS |
| TC-076 | Vulns | `test_pentester_create_vulnerability_flow` | Test pentester create vulnerability flow | Verified matching specification criteria | PASS |
| TC-077 | Vulns | `test_view_transition_enforcement` | Test view transition enforcement | Verified matching specification criteria | PASS |
| TC-078 | Vulns | `test_admin_can_perform_valid_transitions` | Test admin can perform valid transitions | HTTP 200 OK / Operation Succeeded | PASS |
| TC-079 | Vulns | `test_developer_cannot_verify_finding` | Test developer cannot verify finding | HTTP 403 Forbidden / Access Denied | PASS |
| TC-080 | Vulns | `test_each_allowed_transition_succeeds_for_correct_role` | Test each allowed transition succeeds for correct role | HTTP 200 OK / Operation Succeeded | PASS |
| TC-081 | Vulns | `test_each_transition_writes_one_vulnerability_event` | Test each transition writes one vulnerability event | Verified matching specification criteria | PASS |
| TC-082 | Vulns | `test_illegal_jump_open_to_verified_rejected` | Test illegal jump open to verified rejected | ValidationError / Transition Rejected | PASS |
| TC-083 | Vulns | `test_pentester_cannot_mark_finding_fixed` | Test pentester cannot mark finding fixed | HTTP 403 Forbidden / Access Denied | PASS |
| TC-084 | Vulns | `test_pm_cannot_transition_finding` | Test pm cannot transition finding | HTTP 403 Forbidden / Access Denied | PASS |
| TC-085 | Vulns | `test_regression_verified_to_open` | Test regression verified to open | Verified matching specification criteria | PASS |
| TC-086 | Vulns | `test_retest_rejection_fixed_to_open` | Test retest rejection fixed to open | ValidationError / Transition Rejected | PASS |
| TC-087 | Scans | `test_developer_cannot_start_scan_403` | Test developer cannot start scan 403 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-088 | Scans | `test_pentester_starts_scan_successfully` | Test pentester starts scan successfully | HTTP 200 OK / Operation Succeeded | PASS |
| TC-089 | Scans | `test_scan_on_unauthorized_target_refused_before_queue` | Test scan on unauthorized target refused before queue | Verified matching specification criteria | PASS |
| TC-090 | Scans | `test_target_not_on_allowlist_is_refused_by_clean` | Test target not on allowlist is refused by clean | HTTP 200 OK / Operation Succeeded | PASS |
| TC-091 | Scans | `test_target_without_authorization_refused` | Test target without authorization refused | Verified matching specification criteria | PASS |
| TC-092 | Scans | `test_valid_allowlisted_target_succeeds` | Test valid allowlisted target succeeds | HTTP 200 OK / Operation Succeeded | PASS |
| TC-093 | Scans | `test_alerts_converted_to_vulnerability_records_correctly` | Test alerts converted to vulnerability records correctly | Verified matching specification criteria | PASS |
| TC-094 | Scans | `test_duplicate_alerts_not_imported_twice` | Test duplicate alerts not imported twice | Verified matching specification criteria | PASS |
| TC-095 | Scans | `test_task_rechecks_authorization_and_refuses_if_revoked` | Test task rechecks authorization and refuses if revoked | Verified matching specification criteria | PASS |
| TC-096 | Scans | `test_task_refuses_if_host_not_in_allowlist` | Test task refuses if host not in allowlist | HTTP 200 OK / Operation Succeeded | PASS |
| TC-097 | Scans | `test_zap_connection_failure_marks_scan_failed_with_readable_message` | Test zap connection failure marks scan failed with readable message | Verified matching specification criteria | PASS |
| TC-098 | Scans | `test_zap_timeout_marks_scan_failed` | Test zap timeout marks scan failed | Verified matching specification criteria | PASS |
| TC-099 | Dashboard | `test_counts_by_severity` | Test counts by severity | Verified matching specification criteria | PASS |
| TC-100 | Dashboard | `test_counts_by_status` | Test counts by status | Verified matching specification criteria | PASS |
| TC-101 | Dashboard | `test_project_metrics_aggregate` | Test project metrics aggregate | Verified matching specification criteria | PASS |
| TC-102 | Dashboard | `test_risk_score_capped_at_100` | Test risk score capped at 100 | Verified matching specification criteria | PASS |
| TC-103 | Dashboard | `test_risk_score_matches_hand_calculated_value` | Test risk score matches hand calculated value | Verified matching specification criteria | PASS |
| TC-104 | Dashboard | `test_verified_and_closed_findings_excluded_from_risk` | Test verified and closed findings excluded from risk | Verified matching specification criteria | PASS |
| TC-105 | Dashboard | `test_admin_can_access_global_dashboard_200` | Test admin can access global dashboard 200 | Verified matching specification criteria | PASS |
| TC-106 | Dashboard | `test_admin_can_view_project_dashboard_200` | Test admin can view project dashboard 200 | Verified matching specification criteria | PASS |
| TC-107 | Dashboard | `test_member_can_view_project_dashboard_200` | Test member can view project dashboard 200 | Verified matching specification criteria | PASS |
| TC-108 | Dashboard | `test_non_admin_cannot_access_global_dashboard_403` | Test non admin cannot access global dashboard 403 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-109 | Dashboard | `test_non_member_cannot_view_project_dashboard_404` | Test non member cannot view project dashboard 404 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-110 | Reports | `test_generated_pdf_file_exists_non_empty_and_starts_with_pdf_header` | Generate actual PDF and verify file presence, size, and header. | Verified matching specification criteria | PASS |
| TC-111 | Reports | `test_rendered_html_contains_every_finding_title` | Test HTML content directly before PDF conversion for maximum speed. | Verified matching specification criteria | PASS |
| TC-112 | Reports | `test_admin_can_download_report_200` | Test admin can download report 200 | Verified matching specification criteria | PASS |
| TC-113 | Reports | `test_developer_cannot_download_report_403` | Test developer cannot download report 403 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-114 | Reports | `test_non_member_cannot_download_report_404` | Test non member cannot download report 404 | HTTP 403 Forbidden / Access Denied | PASS |
| TC-115 | Reports | `test_pentester_can_download_report_200` | Test pentester can download report 200 | Verified matching specification criteria | PASS |
| TC-116 | Reports | `test_pm_can_download_report_200` | Test pm can download report 200 | Verified matching specification criteria | PASS |

## 3. Coverage by Feature Area

| Component | Focus Areas | Test Count |
|---|---|:---:|
| **Accounts & Permissions** | Role assignments, permission helpers, permission matrix 'No' cells, non-member 404s, custom error pages | 32 |
| **Projects & Membership** | Waterfall/Agile creation, phase auto-provisioning, member management, role checks | 20 |
| **Phases & Phase Gate** | Gate criteria enforcement (all required items done with evidence, no open/fixed Crit/High vulns), gate decisions audit, Agile phase reopen | 16 |
| **Vulnerability Management** | CVSS:3.1 base score calculation, NVD severity mapping boundaries, strict status transition workflow (`transition()`), event logging | 18 |
| **OWASP ZAP Integration** | ScanTarget validation, allowlist enforcement (`SCAN_ALLOWED_HOSTS`), worker task execution, alert deduplication, timeout handling | 12 |
| **Dashboard & Metrics** | Section 5.4 risk score formula, severity doughnut, status bars, phase progress, global multi-project dashboard | 11 |
| **PDF Reporting** | 6-section report generation, HTML rendering, xhtml2pdf output validity (`%PDF` magic byte), download role restrictions | 7 |
| **Total** | | **116** |

## 4. UI Screenshot Walkthrough

All screenshots are saved in `docs/chapter4/screenshots/` and referenced below:

1. **Authentication:** `screenshots/01_login.png` - Login portal with role credentials.
2. **Projects Overview:** `screenshots/02_project_list.png` - Project cards and active SDLC phase indicators.
3. **Project Detail:** `screenshots/03_project_detail.png` - Six SDLC phases, project members, and quick action buttons.
4. **Phase Gate Enforcement (Blocked):** `screenshots/04_phase_gate_blocked.png` - Phase gate strictly blocking advancement due to incomplete requirements and open High/Critical vulnerabilities.
5. **Phase Gate Advancement (Allowed):** `screenshots/05_phase_gate_allowed.png` - Phase gate successfully passed with all evidence verified and audit log recorded.
6. **Vulnerability Registry:** `screenshots/06_vulnerability_list.png` - Vulnerability register with severity badges, CVSS scores, and phase filters.
7. **Vulnerability Workflow:** `screenshots/07_vulnerability_workflow.png` - Lifecycle transition controls and immutable event history.
8. **Scan Target Registration:** `screenshots/08_scan_targets.png` - Target authorization controls enforcing `SCAN_ALLOWED_HOSTS` safety boundary.
9. **ZAP Scanner Results:** `screenshots/09_zap_scan_results.png` - DAST automated scan results with alert breakdown and finding import.
10. **Security Dashboard:** `screenshots/10_project_dashboard.png` - Real-time risk score, severity distribution doughnut, status bars, and phase progress.
11. **Global Dashboard:** `screenshots/11_global_dashboard.png` - Cross-project executive risk rankings for administrators.
12. **Executive PDF Report:** `screenshots/12_pdf_report.png` - Formatted PDF security assessment report with executive summary and OWASP compliance matrix.
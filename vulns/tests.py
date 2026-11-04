"""Tests for the vulns app (Phase 4: Vulnerability management).

Covers all test criteria specified in CLAUDE.md section 7 (Phase 4):
- Score-to-severity boundaries: 0.0 INFO, 3.9 LOW, 4.0 MEDIUM, 6.9 MEDIUM, 7.0 HIGH, 8.9 HIGH, 9.0 CRITICAL, 10.0 CRITICAL.
- An invalid vector is rejected.
- Severity cannot be set through the form (posted value is ignored).
- Each allowed transition succeeds for the correct role.
- Illegal transitions (for example OPEN -> VERIFIED, or Developer making FIXED -> VERIFIED) are rejected.
- Each transition writes one VulnerabilityEvent.
"""

from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import User
from phases.models import Phase
from projects.models import Project, ProjectMember
from projects.services import create_project

from .cvss import CVSSValidationError, parse_cvss_vector, score_to_severity
from .forms import VulnerabilityCreateForm
from .models import Vulnerability, VulnerabilityEvent
from .services import InvalidTransition, can_transition, transition


class CVSSTests(TestCase):
    """Test CVSS:3.1 parsing, validation, and boundary severity mapping."""

    def test_score_to_severity_boundaries(self):
        """Verify boundary mapping as specified in CLAUDE.md:

        0.0 INFO, 3.9 LOW, 4.0 MEDIUM, 6.9 MEDIUM, 7.0 HIGH, 8.9 HIGH, 9.0 CRITICAL, 10.0 CRITICAL.
        """
        self.assertEqual(score_to_severity(0.0), Vulnerability.Severity.INFO)
        self.assertEqual(score_to_severity(3.9), Vulnerability.Severity.LOW)
        self.assertEqual(score_to_severity(4.0), Vulnerability.Severity.MEDIUM)
        self.assertEqual(score_to_severity(6.9), Vulnerability.Severity.MEDIUM)
        self.assertEqual(score_to_severity(7.0), Vulnerability.Severity.HIGH)
        self.assertEqual(score_to_severity(8.9), Vulnerability.Severity.HIGH)
        self.assertEqual(score_to_severity(9.0), Vulnerability.Severity.CRITICAL)
        self.assertEqual(score_to_severity(10.0), Vulnerability.Severity.CRITICAL)

    def test_valid_vector_parsing(self):
        # Standard critical vector (base score 9.8)
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score, severity = parse_cvss_vector(vector)
        self.assertEqual(score, 9.8)
        self.assertEqual(severity, Vulnerability.Severity.CRITICAL)

    def test_invalid_vector_rejected(self):
        invalid_vectors = [
            "",
            "NOT_A_VECTOR",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Invalid metric value
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",          # Wrong CVSS version
        ]
        for inv in invalid_vectors:
            with self.assertRaises(CVSSValidationError):
                parse_cvss_vector(inv)


class VulnerabilityFormTests(TestCase):
    """Test Vulnerability form validation and automatic score derivation."""

    def setUp(self):
        self.pm_user = User.objects.create_user(
            username="pm_form", password="password123", role=User.Role.PM
        )
        self.project = create_project(
            name="Form Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )

    def test_invalid_vector_rejected_in_form(self):
        form = VulnerabilityCreateForm(
            data={
                "title": "Bad Vector Finding",
                "description": "Some description",
                "affected_component": "Component",
                "cvss_vector": "INVALID_CVSS_VECTOR",
            },
            project=self.project,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("cvss_vector", form.errors)

    def test_severity_cannot_be_set_by_form(self):
        """Severity posted in data must be ignored and derived purely from the vector."""
        # Vector score 9.8 -> CRITICAL
        critical_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        form = VulnerabilityCreateForm(
            data={
                "title": "Tampered Severity Finding",
                "description": "Testing that posted severity is ignored",
                "affected_component": "/login",
                "cvss_vector": critical_vector,
                "severity": "LOW",  # User tries to sneak in LOW severity
            },
            project=self.project,
        )
        self.assertTrue(form.is_valid(), form.errors)
        instance = form.save(commit=False)
        self.assertEqual(instance.severity, Vulnerability.Severity.CRITICAL)
        self.assertEqual(float(instance.cvss_score), 9.8)


class VulnerabilityWorkflowTests(TestCase):
    """Test status transitions, role enforcement, and event auditing."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username="admin_w", password="password123", role=User.Role.ADMIN
        )
        self.pm = User.objects.create_user(
            username="pm_w", password="password123", role=User.Role.PM
        )
        self.dev = User.objects.create_user(
            username="dev_w", password="password123", role=User.Role.DEVELOPER
        )
        self.pentester = User.objects.create_user(
            username="pent_w", password="password123", role=User.Role.PENTESTER
        )

        self.project = create_project(
            name="Workflow Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )
        # Add dev and pentester
        ProjectMember.objects.create(
            project=self.project, user=self.dev, project_role=ProjectMember.ProjectRole.DEVELOPER
        )
        ProjectMember.objects.create(
            project=self.project, user=self.pentester, project_role=ProjectMember.ProjectRole.PENTESTER
        )

        self.vuln = Vulnerability.objects.create(
            project=self.project,
            title="XSS Finding",
            description="Reflected XSS",
            affected_component="/profile",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_score=6.1,
            severity=Vulnerability.Severity.MEDIUM,
            status=Vulnerability.Status.OPEN,
            reporter=self.pentester,
        )

    def test_each_allowed_transition_succeeds_for_correct_role(self):
        # 1. Developer moves OPEN -> FIXED
        self.assertTrue(can_transition(self.dev, self.vuln, Vulnerability.Status.FIXED))
        event1 = transition(self.vuln, Vulnerability.Status.FIXED, actor=self.dev, note="Patched input escaping.")
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, Vulnerability.Status.FIXED)
        self.assertEqual(event1.from_status, Vulnerability.Status.OPEN)
        self.assertEqual(event1.to_status, Vulnerability.Status.FIXED)
        self.assertEqual(event1.actor, self.dev)

        # 2. Pentester moves FIXED -> VERIFIED
        self.assertTrue(can_transition(self.pentester, self.vuln, Vulnerability.Status.VERIFIED))
        event2 = transition(self.vuln, Vulnerability.Status.VERIFIED, actor=self.pentester, note="Re-test confirmed fix.")
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, Vulnerability.Status.VERIFIED)
        self.assertEqual(event2.from_status, Vulnerability.Status.FIXED)
        self.assertEqual(event2.to_status, Vulnerability.Status.VERIFIED)

        # 3. Pentester moves VERIFIED -> CLOSED
        self.assertTrue(can_transition(self.pentester, self.vuln, Vulnerability.Status.CLOSED))
        event3 = transition(self.vuln, Vulnerability.Status.CLOSED, actor=self.pentester, note="Ticket closed.")
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, Vulnerability.Status.CLOSED)
        self.assertEqual(event3.to_status, Vulnerability.Status.CLOSED)

    def test_retest_rejection_fixed_to_open(self):
        # Developer fixes finding
        transition(self.vuln, Vulnerability.Status.FIXED, actor=self.dev)
        # Pentester re-tests and rejects fix: FIXED -> OPEN
        self.assertTrue(can_transition(self.pentester, self.vuln, Vulnerability.Status.OPEN))
        event = transition(self.vuln, Vulnerability.Status.OPEN, actor=self.pentester, note="Payload still executes.")
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, Vulnerability.Status.OPEN)
        self.assertEqual(event.note, "Payload still executes.")

    def test_regression_verified_to_open(self):
        transition(self.vuln, Vulnerability.Status.FIXED, actor=self.dev)
        transition(self.vuln, Vulnerability.Status.VERIFIED, actor=self.pentester)
        # Regression: VERIFIED -> OPEN
        self.assertTrue(can_transition(self.pentester, self.vuln, Vulnerability.Status.OPEN))
        event = transition(self.vuln, Vulnerability.Status.OPEN, actor=self.pentester, note="Regression found.")
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, Vulnerability.Status.OPEN)
        self.assertEqual(event.to_status, Vulnerability.Status.OPEN)

    def test_developer_cannot_verify_finding(self):
        transition(self.vuln, Vulnerability.Status.FIXED, actor=self.dev)
        self.assertFalse(can_transition(self.dev, self.vuln, Vulnerability.Status.VERIFIED))
        with self.assertRaises(InvalidTransition):
            transition(self.vuln, Vulnerability.Status.VERIFIED, actor=self.dev)

    def test_pentester_cannot_mark_finding_fixed(self):
        self.assertFalse(can_transition(self.pentester, self.vuln, Vulnerability.Status.FIXED))
        with self.assertRaises(InvalidTransition):
            transition(self.vuln, Vulnerability.Status.FIXED, actor=self.pentester)

    def test_pm_cannot_transition_finding(self):
        self.assertFalse(can_transition(self.pm, self.vuln, Vulnerability.Status.FIXED))
        with self.assertRaises(InvalidTransition):
            transition(self.vuln, Vulnerability.Status.FIXED, actor=self.pm)

    def test_illegal_jump_open_to_verified_rejected(self):
        self.assertFalse(can_transition(self.pentester, self.vuln, Vulnerability.Status.VERIFIED))
        with self.assertRaises(InvalidTransition):
            transition(self.vuln, Vulnerability.Status.VERIFIED, actor=self.pentester)

    def test_admin_can_perform_valid_transitions(self):
        self.assertTrue(can_transition(self.admin, self.vuln, Vulnerability.Status.FIXED))
        transition(self.vuln, Vulnerability.Status.FIXED, actor=self.admin)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, Vulnerability.Status.FIXED)

    def test_each_transition_writes_one_vulnerability_event(self):
        initial_events = VulnerabilityEvent.objects.filter(vulnerability=self.vuln).count()
        transition(self.vuln, Vulnerability.Status.FIXED, actor=self.dev, note="Fixed")
        self.assertEqual(
            VulnerabilityEvent.objects.filter(vulnerability=self.vuln).count(),
            initial_events + 1,
        )


class VulnerabilityViewTests(TestCase):
    """Test permission and view routing for vulnerability management."""

    def setUp(self):
        self.client = Client()
        self.pm = User.objects.create_user(
            username="pm_v_user", password="password123", role=User.Role.PM
        )
        self.dev = User.objects.create_user(
            username="dev_v_user", password="password123", role=User.Role.DEVELOPER
        )
        self.pentester = User.objects.create_user(
            username="pent_v_user", password="password123", role=User.Role.PENTESTER
        )

        self.project = create_project(
            name="View Proj",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )
        ProjectMember.objects.create(
            project=self.project, user=self.dev, project_role=ProjectMember.ProjectRole.DEVELOPER
        )
        ProjectMember.objects.create(
            project=self.project, user=self.pentester, project_role=ProjectMember.ProjectRole.PENTESTER
        )

    def test_developer_cannot_access_create_view_403(self):
        self.client.login(username="dev_v_user", password="password123")
        url = reverse("vulns:create", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 403)

    def test_pentester_can_access_create_view(self):
        self.client.login(username="pent_v_user", password="password123")
        url = reverse("vulns:create", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_pentester_create_vulnerability_flow(self):
        self.client.login(username="pent_v_user", password="password123")
        url = reverse("vulns:create", kwargs={"project_id": self.project.pk})
        resp = self.client.post(url, {
            "title": "SQL Injection in Search",
            "description": "Union based SQLi on /search?q=",
            "affected_component": "GET /search",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "owasp_category": "A03:2021",
        })
        self.assertEqual(resp.status_code, 302)

        vuln = Vulnerability.objects.get(project=self.project, title="SQL Injection in Search")
        self.assertEqual(vuln.severity, Vulnerability.Severity.CRITICAL)
        self.assertEqual(float(vuln.cvss_score), 9.8)
        self.assertEqual(vuln.status, Vulnerability.Status.OPEN)
        self.assertEqual(vuln.reporter, self.pentester)

    def test_view_transition_enforcement(self):
        vuln = Vulnerability.objects.create(
            project=self.project,
            title="CSRF Token Missing",
            description="State changing POST has no CSRF token",
            affected_component="/api/transfer",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            cvss_score=6.5,
            severity=Vulnerability.Severity.MEDIUM,
            status=Vulnerability.Status.OPEN,
            reporter=self.pentester,
        )

        transition_url = reverse("vulns:transition", kwargs={"project_id": self.project.pk, "vid": vuln.pk})

        # Pentester cannot mark it FIXED (403)
        self.client.login(username="pent_v_user", password="password123")
        resp = self.client.post(transition_url, {"new_status": Vulnerability.Status.FIXED})
        self.assertEqual(resp.status_code, 403)

        # Developer CAN mark it FIXED (302 redirect back to detail)
        self.client.login(username="dev_v_user", password="password123")
        resp = self.client.post(transition_url, {
            "new_status": Vulnerability.Status.FIXED,
            "note": "Added csrf_token decorator.",
        })
        self.assertEqual(resp.status_code, 302)
        vuln.refresh_from_db()
        self.assertEqual(vuln.status, Vulnerability.Status.FIXED)


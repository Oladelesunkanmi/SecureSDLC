"""Tests for the dashboard app (Phase 6: Dashboard & Visual Metrics).

Covers all test criteria specified in CLAUDE.md section 7 (Phase 6):
- Counts and risk score match a hand-calculated fixture with known findings.
- Verified and Closed findings are excluded from the risk score.
- Score is capped at 100.
- A user who is not a member cannot see a project's dashboard (404).
- Admin global dashboard permissions.
"""

from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import User
from projects.models import Project, ProjectMember
from projects.services import create_project
from vulns.models import Vulnerability

from .services import (
    count_by_severity,
    count_by_status,
    phase_progress,
    project_metrics,
    risk_score,
)


class DashboardMetricsFixtureTests(TestCase):
    """Test dashboard calculations against known hand-calculated fixtures."""

    def setUp(self):
        self.pm = User.objects.create_user(
            username="pm_dash", password="password123", role=User.Role.PM
        )
        self.project = create_project(
            name="Metrics Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )

        # Hand-calculated fixture findings:
        # 1 Critical OPEN (10)
        Vulnerability.objects.create(
            project=self.project, title="Crit 1", description="", affected_component="",
            severity=Vulnerability.Severity.CRITICAL, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        # 2 High OPEN (2 * 5 = 10)
        Vulnerability.objects.create(
            project=self.project, title="High 1", description="", affected_component="",
            severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        Vulnerability.objects.create(
            project=self.project, title="High 2", description="", affected_component="",
            severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        # 1 High FIXED (5)
        Vulnerability.objects.create(
            project=self.project, title="High 3 (Fixed)", description="", affected_component="",
            severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.FIXED, reporter=self.pm,
        )
        # 2 Medium OPEN (2 * 2 = 4)
        Vulnerability.objects.create(
            project=self.project, title="Med 1", description="", affected_component="",
            severity=Vulnerability.Severity.MEDIUM, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        Vulnerability.objects.create(
            project=self.project, title="Med 2", description="", affected_component="",
            severity=Vulnerability.Severity.MEDIUM, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        # 1 Low OPEN (1)
        Vulnerability.objects.create(
            project=self.project, title="Low 1", description="", affected_component="",
            severity=Vulnerability.Severity.LOW, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        # 1 Info OPEN (0)
        Vulnerability.objects.create(
            project=self.project, title="Info 1", description="", affected_component="",
            severity=Vulnerability.Severity.INFO, status=Vulnerability.Status.OPEN, reporter=self.pm,
        )
        # 1 Critical VERIFIED (does NOT count toward risk score)
        Vulnerability.objects.create(
            project=self.project, title="Crit Verified", description="", affected_component="",
            severity=Vulnerability.Severity.CRITICAL, status=Vulnerability.Status.VERIFIED, reporter=self.pm,
        )
        # 1 High CLOSED (does NOT count toward risk score)
        Vulnerability.objects.create(
            project=self.project, title="High Closed", description="", affected_component="",
            severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.CLOSED, reporter=self.pm,
        )

    def test_risk_score_matches_hand_calculated_value(self):
        # Raw risk = 10 (Crit Open) + 10 (2 High Open) + 5 (1 High Fixed) + 4 (2 Med Open) + 1 (1 Low Open) + 0 (Info)
        # Raw risk = 30
        self.assertEqual(risk_score(self.project), 30)

    def test_counts_by_severity(self):
        sev_counts = count_by_severity(self.project)
        self.assertEqual(sev_counts[Vulnerability.Severity.CRITICAL], 2)
        self.assertEqual(sev_counts[Vulnerability.Severity.HIGH], 4)
        self.assertEqual(sev_counts[Vulnerability.Severity.MEDIUM], 2)
        self.assertEqual(sev_counts[Vulnerability.Severity.LOW], 1)
        self.assertEqual(sev_counts[Vulnerability.Severity.INFO], 1)

    def test_counts_by_status(self):
        st_counts = count_by_status(self.project)
        self.assertEqual(st_counts[Vulnerability.Status.OPEN], 7)
        self.assertEqual(st_counts[Vulnerability.Status.FIXED], 1)
        self.assertEqual(st_counts[Vulnerability.Status.VERIFIED], 1)
        self.assertEqual(st_counts[Vulnerability.Status.CLOSED], 1)

    def test_verified_and_closed_findings_excluded_from_risk(self):
        clean_project = create_project(
            name="Clean Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )
        # Create 3 Critical Verified and 3 Critical Closed findings
        for i in range(3):
            Vulnerability.objects.create(
                project=clean_project, title=f"Verified {i}", description="", affected_component="",
                severity=Vulnerability.Severity.CRITICAL, status=Vulnerability.Status.VERIFIED, reporter=self.pm,
            )
            Vulnerability.objects.create(
                project=clean_project, title=f"Closed {i}", description="", affected_component="",
                severity=Vulnerability.Severity.CRITICAL, status=Vulnerability.Status.CLOSED, reporter=self.pm,
            )
        # Score must be 0 because all critical findings are resolved
        self.assertEqual(risk_score(clean_project), 0)

    def test_risk_score_capped_at_100(self):
        high_risk_project = create_project(
            name="Extreme Risk",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )
        # 15 Critical OPEN findings: 15 * 10 = 150 raw risk
        for i in range(15):
            Vulnerability.objects.create(
                project=high_risk_project, title=f"Crit {i}", description="", affected_component="",
                severity=Vulnerability.Severity.CRITICAL, status=Vulnerability.Status.OPEN, reporter=self.pm,
            )
        # Must cap at 100
        self.assertEqual(risk_score(high_risk_project), 100)

    def test_project_metrics_aggregate(self):
        metrics = project_metrics(self.project)
        self.assertEqual(metrics["risk_score"], 30)
        self.assertEqual(metrics["total_vulns"], 10)
        self.assertEqual(metrics["open_crit_high"], 3)  # 1 Crit Open + 2 High Open
        self.assertIn("severity_chart", metrics)
        self.assertIn("status_chart", metrics)
        self.assertIn("progress_chart", metrics)


class DashboardPermissionViewTests(TestCase):
    """Test dashboard access control and project membership isolation."""

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(
            username="admin_dash_u", password="password123", role=User.Role.ADMIN
        )
        self.pm = User.objects.create_user(
            username="pm_dash_u", password="password123", role=User.Role.PM
        )
        self.non_member = User.objects.create_user(
            username="non_member_u", password="password123", role=User.Role.DEVELOPER
        )

        self.project = create_project(
            name="Access Test Proj",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )

    def test_non_member_cannot_view_project_dashboard_404(self):
        self.client.login(username="non_member_u", password="password123")
        url = reverse("dashboard:project", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        # CLAUDE.md: Non-members receive 404 to avoid disclosing project existence
        self.assertEqual(resp.status_code, 404)

    def test_member_can_view_project_dashboard_200(self):
        self.client.login(username="pm_dash_u", password="password123")
        url = reverse("dashboard:project", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Security Dashboard")
        self.assertContains(resp, "Access Test Proj")

    def test_admin_can_view_project_dashboard_200(self):
        self.client.login(username="admin_dash_u", password="password123")
        url = reverse("dashboard:project", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

    def test_non_admin_cannot_access_global_dashboard_403(self):
        self.client.login(username="pm_dash_u", password="password123")
        url = reverse("dashboard:global")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_access_global_dashboard_200(self):
        self.client.login(username="admin_dash_u", password="password123")
        url = reverse("dashboard:global")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Global Security Risk Dashboard")
        self.assertContains(resp, "Access Test Proj")


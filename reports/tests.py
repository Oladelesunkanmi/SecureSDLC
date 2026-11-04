"""Tests for the reports app (Phase 7: PDF reporting).

Covers all test criteria specified in CLAUDE.md section 7 (Phase 7):
- The generated file exists, is non-empty, and begins with the %PDF header.
- The rendered HTML contains every finding title for the project (test the HTML before PDF conversion for speed).
- Download view permissions: restricted to project members with PM or Pentester role (or Admin).
- Developers receive 403; non-members receive 404.
"""

import os
from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import User
from projects.models import Project, ProjectMember
from projects.services import create_project
from vulns.models import Vulnerability

from .models import Report
from .services import generate_report, render_report_html


class ReportGenerationTests(TestCase):
    """Test report content generation and PDF compilation."""

    def setUp(self):
        self.pm = User.objects.create_user(
            username="pm_rep", password="password123", role=User.Role.PM
        )
        self.project = create_project(
            name="Report Test Project",
            description="Testing automated client and examiner report generation.",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )

        # Seed multiple findings with distinct titles across severities
        self.v1 = Vulnerability.objects.create(
            project=self.project,
            title="Broken Object Level Authorization in Orders API",
            description="Users can view other users orders by modifying the id parameter.",
            affected_component="GET /api/orders/{id}",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=6.5,
            severity=Vulnerability.Severity.MEDIUM,
            owasp_category=Vulnerability.OWASPCategory.A01,
            status=Vulnerability.Status.OPEN,
            reporter=self.pm,
        )
        self.v2 = Vulnerability.objects.create(
            project=self.project,
            title="Remote Code Execution via File Upload",
            description="Arbitrary file upload leads to shell execution.",
            affected_component="POST /api/avatar",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            severity=Vulnerability.Severity.CRITICAL,
            owasp_category=Vulnerability.OWASPCategory.A03,
            status=Vulnerability.Status.OPEN,
            reporter=self.pm,
        )
        self.v3 = Vulnerability.objects.create(
            project=self.project,
            title="Missing HSTS Header in Production",
            description="Strict-Transport-Security header not returned.",
            affected_component="Response Headers",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cvss_score=5.3,
            severity=Vulnerability.Severity.MEDIUM,
            owasp_category=Vulnerability.OWASPCategory.A05,
            status=Vulnerability.Status.FIXED,
            reporter=self.pm,
        )

    def test_rendered_html_contains_every_finding_title(self):
        """Test HTML content directly before PDF conversion for maximum speed."""
        html = render_report_html(self.project, self.pm)

        # Must contain every vulnerability title
        self.assertIn("Broken Object Level Authorization in Orders API", html)
        self.assertIn("Remote Code Execution via File Upload", html)
        self.assertIn("Missing HSTS Header in Production", html)

        # Must contain project metadata and sections
        self.assertIn(self.project.name, html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Technical Security Findings", html)
        self.assertIn("OWASP Top 10", html)
        self.assertIn("Phase Gate Audit Records", html)

    def test_generated_pdf_file_exists_non_empty_and_starts_with_pdf_header(self):
        """Generate actual PDF and verify file presence, size, and header."""
        report = generate_report(self.project, self.pm)

        self.assertIsNotNone(report.pk)
        self.assertTrue(report.file)
        self.assertTrue(os.path.exists(report.file.path))

        file_size = os.path.getsize(report.file.path)
        self.assertGreater(file_size, 500)

        with open(report.file.path, "rb") as f:
            header = f.read(4)
            self.assertEqual(header, b"%PDF")


class ReportViewPermissionTests(TestCase):
    """Test view access and download security (CLAUDE.md section 3 & 7)."""

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(
            username="admin_rep_u", password="password123", role=User.Role.ADMIN
        )
        self.pm = User.objects.create_user(
            username="pm_rep_u", password="password123", role=User.Role.PM
        )
        self.pentester = User.objects.create_user(
            username="pent_rep_u", password="password123", role=User.Role.PENTESTER
        )
        self.dev = User.objects.create_user(
            username="dev_rep_u", password="password123", role=User.Role.DEVELOPER
        )
        self.non_member = User.objects.create_user(
            username="non_member_rep_u", password="password123", role=User.Role.DEVELOPER
        )

        self.project = create_project(
            name="Report View Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )
        ProjectMember.objects.create(
            project=self.project, user=self.pentester, project_role=ProjectMember.ProjectRole.PENTESTER
        )
        ProjectMember.objects.create(
            project=self.project, user=self.dev, project_role=ProjectMember.ProjectRole.DEVELOPER
        )

    def test_developer_cannot_download_report_403(self):
        self.client.login(username="dev_rep_u", password="password123")
        url = reverse("reports:download", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 403)

    def test_non_member_cannot_download_report_404(self):
        self.client.login(username="non_member_rep_u", password="password123")
        url = reverse("reports:download", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 404)

    def test_pm_can_download_report_200(self):
        self.client.login(username="pm_rep_u", password="password123")
        url = reverse("reports:download", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/pdf")
        self.assertIn("attachment;", resp["Content-Disposition"])

    def test_pentester_can_download_report_200(self):
        self.client.login(username="pent_rep_u", password="password123")
        url = reverse("reports:download", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/pdf")

    def test_admin_can_download_report_200(self):
        self.client.login(username="admin_rep_u", password="password123")
        url = reverse("reports:download", kwargs={"project_id": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/pdf")


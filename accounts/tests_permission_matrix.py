"""Comprehensive Permission Matrix Tests (CLAUDE.md §3).

Tests every 'No' cell in the Section 3 permissions table across all 4 roles:
- Admin
- Project Manager (PM)
- Developer
- Pentester
And non-members (who must receive 404, not 403, to prevent project enumeration).
"""

from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from projects.models import Project, ProjectMember
from phases.models import Phase, ChecklistItem, ChecklistResponse
from vulns.models import Vulnerability


class PermissionMatrixNoCellTests(TestCase):
    """Explicitly verify that every capability with 'No' in CLAUDE.md §3 is rejected."""

    def setUp(self):
        # Create users for all 4 roles
        self.admin = User.objects.create_user(
            username="matrix_admin", password="password123", role="ADMIN", is_staff=True
        )
        self.pm = User.objects.create_user(
            username="matrix_pm", password="password123", role="PM"
        )
        self.dev = User.objects.create_user(
            username="matrix_dev", password="password123", role="DEVELOPER"
        )
        self.pentester = User.objects.create_user(
            username="matrix_pen", password="password123", role="PENTESTER"
        )
        self.outsider = User.objects.create_user(
            username="matrix_outsider", password="password123", role="DEVELOPER"
        )

        # Create project and assign PM, Dev, Pentester as members
        self.project = Project.objects.create(
            name="Matrix Security Project",
            description="Testing permission matrix",
            sdlc_model="WATERFALL",
            created_by=self.pm,
        )
        ProjectMember.objects.create(project=self.project, user=self.pm, project_role="PM")
        ProjectMember.objects.create(project=self.project, user=self.dev, project_role="DEVELOPER")
        ProjectMember.objects.create(project=self.project, user=self.pentester, project_role="PENTESTER")

        # Create phase
        self.req_phase = Phase.objects.create(
            project=self.project, kind="REQUIREMENTS", order=1, status="IN_PROGRESS"
        )
        self.test_phase = Phase.objects.create(
            project=self.project, kind="TESTING", order=4, status="NOT_STARTED"
        )

        # Create a sample vulnerability
        self.vuln_open = Vulnerability.objects.create(
            project=self.project,
            phase=self.req_phase,
            title="SQL Injection in auth",
            description="Parameter id unescaped",
            affected_component="login.py",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            severity="CRITICAL",
            owasp_category="A03:2021-Injection",
            status="OPEN",
            source="MANUAL",
            reporter=self.pentester,
        )
        self.vuln_fixed = Vulnerability.objects.create(
            project=self.project,
            phase=self.req_phase,
            title="Reflected XSS",
            description="Search query unescaped",
            affected_component="search.py",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            cvss_score=6.1,
            severity="MEDIUM",
            owasp_category="A03:2021-Injection",
            status="FIXED",
            source="MANUAL",
            reporter=self.pentester,
        )

    # 1. Manage users and roles: Admin ONLY (PM: No, Dev: No, Pentester: No)
    def test_pm_cannot_access_django_admin(self):
        self.client.login(username="matrix_pm", password="password123")
        resp = self.client.get(reverse("admin:index"))
        # Non-staff redirected to admin login or rejected
        self.assertNotEqual(resp.status_code, 200)

    def test_dev_cannot_access_django_admin(self):
        self.client.login(username="matrix_dev", password="password123")
        resp = self.client.get(reverse("admin:index"))
        self.assertNotEqual(resp.status_code, 200)

    def test_pentester_cannot_access_django_admin(self):
        self.client.login(username="matrix_pen", password="password123")
        resp = self.client.get(reverse("admin:index"))
        self.assertNotEqual(resp.status_code, 200)

    # 2. Create project: Admin, PM (Developer: No, Pentester: No)
    def test_developer_cannot_create_project(self):
        self.client.login(username="matrix_dev", password="password123")
        resp = self.client.get(reverse("projects:create"))
        self.assertEqual(resp.status_code, 403)
        post_resp = self.client.post(reverse("projects:create"), {
            "name": "Dev Forbidden Project",
            "description": "Dev attempt",
            "sdlc_model": "WATERFALL",
        })
        self.assertEqual(post_resp.status_code, 403)

    def test_pentester_cannot_create_project(self):
        self.client.login(username="matrix_pen", password="password123")
        resp = self.client.get(reverse("projects:create"))
        self.assertEqual(resp.status_code, 403)

    # 3. Add or remove project members: Admin, PM (Developer: No, Pentester: No)
    def test_developer_cannot_manage_members(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("projects:members", kwargs={"pk": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(url, {}).status_code, 403)

    def test_pentester_cannot_manage_members(self):
        self.client.login(username="matrix_pen", password="password123")
        url = reverse("projects:members", kwargs={"pk": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)

    # 4. View projects: Non-members must receive 404 (No project enumeration)
    def test_non_member_cannot_view_project_detail(self):
        self.client.login(username="matrix_outsider", password="password123")
        url = reverse("projects:detail", kwargs={"pk": self.project.pk})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 404)

    def test_non_member_cannot_view_phases(self):
        self.client.login(username="matrix_outsider", password="password123")
        url = reverse("phases:detail", kwargs={"project_id": self.project.pk, "kind": "REQUIREMENTS"})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_non_member_cannot_view_vulns(self):
        self.client.login(username="matrix_outsider", password="password123")
        url = reverse("vulns:list", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_non_member_cannot_view_scans(self):
        self.client.login(username="matrix_outsider", password="password123")
        url = reverse("scans:list", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_non_member_cannot_view_dashboard(self):
        self.client.login(username="matrix_outsider", password="password123")
        url = reverse("dashboard:project", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    # 5. Advance phase (phase gate): Admin, PM (Developer: No, Pentester: No)
    def test_developer_cannot_advance_phase(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("phases:advance", kwargs={"project_id": self.project.pk, "kind": "REQUIREMENTS"})
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 403)

    def test_pentester_cannot_advance_phase(self):
        self.client.login(username="matrix_pen", password="password123")
        url = reverse("phases:advance", kwargs={"project_id": self.project.pk, "kind": "REQUIREMENTS"})
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 403)

    # 6. Register scan targets: Admin, PM, Pentester (Developer: No)
    def test_developer_cannot_register_scan_target(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("scans:targets", kwargs={"project_id": self.project.pk})
        # Developer can view targets list, but registration form is omitted
        get_resp = self.client.get(url)
        self.assertEqual(get_resp.status_code, 200)
        self.assertContains(get_resp, "You do not have permission to register targets")
        self.assertNotContains(get_resp, "Register Target</button>")

        # Attempting to POST returns 403 Forbidden
        post_resp = self.client.post(url, {
            "url": "http://localhost:3000",
            "environment": "LOCAL_TEST",
            "authorization_confirmed": True,
            "authorized_by": "Developer test",
        })
        self.assertEqual(post_resp.status_code, 403)

    # 7. Create vulnerability finding: Admin, Pentester (PM: No, Developer: No)
    def test_pm_cannot_create_vulnerability(self):
        self.client.login(username="matrix_pm", password="password123")
        url = reverse("vulns:create", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)
        resp = self.client.post(url, {
            "title": "PM Vuln",
            "description": "Desc",
            "affected_component": "Comp",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "owasp_category": "A01:2021-Broken Access Control",
        })
        self.assertEqual(resp.status_code, 403)

    def test_developer_cannot_create_vulnerability(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("vulns:create", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)

    # 8. Move finding to Fixed: Admin, Developer (PM: No, Pentester: No)
    def test_pm_cannot_move_finding_to_fixed(self):
        self.client.login(username="matrix_pm", password="password123")
        url = reverse("vulns:transition", kwargs={"project_id": self.project.pk, "vid": self.vuln_open.pk})
        resp = self.client.post(url, {"status": "FIXED", "note": "PM attempt"})
        self.assertEqual(resp.status_code, 403)

    def test_pentester_cannot_move_finding_to_fixed(self):
        self.client.login(username="matrix_pen", password="password123")
        url = reverse("vulns:transition", kwargs={"project_id": self.project.pk, "vid": self.vuln_open.pk})
        resp = self.client.post(url, {"status": "FIXED", "note": "Pentester attempt"})
        self.assertEqual(resp.status_code, 403)

    # 9. Move finding to Verified or Closed: Admin, Pentester (PM: No, Developer: No)
    def test_pm_cannot_verify_finding(self):
        self.client.login(username="matrix_pm", password="password123")
        url = reverse("vulns:transition", kwargs={"project_id": self.project.pk, "vid": self.vuln_fixed.pk})
        resp = self.client.post(url, {"status": "VERIFIED", "note": "PM attempt"})
        self.assertEqual(resp.status_code, 403)

    def test_developer_cannot_verify_finding(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("vulns:transition", kwargs={"project_id": self.project.pk, "vid": self.vuln_fixed.pk})
        resp = self.client.post(url, {"status": "VERIFIED", "note": "Dev attempt"})
        self.assertEqual(resp.status_code, 403)

    # 10. Trigger a ZAP scan: Admin, Pentester (PM: No, Developer: No)
    def test_pm_cannot_trigger_scan(self):
        self.client.login(username="matrix_pm", password="password123")
        url = reverse("scans:create", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(url, {}).status_code, 403)

    def test_developer_cannot_trigger_scan(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("scans:create", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(url, {}).status_code, 403)

    # 11. Generate PDF report: Admin, PM, Pentester (Developer: No)
    def test_developer_cannot_generate_report(self):
        self.client.login(username="matrix_dev", password="password123")
        url = reverse("reports:download", kwargs={"project_id": self.project.pk})
        self.assertEqual(self.client.get(url).status_code, 403)

    # 12. Global dashboard: Admin ONLY (PM: No, Dev: No, Pentester: No)
    def test_pm_cannot_access_global_dashboard(self):
        self.client.login(username="matrix_pm", password="password123")
        resp = self.client.get(reverse("dashboard:global"))
        self.assertEqual(resp.status_code, 403)

    def test_dev_cannot_access_global_dashboard(self):
        self.client.login(username="matrix_dev", password="password123")
        resp = self.client.get(reverse("dashboard:global"))
        self.assertEqual(resp.status_code, 403)

    def test_pentester_cannot_access_global_dashboard(self):
        self.client.login(username="matrix_pen", password="password123")
        resp = self.client.get(reverse("dashboard:global"))
        self.assertEqual(resp.status_code, 403)


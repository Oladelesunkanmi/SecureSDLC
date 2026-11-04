"""Tests for the scans app (Phase 5: Scanner integration with OWASP ZAP).

Covers all test criteria specified in CLAUDE.md section 7 (Phase 5):
- A scan on an unregistered or unauthorized target is refused before the task is queued.
- A target not on the allowlist is refused by clean().
- The task re-checks authorization and refuses if it has been revoked.
- Alerts are converted to Vulnerability records correctly.
- Duplicate alerts are not imported twice.
- A ZAP connection failure marks the scan FAILED with a readable message.
- A timeout marks the scan FAILED.
"""

from unittest.mock import MagicMock, patch

from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from accounts.models import User
from projects.models import Project, ProjectMember
from projects.services import create_project
from vulns.models import Vulnerability

from .forms import ScanTargetForm
from .models import Scan, ScanTarget
from .tasks import import_alerts_to_vulnerabilities, run_zap_scan
from .zap_client import ZAPClient, ZAPClientError, ZAPTimeoutError


class ScanSafetyValidationTests(TestCase):
    """Test ScanTarget validation and allowlist enforcement (CLAUDE.md section 5.5)."""

    def setUp(self):
        self.pm = User.objects.create_user(
            username="pm_target", password="password123", role=User.Role.PM
        )
        self.project = create_project(
            name="Target Safety Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )

    def test_target_without_authorization_refused(self):
        target = ScanTarget(
            project=self.project,
            url="http://localhost:3000",
            environment=ScanTarget.Environment.LOCAL_TEST,
            authorization_confirmed=False,  # Unconfirmed
            authorized_by="Lead",
        )
        with self.assertRaises(ValidationError) as ctx:
            target.full_clean()
        self.assertIn("authorization_confirmed", ctx.exception.message_dict)

    @override_settings(SCAN_ALLOWED_HOSTS=["localhost", "127.0.0.1", "juice-shop"])
    def test_target_not_on_allowlist_is_refused_by_clean(self):
        target = ScanTarget(
            project=self.project,
            url="https://google.com/test",  # Not on allowlist
            environment=ScanTarget.Environment.LOCAL_TEST,
            authorization_confirmed=True,
            authorized_by="Lead",
        )
        with self.assertRaises(ValidationError) as ctx:
            target.full_clean()
        self.assertIn("url", ctx.exception.message_dict)

    @override_settings(SCAN_ALLOWED_HOSTS=["localhost", "127.0.0.1"])
    def test_valid_allowlisted_target_succeeds(self):
        target = ScanTarget(
            project=self.project,
            url="http://localhost:3000",
            environment=ScanTarget.Environment.LOCAL_TEST,
            authorization_confirmed=True,
            authorized_by="Project Manager",
        )
        # Should not raise
        target.full_clean()
        target.save()
        self.assertIsNotNone(target.pk)


class ScanQueueViewTests(TestCase):
    """Test scan views and permissions."""

    def setUp(self):
        self.client = Client()
        self.pm = User.objects.create_user(
            username="pm_scan_view", password="password123", role=User.Role.PM
        )
        self.dev = User.objects.create_user(
            username="dev_scan_view", password="password123", role=User.Role.DEVELOPER
        )
        self.pentester = User.objects.create_user(
            username="pent_scan_view", password="password123", role=User.Role.PENTESTER
        )

        self.project = create_project(
            name="Scan View Project",
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

        self.authorized_target = ScanTarget.objects.create(
            project=self.project,
            url="http://localhost:3000",
            environment=ScanTarget.Environment.LOCAL_TEST,
            authorization_confirmed=True,
            authorized_by="PM",
        )

    def test_developer_cannot_start_scan_403(self):
        self.client.login(username="dev_scan_view", password="password123")
        url = reverse("scans:create", kwargs={"project_id": self.project.pk})
        resp = self.client.post(url, {"target_id": self.authorized_target.pk})
        self.assertEqual(resp.status_code, 403)

    def test_scan_on_unauthorized_target_refused_before_queue(self):
        unauth_target = ScanTarget.objects.create(
            project=self.project,
            url="http://localhost:3000",
            environment=ScanTarget.Environment.LOCAL_TEST,
            authorization_confirmed=False,
            authorized_by="PM",
        )

        self.client.login(username="pent_scan_view", password="password123")
        url = reverse("scans:create", kwargs={"project_id": self.project.pk})
        resp = self.client.post(url, {"target_id": unauth_target.pk})
        # Should refuse with error and redirect back to create
        self.assertEqual(resp.status_code, 302)
        # Scan should not be queued
        self.assertEqual(Scan.objects.filter(target=unauth_target).count(), 0)

    @patch("scans.views.async_task")
    def test_pentester_starts_scan_successfully(self, mock_async):
        self.client.login(username="pent_scan_view", password="password123")
        url = reverse("scans:create", kwargs={"project_id": self.project.pk})
        resp = self.client.post(url, {"target_id": self.authorized_target.pk})
        self.assertEqual(resp.status_code, 302)

        scan = Scan.objects.filter(target=self.authorized_target).first()
        self.assertIsNotNone(scan)
        self.assertEqual(scan.status, Scan.Status.QUEUED)
        self.assertEqual(scan.requested_by, self.pentester)
        mock_async.assert_called_once_with(run_zap_scan, scan.id)


class ZAPScanTaskMockedTests(TestCase):
    """Test background task execution with mocked ZAP client."""

    def setUp(self):
        self.pm = User.objects.create_user(
            username="pm_task", password="password123", role=User.Role.PM
        )
        self.pentester = User.objects.create_user(
            username="pent_task", password="password123", role=User.Role.PENTESTER
        )
        self.project = create_project(
            name="ZAP Task Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm,
        )
        self.target = ScanTarget.objects.create(
            project=self.project,
            url="http://localhost:3000",
            environment=ScanTarget.Environment.LOCAL_TEST,
            authorization_confirmed=True,
            authorized_by="Security Team",
        )
        self.scan = Scan.objects.create(
            project=self.project,
            target=self.target,
            tool=Scan.Tool.ZAP,
            status=Scan.Status.QUEUED,
            requested_by=self.pentester,
        )

    def test_task_rechecks_authorization_and_refuses_if_revoked(self):
        # Revoke authorization
        self.target.authorization_confirmed = False
        self.target.save_base(raw=True)

        success = run_zap_scan(self.scan.id)
        self.assertFalse(success)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.FAILED)
        self.assertIn("authorization is not confirmed", self.scan.error_message)

    @override_settings(SCAN_ALLOWED_HOSTS=["127.0.0.1"])
    def test_task_refuses_if_host_not_in_allowlist(self):
        # Target url is localhost:3000, but allowlist only contains 127.0.0.1
        success = run_zap_scan(self.scan.id)
        self.assertFalse(success)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.FAILED)
        self.assertIn("not on the scan allowlist", self.scan.error_message)

    def test_alerts_converted_to_vulnerability_records_correctly(self):
        mock_client = MagicMock(spec=ZAPClient)
        mock_client.start_spider.return_value = "1"
        mock_client.start_active_scan.return_value = "1"
        mock_client.get_alerts.return_value = [
            {
                "pluginId": "10038",
                "alert": "Content Security Policy (CSP) Header Not Set",
                "description": "CSP was not provided in response headers.",
                "url": "http://localhost:3000/",
                "risk": "Medium",
                "cweid": "16",
            },
            {
                "pluginId": "40018",
                "alert": "SQL Injection",
                "description": "SQLi discovered in parameter id.",
                "url": "http://localhost:3000/rest/products/search",
                "risk": "High",
                "cweid": "89",
            },
        ]

        success = run_zap_scan(self.scan.id, client=mock_client)
        self.assertTrue(success)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.DONE)
        self.assertEqual(len(self.scan.raw_result), 2)

        # Check imported Vulnerabilities
        vulns = Vulnerability.objects.filter(scan=self.scan).order_by("title")
        self.assertEqual(vulns.count(), 2)

        sqli = vulns.filter(title="SQL Injection").first()
        self.assertIsNotNone(sqli)
        self.assertEqual(sqli.severity, Vulnerability.Severity.HIGH)
        self.assertEqual(float(sqli.cvss_score), 7.5)
        self.assertEqual(sqli.source, Vulnerability.Source.ZAP)
        self.assertEqual(sqli.zap_alert_id, "40018")
        self.assertEqual(sqli.owasp_category, Vulnerability.OWASPCategory.A03)

    def test_duplicate_alerts_not_imported_twice(self):
        mock_client = MagicMock(spec=ZAPClient)
        mock_client.start_spider.return_value = "1"
        mock_client.start_active_scan.return_value = "1"
        mock_client.get_alerts.return_value = [
            {
                "pluginId": "10038",
                "alert": "CSP Missing",
                "description": "CSP header missing",
                "url": "http://localhost:3000/",
                "risk": "Low",
            }
        ]

        # Run first scan
        run_zap_scan(self.scan.id, client=mock_client)
        self.assertEqual(Vulnerability.objects.filter(project=self.project).count(), 1)

        # Run second scan on same target with duplicate alert
        scan2 = Scan.objects.create(
            project=self.project,
            target=self.target,
            status=Scan.Status.QUEUED,
            requested_by=self.pentester,
        )
        run_zap_scan(scan2.id, client=mock_client)

        # Count should still be 1 (no duplicates)
        self.assertEqual(Vulnerability.objects.filter(project=self.project).count(), 1)

    def test_zap_connection_failure_marks_scan_failed_with_readable_message(self):
        mock_client = MagicMock(spec=ZAPClient)
        mock_client.start_spider.side_effect = ZAPClientError("Connection refused on port 8080")

        success = run_zap_scan(self.scan.id, client=mock_client)
        self.assertFalse(success)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.FAILED)
        self.assertIn("Connection refused on port 8080", self.scan.error_message)

    def test_zap_timeout_marks_scan_failed(self):
        mock_client = MagicMock(spec=ZAPClient)
        mock_client.start_spider.return_value = "1"
        mock_client.wait_for_spider.side_effect = ZAPTimeoutError("Scan operation timed out after 900 seconds")

        success = run_zap_scan(self.scan.id, client=mock_client)
        self.assertFalse(success)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, Scan.Status.FAILED)
        self.assertIn("timed out", self.scan.error_message)

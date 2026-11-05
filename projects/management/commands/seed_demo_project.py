"""Seed a rich, complete demonstration project for examiner evaluation and Chapter 4 demos."""

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import User
from projects.models import Project, ProjectMember
from projects.services import create_project
from phases.models import Phase, ChecklistItem, ChecklistResponse, GateDecision
from vulns.models import Vulnerability, VulnerabilityEvent
from scans.models import Scan, ScanTarget
from reports.services import generate_report


class Command(BaseCommand):
    help = "Seed an end-to-end demo project with members, checklists, vulnerabilities, scans, and reports"

    def handle(self, *args, **options):
        # 1. Ensure users exist
        admin, _ = User.objects.get_or_create(username="admin", defaults={"role": User.Role.ADMIN, "is_staff": True, "is_superuser": True})
        admin.set_password("demo123")
        admin.save()

        pm, _ = User.objects.get_or_create(username="pm", defaults={"role": User.Role.PM, "is_staff": True})
        pm.set_password("demo123")
        pm.save()

        dev, _ = User.objects.get_or_create(username="dev", defaults={"role": User.Role.DEVELOPER})
        dev.set_password("demo123")
        dev.save()

        pentester, _ = User.objects.get_or_create(username="pentester", defaults={"role": User.Role.PENTESTER})
        pentester.set_password("demo123")
        pentester.save()

        self.stdout.write("Demo users verified (admin, pm, dev, pentester / password: demo123)")

        # 2. Create or reset demo project
        project_name = "SecureSDLC Demo Application"
        Project.objects.filter(name=project_name).delete()

        project = create_project(
            name=project_name,
            description="Production Banking Application incorporating continuous penetration testing across all SDLC phases.",
            sdlc_model="WATERFALL",
            created_by=pm,
        )

        # 3. Add other members (PM already added by create_project)
        ProjectMember.objects.get_or_create(project=project, user=dev, defaults={"project_role": "DEVELOPER"})
        ProjectMember.objects.get_or_create(project=project, user=pentester, defaults={"project_role": "PENTESTER"})

        # 4. Get phases (automatically created in signal/create)
        req_phase = project.phases.get(kind="REQUIREMENTS")
        design_phase = project.phases.get(kind="DESIGN")
        coding_phase = project.phases.get(kind="CODING")
        testing_phase = project.phases.get(kind="TESTING")

        req_phase.status = "COMPLETED"
        req_phase.save()

        design_phase.status = "IN_PROGRESS"
        design_phase.save()

        project.current_phase = design_phase
        project.save()

        # 5. Populate Requirements Checklist responses
        req_items = ChecklistItem.objects.filter(phase_kind="REQUIREMENTS")
        for item in req_items:
            ChecklistResponse.objects.create(
                project=project,
                item=item,
                done=True,
                evidence=f"Verified and approved in security specification document SEC-DOC-2026-v1.2. Architecture signed off by {pm.username}.",
                completed_by=pm,
                completed_at=timezone.now(),
            )

        # Record Gate decision for advancing Requirements
        GateDecision.objects.create(
            project=project,
            phase=req_phase,
            actor=pm,
            allowed=True,
            reasons=["All 4 required checklist items completed with non-empty evidence.", "No open Critical or High vulnerabilities."],
        )

        # Populate Design phase with partial checklist
        design_items = ChecklistItem.objects.filter(phase_kind="DESIGN")
        for idx, item in enumerate(design_items):
            if idx < 3:
                ChecklistResponse.objects.create(
                    project=project,
                    item=item,
                    done=True,
                    evidence=f"Threat model STRIDE analysis completed for trust boundary {idx + 1}.",
                    completed_by=dev,
                    completed_at=timezone.now(),
                )

        # 6. Add vulnerabilities across severities and statuses
        v1 = Vulnerability.objects.create(
            project=project,
            phase=design_phase,
            title="SQL Injection in Authentication API",
            description="The `/api/v1/login` endpoint concatenates user input directly into SQL queries without parameterization.",
            affected_component="/api/v1/auth/login",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            severity="CRITICAL",
            owasp_category="A03:2021-Injection",
            status="OPEN",
            source="MANUAL",
            reporter=pentester,
            assignee=dev,
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v1,
            from_status="",
            to_status="OPEN",
            actor=pentester,
            note="Discovered during design phase threat modeling review.",
        )

        v2 = Vulnerability.objects.create(
            project=project,
            phase=design_phase,
            title="BOLA / Insecure Direct Object Reference on User Accounts",
            description="Account balance endpoint does not verify whether the requesting user owns the requested account ID parameter.",
            affected_component="/api/v1/accounts/{id}/balance",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            cvss_score=8.1,
            severity="HIGH",
            owasp_category="A01:2021-Broken Access Control",
            status="FIXED",
            source="MANUAL",
            reporter=pentester,
            assignee=dev,
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v2,
            from_status="",
            to_status="OPEN",
            actor=pentester,
            note="Initial discovery in authorization schema review.",
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v2,
            from_status="OPEN",
            to_status="FIXED",
            actor=dev,
            note="Added tenant validation middleware and object-level permission check. Ready for re-test.",
        )

        v3 = Vulnerability.objects.create(
            project=project,
            phase=req_phase,
            title="Cross-Site Scripting (Reflected) in Transaction Filter",
            description="Transaction filter query parameter reflected without HTML entity encoding.",
            affected_component="transactions/views.py:search",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            cvss_score=6.1,
            severity="MEDIUM",
            owasp_category="A03:2021-Injection",
            status="VERIFIED",
            source="MANUAL",
            reporter=pentester,
            assignee=dev,
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v3,
            from_status="",
            to_status="OPEN",
            actor=pentester,
            note="Discovered in input validation review.",
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v3,
            from_status="OPEN",
            to_status="FIXED",
            actor=dev,
            note="Escaped filter parameters with Django template filters.",
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v3,
            from_status="FIXED",
            to_status="VERIFIED",
            actor=pentester,
            note="Verified fix against XSS polyglots. No script execution observed.",
        )

        v4 = Vulnerability.objects.create(
            project=project,
            phase=req_phase,
            title="Missing Content-Security-Policy Header",
            description="HTTP response does not include a Content-Security-Policy (CSP) header.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            cvss_score=4.3,
            severity="MEDIUM",
            owasp_category="A05:2021-Security Misconfiguration",
            status="CLOSED",
            source="MANUAL",
            reporter=pentester,
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v4,
            from_status="",
            to_status="OPEN",
            actor=pentester,
            note="Reported.",
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v4,
            from_status="OPEN",
            to_status="FIXED",
            actor=dev,
            note="Configured django-csp middleware in prod settings.",
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v4,
            from_status="FIXED",
            to_status="VERIFIED",
            actor=pentester,
            note="Verified headers present.",
        )
        VulnerabilityEvent.objects.create(
            vulnerability=v4,
            from_status="VERIFIED",
            to_status="CLOSED",
            actor=pentester,
            note="Closed out. Ticket complete.",
        )

        # 7. Register Scan Target
        target = ScanTarget.objects.create(
            project=project,
            url="http://localhost:3000",
            environment="LOCAL_TEST",
            authorization_confirmed=True,
            authorized_by="Lead Security Architect Jane Doe",
            authorized_at=timezone.now(),
        )

        # 8. Create a completed Scan with sample ZAP alerts
        scan = Scan.objects.create(
            project=project,
            target=target,
            tool="ZAP",
            status="DONE",
            started_at=timezone.now(),
            finished_at=timezone.now(),
            requested_by=pentester,
            raw_result=[
                {
                    "alert": "Cross-Domain JavaScript Source File Inclusion",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": "http://localhost:3000/#/score-board",
                    "description": "The page includes one or more script files from a third party domain.",
                    "solution": "Ensure JavaScript files are hosted locally or protected by Subresource Integrity (SRI).",
                },
                {
                    "alert": "Server Leaks Version Information via 'Server' HTTP Header",
                    "risk": "Low",
                    "confidence": "High",
                    "url": "http://localhost:3000/rest/admin/application-version",
                    "description": "The web/application server discloses version details in the 'Server' header.",
                    "solution": "Configure server banner masking in reverse proxy.",
                },
                {
                    "alert": "Directory Browsing",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "url": "http://localhost:3000/ftp",
                    "description": "Directory browsing is enabled and lists sensitive backup files.",
                    "solution": "Disable directory indexing in server config.",
                }
            ],
        )

        # Import one of the ZAP findings as a linked Vulnerability
        Vulnerability.objects.create(
            project=project,
            phase=testing_phase,
            title="[ZAP] Directory Browsing",
            description="Directory browsing is enabled and lists sensitive backup files.",
            affected_component="http://localhost:3000/ftp",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cvss_score=5.3,
            severity="MEDIUM",
            owasp_category="A01:2021-Broken Access Control",
            status="OPEN",
            source="ZAP",
            reporter=pentester,
            scan=scan,
            zap_alert_id="10033",
        )

        # 9. Generate PDF report
        report_record = generate_report(project, pm)
        self.stdout.write(self.style.SUCCESS(f"Generated PDF report: {report_record.file.name}"))

        self.stdout.write(self.style.SUCCESS(f"Successfully seeded demo project '{project.name}' (ID: {project.pk})"))

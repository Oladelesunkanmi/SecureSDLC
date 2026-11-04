"""PDF Report generation service using xhtml2pdf (CLAUDE.md section 7, Phase 7)."""

import io
from typing import Any, Dict

from django.conf import settings
from django.core.files.base import ContentFile
from django.template.loader import render_to_string
from django.utils import timezone
from xhtml2pdf import pisa

from dashboard.services import risk_score
from phases.models import GateDecision, Phase
from scans.models import Scan
from vulns.models import Vulnerability

from .models import Report


def get_plain_language_assessment(score: int, open_blocking: int) -> str:
    """Generate a clear, examiner/client-facing plain-language assessment from metrics."""
    if open_blocking > 0 or score > 50:
        return (
            f"High Risk Posture (Score: {score}/100): The project currently has {open_blocking} "
            f"unresolved Critical or High severity findings that actively block phase advancement. "
            f"Immediate remediation and re-testing are required before advancing through the SDLC."
        )
    elif score > 20:
        return (
            f"Moderate Risk Posture (Score: {score}/100): Security testing is progressing. "
            f"Residual risk is concentrated in lower-severity or non-blocking defects. "
            f"Ensure all required phase checklist evidence is documented."
        )
    else:
        return (
            f"Low Risk Posture (Score: {score}/100): The application satisfies core Secure SDLC "
            f"gate requirements. No critical or high severity findings are open, and phase controls "
            f"have been verified."
        )


def build_owasp_compliance_data(project) -> list[dict[str, Any]]:
    """Build compliance matrix across the OWASP Top 10 (2021) categories."""
    owasp_rows = []

    for code, title in Vulnerability.OWASPCategory.choices:
        short_code = code.split(":")[0]  # e.g. "A01"
        vulns_in_cat = Vulnerability.objects.filter(
            project=project,
            owasp_category=code,
        )
        total_count = vulns_in_cat.count()
        unresolved = vulns_in_cat.filter(
            status__in=[Vulnerability.Status.OPEN, Vulnerability.Status.FIXED]
        ).count()

        owasp_rows.append({
            "code": short_code,
            "title": title,
            "count": total_count,
            "compliant": unresolved == 0,
        })

    return owasp_rows


def build_report_context(project, user) -> dict[str, Any]:
    """Compile all project data required for the assessment report."""
    now = timezone.now()
    score = risk_score(project)

    vulnerabilities = Vulnerability.objects.filter(
        project=project
    ).prefetch_related("events__actor").select_related("phase", "reporter").order_by("-severity", "title")

    total_vulns = vulnerabilities.count()
    open_blocking = vulnerabilities.filter(
        status=Vulnerability.Status.OPEN,
        severity__in=[Vulnerability.Severity.CRITICAL, Vulnerability.Severity.HIGH],
    ).count()

    phases = Phase.objects.filter(project=project).order_by("order")
    gate_decisions = GateDecision.objects.filter(
        project=project
    ).select_related("phase", "actor").order_by("-timestamp")[:20]

    scans = Scan.objects.filter(
        project=project
    ).select_related("target").order_by("-created_at")

    owasp_compliance = build_owasp_compliance_data(project)
    assessment = get_plain_language_assessment(score, open_blocking)

    return {
        "project": project,
        "generated_by": user,
        "generated_at": now,
        "risk_score": score,
        "total_vulns": total_vulns,
        "open_blocking": open_blocking,
        "plain_language_assessment": assessment,
        "vulnerabilities": vulnerabilities,
        "owasp_compliance": owasp_compliance,
        "phases": phases,
        "gate_decisions": gate_decisions,
        "scans": scans,
    }


def render_report_html(project, user) -> str:
    """Render the report HTML template to a string (used directly in unit tests for speed)."""
    context = build_report_context(project, user)
    return render_to_string("reports/report.html", context)


def generate_report(project, user) -> Report:
    """Render HTML and write the PDF report with xhtml2pdf, saving to MEDIA_ROOT/reports/."""
    html_content = render_report_html(project, user)

    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf_buffer)

    if pisa_status.err:
        raise RuntimeError(f"xhtml2pdf encountered errors rendering PDF: {pisa_status.err}")

    pdf_bytes = pdf_buffer.getvalue()

    filename = f"security_report_{project.pk}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    report = Report(
        project=project,
        generated_by=user,
    )
    report.file.save(filename, ContentFile(pdf_bytes), save=True)

    return report


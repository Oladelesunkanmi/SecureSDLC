"""Dashboard and security metrics services (CLAUDE.md section 5.4 and Phase 6)."""

from typing import Any, Dict, List
from django.db.models import Count

from phases.models import ChecklistItem, ChecklistResponse, Phase
from vulns.models import Vulnerability

# Severity weights defined by CLAUDE.md section 5.4
SEVERITY_WEIGHTS = {
    Vulnerability.Severity.CRITICAL: 10,
    Vulnerability.Severity.HIGH: 5,
    Vulnerability.Severity.MEDIUM: 2,
    Vulnerability.Severity.LOW: 1,
    Vulnerability.Severity.INFO: 0,
}


def risk_score(project) -> int:
    """Calculate the overall security risk score (0–100) for ``project``.

    CLAUDE.md section 5.4:
    Weights: Critical 10, High 5, Medium 2, Low 1, Info 0.
    Raw risk = sum of weights for all findings in status OPEN or FIXED.
    Project risk score = min(100, raw risk).
    Verified and Closed findings do not count.

    Limitations:
    Does not weight findings by specific asset criticality or financial impact.
    """
    active_findings = Vulnerability.objects.filter(
        project=project,
        status__in=[Vulnerability.Status.OPEN, Vulnerability.Status.FIXED],
    ).values_list("severity", flat=True)

    raw_risk = sum(SEVERITY_WEIGHTS.get(sev, 0) for sev in active_findings)
    return min(100, raw_risk)


def count_by_severity(project) -> dict[str, int]:
    """Return dictionary of vulnerability counts grouped by severity level."""
    counts = {
        Vulnerability.Severity.CRITICAL: 0,
        Vulnerability.Severity.HIGH: 0,
        Vulnerability.Severity.MEDIUM: 0,
        Vulnerability.Severity.LOW: 0,
        Vulnerability.Severity.INFO: 0,
    }

    db_counts = (
        Vulnerability.objects.filter(project=project)
        .values("severity")
        .annotate(total=Count("id"))
    )

    for entry in db_counts:
        sev = entry["severity"]
        if sev in counts:
            counts[sev] = entry["total"]

    return counts


def count_by_status(project) -> dict[str, int]:
    """Return dictionary of vulnerability counts grouped by status."""
    counts = {
        Vulnerability.Status.OPEN: 0,
        Vulnerability.Status.FIXED: 0,
        Vulnerability.Status.VERIFIED: 0,
        Vulnerability.Status.CLOSED: 0,
    }

    db_counts = (
        Vulnerability.objects.filter(project=project)
        .values("status")
        .annotate(total=Count("id"))
    )

    for entry in db_counts:
        st = entry["status"]
        if st in counts:
            counts[st] = entry["total"]

    return counts


def phase_progress(project) -> list[dict[str, Any]]:
    """Return checklist completion progress percentage for each of the 6 SDLC phases."""
    progress_list = []

    for kind, label in Phase.Kind.choices:
        total_items = ChecklistItem.objects.filter(phase_kind=kind).count()
        done_items = ChecklistResponse.objects.filter(
            project=project,
            item__phase_kind=kind,
            done=True,
        ).exclude(evidence="").count()

        percent = round((done_items / total_items) * 100) if total_items > 0 else 0
        progress_list.append({
            "kind": kind,
            "label": label,
            "total": total_items,
            "done": done_items,
            "percent": percent,
        })

    return progress_list


def project_metrics(project) -> dict[str, Any]:
    """Compile all project metrics and chart datasets for the dashboard view."""
    sev_counts = count_by_severity(project)
    status_counts = count_by_status(project)
    score = risk_score(project)
    progress = phase_progress(project)

    total_vulns = sum(sev_counts.values())
    open_crit_high = Vulnerability.objects.filter(
        project=project,
        status=Vulnerability.Status.OPEN,
        severity__in=[Vulnerability.Severity.CRITICAL, Vulnerability.Severity.HIGH],
    ).count()

    # Chart 1: Severity Doughnut
    severity_chart = {
        "labels": ["Critical", "High", "Medium", "Low", "Info"],
        "data": [
            sev_counts[Vulnerability.Severity.CRITICAL],
            sev_counts[Vulnerability.Severity.HIGH],
            sev_counts[Vulnerability.Severity.MEDIUM],
            sev_counts[Vulnerability.Severity.LOW],
            sev_counts[Vulnerability.Severity.INFO],
        ],
        "colors": ["#dc3545", "#fd7e14", "#0dcaf0", "#6c757d", "#adb5bd"],
    }

    # Chart 2: Status Bar
    status_chart = {
        "labels": ["Open", "Fixed", "Verified", "Closed"],
        "data": [
            status_counts[Vulnerability.Status.OPEN],
            status_counts[Vulnerability.Status.FIXED],
            status_counts[Vulnerability.Status.VERIFIED],
            status_counts[Vulnerability.Status.CLOSED],
        ],
        "colors": ["#dc3545", "#0d6efd", "#198754", "#212529"],
    }

    # Chart 3: Phase Progress
    progress_chart = {
        "labels": [p["label"] for p in progress],
        "data": [p["percent"] for p in progress],
    }

    return {
        "risk_score": score,
        "total_vulns": total_vulns,
        "open_crit_high": open_crit_high,
        "severity_counts": sev_counts,
        "status_counts": status_counts,
        "phase_progress": progress,
        "severity_chart": severity_chart,
        "status_chart": status_chart,
        "progress_chart": progress_chart,
    }


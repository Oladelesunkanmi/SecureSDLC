"""Phase gate and checklist services.

Implements the phase gate business rules (CLAUDE.md section 5.1).
``can_advance(project, phase) -> GateResult`` is the single authoritative source
of truth for whether a phase may advance.
"""

from dataclasses import dataclass, field
from typing import List

from django.db import transaction

from vulns.models import Vulnerability

from .models import ChecklistItem, ChecklistResponse, GateDecision, Phase


@dataclass
class GateResult:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


def can_advance(project, phase: Phase) -> GateResult:
    """Evaluate whether ``phase`` of ``project`` can advance through the phase gate.

    Rules (CLAUDE.md section 5.1):
    1. Every ChecklistItem with required=True for that phase has a ChecklistResponse
       with done=True and non-empty evidence.
    2. No Vulnerability with phase=this phase has status OPEN or FIXED and severity
       CRITICAL or HIGH. (A FIXED finding is not verified yet, so it still blocks.)
    3. The phase is not already COMPLETED.
    4. Waterfall projects: phases advance strictly in order. Advancing is only forward.
    """
    reasons: list[str] = []

    # Rule 3: Phase is not already COMPLETED.
    if phase.status == Phase.Status.COMPLETED:
        reasons.append(f"Phase {phase.get_kind_display()} is already completed.")

    # Rule 4: Waterfall projects advance strictly in order.
    if project.sdlc_model == "WATERFALL":
        # Must be currently IN_PROGRESS to advance.
        if phase.status != Phase.Status.IN_PROGRESS:
            reasons.append(f"Phase {phase.get_kind_display()} is not currently in progress.")

        # Earlier phases must all be COMPLETED.
        earlier_uncompleted = Phase.objects.filter(
            project=project,
            order__lt=phase.order,
        ).exclude(status=Phase.Status.COMPLETED)
        if earlier_uncompleted.exists():
            names = ", ".join(p.get_kind_display() for p in earlier_uncompleted)
            reasons.append(f"Earlier phases ({names}) must be completed first.")

    # Rule 1: Every required ChecklistItem must be done with non-empty evidence.
    required_items = ChecklistItem.objects.filter(
        phase_kind=phase.kind,
        required=True,
    ).order_by("code")

    existing_responses = {
        resp.item_id: resp
        for resp in ChecklistResponse.objects.filter(
            project=project,
            item__in=required_items,
        )
    }

    for item in required_items:
        resp = existing_responses.get(item.id)
        if not resp or not resp.done or not (resp.evidence and resp.evidence.strip()):
            reasons.append(
                f"Required checklist item '{item.code}: {item.text}' is not completed with evidence."
            )

    # Rule 2: No OPEN or FIXED vulnerability with CRITICAL or HIGH severity in this phase.
    blocking_vulns = Vulnerability.objects.filter(
        project=project,
        phase=phase,
        status__in=[Vulnerability.Status.OPEN, Vulnerability.Status.FIXED],
        severity__in=[Vulnerability.Severity.CRITICAL, Vulnerability.Severity.HIGH],
    ).order_by("severity", "title")

    for vuln in blocking_vulns:
        reasons.append(
            f"Vulnerability '{vuln.title}' [{vuln.severity}] is {vuln.get_status_display()} "
            f"and blocks advancing until verified or closed."
        )

    allowed = len(reasons) == 0
    return GateResult(allowed=allowed, reasons=reasons)


def advance_phase(project, phase: Phase, actor) -> tuple[bool, GateResult]:
    """Attempt to advance ``phase`` through the gate and log a ``GateDecision``."""
    result = can_advance(project, phase)

    # Record the gate attempt audit log regardless of outcome
    GateDecision.objects.create(
        project=project,
        phase=phase,
        action=GateDecision.Action.ADVANCE,
        allowed=result.allowed,
        reasons=result.reasons,
        actor=actor,
    )

    if not result.allowed:
        return False, result

    with transaction.atomic():
        phase.status = Phase.Status.COMPLETED
        phase.save(update_fields=["status", "updated_at"])

        if project.sdlc_model == "WATERFALL":
            next_phase = Phase.objects.filter(
                project=project,
                order=phase.order + 1,
            ).first()
            if next_phase:
                next_phase.status = Phase.Status.IN_PROGRESS
                next_phase.save(update_fields=["status", "updated_at"])
                project.current_phase = next_phase
            else:
                project.current_phase = phase
            project.save(update_fields=["current_phase", "updated_at"])

    return True, result


def reopen_phase(project, phase: Phase, actor) -> None:
    """Reopen an earlier phase for Agile projects only.

    Sets the phase back to IN_PROGRESS and logs a GateDecision event.
    Raises ValueError if the project is Waterfall.
    """
    if project.sdlc_model != "AGILE":
        raise ValueError("Only Agile projects allow reopening earlier phases.")

    with transaction.atomic():
        phase.status = Phase.Status.IN_PROGRESS
        phase.save(update_fields=["status", "updated_at"])

        project.current_phase = phase
        project.save(update_fields=["current_phase", "updated_at"])

        GateDecision.objects.create(
            project=project,
            phase=phase,
            action=GateDecision.Action.REOPEN,
            allowed=True,
            reasons=["Phase reopened for a new iteration."],
            actor=actor,
        )


"""Views for the phases app.

Handles phase checklist review, evidence submission, phase gate advancement,
and Agile phase reopening.
"""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from accounts.permissions import can_advance_phase, can_reopen_phase
from projects.mixins import ProjectMemberRequiredMixin
from vulns.models import Vulnerability

from .models import ChecklistItem, ChecklistResponse, GateDecision, Phase
from .services import advance_phase, can_advance, reopen_phase


class PhaseDetailView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """View and complete security checklist items for a specific phase."""

    def get_phase(self, kind: str) -> Phase:
        phase = Phase.objects.filter(
            project=self.project,
            kind__iexact=kind,
        ).first()
        if not phase:
            raise Http404(f"Phase '{kind}' not found for this project.")
        return phase

    def get(self, request, project_id, kind):
        phase = self.get_phase(kind)
        checklist_items = ChecklistItem.objects.filter(phase_kind=phase.kind).order_by("code")
        responses = {
            resp.item_id: resp
            for resp in ChecklistResponse.objects.filter(
                project=self.project,
                item__in=checklist_items,
            )
        }

        checklist = []
        for item in checklist_items:
            checklist.append({
                "item": item,
                "response": responses.get(item.id),
            })

        gate_result = can_advance(self.project, phase)
        recent_decisions = GateDecision.objects.filter(
            project=self.project,
            phase=phase,
        ).order_by("-timestamp")[:5]

        phase_vulns = Vulnerability.objects.filter(
            project=self.project,
            phase=phase,
        ).order_by("-created_at")

        advance_allowed = can_advance_phase(request.user, self.project)
        can_reopen = can_reopen_phase(request.user, self.project) and self.project.sdlc_model == "AGILE"

        return render(request, "phases/phase_detail.html", {
            "project": self.project,
            "phase": phase,
            "checklist": checklist,
            "gate_result": gate_result,
            "recent_decisions": recent_decisions,
            "phase_vulns": phase_vulns,
            "advance_allowed": advance_allowed,
            "can_advance": advance_allowed,
            "can_reopen": can_reopen,
        })

    def post(self, request, project_id, kind):
        phase = self.get_phase(kind)
        item_id = request.POST.get("item_id")
        item = get_object_or_404(ChecklistItem, pk=item_id, phase_kind=phase.kind)

        done = request.POST.get("done") == "1"
        evidence = request.POST.get("evidence", "").strip()

        # Business rule: Evidence is required before an item can be marked done.
        if done and not evidence:
            messages.error(
                request,
                f"Evidence is required before checklist item '{item.code}' can be marked done."
            )
            return redirect("phases:detail", project_id=self.project.pk, kind=phase.kind.lower())

        response_obj, _ = ChecklistResponse.objects.get_or_create(
            project=self.project,
            item=item,
        )
        response_obj.done = done
        response_obj.evidence = evidence
        if done:
            response_obj.completed_by = request.user
            response_obj.completed_at = timezone.now()
        else:
            response_obj.completed_by = None
            response_obj.completed_at = None
        response_obj.save()

        status_text = "marked done" if done else "saved"
        messages.success(request, f"Checklist item '{item.code}' {status_text}.")
        return redirect("phases:detail", project_id=self.project.pk, kind=phase.kind.lower())


class PhaseAdvanceView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """POST-only view to advance a phase through the gate."""

    def get(self, request, project_id, kind):
        return HttpResponseNotAllowed(["POST"])

    def post(self, request, project_id, kind):
        if not can_advance_phase(request.user, self.project):
            return HttpResponseForbidden("You do not have permission to advance phases.")

        phase = Phase.objects.filter(project=self.project, kind__iexact=kind).first()
        if not phase:
            raise Http404

        allowed, result = advance_phase(self.project, phase, actor=request.user)
        if allowed:
            messages.success(
                request,
                f"Phase '{phase.get_kind_display()}' has passed the security gate and is marked Completed!"
            )
        else:
            for reason in result.reasons:
                messages.error(request, f"Gate blocked: {reason}")

        return redirect("phases:detail", project_id=self.project.pk, kind=phase.kind.lower())


class PhaseReopenView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """POST-only view to reopen an Agile phase."""

    def get(self, request, project_id, kind):
        return HttpResponseNotAllowed(["POST"])

    def post(self, request, project_id, kind):
        if not can_reopen_phase(request.user, self.project):
            return HttpResponseForbidden("You do not have permission to reopen phases.")

        phase = Phase.objects.filter(project=self.project, kind__iexact=kind).first()
        if not phase:
            raise Http404

        try:
            reopen_phase(self.project, phase, actor=request.user)
            messages.success(
                request,
                f"Phase '{phase.get_kind_display()}' reopened for a new iteration."
            )
        except ValueError as e:
            messages.error(request, str(e))

        return redirect("phases:detail", project_id=self.project.pk, kind=phase.kind.lower())


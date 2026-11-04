"""Views for vulnerability management (Phase 4)."""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from accounts.permissions import can_create_vuln
from phases.models import Phase
from projects.mixins import ProjectMemberRequiredMixin

from .forms import VulnerabilityCreateForm
from .models import Vulnerability, VulnerabilityEvent
from .services import can_transition, get_available_transitions, transition, InvalidTransition


class VulnerabilityListView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """List vulnerabilities for a project with filters."""

    def get(self, request, project_id):
        qs = Vulnerability.objects.filter(project=self.project).select_related("phase", "reporter", "assignee")

        severity = request.GET.get("severity")
        if severity and severity in Vulnerability.Severity.values:
            qs = qs.filter(severity=severity)

        status = request.GET.get("status")
        if status and status in Vulnerability.Status.values:
            qs = qs.filter(status=status)

        phase_id = request.GET.get("phase")
        if phase_id:
            qs = qs.filter(phase_id=phase_id)

        phases = Phase.objects.filter(project=self.project).order_by("order")
        can_create = can_create_vuln(request.user, self.project)

        return render(request, "vulns/vuln_list.html", {
            "project": self.project,
            "vulnerabilities": qs,
            "phases": phases,
            "can_create": can_create,
            "selected_severity": severity,
            "selected_status": status,
            "selected_phase": phase_id,
            "severities": Vulnerability.Severity.choices,
            "statuses": Vulnerability.Status.choices,
        })


class VulnerabilityCreateView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Create a new vulnerability finding (Pentester and Admin only)."""

    def dispatch(self, request, *args, **kwargs):
        # We need self.project populated by ProjectMemberRequiredMixin first
        dispatch_resp = super().dispatch(request, *args, **kwargs)
        # If project mixin returned 404, dispatch_resp is an exception or response
        return dispatch_resp

    def get(self, request, project_id):
        if not can_create_vuln(request.user, self.project):
            return HttpResponseForbidden("Only Pentesters and Admins can log vulnerability findings.")
        form = VulnerabilityCreateForm(project=self.project)
        return render(request, "vulns/vuln_create.html", {
            "project": self.project,
            "form": form,
        })

    def post(self, request, project_id):
        if not can_create_vuln(request.user, self.project):
            return HttpResponseForbidden("Only Pentesters and Admins can log vulnerability findings.")

        form = VulnerabilityCreateForm(request.POST, project=self.project)
        if form.is_valid():
            vuln = form.save(commit=False)
            vuln.project = self.project
            vuln.reporter = request.user
            vuln.status = Vulnerability.Status.OPEN
            vuln.source = Vulnerability.Source.MANUAL
            vuln.save()

            # Record initial creation event
            VulnerabilityEvent.objects.create(
                vulnerability=vuln,
                from_status=Vulnerability.Status.OPEN,
                to_status=Vulnerability.Status.OPEN,
                actor=request.user,
                note="Finding reported and opened.",
            )

            messages.success(request, f"Vulnerability '{vuln.title}' logged with severity {vuln.severity} (CVSS {vuln.cvss_score}).")
            return redirect("vulns:detail", project_id=self.project.pk, vid=vuln.pk)

        return render(request, "vulns/vuln_create.html", {
            "project": self.project,
            "form": form,
        })


class VulnerabilityDetailView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Detail view for a vulnerability including CVSS breakdown, status, and event audit history."""

    def get(self, request, project_id, vid):
        vuln = get_object_or_404(Vulnerability, pk=vid, project=self.project)
        events = vuln.events.select_related("actor").order_by("created_at")
        available_transitions = get_available_transitions(request.user, vuln)

        return render(request, "vulns/vuln_detail.html", {
            "project": self.project,
            "vuln": vuln,
            "events": events,
            "available_transitions": available_transitions,
        })


class VulnerabilityTransitionView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """POST-only view to advance/reopen vulnerability status."""

    def get(self, request, project_id, vid):
        return HttpResponseNotAllowed(["POST"])

    def post(self, request, project_id, vid):
        vuln = get_object_or_404(Vulnerability, pk=vid, project=self.project)
        new_status = request.POST.get("new_status")
        note = request.POST.get("note", "").strip()

        if not can_transition(request.user, vuln, new_status):
            return HttpResponseForbidden("You do not have permission to perform this status transition.")

        try:
            transition(vuln, new_status, actor=request.user, note=note)
            messages.success(request, f"Vulnerability moved to {vuln.get_status_display()}.")
        except InvalidTransition as exc:
            messages.error(request, str(exc))

        return redirect("vulns:detail", project_id=self.project.pk, vid=vuln.pk)

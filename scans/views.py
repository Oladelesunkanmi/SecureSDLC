"""Views for scan target registration, scan execution, and results display (Phase 5)."""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from django_q.tasks import async_task

from accounts.permissions import can_register_target, can_trigger_scan
from projects.mixins import ProjectMemberRequiredMixin
from vulns.models import Vulnerability

from .forms import ScanTargetForm
from .models import Scan, ScanTarget
from .tasks import run_zap_scan


class TargetRegisterView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """View and register authorized scan targets."""

    def get(self, request, project_id):
        targets = ScanTarget.objects.filter(project=self.project).order_by("-created_at")
        form = ScanTargetForm()
        can_register = can_register_target(request.user, self.project)
        return render(request, "scans/target_list.html", {
            "project": self.project,
            "targets": targets,
            "form": form,
            "can_register": can_register,
        })

    def post(self, request, project_id):
        if not can_register_target(request.user, self.project):
            return HttpResponseForbidden("You do not have permission to register scan targets.")

        form = ScanTargetForm(request.POST)
        if form.is_valid():
            target = form.save(commit=False)
            target.project = self.project
            try:
                target.full_clean()
                target.save()
                messages.success(request, f"Scan target '{target.url}' registered successfully.")
                return redirect("scans:targets", project_id=self.project.pk)
            except Exception as exc:
                messages.error(request, str(exc))

        targets = ScanTarget.objects.filter(project=self.project).order_by("-created_at")
        return render(request, "scans/target_list.html", {
            "project": self.project,
            "targets": targets,
            "form": form,
            "can_register": True,
        })


class ScanListView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """List security scans performed for a project."""

    def get(self, request, project_id):
        scans = Scan.objects.filter(project=self.project).select_related("target", "requested_by").order_by("-created_at")
        can_scan = can_trigger_scan(request.user, self.project)
        return render(request, "scans/scan_list.html", {
            "project": self.project,
            "scans": scans,
            "can_scan": can_scan,
        })


class ScanCreateView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Trigger a new ZAP scan against an authorized target (Pentester/Admin only)."""

    def get(self, request, project_id):
        if not can_trigger_scan(request.user, self.project):
            return HttpResponseForbidden("Only Pentesters and Admins can trigger security scans.")

        targets = ScanTarget.objects.filter(project=self.project, authorization_confirmed=True)
        return render(request, "scans/scan_create.html", {
            "project": self.project,
            "targets": targets,
        })

    def post(self, request, project_id):
        if not can_trigger_scan(request.user, self.project):
            return HttpResponseForbidden("Only Pentesters and Admins can trigger security scans.")

        target_id = request.POST.get("target_id")
        target = get_object_or_404(ScanTarget, pk=target_id, project=self.project)

        if not target.authorization_confirmed:
            messages.error(request, "Cannot scan an unauthorized target.")
            return redirect("scans:create", project_id=self.project.pk)

        # Create Scan record in QUEUED status
        scan = Scan.objects.create(
            project=self.project,
            target=target,
            tool=Scan.Tool.ZAP,
            status=Scan.Status.QUEUED,
            requested_by=request.user,
        )

        # Queue Django-Q background task
        async_task(run_zap_scan, scan.id)

        messages.success(request, f"ZAP scan #{scan.id} queued against {target.url}.")
        return redirect("scans:detail", project_id=self.project.pk, sid=scan.pk)


class ScanDetailView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """View scan status, execution logs, and imported findings."""

    def get(self, request, project_id, sid):
        scan = get_object_or_404(Scan, pk=sid, project=self.project)
        imported_vulns = Vulnerability.objects.filter(scan=scan).order_by("-severity", "title")
        return render(request, "scans/scan_detail.html", {
            "project": self.project,
            "scan": scan,
            "imported_vulns": imported_vulns,
        })


class ScanStatusJSONView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """JSON polling endpoint returning scan status."""

    def get(self, request, project_id, sid):
        scan = get_object_or_404(Scan, pk=sid, project=self.project)
        return JsonResponse({
            "status": scan.status,
            "status_display": scan.get_status_display(),
            "is_complete": scan.status in [Scan.Status.DONE, Scan.Status.FAILED],
            "error_message": scan.error_message,
        })


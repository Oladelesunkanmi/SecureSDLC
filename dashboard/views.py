"""Views for project and global security dashboards (Phase 6)."""

import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.views import View

from accounts.models import User
from accounts.permissions import has_global_role
from projects.mixins import ProjectMemberRequiredMixin
from projects.models import Project

from .services import project_metrics, risk_score


class ProjectDashboardView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Project-level security dashboard presenting metrics and Chart.js visualizations."""

    def get(self, request, project_id):
        metrics = project_metrics(self.project)

        context = {
            "project": self.project,
            "metrics": metrics,
            "severity_chart_json": json.dumps(metrics["severity_chart"]),
            "status_chart_json": json.dumps(metrics["status_chart"]),
            "progress_chart_json": json.dumps(metrics["progress_chart"]),
        }
        return render(request, "dashboard/project_dashboard.html", context)


class GlobalDashboardView(LoginRequiredMixin, View):
    """Global security dashboard for Admins summarizing risk across all projects."""

    def get(self, request):
        if not has_global_role(request.user, User.Role.ADMIN):
            return HttpResponseForbidden("Only administrators may access the global dashboard.")

        projects = Project.objects.all().select_related("current_phase", "created_by").order_by("-created_at")

        projects_data = []
        for p in projects:
            score = risk_score(p)
            vuln_count = p.vulnerabilities.count()
            open_blocking = p.vulnerabilities.filter(
                status="OPEN",
                severity__in=["CRITICAL", "HIGH"],
            ).count()

            projects_data.append({
                "project": p,
                "risk_score": score,
                "total_vulns": vuln_count,
                "open_blocking": open_blocking,
            })

        # Sort projects by risk score descending (highest risk first)
        projects_data.sort(key=lambda item: item["risk_score"], reverse=True)

        return render(request, "dashboard/global_dashboard.html", {
            "projects_data": projects_data,
        })

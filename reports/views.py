"""Views for generating and downloading PDF reports (Phase 7)."""

import os
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, HttpResponseForbidden
from django.views import View

from accounts.permissions import can_generate_report
from projects.mixins import ProjectMemberRequiredMixin

from .services import generate_report


class ReportDownloadView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Generate and immediately download the comprehensive PDF security report.

    Restricted to project members with PM or Pentester role (or Admin).
    Developers are excluded (CLAUDE.md section 3 & 7).
    """

    def get(self, request, project_id):
        if not can_generate_report(request.user, self.project):
            return HttpResponseForbidden("You do not have permission to generate security reports.")

        report = generate_report(self.project, request.user)

        response = FileResponse(report.file.open("rb"), content_type="application/pdf")
        filename = os.path.basename(report.file.name)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


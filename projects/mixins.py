"""Reusable mixins for project-scoped views."""

from django.http import Http404

from accounts.models import User
from .models import Project, ProjectMember


class ProjectMemberRequiredMixin:
    """View mixin that enforces project membership.

    The view must capture a ``pk`` kwarg referring to a Project. Non-members
    receive a 404 (not 403) so that project existence is not revealed.

    Admins (global role ADMIN) can access any project.

    Sets ``self.project`` and ``self.membership`` on the view for convenience.
    """

    def dispatch(self, request, *args, **kwargs):
        project_id = kwargs.get("project_id") or kwargs.get("pk")
        try:
            self.project = Project.objects.get(pk=project_id)
        except Project.DoesNotExist:
            raise Http404

        if request.user.role == User.Role.ADMIN:
            self.membership = None  # Admin bypasses membership
            return super().dispatch(request, *args, **kwargs)

        try:
            self.membership = ProjectMember.objects.get(
                project=self.project,
                user=request.user,
            )
        except ProjectMember.DoesNotExist:
            raise Http404

        return super().dispatch(request, *args, **kwargs)


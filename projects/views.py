"""Views for the projects app."""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from accounts.models import User
from accounts.permissions import has_global_role

from .forms import AddMemberForm, ProjectCreateForm
from .mixins import ProjectMemberRequiredMixin
from .models import Project, ProjectMember
from .services import add_member, create_project, remove_member


class ProjectListView(LoginRequiredMixin, View):
    """List projects the user belongs to, or all projects for Admin."""

    def get(self, request):
        if has_global_role(request.user, User.Role.ADMIN):
            projects = Project.objects.all().order_by("-created_at")
        else:
            member_project_ids = ProjectMember.objects.filter(
                user=request.user
            ).values_list("project_id", flat=True)
            projects = Project.objects.filter(id__in=member_project_ids).order_by("-created_at")

        return render(request, "projects/project_list.html", {"projects": projects})


class ProjectCreateView(LoginRequiredMixin, View):
    """Create a new project. Only Admin and PM may access."""

    def dispatch(self, request, *args, **kwargs):
        if not has_global_role(request.user, User.Role.ADMIN, User.Role.PM):
            return HttpResponseForbidden("You do not have permission to create projects.")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = ProjectCreateForm()
        return render(request, "projects/project_create.html", {"form": form})

    def post(self, request):
        form = ProjectCreateForm(request.POST)
        if form.is_valid():
            project = create_project(
                name=form.cleaned_data["name"],
                description=form.cleaned_data["description"],
                sdlc_model=form.cleaned_data["sdlc_model"],
                created_by=request.user,
            )
            messages.success(request, f'Project "{project.name}" created.')
            return redirect("projects:detail", pk=project.pk)
        return render(request, "projects/project_create.html", {"form": form})


class ProjectDetailView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Project detail: phases, members, summary."""

    def get(self, request, pk):
        phases = self.project.phases.order_by("order")
        members_qs = self.project.members.select_related("user").order_by("project_role")
        return render(request, "projects/project_detail.html", {
            "project": self.project,
            "phases": phases,
            "members": members_qs,
            "membership": self.membership,
        })


class ProjectMembersView(LoginRequiredMixin, ProjectMemberRequiredMixin, View):
    """Add or remove project members. Only Admin and PM (on the project) may access."""

    def _can_manage(self, request) -> bool:
        if has_global_role(request.user, User.Role.ADMIN):
            return True
        if self.membership and self.membership.project_role == ProjectMember.ProjectRole.PM:
            return True
        return False

    def get(self, request, pk):
        if not self._can_manage(request):
            return HttpResponseForbidden("You do not have permission to manage members.")
        form = AddMemberForm(project=self.project)
        members_qs = self.project.members.select_related("user").order_by("project_role")
        return render(request, "projects/project_members.html", {
            "project": self.project,
            "form": form,
            "members": members_qs,
        })

    def post(self, request, pk):
        if not self._can_manage(request):
            return HttpResponseForbidden("You do not have permission to manage members.")

        action = request.POST.get("action")

        if action == "add":
            form = AddMemberForm(request.POST, project=self.project)
            if form.is_valid():
                try:
                    add_member(
                        self.project,
                        form.cleaned_data["user"],
                        form.cleaned_data["project_role"],
                    )
                    messages.success(request, "Member added.")
                except ValueError as e:
                    messages.error(request, str(e))
            else:
                messages.error(request, "Invalid form data.")

        elif action == "remove":
            user_id = request.POST.get("user_id")
            user = get_object_or_404(User, pk=user_id)
            try:
                remove_member(self.project, user)
                messages.success(request, f"{user.username} removed from the project.")
            except ValueError as e:
                messages.error(request, str(e))

        return redirect("projects:members", pk=self.project.pk)


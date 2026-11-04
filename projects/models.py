"""Projects app models.

Defines ``Project`` and ``ProjectMember``.
"""

from django.conf import settings
from django.db import models


class Project(models.Model):
    """A software project tracked through six SDLC phases."""

    class SDLCModel(models.TextChoices):
        WATERFALL = "WATERFALL", "Waterfall"
        AGILE = "AGILE", "Agile"

    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    sdlc_model = models.CharField(max_length=20, choices=SDLCModel.choices)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_projects",
    )
    current_phase = models.ForeignKey(
        "phases.Phase",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class ProjectMember(models.Model):
    """Associates a user with a project in a specific project role.

    The project role is separate from the global role (User.role) so a user
    can be a Developer on one project and a Pentester on another.
    """

    class ProjectRole(models.TextChoices):
        PM = "PM", "Project Manager"
        DEVELOPER = "DEVELOPER", "Developer"
        PENTESTER = "PENTESTER", "Pentester"

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="members",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="project_memberships",
    )
    project_role = models.CharField(max_length=20, choices=ProjectRole.choices)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("project", "user")

    def __str__(self) -> str:
        return f"{self.user.username} on {self.project.name} ({self.get_project_role_display()})"


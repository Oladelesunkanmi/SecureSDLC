"""Phases app models.

Defines the ``Phase`` model — the six SDLC phases that every project passes
through. Checklist models are added in Phase 3.
"""

from django.db import models


class Phase(models.Model):
    """One SDLC phase within a project."""

    class Kind(models.TextChoices):
        REQUIREMENTS = "REQUIREMENTS", "Requirements"
        DESIGN = "DESIGN", "Design"
        CODING = "CODING", "Coding"
        TESTING = "TESTING", "Testing"
        DEPLOYMENT = "DEPLOYMENT", "Deployment"
        MAINTENANCE = "MAINTENANCE", "Maintenance"

    class Status(models.TextChoices):
        NOT_STARTED = "NOT_STARTED", "Not Started"
        IN_PROGRESS = "IN_PROGRESS", "In Progress"
        COMPLETED = "COMPLETED", "Completed"

    # The order each phase kind should appear in.
    KIND_ORDER = {
        Kind.REQUIREMENTS: 1,
        Kind.DESIGN: 2,
        Kind.CODING: 3,
        Kind.TESTING: 4,
        Kind.DEPLOYMENT: 5,
        Kind.MAINTENANCE: 6,
    }

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="phases",
    )
    kind = models.CharField(max_length=20, choices=Kind.choices)
    order = models.PositiveIntegerField()
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.NOT_STARTED,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("project", "kind")
        ordering = ["order"]

    def __str__(self) -> str:
        return f"{self.project.name} – {self.get_kind_display()} ({self.get_status_display()})"


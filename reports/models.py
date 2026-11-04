"""Reports app models (CLAUDE.md section 4 and Phase 7)."""

from django.conf import settings
from django.db import models


class Report(models.Model):
    """A generated PDF security report for a project."""

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="reports",
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="generated_reports",
    )
    generated_at = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to="reports/")

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"Report for {self.project.name} ({self.generated_at.strftime('%Y-%m-%d %H:%M')})"


"""Phases app models.

Defines the ``Phase`` model, checklist templates (``ChecklistItem``), project
checklist responses (``ChecklistResponse``), and the gate decision audit log (``GateDecision``).
"""

from django.conf import settings
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


class ChecklistItem(models.Model):
    """Global template item for a phase security checklist (seeded from fixture)."""

    phase_kind = models.CharField(max_length=20, choices=Phase.Kind.choices)
    code = models.CharField(max_length=20, unique=True)
    text = models.CharField(max_length=255)
    guidance = models.TextField(blank=True)
    required = models.BooleanField(default=True)
    owasp_ref = models.CharField(max_length=50, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["phase_kind", "code"]

    def __str__(self) -> str:
        req_flag = " (Required)" if self.required else " (Optional)"
        return f"[{self.code}] {self.text}{req_flag}"


class ChecklistResponse(models.Model):
    """A project's response and evidence for a specific checklist item."""

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="checklist_responses",
    )
    item = models.ForeignKey(
        ChecklistItem,
        on_delete=models.CASCADE,
        related_name="responses",
    )
    done = models.BooleanField(default=False)
    evidence = models.TextField(blank=True)
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="completed_checklist_items",
    )
    completed_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("project", "item")
        ordering = ["item__code"]

    def __str__(self) -> str:
        status = "Done" if self.done else "Pending"
        return f"{self.project.name} - {self.item.code}: {status}"


class GateDecision(models.Model):
    """Audit log of every phase gate evaluation (allowed or blocked) or phase reopen."""

    class Action(models.TextChoices):
        ADVANCE = "ADVANCE", "Advance Phase"
        REOPEN = "REOPEN", "Reopen Phase"

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="gate_decisions",
    )
    phase = models.ForeignKey(
        Phase,
        on_delete=models.CASCADE,
        related_name="gate_decisions",
    )
    action = models.CharField(
        max_length=20,
        choices=Action.choices,
        default=Action.ADVANCE,
    )
    allowed = models.BooleanField()
    reasons = models.JSONField(default=list)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="gate_decisions",
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        result = "Allowed" if self.allowed else "Blocked"
        return f"{self.project.name} {self.phase.get_kind_display()} ({self.action}): {result}"

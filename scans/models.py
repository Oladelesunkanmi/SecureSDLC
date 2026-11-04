"""Scans app models: ScanTarget and Scan (CLAUDE.md section 4 and section 5.5)."""

from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class ScanTarget(models.Model):
    """An authorized web application target for security scanning."""

    class Environment(models.TextChoices):
        LOCAL_TEST = "LOCAL_TEST", "Local Test (e.g. Docker / Localhost)"
        STAGING = "STAGING", "Staging Environment"

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="scan_targets",
    )
    url = models.URLField(max_length=255, help_text="Target URL (must be an allowed test host, e.g. http://localhost:3000)")
    environment = models.CharField(
        max_length=20,
        choices=Environment.choices,
        default=Environment.LOCAL_TEST,
    )
    authorization_confirmed = models.BooleanField(
        default=False,
        help_text="Explicit authorization confirmed by project owner/security team",
    )
    authorized_by = models.CharField(max_length=150)
    authorized_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.url} ({self.get_environment_display()})"

    def save(self, *args, **kwargs):
        if self.authorization_confirmed and not self.authorized_at:
            from django.utils import timezone
            self.authorized_at = timezone.now()
        super().save(*args, **kwargs)

    def clean(self):
        super().clean()

        # Rule 1: Authorization must be confirmed
        if not self.authorization_confirmed:
            raise ValidationError({
                "authorization_confirmed": "Explicit authorization must be confirmed to register a scan target."
            })

        # Rule 2: Host must be on SCAN_ALLOWED_HOSTS
        if not self.url:
            return

        parsed = urlparse(self.url)
        host = (parsed.hostname or "").strip().lower()

        allowed_hosts = [h.strip().lower() for h in getattr(settings, "SCAN_ALLOWED_HOSTS", [])]
        if not host or host not in allowed_hosts:
            raise ValidationError({
                "url": f"Host '{host}' is not on the scan allowlist ({', '.join(allowed_hosts)}). Production or arbitrary hosts are prohibited."
            })

        # Rule 3: Environment cannot be production
        if self.environment not in [self.Environment.LOCAL_TEST, self.Environment.STAGING]:
            raise ValidationError({
                "environment": "Only LOCAL_TEST and STAGING environments are permitted."
            })


class Scan(models.Model):
    """An execution of a security scanning tool against an authorized target."""

    class Tool(models.TextChoices):
        ZAP = "ZAP", "OWASP ZAP"

    class Status(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        RUNNING = "RUNNING", "Running"
        DONE = "DONE", "Completed"
        FAILED = "FAILED", "Failed"

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="scans",
    )
    target = models.ForeignKey(
        ScanTarget,
        on_delete=models.CASCADE,
        related_name="scans",
    )
    tool = models.CharField(
        max_length=20,
        choices=Tool.choices,
        default=Tool.ZAP,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="requested_scans",
    )
    raw_result = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.tool} scan #{self.id} on {self.target.url} ({self.get_status_display()})"

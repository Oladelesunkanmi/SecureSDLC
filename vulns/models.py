"""Vulnerabilities app models.

Defines ``Vulnerability`` and ``VulnerabilityEvent``.
"""

from django.conf import settings
from django.db import models


class Vulnerability(models.Model):
    """A security vulnerability finding associated with a project and optional phase."""

    class Severity(models.TextChoices):
        CRITICAL = "CRITICAL", "Critical"
        HIGH = "HIGH", "High"
        MEDIUM = "MEDIUM", "Medium"
        LOW = "LOW", "Low"
        INFO = "INFO", "Informational"

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        FIXED = "FIXED", "Fixed"
        VERIFIED = "VERIFIED", "Verified"
        CLOSED = "CLOSED", "Closed"

    class Source(models.TextChoices):
        MANUAL = "MANUAL", "Manual"
        ZAP = "ZAP", "OWASP ZAP"

    class OWASPCategory(models.TextChoices):
        A01 = "A01:2021", "A01:2021 – Broken Access Control"
        A02 = "A02:2021", "A02:2021 – Cryptographic Failures"
        A03 = "A03:2021", "A03:2021 – Injection"
        A04 = "A04:2021", "A04:2021 – Insecure Design"
        A05 = "A05:2021", "A05:2021 – Security Misconfiguration"
        A06 = "A06:2021", "A06:2021 – Vulnerable and Outdated Components"
        A07 = "A07:2021", "A07:2021 – Identification and Authentication Failures"
        A08 = "A08:2021", "A08:2021 – Software and Data Integrity Failures"
        A09 = "A09:2021", "A09:2021 – Security Logging and Monitoring Failures"
        A10 = "A10:2021", "A10:2021 – Server-Side Request Forgery (SSRF)"

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    phase = models.ForeignKey(
        "phases.Phase",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="vulnerabilities",
    )
    title = models.CharField(max_length=200)
    description = models.TextField()
    affected_component = models.CharField(max_length=255)

    cvss_vector = models.CharField(max_length=150, blank=True)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, default=0.0)
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.INFO,
    )

    owasp_category = models.CharField(
        max_length=20,
        choices=OWASPCategory.choices,
        blank=True,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.OPEN,
    )
    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.MANUAL,
    )

    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reported_vulnerabilities",
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_vulnerabilities",
    )

    zap_alert_id = models.CharField(max_length=100, blank=True, null=True)
    due_date = models.DateField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "vulnerabilities"

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title} ({self.get_status_display()})"


class VulnerabilityEvent(models.Model):
    """Audit trail for vulnerability status changes."""

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="events",
    )
    from_status = models.CharField(max_length=20, choices=Vulnerability.Status.choices)
    to_status = models.CharField(max_length=20, choices=Vulnerability.Status.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
    )
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.vulnerability.title}: {self.from_status} -> {self.to_status}"


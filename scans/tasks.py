"""Background scanning tasks executed via Django-Q (CLAUDE.md section 5.5 and Phase 5)."""

import logging
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone

from vulns.cvss import parse_cvss_vector
from vulns.models import Vulnerability, VulnerabilityEvent

from .models import Scan, ScanTarget
from .zap_client import ZAPClient, ZAPClientError, ZAPTimeoutError

logger = logging.getLogger(__name__)

# Default CVSS:3.1 vectors mapped from ZAP risk levels (CLAUDE.md section 5.2 approximation)
ZAP_RISK_TO_CVSS = {
    "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",           # Score 7.5, HIGH
    "Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",         # Score 5.3, MEDIUM
    "Low": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",            # Score 3.5, LOW
    "Informational": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # Score 0.0, INFO
    "Info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",           # Score 0.0, INFO
}

# Map common CWE or tags to OWASP Top 10 (2021) categories
CWE_TO_OWASP = {
    "79": Vulnerability.OWASPCategory.A03,    # XSS -> Injection
    "89": Vulnerability.OWASPCategory.A03,    # SQLi -> Injection
    "78": Vulnerability.OWASPCategory.A03,    # OS Command Injection
    "352": Vulnerability.OWASPCategory.A01,   # CSRF -> Broken Access Control
    "287": Vulnerability.OWASPCategory.A07,   # Improper Authentication
    "384": Vulnerability.OWASPCategory.A07,   # Session Fixation
    "200": Vulnerability.OWASPCategory.A05,   # Information Disclosure
    "16": Vulnerability.OWASPCategory.A05,    # Configuration
    "311": Vulnerability.OWASPCategory.A02,   # Missing Encryption
    "319": Vulnerability.OWASPCategory.A02,   # Cleartext Transmission
    "918": Vulnerability.OWASPCategory.A10,   # SSRF
}


def map_owasp_category(alert: dict) -> str:
    """Infer OWASP 2021 category from ZAP alert tags or CWE."""
    tags = alert.get("tags") or {}
    if isinstance(tags, dict):
        for key in tags:
            upper_k = key.upper()
            for cat in Vulnerability.OWASPCategory.values:
                # e.g. "A01:2021" -> "A01"
                short_code = cat.split(":")[0]
                if short_code in upper_k:
                    return cat

    cwe_id = str(alert.get("cweid", "")).strip()
    if cwe_id in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe_id]

    return ""


def run_zap_scan(scan_id: int, client: ZAPClient = None) -> bool:
    """Django-Q task that executes an OWASP ZAP scan against a registered target.

    Safety checks (CLAUDE.md section 5.5):
    - Target must have authorization_confirmed=True.
    - Host must be present on settings.SCAN_ALLOWED_HOSTS.
    - Re-checked before execution.
    """
    try:
        scan = Scan.objects.select_related("project", "target", "requested_by").get(pk=scan_id)
    except Scan.DoesNotExist:
        logger.error(f"Scan #{scan_id} does not exist.")
        return False

    target = scan.target

    # Safety Re-check 1: Target authorization
    if not target.authorization_confirmed:
        scan.status = Scan.Status.FAILED
        scan.error_message = "Scan refused: target authorization is not confirmed or has been revoked."
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "finished_at"])
        return False

    # Safety Re-check 2: Allowlist verification
    parsed = urlparse(target.url)
    host = (parsed.hostname or "").strip().lower()
    allowed_hosts = [h.strip().lower() for h in getattr(settings, "SCAN_ALLOWED_HOSTS", [])]
    if not host or host not in allowed_hosts:
        scan.status = Scan.Status.FAILED
        scan.error_message = f"Scan refused: host '{host}' is not on the scan allowlist."
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "finished_at"])
        return False

    # Mark scan RUNNING
    scan.status = Scan.Status.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=["status", "started_at"])

    # Instantiate ZAP client if not injected (for testing)
    zap = client or ZAPClient()

    try:
        # Step 1: Run spider to discover URLs
        logger.info(f"Starting ZAP spider on {target.url} for scan #{scan.id}")
        spider_id = zap.start_spider(target.url)
        zap.wait_for_spider(spider_id)

        # Step 2: Run active scan for vulnerabilities
        logger.info(f"Starting ZAP active scan on {target.url} for scan #{scan.id}")
        ascan_id = zap.start_active_scan(target.url)
        zap.wait_for_ascan(ascan_id)

        # Step 3: Fetch findings
        alerts = zap.get_alerts(target.url)
        scan.raw_result = alerts

        # Step 4: Import and deduplicate findings as Vulnerabilities
        import_alerts_to_vulnerabilities(scan, alerts)

        scan.status = Scan.Status.DONE
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "raw_result", "finished_at"])
        return True

    except ZAPTimeoutError as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = f"Scan timed out: {exc}"
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "finished_at"])
        logger.warning(f"Scan #{scan.id} timed out: {exc}")
        return False

    except ZAPClientError as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = f"ZAP communication failure: {exc}"
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "finished_at"])
        logger.error(f"Scan #{scan.id} failed: {exc}")
        return False

    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = f"Unexpected error during scan execution: {exc}"
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "finished_at"])
        logger.exception(f"Unexpected error in scan #{scan.id}")
        return False


def import_alerts_to_vulnerabilities(scan: Scan, alerts: list[dict]) -> int:
    """Convert raw ZAP alerts into Vulnerability records, with deduplication on (target, zap_alert_id, url)."""
    imported_count = 0
    fallback_reporter = scan.requested_by

    # Testing phase of this project (for linking finding to TESTING phase)
    testing_phase = scan.project.phases.filter(kind="TESTING").first()

    for alert in alerts:
        alert_plugin_id = str(alert.get("pluginId") or alert.get("id") or alert.get("alertId") or "")
        alert_url = alert.get("url") or scan.target.url

        # Deduplicate on (target, zap_alert_id, url)
        exists = Vulnerability.objects.filter(
            project=scan.project,
            zap_alert_id=alert_plugin_id,
            affected_component=alert_url,
        ).exists()

        if exists:
            continue

        zap_risk = alert.get("risk", "Low")
        cvss_vector = ZAP_RISK_TO_CVSS.get(zap_risk, ZAP_RISK_TO_CVSS["Low"])
        score, severity = parse_cvss_vector(cvss_vector)
        owasp_cat = map_owasp_category(alert)

        vuln = Vulnerability.objects.create(
            project=scan.project,
            phase=testing_phase,
            title=alert.get("alert", "Unnamed ZAP Alert"),
            description=alert.get("description", "No description provided by ZAP."),
            affected_component=alert_url,
            cvss_vector=cvss_vector,
            cvss_score=score,
            severity=severity,
            owasp_category=owasp_cat,
            status=Vulnerability.Status.OPEN,
            source=Vulnerability.Source.ZAP,
            reporter=fallback_reporter,
            scan=scan,
            zap_alert_id=alert_plugin_id,
        )

        VulnerabilityEvent.objects.create(
            vulnerability=vuln,
            from_status=Vulnerability.Status.OPEN,
            to_status=Vulnerability.Status.OPEN,
            actor=fallback_reporter,
            note=f"Imported from {scan.tool} scan #{scan.id} (Risk: {zap_risk}).",
        )
        imported_count += 1

    return imported_count

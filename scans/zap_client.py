"""OWASP ZAP API client wrapper (CLAUDE.md section 5.5 and Phase 5)."""

import time
from typing import Any, List, Optional
from urllib.parse import urlparse

from django.conf import settings
from zapv2 import ZAPv2


class ZAPClientError(Exception):
    """Base exception for ZAP client communication errors."""
    pass


class ZAPTimeoutError(ZAPClientError):
    """Raised when a ZAP scan operation exceeds the configured timeout."""
    pass


class ZAPClient:
    """Wrapper around zapv2.ZAPv2 for spidering, active scanning, and alert collection."""

    def __init__(
        self,
        zap_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ):
        self.zap_url = zap_url or getattr(settings, "ZAP_API_URL", "http://localhost:8080")
        self.api_key = api_key if api_key is not None else getattr(settings, "ZAP_API_KEY", "")
        self.timeout_seconds = timeout_seconds or getattr(settings, "SCAN_TIMEOUT_SECONDS", 900)

        proxies = {
            "http": self.zap_url,
            "https": self.zap_url,
        }
        self.zap = ZAPv2(proxies=proxies, apikey=self.api_key)

    def start_spider(self, url: str) -> str:
        """Start the ZAP spider against ``url`` and return the spider scan ID."""
        try:
            scan_id = self.zap.spider.scan(url=url)
            return str(scan_id)
        except Exception as exc:
            raise ZAPClientError(f"Failed to start ZAP spider on {url}: {exc}") from exc

    def wait_for_spider(self, scan_id: str, timeout: Optional[int] = None, poll_interval: float = 1.0) -> None:
        """Wait until spidering completes or timeout expires."""
        max_time = timeout if timeout is not None else self.timeout_seconds
        start_time = time.time()

        while True:
            try:
                status_raw = self.zap.spider.status(scan_id)
                progress = int(status_raw)
            except Exception as exc:
                raise ZAPClientError(f"Error checking spider status for scan #{scan_id}: {exc}") from exc

            if progress >= 100:
                break

            if (time.time() - start_time) > max_time:
                raise ZAPTimeoutError(f"ZAP spider scan #{scan_id} timed out after {max_time} seconds.")

            time.sleep(poll_interval)

    def start_active_scan(self, url: str) -> str:
        """Start an active vulnerability scan against ``url`` and return the scan ID."""
        try:
            scan_id = self.zap.ascan.scan(url=url)
            return str(scan_id)
        except Exception as exc:
            raise ZAPClientError(f"Failed to start ZAP active scan on {url}: {exc}") from exc

    def wait_for_ascan(self, scan_id: str, timeout: Optional[int] = None, poll_interval: float = 2.0) -> None:
        """Wait until active scan completes or timeout expires."""
        max_time = timeout if timeout is not None else self.timeout_seconds
        start_time = time.time()

        while True:
            try:
                status_raw = self.zap.ascan.status(scan_id)
                progress = int(status_raw)
            except Exception as exc:
                raise ZAPClientError(f"Error checking active scan status for scan #{scan_id}: {exc}") from exc

            if progress >= 100:
                break

            if (time.time() - start_time) > max_time:
                raise ZAPTimeoutError(f"ZAP active scan #{scan_id} timed out after {max_time} seconds.")

            time.sleep(poll_interval)

    def get_alerts(self, url: Optional[str] = None) -> list[dict[str, Any]]:
        """Retrieve alerts for the specified target URL."""
        try:
            alerts = self.zap.core.alerts(baseurl=url)
            if isinstance(alerts, list):
                return alerts
            return []
        except Exception as exc:
            raise ZAPClientError(f"Failed to fetch alerts from ZAP: {exc}") from exc


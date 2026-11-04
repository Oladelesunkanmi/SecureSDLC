"""CVSS v3.1 parsing, validation, and severity derivation (CLAUDE.md section 5.2)."""

import cvss
from cvss.exceptions import CVSSError


class CVSSValidationError(ValueError):
    """Raised when a CVSS vector string is invalid or cannot be parsed."""
    pass


def score_to_severity(score: float) -> str:
    """Map a CVSS base score to severity using the NVD scale (CLAUDE.md section 5.2).

    Boundaries:
    - 0.0 -> INFO
    - 0.1–3.9 -> LOW
    - 4.0–6.9 -> MEDIUM
    - 7.0–8.9 -> HIGH
    - 9.0–10.0 -> CRITICAL
    """
    s = round(float(score), 1)

    if s <= 0.0:
        return "INFO"
    elif s <= 3.9:
        return "LOW"
    elif s <= 6.9:
        return "MEDIUM"
    elif s <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"


def parse_cvss_vector(vector: str) -> tuple[float, str]:
    """Parse and validate a CVSS:3.1 vector string, returning ``(base_score, severity)``.

    Raises ``CVSSValidationError`` if the vector is invalid or malformed.
    """
    if not vector or not isinstance(vector, str):
        raise CVSSValidationError("CVSS vector cannot be empty.")

    cleaned = vector.strip()
    try:
        c = cvss.CVSS3(cleaned)
        # c.base_score is the float base score (0.0 - 10.0)
        base_score = float(c.base_score)
        severity = score_to_severity(base_score)
        return base_score, severity
    except CVSSError as exc:
        raise CVSSValidationError(f"Invalid CVSS:3.1 vector: {exc}") from exc
    except Exception as exc:
        raise CVSSValidationError(f"Could not parse CVSS vector: {exc}") from exc

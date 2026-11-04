"""Vulnerability transition and lifecycle services (CLAUDE.md section 5.3)."""

from django.db import transaction

from accounts.models import User
from accounts.permissions import has_global_role
from projects.models import ProjectMember

from .models import Vulnerability, VulnerabilityEvent


class InvalidTransition(ValueError):
    """Raised when an illegal status transition or unauthorized transition is attempted."""
    pass


# Map of (from_status, to_status) -> allowed roles
# Global role ADMIN is always permitted.
ALLOWED_TRANSITIONS = {
    (Vulnerability.Status.OPEN, Vulnerability.Status.FIXED): {ProjectMember.ProjectRole.DEVELOPER},
    (Vulnerability.Status.FIXED, Vulnerability.Status.VERIFIED): {ProjectMember.ProjectRole.PENTESTER},
    (Vulnerability.Status.VERIFIED, Vulnerability.Status.CLOSED): {ProjectMember.ProjectRole.PENTESTER},
    (Vulnerability.Status.FIXED, Vulnerability.Status.OPEN): {ProjectMember.ProjectRole.PENTESTER},
    (Vulnerability.Status.VERIFIED, Vulnerability.Status.OPEN): {ProjectMember.ProjectRole.PENTESTER},
}


def can_transition(user, vuln: Vulnerability, new_status: str) -> bool:
    """Return whether ``user`` is allowed to transition ``vuln`` to ``new_status``."""
    if not user or not user.is_authenticated:
        return False

    pair = (vuln.status, new_status)
    if pair not in ALLOWED_TRANSITIONS:
        return False

    # Admin is site-wide superuser and can execute any valid transition
    if has_global_role(user, User.Role.ADMIN):
        return True

    # Look up project membership role
    membership = ProjectMember.objects.filter(
        project=vuln.project,
        user=user,
    ).first()
    if not membership:
        return False

    allowed_roles = ALLOWED_TRANSITIONS[pair]
    return membership.project_role in allowed_roles


def get_available_transitions(user, vuln: Vulnerability) -> list[tuple[str, str]]:
    """Return list of (status_value, status_display) that ``user`` is allowed to transition to."""
    available = []
    for (from_st, to_st) in ALLOWED_TRANSITIONS:
        if from_st == vuln.status and can_transition(user, vuln, to_st):
            # Display label
            display = dict(Vulnerability.Status.choices).get(to_st, to_st)
            available.append((to_st, display))
    return available


def transition(vuln: Vulnerability, new_status: str, actor, note: str = "") -> VulnerabilityEvent:
    """Transition ``vuln`` to ``new_status``, recorded with a ``VulnerabilityEvent``.

    Enforces CLAUDE.md section 5.3:
    - OPEN -> FIXED (Developer, Admin)
    - FIXED -> VERIFIED (Pentester, Admin)
    - VERIFIED -> CLOSED (Pentester, Admin)
    - FIXED -> OPEN (Pentester, Admin: fix rejected on re-test)
    - VERIFIED -> OPEN (Pentester, Admin: regression)

    Raises ``InvalidTransition`` if the transition is illegal or unauthorized.
    """
    pair = (vuln.status, new_status)
    if pair not in ALLOWED_TRANSITIONS:
        raise InvalidTransition(
            f"Transition from {vuln.status} to {new_status} is not allowed."
        )

    if not can_transition(actor, vuln, new_status):
        actor_role = getattr(actor, "role", "Anonymous")
        raise InvalidTransition(
            f"User '{getattr(actor, 'username', 'Unknown')}' ({actor_role}) does not have permission "
            f"to transition finding from {vuln.status} to {new_status}."
        )

    with transaction.atomic():
        old_status = vuln.status
        vuln.status = new_status
        vuln.save(update_fields=["status", "updated_at"])

        event = VulnerabilityEvent.objects.create(
            vulnerability=vuln,
            from_status=old_status,
            to_status=new_status,
            actor=actor,
            note=note.strip(),
        )

    return event

"""Permission helpers for the SecureSDLC project.

Provides role and capability checks (CLAUDE.md section 3).
"""

from .models import User


def has_global_role(user, *roles) -> bool:
    """Return ``True`` if ``user.role`` matches any of the provided ``roles``."""
    if not user or not getattr(user, "role", None):
        return False
    role_value = user.role
    normalized = {r if isinstance(r, str) else r.value for r in roles}
    return role_value in normalized


def can_advance_phase(user, project) -> bool:
    """Check whether a user can advance a phase through the gate (Admin, PM)."""
    if not user or not user.is_authenticated:
        return False
    if has_global_role(user, User.Role.ADMIN):
        return True
    from projects.models import ProjectMember

    return ProjectMember.objects.filter(
        project=project,
        user=user,
        project_role=ProjectMember.ProjectRole.PM,
    ).exists()


def can_reopen_phase(user, project) -> bool:
    """Check whether a user can reopen an Agile phase (Admin, PM)."""
    return can_advance_phase(user, project)


def can_create_vuln(user, project) -> bool:
    """Check whether a user can create a vulnerability finding (Admin, Pentester)."""
    if not user or not user.is_authenticated:
        return False
    if has_global_role(user, User.Role.ADMIN):
        return True
    from projects.models import ProjectMember

    return ProjectMember.objects.filter(
        project=project,
        user=user,
        project_role=ProjectMember.ProjectRole.PENTESTER,
    ).exists()


def can_register_target(user, project) -> bool:
    """Check whether a user can register a scan target (Admin, PM, Pentester)."""
    if not user or not user.is_authenticated:
        return False
    if has_global_role(user, User.Role.ADMIN):
        return True
    from projects.models import ProjectMember

    return ProjectMember.objects.filter(
        project=project,
        user=user,
        project_role__in=[ProjectMember.ProjectRole.PM, ProjectMember.ProjectRole.PENTESTER],
    ).exists()


def can_trigger_scan(user, project) -> bool:
    """Check whether a user can trigger a ZAP scan (Admin, Pentester)."""
    return can_create_vuln(user, project)

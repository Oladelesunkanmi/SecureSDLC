"""Permission helpers for the SecureSDLC project.

Provides a simple function to check a user's global role.
"""

from .models import User

def has_global_role(user, *roles) -> bool:
    """Return ``True`` if ``user.role`` matches any of the provided ``roles``.

    ``roles`` can be either the enum values (e.g. ``User.Role.ADMIN``) or the
    raw string identifiers (e.g. ``"ADMIN"``). The function gracefully handles
    ``None`` or anonymous users by returning ``False``.
    """
    if not user or not getattr(user, "role", None):
        return False
    role_value = user.role
    # Normalise supplied roles to their string values
    normalized = {r if isinstance(r, str) else r.value for r in roles}
    return role_value in normalized


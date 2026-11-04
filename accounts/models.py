"""Accounts app models.

Defines a custom ``User`` model extending ``AbstractUser`` with a ``role`` field.
"""

from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """Custom user with a role.

    Roles (global permissions):
    - ADMIN
    - PM (Project Manager)
    - DEVELOPER
    - PENTESTER
    """

    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        PM = "PM", "Project Manager"
        DEVELOPER = "DEVELOPER", "Developer"
        PENTESTER = "PENTESTER", "Pentester"

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.DEVELOPER,
    )

    def __str__(self) -> str:
        return f"{self.username} ({self.get_role_display()})"


from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom admin for User displaying the role column."""

    list_display = ("username", "email", "first_name", "last_name", "role")
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Role information", {"fields": ("role",)}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ("Role information", {"fields": ("role",)}),
    )


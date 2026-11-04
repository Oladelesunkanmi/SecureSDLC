from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = "Create demo users for each role (admin, pm, developer, pentester)"

    def handle(self, *args, **options):
        User = get_user_model()
        users = [
            {"username": "admin", "role": User.Role.ADMIN, "is_staff": True, "is_superuser": True},
            {"username": "pm", "role": User.Role.PM, "is_staff": True},
            {"username": "dev", "role": User.Role.DEVELOPER},
            {"username": "pentester", "role": User.Role.PENTESTER},
        ]
        password = "demo123"
        for u in users:
            obj, created = User.objects.get_or_create(username=u["username"], defaults={
                "role": u["role"],
                "is_staff": u.get("is_staff", False),
                "is_superuser": u.get("is_superuser", False),
            })
            if created:
                obj.set_password(password)
                obj.save()
                self.stdout.write(self.style.SUCCESS(f"Created {obj.username} ({obj.role})"))
            else:
                self.stdout.write(f"User {obj.username} already exists")


from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import User
from accounts.permissions import has_global_role


class AccountsTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_unauthenticated_redirect_to_login(self):
        response = self.client.get(reverse("projects:list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.url)

    def test_role_creation_and_has_global_role(self):
        for role_name in [User.Role.ADMIN, User.Role.PM, User.Role.DEVELOPER, User.Role.PENTESTER]:
            user = User.objects.create_user(
                username=f"user_{role_name.lower()}",
                password="password123",
                role=role_name,
            )
            self.assertEqual(user.role, role_name)
            self.assertTrue(has_global_role(user, role_name))
            self.assertFalse(has_global_role(user, "NON_EXISTENT_ROLE"))

    def test_has_global_role_multiple(self):
        dev = User.objects.create_user(username="dev1", password="pw", role=User.Role.DEVELOPER)
        self.assertTrue(has_global_role(dev, User.Role.ADMIN, User.Role.DEVELOPER))
        self.assertFalse(has_global_role(dev, User.Role.ADMIN, User.Role.PM))

    def test_has_global_role_anonymous_or_none(self):
        self.assertFalse(has_global_role(None, User.Role.ADMIN))


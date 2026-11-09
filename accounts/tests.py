from django.test import TestCase, Client, override_settings
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

    @override_settings(DEBUG=False)
    def test_custom_404_page_no_stack_trace(self):
        response = self.client.get("/non-existent-endpoint-xyz-404/")
        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "404.html")
        self.assertContains(response, "Page or Resource Not Found", status_code=404)
        self.assertNotContains(response, "Traceback", status_code=404)
        self.assertNotContains(response, "Using the URLconf defined in", status_code=404)

    def test_logout_get_renders_logged_out_page_and_clears_session(self):
        user = User.objects.create_user(username="logout_u1", password="password123")
        self.client.login(username="logout_u1", password="password123")
        response = self.client.get(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/logged_out.html")
        self.assertContains(response, "Successfully Signed Out")
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_logout_post_renders_logged_out_page_and_clears_session(self):
        user = User.objects.create_user(username="logout_u2", password="password123")
        self.client.login(username="logout_u2", password="password123")
        response = self.client.post(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/logged_out.html")
        self.assertContains(response, "Successfully Signed Out")
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_logout_post_with_next_redirects(self):
        user = User.objects.create_user(username="logout_u3", password="password123")
        self.client.login(username="logout_u3", password="password123")
        response = self.client.post(f"{reverse('accounts:logout')}?next={reverse('accounts:login')}")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("accounts:login"))
        self.assertFalse(response.wsgi_request.user.is_authenticated)



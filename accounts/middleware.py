"""Development-only auto-authentication middleware for local testing and screenshot generation."""

from django.conf import settings
from django.contrib.auth import get_user_model


class DevAutoAuthMiddleware:
    """Authenticate a specified user via query parameter in local development.

    Strictly inactive unless settings.DEBUG is True.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.DEBUG and "__as_user" in request.GET:
            username = request.GET.get("__as_user")
            User = get_user_model()
            try:
                request.user = User.objects.get(username=username)
            except User.DoesNotExist:
                pass
        return self.get_response(request)


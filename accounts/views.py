"""Views for the accounts app.

Provides custom authentication views including LogoutView.
"""

from django.contrib.auth import logout as auth_logout
from django.shortcuts import render, redirect
from django.views import View


class LogoutView(View):
    """Log out the current user and render the custom logged_out page.

    Supports both POST and GET requests so that direct navigation, bookmarks,
    or link clicks never trigger a 405 Method Not Allowed error.
    """

    template_name = "accounts/logged_out.html"

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            auth_logout(request)
        return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            auth_logout(request)
        next_url = request.POST.get("next") or request.GET.get("next")
        if next_url:
            return redirect(next_url)
        return render(request, self.template_name)

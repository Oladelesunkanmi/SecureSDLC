"""Forms for the scans app (Phase 5)."""

from django import forms
from .models import ScanTarget


class ScanTargetForm(forms.ModelForm):
    """Form to register a test scan target with mandatory ethical authorization confirmation."""

    authorization_confirmed = forms.BooleanField(
        required=True,
        label="I confirm I have explicit written authorization to perform security testing on this target.",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )

    class Meta:
        model = ScanTarget
        fields = [
            "url",
            "environment",
            "authorization_confirmed",
            "authorized_by",
        ]
        widgets = {
            "url": forms.URLInput(attrs={
                "class": "form-control",
                "placeholder": "http://localhost:3000",
            }),
            "environment": forms.Select(attrs={"class": "form-select"}),
            "authorized_by": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. Lead Developer / Security Team Lead",
            }),
        }
        help_texts = {
            "url": "Only hosts on SCAN_ALLOWED_HOSTS (e.g. localhost, 127.0.0.1, host.docker.internal, juice-shop) are permitted.",
            "authorized_by": "Name and title of the authorized system owner.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["authorized_by"].required = True


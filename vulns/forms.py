"""Forms for vulnerability creation and filtering (Phase 4)."""

from django import forms
from django.contrib.auth import get_user_model

from phases.models import Phase
from .cvss import CVSSValidationError, parse_cvss_vector
from .models import Vulnerability

User = get_user_model()


class VulnerabilityCreateForm(forms.ModelForm):
    """Form for logging a new security vulnerability (Pentester only).

    CVSS vector is validated using CVSS v3.1 rules.
    Base score and severity are derived automatically and cannot be supplied by the user.
    """

    class Meta:
        model = Vulnerability
        fields = [
            "title",
            "description",
            "affected_component",
            "cvss_vector",
            "owasp_category",
            "phase",
            "assignee",
            "due_date",
        ]
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. Broken Object Level Authorization in /api/users"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 4, "placeholder": "Detailed reproduction steps, impact, and proof of concept..."}),
            "affected_component": forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. GET /api/v1/orders/{id}"}),
            "cvss_vector": forms.TextInput(attrs={
                "class": "form-control font-monospace",
                "placeholder": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }),
            "owasp_category": forms.Select(attrs={"class": "form-select"}),
            "phase": forms.Select(attrs={"class": "form-select"}),
            "assignee": forms.Select(attrs={"class": "form-select"}),
            "due_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
        }
        help_texts = {
            "cvss_vector": (
                'Provide a valid CVSS:3.1 vector string. Use the '
                '<a href="https://www.first.org/cvss/calculator/3.1" target="_blank" rel="noopener">FIRST CVSS 3.1 Calculator</a> '
                'to calculate your vector. Base score and severity are derived automatically.'
            )
        }

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        if project:
            # Only phases belonging to this project
            self.fields["phase"].queryset = Phase.objects.filter(project=project).order_by("order")
            # Only users that are members of this project
            member_ids = project.members.values_list("user_id", flat=True)
            self.fields["assignee"].queryset = User.objects.filter(id__in=member_ids)
        self.fields["phase"].required = False
        self.fields["assignee"].required = False
        self.fields["due_date"].required = False

    def clean_cvss_vector(self) -> str:
        vector = self.cleaned_data.get("cvss_vector", "").strip()
        if not vector:
            raise forms.ValidationError("CVSS:3.1 vector is required.")
        try:
            score, severity = parse_cvss_vector(vector)
            # Store calculated attributes on form instance for save()
            self._computed_score = score
            self._computed_severity = severity
        except CVSSValidationError as e:
            raise forms.ValidationError(str(e))
        return vector

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.cvss_score = getattr(self, "_computed_score", 0.0)
        instance.severity = getattr(self, "_computed_severity", Vulnerability.Severity.INFO)
        if commit:
            instance.save()
        return instance


class TransitionForm(forms.Form):
    """Form for transitioning a vulnerability status."""

    new_status = forms.ChoiceField(
        choices=Vulnerability.Status.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    note = forms.CharField(
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Reason / re-test verification notes..."}),
        required=False,
    )

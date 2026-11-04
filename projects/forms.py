"""Forms for the projects app."""

from django import forms
from django.contrib.auth import get_user_model

from .models import Project, ProjectMember

User = get_user_model()


class ProjectCreateForm(forms.Form):
    """Form for creating a new project."""

    name = forms.CharField(max_length=150)
    description = forms.CharField(widget=forms.Textarea, required=False)
    sdlc_model = forms.ChoiceField(choices=Project.SDLCModel.choices)


class AddMemberForm(forms.Form):
    """Form for adding a member to a project."""

    user = forms.ModelChoiceField(queryset=User.objects.all())
    project_role = forms.ChoiceField(choices=ProjectMember.ProjectRole.choices)

    def __init__(self, *args, project=None, **kwargs):
        super().__init__(*args, **kwargs)
        if project:
            # Exclude users who are already members.
            existing_user_ids = project.members.values_list("user_id", flat=True)
            self.fields["user"].queryset = User.objects.exclude(id__in=existing_user_ids)


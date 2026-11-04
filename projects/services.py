"""Project creation and membership services.

Business logic lives here; views call these functions.
"""

from django.db import transaction

from phases.models import Phase

from .models import Project, ProjectMember


def create_project(*, name: str, description: str, sdlc_model: str, created_by) -> Project:
    """Create a project, its six phases, and add the creator as PM.

    For Waterfall projects the first phase (Requirements) starts IN_PROGRESS.
    For Agile projects all phases start NOT_STARTED (the PM chooses which to
    open first).
    """
    with transaction.atomic():
        project = Project.objects.create(
            name=name,
            description=description,
            sdlc_model=sdlc_model,
            created_by=created_by,
        )

        first_phase = None
        for kind, label in Phase.Kind.choices:
            order = Phase.KIND_ORDER[kind]
            status = Phase.Status.NOT_STARTED
            if sdlc_model == Project.SDLCModel.WATERFALL and order == 1:
                status = Phase.Status.IN_PROGRESS

            phase = Phase.objects.create(
                project=project,
                kind=kind,
                order=order,
                status=status,
            )
            if order == 1:
                first_phase = phase

        # Set current_phase to the first phase.
        project.current_phase = first_phase
        project.save(update_fields=["current_phase"])

        # Add the creator as a PM on the project.
        ProjectMember.objects.create(
            project=project,
            user=created_by,
            project_role=ProjectMember.ProjectRole.PM,
        )

    return project


def add_member(project: Project, user, project_role: str) -> ProjectMember:
    """Add a user to a project with the given project role.

    Raises ``ValueError`` if the user is already a member.
    """
    if ProjectMember.objects.filter(project=project, user=user).exists():
        raise ValueError(f"{user.username} is already a member of {project.name}.")
    return ProjectMember.objects.create(
        project=project,
        user=user,
        project_role=project_role,
    )


def remove_member(project: Project, user) -> None:
    """Remove a user from a project.

    Raises ``ValueError`` if the user is the last PM on the project.
    """
    membership = ProjectMember.objects.filter(project=project, user=user).first()
    if membership is None:
        raise ValueError(f"{user.username} is not a member of {project.name}.")

    if membership.project_role == ProjectMember.ProjectRole.PM:
        pm_count = ProjectMember.objects.filter(
            project=project,
            project_role=ProjectMember.ProjectRole.PM,
        ).count()
        if pm_count <= 1:
            raise ValueError("Cannot remove the last Project Manager from a project.")

    membership.delete()


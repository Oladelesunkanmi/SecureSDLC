"""Tests for the projects app (Phase 2).

Covers:
- Creating a project creates six phases in the correct order.
- A Developer cannot create a project (403).
- A non-member requesting a project detail gets 404.
- Removing the last PM is refused.
- Adding the same user twice to a project is refused.
"""

from django.test import TestCase, Client
from django.urls import reverse

from accounts.models import User
from phases.models import Phase
from projects.models import Project, ProjectMember
from projects.services import add_member, create_project, remove_member


class ProjectCreationTests(TestCase):
    """Test that creating a project creates six phases correctly."""

    def setUp(self):
        self.pm_user = User.objects.create_user(
            username="testpm", password="pass1234", role=User.Role.PM
        )

    def test_create_project_creates_six_phases(self):
        project = create_project(
            name="Test Project",
            description="A test",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        phases = Phase.objects.filter(project=project).order_by("order")
        self.assertEqual(phases.count(), 6)
        expected_kinds = [
            Phase.Kind.REQUIREMENTS,
            Phase.Kind.DESIGN,
            Phase.Kind.CODING,
            Phase.Kind.TESTING,
            Phase.Kind.DEPLOYMENT,
            Phase.Kind.MAINTENANCE,
        ]
        for i, phase in enumerate(phases):
            self.assertEqual(phase.kind, expected_kinds[i])
            self.assertEqual(phase.order, i + 1)

    def test_waterfall_first_phase_in_progress(self):
        project = create_project(
            name="Waterfall",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        first = Phase.objects.get(project=project, order=1)
        self.assertEqual(first.status, Phase.Status.IN_PROGRESS)
        # All other phases should be NOT_STARTED.
        for phase in Phase.objects.filter(project=project).exclude(order=1):
            self.assertEqual(phase.status, Phase.Status.NOT_STARTED)

    def test_agile_all_phases_not_started(self):
        project = create_project(
            name="Agile",
            description="",
            sdlc_model=Project.SDLCModel.AGILE,
            created_by=self.pm_user,
        )
        for phase in Phase.objects.filter(project=project):
            self.assertEqual(phase.status, Phase.Status.NOT_STARTED)

    def test_current_phase_set(self):
        project = create_project(
            name="CurPhase",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        self.assertIsNotNone(project.current_phase)
        self.assertEqual(project.current_phase.order, 1)

    def test_creator_added_as_pm(self):
        project = create_project(
            name="AutoPM",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        membership = ProjectMember.objects.get(project=project, user=self.pm_user)
        self.assertEqual(membership.project_role, ProjectMember.ProjectRole.PM)


class ProjectPermissionTests(TestCase):
    """Test permission rules on project views."""

    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username="admin_t", password="pass1234", role=User.Role.ADMIN
        )
        self.pm_user = User.objects.create_user(
            username="pm_t", password="pass1234", role=User.Role.PM
        )
        self.dev_user = User.objects.create_user(
            username="dev_t", password="pass1234", role=User.Role.DEVELOPER
        )
        self.pentester_user = User.objects.create_user(
            username="pent_t", password="pass1234", role=User.Role.PENTESTER
        )
        # Create a project by PM.
        self.project = create_project(
            name="PermTest",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )

    def test_developer_cannot_create_project(self):
        self.client.login(username="dev_t", password="pass1234")
        resp = self.client.get(reverse("projects:create"))
        self.assertEqual(resp.status_code, 403)

    def test_pm_can_create_project(self):
        self.client.login(username="pm_t", password="pass1234")
        resp = self.client.get(reverse("projects:create"))
        self.assertEqual(resp.status_code, 200)

    def test_admin_can_create_project(self):
        self.client.login(username="admin_t", password="pass1234")
        resp = self.client.get(reverse("projects:create"))
        self.assertEqual(resp.status_code, 200)

    def test_non_member_gets_404_on_detail(self):
        self.client.login(username="dev_t", password="pass1234")
        resp = self.client.get(reverse("projects:detail", kwargs={"pk": self.project.pk}))
        self.assertEqual(resp.status_code, 404)

    def test_member_gets_200_on_detail(self):
        self.client.login(username="pm_t", password="pass1234")
        resp = self.client.get(reverse("projects:detail", kwargs={"pk": self.project.pk}))
        self.assertEqual(resp.status_code, 200)

    def test_admin_can_see_any_project(self):
        self.client.login(username="admin_t", password="pass1234")
        resp = self.client.get(reverse("projects:detail", kwargs={"pk": self.project.pk}))
        self.assertEqual(resp.status_code, 200)

    def test_nonexistent_project_returns_404(self):
        self.client.login(username="pm_t", password="pass1234")
        resp = self.client.get(reverse("projects:detail", kwargs={"pk": 99999}))
        self.assertEqual(resp.status_code, 404)


class MembershipTests(TestCase):
    """Test membership add/remove rules."""

    def setUp(self):
        self.pm_user = User.objects.create_user(
            username="pm_m", password="pass1234", role=User.Role.PM
        )
        self.dev_user = User.objects.create_user(
            username="dev_m", password="pass1234", role=User.Role.DEVELOPER
        )
        self.project = create_project(
            name="MemberTest",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )

    def test_add_member(self):
        member = add_member(self.project, self.dev_user, ProjectMember.ProjectRole.DEVELOPER)
        self.assertEqual(member.project, self.project)
        self.assertEqual(member.user, self.dev_user)

    def test_add_duplicate_member_raises(self):
        add_member(self.project, self.dev_user, ProjectMember.ProjectRole.DEVELOPER)
        with self.assertRaises(ValueError):
            add_member(self.project, self.dev_user, ProjectMember.ProjectRole.DEVELOPER)

    def test_remove_last_pm_raises(self):
        with self.assertRaises(ValueError):
            remove_member(self.project, self.pm_user)

    def test_remove_non_last_pm_succeeds(self):
        pm2 = User.objects.create_user(username="pm2", password="pass1234", role=User.Role.PM)
        add_member(self.project, pm2, ProjectMember.ProjectRole.PM)
        # Now removing the original PM should work.
        remove_member(self.project, self.pm_user)
        self.assertFalse(
            ProjectMember.objects.filter(project=self.project, user=self.pm_user).exists()
        )

    def test_remove_developer_succeeds(self):
        add_member(self.project, self.dev_user, ProjectMember.ProjectRole.DEVELOPER)
        remove_member(self.project, self.dev_user)
        self.assertFalse(
            ProjectMember.objects.filter(project=self.project, user=self.dev_user).exists()
        )


class ProjectListVisibilityTests(TestCase):
    """Users should only see projects they belong to (Admin sees all)."""

    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username="admin_v", password="pass1234", role=User.Role.ADMIN
        )
        self.pm_user = User.objects.create_user(
            username="pm_v", password="pass1234", role=User.Role.PM
        )
        self.dev_user = User.objects.create_user(
            username="dev_v", password="pass1234", role=User.Role.DEVELOPER
        )
        self.project = create_project(
            name="VisibilityTest",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )

    def test_member_sees_own_project(self):
        self.client.login(username="pm_v", password="pass1234")
        resp = self.client.get(reverse("projects:list"))
        self.assertContains(resp, "VisibilityTest")

    def test_non_member_does_not_see_project(self):
        self.client.login(username="dev_v", password="pass1234")
        resp = self.client.get(reverse("projects:list"))
        self.assertNotContains(resp, "VisibilityTest")

    def test_admin_sees_all_projects(self):
        self.client.login(username="admin_v", password="pass1234")
        resp = self.client.get(reverse("projects:list"))
        self.assertContains(resp, "VisibilityTest")


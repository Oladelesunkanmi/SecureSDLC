"""Tests for the phases app and phase gate system (Phase 3).

Covers all test requirements specified in CLAUDE.md section 7 (Phase 3):
- Advance is allowed when all required items are done with evidence and no blocking findings exist.
- Advance is blocked when a required item is not done.
- Marking an item done without evidence is refused.
- Advance is blocked by an open High finding in that phase.
- Advance is not blocked by a High finding in a different phase.
- A FIXED Critical finding still blocks (not yet verified).
- A Developer cannot call the advance endpoint (403).
- Waterfall cannot skip a phase.
- Every attempt writes a GateDecision.
"""

from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import User
from phases.models import ChecklistItem, ChecklistResponse, GateDecision, Phase
from phases.services import advance_phase, can_advance, reopen_phase
from projects.models import Project, ProjectMember
from projects.services import create_project
from vulns.models import Vulnerability


class PhaseGateServiceTests(TestCase):
    """Unit tests for can_advance and gate service logic."""

    @classmethod
    def setUpTestData(cls):
        # Create checklist items for Requirements and Design phases
        cls.req1 = ChecklistItem.objects.create(
            phase_kind=Phase.Kind.REQUIREMENTS,
            code="REQ-01",
            text="Threat model",
            required=True,
        )
        cls.req2 = ChecklistItem.objects.create(
            phase_kind=Phase.Kind.REQUIREMENTS,
            code="REQ-02",
            text="Security requirements",
            required=True,
        )
        cls.req_opt = ChecklistItem.objects.create(
            phase_kind=Phase.Kind.REQUIREMENTS,
            code="REQ-03",
            text="Optional item",
            required=False,
        )
        cls.des1 = ChecklistItem.objects.create(
            phase_kind=Phase.Kind.DESIGN,
            code="DES-01",
            text="Architecture review",
            required=True,
        )

    def setUp(self):
        self.pm_user = User.objects.create_user(
            username="pm_gate", password="password123", role=User.Role.PM
        )
        self.project = create_project(
            name="Gate Test Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        self.req_phase = Phase.objects.get(project=self.project, kind=Phase.Kind.REQUIREMENTS)
        self.des_phase = Phase.objects.get(project=self.project, kind=Phase.Kind.DESIGN)

    def test_advance_blocked_when_required_item_not_done(self):
        # Neither req1 nor req2 is completed
        result = can_advance(self.project, self.req_phase)
        self.assertFalse(result.allowed)
        self.assertTrue(any("REQ-01" in r for r in result.reasons))
        self.assertTrue(any("REQ-02" in r for r in result.reasons))

    def test_advance_blocked_when_item_done_but_empty_evidence(self):
        ChecklistResponse.objects.create(
            project=self.project,
            item=self.req1,
            done=True,
            evidence="   ",  # whitespace only
        )
        ChecklistResponse.objects.create(
            project=self.project,
            item=self.req2,
            done=True,
            evidence="Valid evidence",
        )
        result = can_advance(self.project, self.req_phase)
        self.assertFalse(result.allowed)
        self.assertTrue(any("REQ-01" in r for r in result.reasons))

    def test_advance_allowed_when_required_items_done_with_evidence(self):
        ChecklistResponse.objects.create(
            project=self.project,
            item=self.req1,
            done=True,
            evidence="STRIDE model completed.",
        )
        ChecklistResponse.objects.create(
            project=self.project,
            item=self.req2,
            done=True,
            evidence="Requirements documented in confluence.",
        )
        # Optional item not done should NOT block
        result = can_advance(self.project, self.req_phase)
        self.assertTrue(result.allowed)
        self.assertEqual(len(result.reasons), 0)

    def test_advance_blocked_by_open_high_vulnerability_in_phase(self):
        # Complete required checklist items
        ChecklistResponse.objects.create(
            project=self.project, item=self.req1, done=True, evidence="Done"
        )
        ChecklistResponse.objects.create(
            project=self.project, item=self.req2, done=True, evidence="Done"
        )

        # Add open HIGH vulnerability to Requirements phase
        Vulnerability.objects.create(
            project=self.project,
            phase=self.req_phase,
            title="Broken Auth Logic",
            description="High risk finding",
            affected_component="/api/auth",
            severity=Vulnerability.Severity.HIGH,
            status=Vulnerability.Status.OPEN,
            reporter=self.pm_user,
        )

        result = can_advance(self.project, self.req_phase)
        self.assertFalse(result.allowed)
        self.assertTrue(any("Broken Auth Logic" in r for r in result.reasons))

    def test_advance_not_blocked_by_high_vulnerability_in_different_phase(self):
        # Complete required checklist items for Requirements
        ChecklistResponse.objects.create(
            project=self.project, item=self.req1, done=True, evidence="Done"
        )
        ChecklistResponse.objects.create(
            project=self.project, item=self.req2, done=True, evidence="Done"
        )

        # High vulnerability in Design phase, NOT Requirements phase
        Vulnerability.objects.create(
            project=self.project,
            phase=self.des_phase,
            title="Design Threat",
            description="Desc",
            affected_component="DB",
            severity=Vulnerability.Severity.HIGH,
            status=Vulnerability.Status.OPEN,
            reporter=self.pm_user,
        )

        result = can_advance(self.project, self.req_phase)
        self.assertTrue(result.allowed)

    def test_fixed_critical_finding_still_blocks_until_verified(self):
        # Complete checklist items
        ChecklistResponse.objects.create(
            project=self.project, item=self.req1, done=True, evidence="Done"
        )
        ChecklistResponse.objects.create(
            project=self.project, item=self.req2, done=True, evidence="Done"
        )

        # FIXED Critical vulnerability still blocks
        Vulnerability.objects.create(
            project=self.project,
            phase=self.req_phase,
            title="SQL Injection",
            description="Critical finding fixed by dev",
            affected_component="/search",
            severity=Vulnerability.Severity.CRITICAL,
            status=Vulnerability.Status.FIXED,  # Fixed but not verified
            reporter=self.pm_user,
        )

        result = can_advance(self.project, self.req_phase)
        self.assertFalse(result.allowed)
        self.assertTrue(any("SQL Injection" in r for r in result.reasons))

    def test_verified_or_closed_critical_finding_does_not_block(self):
        # Complete checklist items
        ChecklistResponse.objects.create(
            project=self.project, item=self.req1, done=True, evidence="Done"
        )
        ChecklistResponse.objects.create(
            project=self.project, item=self.req2, done=True, evidence="Done"
        )

        Vulnerability.objects.create(
            project=self.project,
            phase=self.req_phase,
            title="SQL Injection",
            description="Fixed and verified",
            affected_component="/search",
            severity=Vulnerability.Severity.CRITICAL,
            status=Vulnerability.Status.VERIFIED,
            reporter=self.pm_user,
        )

        result = can_advance(self.project, self.req_phase)
        self.assertTrue(result.allowed)

    def test_waterfall_cannot_skip_phases(self):
        # Try to advance Design phase while Requirements is still IN_PROGRESS
        ChecklistResponse.objects.create(
            project=self.project, item=self.des1, done=True, evidence="Design Done"
        )
        result = can_advance(self.project, self.des_phase)
        self.assertFalse(result.allowed)
        self.assertTrue(any("Earlier phases" in r or "not currently in progress" in r for r in result.reasons))

    def test_every_attempt_writes_gate_decision(self):
        initial_decisions = GateDecision.objects.filter(project=self.project).count()
        success, result = advance_phase(self.project, self.req_phase, actor=self.pm_user)
        self.assertFalse(success)
        self.assertEqual(
            GateDecision.objects.filter(project=self.project).count(),
            initial_decisions + 1,
        )
        decision = GateDecision.objects.filter(project=self.project).latest("timestamp")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.actor, self.pm_user)

    def test_successful_advance_transitions_next_phase_in_waterfall(self):
        ChecklistResponse.objects.create(
            project=self.project, item=self.req1, done=True, evidence="Done"
        )
        ChecklistResponse.objects.create(
            project=self.project, item=self.req2, done=True, evidence="Done"
        )

        success, result = advance_phase(self.project, self.req_phase, actor=self.pm_user)
        self.assertTrue(success)

        self.req_phase.refresh_from_db()
        self.des_phase.refresh_from_db()
        self.project.refresh_from_db()

        self.assertEqual(self.req_phase.status, Phase.Status.COMPLETED)
        self.assertEqual(self.des_phase.status, Phase.Status.IN_PROGRESS)
        self.assertEqual(self.project.current_phase, self.des_phase)


class PhaseViewTests(TestCase):
    """View and permission tests for phase endpoints."""

    @classmethod
    def setUpTestData(cls):
        cls.item = ChecklistItem.objects.create(
            phase_kind=Phase.Kind.REQUIREMENTS,
            code="REQ-TEST",
            text="Test Item",
            required=True,
        )

    def setUp(self):
        self.client = Client()
        self.pm_user = User.objects.create_user(
            username="pm_view", password="password123", role=User.Role.PM
        )
        self.dev_user = User.objects.create_user(
            username="dev_view", password="password123", role=User.Role.DEVELOPER
        )
        self.project = create_project(
            name="View Test Project",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        # Add dev to project
        ProjectMember.objects.create(
            project=self.project,
            user=self.dev_user,
            project_role=ProjectMember.ProjectRole.DEVELOPER,
        )
        self.phase = Phase.objects.get(project=self.project, kind=Phase.Kind.REQUIREMENTS)

    def test_developer_cannot_call_advance_endpoint_403(self):
        self.client.login(username="dev_view", password="password123")
        url = reverse("phases:advance", kwargs={"project_id": self.project.pk, "kind": "requirements"})
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 403)

    def test_pm_can_call_advance_endpoint(self):
        self.client.login(username="pm_view", password="password123")
        url = reverse("phases:advance", kwargs={"project_id": self.project.pk, "kind": "requirements"})
        resp = self.client.post(url)
        # Should redirect back to phase detail (with messages)
        self.assertEqual(resp.status_code, 302)

    def test_marking_item_done_without_evidence_is_refused(self):
        self.client.login(username="dev_view", password="password123")
        url = reverse("phases:detail", kwargs={"project_id": self.project.pk, "kind": "requirements"})
        resp = self.client.post(url, {
            "item_id": self.item.pk,
            "done": "1",
            "evidence": "",  # Empty evidence
        })
        self.assertEqual(resp.status_code, 302)

        # Verify not marked done in DB
        resp_obj = ChecklistResponse.objects.filter(project=self.project, item=self.item).first()
        self.assertTrue(resp_obj is None or not resp_obj.done)

    def test_marking_item_done_with_evidence_succeeds(self):
        self.client.login(username="dev_view", password="password123")
        url = reverse("phases:detail", kwargs={"project_id": self.project.pk, "kind": "requirements"})
        resp = self.client.post(url, {
            "item_id": self.item.pk,
            "done": "1",
            "evidence": "Detailed verification documentation.",
        })
        self.assertEqual(resp.status_code, 302)

        resp_obj = ChecklistResponse.objects.get(project=self.project, item=self.item)
        self.assertTrue(resp_obj.done)
        self.assertEqual(resp_obj.evidence, "Detailed verification documentation.")
        self.assertEqual(resp_obj.completed_by, self.dev_user)


class AgileReopenTests(TestCase):
    """Test Agile reopening of earlier phases."""

    def setUp(self):
        self.pm_user = User.objects.create_user(
            username="pm_agile", password="password123", role=User.Role.PM
        )
        self.agile_project = create_project(
            name="Agile Proj",
            description="",
            sdlc_model=Project.SDLCModel.AGILE,
            created_by=self.pm_user,
        )
        self.waterfall_project = create_project(
            name="Waterfall Proj",
            description="",
            sdlc_model=Project.SDLCModel.WATERFALL,
            created_by=self.pm_user,
        )
        self.agile_req = Phase.objects.get(project=self.agile_project, kind=Phase.Kind.REQUIREMENTS)
        self.agile_req.status = Phase.Status.COMPLETED
        self.agile_req.save()

        self.wf_req = Phase.objects.get(project=self.waterfall_project, kind=Phase.Kind.REQUIREMENTS)
        self.wf_req.status = Phase.Status.COMPLETED
        self.wf_req.save()

    def test_agile_reopen_succeeds(self):
        reopen_phase(self.agile_project, self.agile_req, actor=self.pm_user)
        self.agile_req.refresh_from_db()
        self.assertEqual(self.agile_req.status, Phase.Status.IN_PROGRESS)
        self.assertEqual(self.agile_project.current_phase, self.agile_req)

        decision = GateDecision.objects.filter(
            project=self.agile_project,
            phase=self.agile_req,
            action=GateDecision.Action.REOPEN,
        ).first()
        self.assertIsNotNone(decision)
        self.assertTrue(decision.allowed)

    def test_waterfall_reopen_refused(self):
        with self.assertRaises(ValueError):
            reopen_phase(self.waterfall_project, self.wf_req, actor=self.pm_user)

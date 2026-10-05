import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import (
    ConflictError,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from ai_governance_foundation.permissions import PermissionService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database

SCOPE = {"collections": ["docs"], "sensitivity": "internal"}


class PermissionServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = FixedClock(datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        self.domain = DomainService(self.database, self.clock)
        self.service = PermissionService(self.database, self.clock)
        self.domain.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="机构")
        self.domain.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="ad1",
                                   display_name="管理员", role="admin", organization_id="o1")
        self.domain.register_actor(request_id="reviewer", actor_id="ad1", new_actor_id="rv1",
                                   display_name="审查员", role="reviewer", organization_id="o1")
        self.domain.register_actor(request_id="operator", actor_id="ad1", new_actor_id="op1",
                                   display_name="操作员", role="operator", organization_id="o1")

    def tearDown(self):
        self.database.close()

    def _grant(self, **overrides):
        params = {"request_id": "grant-1", "actor_id": "ad1", "effect": "allow",
                  "grant_type": "standing", "model_id": "m1", "task_id": "t1",
                  "actor_scope": "agent-1", "tool": "query", "data_scope": SCOPE,
                  "reason": "最小授权"}
        params.update(overrides)
        return self.service.register_grant(**params)

    def test_operator_cannot_register_grant(self):
        with self.assertRaises(PermissionDenied):
            self._grant(request_id="g-x", actor_id="op1")

    def test_reviewer_can_register_grant(self):
        result = self._grant(request_id="g-rv", actor_id="rv1")
        self.assertFalse(result["replayed"])
        self.assertEqual("rv1", result["approved_by"])

    def test_temporary_grant_requires_future_expiry(self):
        with self.assertRaises(ValidationError):
            self._grant(request_id="g-temp1", grant_type="temporary")
        with self.assertRaises(ValidationError):
            self._grant(request_id="g-temp2", grant_type="standing",
                        expires_at="2026-10-05T09:00:00Z")
        with self.assertRaises(ValidationError):
            self._grant(request_id="g-temp3", grant_type="temporary",
                        expires_at="2026-10-05T07:00:00Z")

    def test_call_allowed_denied_escalated(self):
        grant = self._grant()
        allowed = self.service.request_tool_call(
            request_id="c-ok", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual(grant["grant_id"], allowed["winning_grant_id"])
        self.assertEqual("allowed", allowed["status"])

        denied = self.service.request_tool_call(
            request_id="c-bad-scope", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope={"collections": ["secrets"], "sensitivity": "restricted"})
        self.assertEqual("deny", denied["decision"])
        self.assertEqual("scope_not_granted", denied["rule"])

        escalated = self.service.request_tool_call(
            request_id="c-tool", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="destroy", data_scope=SCOPE)
        self.assertEqual("escalate", escalated["decision"])
        self.assertIsNotNone(escalated["approval_id"])

    def test_call_request_is_idempotent(self):
        self._grant()
        first = self.service.request_tool_call(
            request_id="c-idem", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        second = self.service.request_tool_call(
            request_id="c-idem", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["call_id"], second["call_id"])

    def test_deny_grant_blocks_overlapping_request(self):
        self._grant(request_id="g-allow", effect="allow",
                    data_scope={"collections": ["*"], "sensitivity": "restricted"})
        self._grant(request_id="g-deny", effect="deny",
                    data_scope={"collections": ["hr"], "sensitivity": "confidential"})
        result = self.service.request_tool_call(
            request_id="c-hr", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope={"collections": ["hr"], "sensitivity": "confidential"})
        self.assertEqual("deny", result["decision"])
        self.assertEqual("explicit_deny_precedence", result["rule"])

    def test_approval_approval_creates_temporary_grant(self):
        escalated = self.service.request_tool_call(
            request_id="c-esc", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE, reason="需要导出")
        resolved = self.service.resolve_approval(
            request_id="a-ok", actor_id="rv1", approval_id=escalated["approval_id"],
            decision="approved", reason="限时放行", valid_minutes=15)
        self.assertEqual("approved", resolved["status"])
        self.assertIsNotNone(resolved["grant_id"])
        self.assertEqual("2026-10-05T08:15:00Z", resolved["expires_at"])
        stored = self.service.get_grant(resolved["grant_id"])
        self.assertEqual("temporary", stored.grant_type)
        self.assertEqual(escalated["approval_id"], stored.source_approval_id)
        followup = self.service.request_tool_call(
            request_id="c-follow", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE)
        self.assertEqual("allow", followup["decision"])
        self.assertEqual(resolved["grant_id"], followup["winning_grant_id"])

    def test_approval_rejected_leaves_call_rejected(self):
        escalated = self.service.request_tool_call(
            request_id="c-esc2", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE)
        resolved = self.service.resolve_approval(
            request_id="a-no", actor_id="ad1", approval_id=escalated["approval_id"],
            decision="rejected", reason="风险过高")
        self.assertEqual("rejected", resolved["call_status"])
        self.assertIsNone(resolved["grant_id"])
        with self.assertRaises(ConflictError):
            self.service.resolve_approval(
                request_id="a-again", actor_id="ad1", approval_id=escalated["approval_id"],
                decision="approved", reason="重复裁决", valid_minutes=5)

    def test_approval_requires_valid_window(self):
        escalated = self.service.request_tool_call(
            request_id="c-esc3", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE)
        with self.assertRaises(ValidationError):
            self.service.resolve_approval(
                request_id="a-bad", actor_id="ad1", approval_id=escalated["approval_id"],
                decision="approved", reason="无期限", valid_minutes=0)

    def test_operator_cannot_resolve_approval(self):
        escalated = self.service.request_tool_call(
            request_id="c-esc4", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE)
        with self.assertRaises(PermissionDenied):
            self.service.resolve_approval(
                request_id="a-op", actor_id="op1", approval_id=escalated["approval_id"],
                decision="approved", reason="越权", valid_minutes=5)

    def test_temporary_grant_expires_and_is_swept(self):
        escalated = self.service.request_tool_call(
            request_id="c-exp", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE)
        resolved = self.service.resolve_approval(
            request_id="a-exp", actor_id="ad1", approval_id=escalated["approval_id"],
            decision="approved", reason="限时", valid_minutes=30)
        self.clock._value = datetime(2026, 10, 5, 8, 31, tzinfo=timezone.utc)
        swept = self.service.reconcile_expirations()
        self.assertEqual([resolved["grant_id"]], swept["expired_grant_ids"])
        stored = self.service.get_grant(resolved["grant_id"])
        self.assertEqual("expired", stored.status)
        active = self.service.list_grants(active_only=True)
        self.assertNotIn(resolved["grant_id"], {grant.grant_id for grant in active})
        again = self.service.request_tool_call(
            request_id="c-exp-late", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="export", data_scope=SCOPE)
        self.assertEqual("escalate", again["decision"])

    def test_revoke_removes_grant(self):
        grant = self._grant(request_id="g-rev")
        self.service.revoke_grant(request_id="r-rev", actor_id="ad1",
                                  grant_id=grant["grant_id"], reason="演练结束")
        stored = self.service.get_grant(grant["grant_id"])
        self.assertEqual("revoked", stored.status)
        with self.assertRaises(ConflictError):
            self.service.revoke_grant(request_id="r-rev2", actor_id="ad1",
                                      grant_id=grant["grant_id"], reason="再次撤销")

    def test_finish_call_lifecycle(self):
        self._grant()
        allowed = self.service.request_tool_call(
            request_id="c-fin", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        finished = self.service.finish_tool_call(
            request_id="f-fin", actor_id="agent-1", call_id=allowed["call_id"],
            outcome="completed", result_summary="完成")
        self.assertEqual("completed", finished["status"])
        with self.assertRaises(ConflictError):
            self.service.finish_tool_call(
                request_id="f-fin2", actor_id="agent-1", call_id=allowed["call_id"],
                outcome="failed", result_summary="重复")

    def test_timeline_replays_full_process(self):
        grant = self._grant(request_id="g-tl")
        call = self.service.request_tool_call(
            request_id="c-tl", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        self.service.finish_tool_call(
            request_id="f-tl", actor_id="agent-1", call_id=call["call_id"],
            outcome="completed", result_summary="ok")
        timeline = self.service.call_timeline(call["call_id"])
        actions = [event["action"] for event in timeline["events"]]
        self.assertEqual(["tool_call.requested", "tool_call.allow", "tool_call.completed"], actions)
        self.assertEqual(grant["grant_id"], timeline["winning_grant"]["grant_id"])
        self.assertTrue(timeline["call"]["terminal"])

    def test_timeline_for_unknown_call_raises(self):
        with self.assertRaises(NotFoundError):
            self.service.call_timeline("missing")

    def test_audit_chain_covers_permission_events(self):
        self._grant(request_id="g-audit")
        call = self.service.request_tool_call(
            request_id="c-audit", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        self.service.finish_tool_call(
            request_id="f-audit", actor_id="agent-1", call_id=call["call_id"],
            outcome="failed", result_summary="异常")
        valid, count = self.service.verify_audit()
        self.assertTrue(valid)
        self.assertGreaterEqual(count, 3)


class PermissionPersistenceTest(unittest.TestCase):
    def test_state_and_audit_survive_restart(self):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "perm.sqlite3"
        clock = FixedClock(datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        database = Database(path)
        domain = DomainService(database, clock)
        service = PermissionService(database, clock)
        domain.register_organization(request_id="org", actor_id="bootstrap",
                                     organization_id="o1", name="机构")
        domain.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="ad1",
                              display_name="管理员", role="admin", organization_id="o1")
        grant = service.register_grant(
            request_id="g-keep", actor_id="ad1", effect="allow", grant_type="standing",
            model_id="m1", task_id="t1", actor_scope="agent-1", tool="query",
            data_scope=SCOPE, reason="持久化验证")
        call = service.request_tool_call(
            request_id="c-keep", model_id="m1", task_id="t1", actor_id="agent-1",
            tool="query", data_scope=SCOPE)
        database.close()

        restarted = Database(path)
        service2 = PermissionService(restarted, clock)
        restored_grant = service2.get_grant(grant["grant_id"])
        self.assertEqual("active", restored_grant.status)
        restored_call = service2.get_tool_call(call["call_id"])
        self.assertEqual("allowed", restored_call.status)
        timeline = service2.call_timeline(call["call_id"])
        self.assertEqual(2, timeline["event_count"])
        valid, _ = service2.verify_audit()
        self.assertTrue(valid)
        restarted.close()
        directory.cleanup()


if __name__ == "__main__":
    unittest.main()

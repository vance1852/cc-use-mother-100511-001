import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, PermissionDenied, ValidationError
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)


class PermissionServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database, FixedClock(T0))
        self.permissions = self.service.permissions
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="安全演练机构")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin1",
                                    display_name="平台主管", role="admin", organization_id="o1")
        self.service.register_actor(request_id="op", actor_id="admin1", new_actor_id="op1",
                                    display_name="操作员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="rev", actor_id="admin1", new_actor_id="rev1",
                                    display_name="复核员", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="aud", actor_id="admin1", new_actor_id="aud1",
                                    display_name="审计员", role="auditor", organization_id="o1")

    def tearDown(self):
        self.database.close()

    def grant(self, **overrides):
        params = {"request_id": "g1", "actor_id": "op1", "model_id": "m1", "task_id": "t1",
                  "operator_id": "op1", "tool_name": "search", "data_scope": "dataset:public:*",
                  "effect": "allow", "priority": 0, "reason": "演练授权"}
        params.update(overrides)
        return self.permissions.register_grant(**params)

    def request(self, **overrides):
        params = {"request_id": "c1", "actor_id": "op1", "model_id": "m1", "task_id": "t1",
                  "operator_id": "op1", "tool_name": "search",
                  "data_scope": "dataset:public:images"}
        params.update(overrides)
        return self.permissions.request_tool_call(**params)

    def denied_call(self, request_id="c-deny"):
        self.grant(request_id="g-deny", tool_name="delete", effect="deny")
        return self.request(request_id=request_id, tool_name="delete")

    # ---------- 权限登记 ----------

    def test_register_grant_requires_operator_role(self):
        with self.assertRaises(PermissionDenied):
            self.grant(actor_id="aud1")

    def test_register_grant_validates_scope_and_expiry(self):
        with self.assertRaises(ValidationError):
            self.grant(request_id="g-bad", data_scope="bad scope!")
        with self.assertRaises(ValidationError):
            self.grant(request_id="g-past", expires_at="2026-10-01T07:00:00Z")

    def test_duplicate_active_grant_rejected(self):
        self.grant()
        with self.assertRaises(ConflictError):
            self.grant(request_id="g2")

    def test_revoke_grant_blocks_further_calls(self):
        receipt = self.grant()
        self.permissions.revoke_grant(request_id="r1", actor_id="admin1",
                                      grant_id=receipt.resource_id, reason="演练结束")
        result = self.request()
        self.assertEqual("denied", result["call"]["status"])
        with self.assertRaises(ConflictError):
            self.permissions.revoke_grant(request_id="r2", actor_id="admin1",
                                          grant_id=receipt.resource_id, reason="重复撤销")

    # ---------- 调用前逐项核验与裁决 ----------

    def test_allow_grant_approves_call_with_item_checks(self):
        receipt = self.grant(expires_at="2026-10-01T09:00:00Z")
        result = self.request()
        call = result["call"]
        self.assertEqual("approved", call["status"])
        decision = call["decision"]
        self.assertEqual("allow", decision["effect"])
        self.assertEqual("single_match", decision["rule"])
        self.assertEqual(receipt.resource_id, decision["winning_grant_id"])
        items = {check["item"] for check in decision["checks"]}
        self.assertEqual({"model", "task", "operator", "tool", "data_scope", "expiry"}, items)
        self.assertTrue(all(check["result"] == "pass" for check in decision["checks"]))

    def test_call_without_grant_is_denied_with_explanation(self):
        result = self.request()
        decision = result["call"]["decision"]
        self.assertEqual("denied", result["call"]["status"])
        self.assertEqual("no_matching_grant", decision["rule"])
        self.assertTrue(decision["explanation"])

    def test_dimension_mismatch_is_reported_per_item(self):
        self.grant(tool_name="search")
        result = self.request(tool_name="delete")
        decision = result["call"]["decision"]
        self.assertEqual("no_matching_grant", decision["rule"])
        summary = {check["item"]: check for check in decision["checks"]}
        self.assertEqual("fail", summary["tool"]["result"])
        self.assertEqual(1, summary["tool"]["failed_grants"])
        self.assertEqual("pass", summary["model"]["result"])

    def test_deny_grant_blocks_call(self):
        self.grant(tool_name="delete", effect="deny")
        result = self.request(tool_name="delete")
        self.assertEqual("denied", result["call"]["status"])
        self.assertEqual("single_match", result["call"]["decision"]["rule"])

    def test_conflict_higher_priority_deny_wins(self):
        self.grant(request_id="g-allow", tool_name="export", priority=0)
        self.grant(request_id="g-deny", tool_name="export", effect="deny", priority=10)
        result = self.request(tool_name="export")
        decision = result["call"]["decision"]
        self.assertEqual("denied", result["call"]["status"])
        self.assertEqual("highest_priority", decision["rule"])
        self.assertTrue(decision["conflict"])
        self.assertEqual(2, len(decision["matched_grants"]))
        self.assertIn("优先级", decision["explanation"])

    def test_conflict_higher_priority_allow_wins(self):
        self.grant(request_id="g-allow", tool_name="export", priority=10)
        self.grant(request_id="g-deny", tool_name="export", effect="deny", priority=0)
        result = self.request(tool_name="export")
        self.assertEqual("approved", result["call"]["status"])
        self.assertTrue(result["call"]["decision"]["conflict"])

    def test_more_specific_scope_wins_at_same_priority(self):
        self.grant(request_id="g-wide", tool_name="export", data_scope="dataset:public:*")
        self.grant(request_id="g-narrow", tool_name="export", effect="deny",
                   data_scope="dataset:public:images")
        result = self.request(tool_name="export")
        decision = result["call"]["decision"]
        self.assertEqual("denied", result["call"]["status"])
        self.assertEqual("highest_priority", decision["rule"])

    def test_conflict_tie_fails_safe_to_deny(self):
        self.grant(request_id="g-allow", tool_name="export", priority=5)
        self.grant(request_id="g-deny", tool_name="export", effect="deny", priority=5)
        result = self.request(tool_name="export")
        decision = result["call"]["decision"]
        self.assertEqual("denied", result["call"]["status"])
        self.assertEqual("conflict_tie_deny", decision["rule"])
        self.assertIsNone(decision["winning_grant_id"])
        self.assertIn("失败安全", decision["explanation"])

    def test_non_admin_cannot_request_for_other_operator(self):
        with self.assertRaises(PermissionDenied):
            self.request(operator_id="admin1")

    # ---------- 临时授权到期 ----------

    def test_temporary_grant_expires_automatically(self):
        self.grant(expires_at="2026-10-01T09:00:00Z")
        self.assertEqual("approved", self.request()["call"]["status"])
        # 两小时后重启服务：到期授权被标记失效，之后的调用被拒绝。
        later = DomainService(self.database,
                              FixedClock(datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)))
        grants = later.permissions.list_grants(actor_id="admin1")
        self.assertEqual("expired", grants[0].status)
        result = later.permissions.request_tool_call(
            request_id="c2", actor_id="op1", model_id="m1", task_id="t1",
            operator_id="op1", tool_name="search", data_scope="dataset:public:images")
        self.assertEqual("denied", result["call"]["status"])
        self.assertEqual("no_matching_grant", result["call"]["decision"]["rule"])
        self.assertEqual(1, result["call"]["decision"]["excluded"]["expired"])
        actions = [event["action"] for event in later.audit_events()]
        self.assertIn("grant.expired", actions)

    # ---------- 升级与人工干预 ----------

    def test_escalation_and_manual_intervention_flow(self):
        blocked = self.denied_call()
        call_id = blocked["call"]["call_id"]
        escalated = self.permissions.escalate_tool_call(
            request_id="e1", actor_id="op1", call_id=call_id, reason="演练需要临时删除样本")
        self.assertEqual("escalated", escalated["call"]["status"])
        intervened = self.permissions.intervene_tool_call(
            request_id="i1", actor_id="rev1", call_id=call_id,
            decision="approve", note="值班复核员人工放行")
        self.assertEqual("approved_manual", intervened["call"]["status"])
        completed = self.permissions.complete_tool_call(
            request_id="d1", actor_id="op1", call_id=call_id, outcome="succeeded")
        self.assertEqual("completed", completed["call"]["status"])
        replay = self.permissions.get_tool_call(actor_id="aud1", call_id=call_id)
        self.assertEqual(["requested", "decided", "escalated", "intervened", "completed"],
                         [event["event_type"] for event in replay["timeline"]])
        actions = [event["action"] for event in self.service.audit_events()]
        for expected in ("tool_call.requested", "tool_call.decided", "tool_call.escalated",
                         "tool_call.intervened", "tool_call.completed"):
            self.assertIn(expected, actions)

    def test_intervention_reject_closes_call(self):
        blocked = self.denied_call()
        call_id = blocked["call"]["call_id"]
        self.permissions.escalate_tool_call(request_id="e1", actor_id="op1",
                                            call_id=call_id, reason="需要删除")
        result = self.permissions.intervene_tool_call(
            request_id="i1", actor_id="rev1", call_id=call_id,
            decision="reject", note="风险过高，维持拒绝")
        self.assertEqual("rejected", result["call"]["status"])
        with self.assertRaises(ConflictError):
            self.permissions.complete_tool_call(request_id="d1", actor_id="op1",
                                                call_id=call_id, outcome="succeeded")

    def test_requester_cannot_intervene_own_call(self):
        self.service.register_actor(request_id="admin2", actor_id="admin1", new_actor_id="admin2",
                                    display_name="第二管理员", role="admin", organization_id="o1")
        blocked = self.request(request_id="c-admin", actor_id="admin1", operator_id="admin1",
                               tool_name="delete")
        call_id = blocked["call"]["call_id"]
        self.permissions.escalate_tool_call(request_id="e1", actor_id="admin1",
                                            call_id=call_id, reason="自测")
        with self.assertRaises(PermissionDenied):
            self.permissions.intervene_tool_call(request_id="i1", actor_id="admin1",
                                                 call_id=call_id, decision="approve", note="自批")
        result = self.permissions.intervene_tool_call(request_id="i2", actor_id="admin2",
                                                      call_id=call_id, decision="approve",
                                                      note="交叉复核通过")
        self.assertEqual("approved_manual", result["call"]["status"])

    def test_intervene_requires_escalated_status(self):
        blocked = self.denied_call()
        with self.assertRaises(ConflictError):
            self.permissions.intervene_tool_call(request_id="i1", actor_id="rev1",
                                                 call_id=blocked["call"]["call_id"],
                                                 decision="approve", note="未升级")

    def test_escalate_only_by_requester(self):
        blocked = self.denied_call()
        with self.assertRaises(PermissionDenied):
            self.permissions.escalate_tool_call(request_id="e1", actor_id="rev1",
                                                call_id=blocked["call"]["call_id"], reason="越权")

    def test_complete_requires_approved_status(self):
        blocked = self.denied_call()
        with self.assertRaises(ConflictError):
            self.permissions.complete_tool_call(request_id="d1", actor_id="op1",
                                                call_id=blocked["call"]["call_id"],
                                                outcome="succeeded")

    # ---------- 幂等与复盘 ----------

    def test_request_replays_same_call(self):
        self.grant()
        first = self.request()
        second = self.request()
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["call"]["call_id"], second["call"]["call_id"])

    def test_request_id_rejects_changed_payload(self):
        self.grant()
        self.request()
        with self.assertRaises(ConflictError):
            self.request(tool_name="delete")

    def test_lifecycle_retry_is_safe_after_state_moved_on(self):
        self.grant()
        call_id = self.request()["call"]["call_id"]
        done = self.permissions.complete_tool_call(request_id="d1", actor_id="op1",
                                                   call_id=call_id, outcome="succeeded")
        retry = self.permissions.complete_tool_call(request_id="d1", actor_id="op1",
                                                    call_id=call_id, outcome="succeeded")
        self.assertFalse(done["replayed"])
        self.assertTrue(retry["replayed"])
        self.assertEqual("completed", retry["call"]["status"])

    def test_replay_requires_same_organization(self):
        self.service.register_organization(request_id="org2", actor_id="admin1",
                                           organization_id="o2", name="第二机构")
        self.service.register_actor(request_id="op2", actor_id="admin1", new_actor_id="op2",
                                    display_name="外部操作员", role="operator", organization_id="o2")
        self.grant()
        call_id = self.request()["call"]["call_id"]
        with self.assertRaises(PermissionDenied):
            self.permissions.get_tool_call(actor_id="op2", call_id=call_id)
        replay = self.permissions.get_tool_call(actor_id="aud1", call_id=call_id)
        self.assertEqual(2, len(replay["timeline"]))

    # ---------- 重启还原 ----------

    def test_restart_restores_grants_calls_and_audit_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "svc.sqlite3"
            first = Database(path)
            service = DomainService(first, FixedClock(T0))
            service.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="安全演练机构")
            service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin1",
                                   display_name="主管", role="admin", organization_id="o1")
            service.register_actor(request_id="op", actor_id="admin1", new_actor_id="op1",
                                   display_name="操作员", role="operator", organization_id="o1")
            service.permissions.register_grant(request_id="g1", actor_id="op1", model_id="m1",
                                               task_id="t1", operator_id="op1", tool_name="search",
                                               data_scope="dataset:public:*", reason="长期授权")
            call = service.permissions.request_tool_call(
                request_id="c1", actor_id="op1", model_id="m1", task_id="t1", operator_id="op1",
                tool_name="search", data_scope="dataset:public:images")
            self.assertEqual("approved", call["call"]["status"])
            first.close()

            second = Database(path)
            restored = DomainService(second, FixedClock(datetime(2026, 10, 2, 8, 0,
                                                               tzinfo=timezone.utc)))
            valid, count = restored.verify_audit()
            self.assertTrue(valid)
            self.assertGreater(count, 0)
            again = restored.permissions.request_tool_call(
                request_id="c2", actor_id="op1", model_id="m1", task_id="t1", operator_id="op1",
                tool_name="search", data_scope="dataset:public:images")
            self.assertEqual("approved", again["call"]["status"])
            replay = restored.permissions.get_tool_call(actor_id="admin1",
                                                        call_id=call["call"]["call_id"])
            self.assertEqual(["requested", "decided"],
                             [event["event_type"] for event in replay["timeline"]])
            valid_after, _ = restored.verify_audit()
            self.assertTrue(valid_after)
            second.close()


if __name__ == "__main__":
    unittest.main()

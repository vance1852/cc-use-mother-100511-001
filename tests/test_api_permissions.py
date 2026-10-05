import unittest

from ai_governance_foundation.api import route
from ai_governance_foundation.permissions import PermissionService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class PermissionApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)
        self.permissions = PermissionService(self.database, self.service.clock)
        self.route = lambda method, path, body=None, actor="": route(
            self.service, method, path, body or {}, {"X-Actor-Id": actor}, self.permissions)
        self.route("POST", "/organizations",
                   {"request_id": "org", "organization_id": "o1", "name": "机构"}, "bootstrap")
        self.route("POST", "/actors",
                   {"request_id": "admin", "new_actor_id": "ad1", "display_name": "管理员",
                    "role": "admin", "organization_id": "o1"}, "bootstrap")

    def tearDown(self):
        self.database.close()

    def test_grant_registration_and_tool_call_flow(self):
        status, body = self.route("POST", "/grants", {
            "request_id": "g1", "effect": "allow", "grant_type": "standing",
            "model_id": "m1", "task_id": "t1", "actor_scope": "agent-1", "tool": "query",
            "data_scope": {"collections": ["docs"], "sensitivity": "internal"},
            "reason": "最小授权"}, "ad1")
        self.assertEqual(201, status)
        grant_id = body["grant_id"]

        status, body = self.route("POST", "/tool-calls", {
            "request_id": "c1", "model_id": "m1", "task_id": "t1", "actor_id": "agent-1",
            "tool": "query", "data_scope": {"collections": ["docs"], "sensitivity": "internal"}},
            "agent-1")
        self.assertEqual(201, status)
        self.assertEqual("allow", body["decision"])
        self.assertEqual(grant_id, body["winning_grant_id"])
        call_id = body["call_id"]

        status, body = self.route("GET", f"/tool-calls/{call_id}/timeline")
        self.assertEqual(200, status)
        self.assertEqual(2, body["event_count"])
        self.assertEqual(grant_id, body["winning_grant"]["grant_id"])

    def test_escalation_and_approval_endpoints(self):
        status, body = self.route("POST", "/tool-calls", {
            "request_id": "c2", "model_id": "m1", "task_id": "t1", "actor_id": "agent-1",
            "tool": "export",
            "data_scope": {"collections": ["docs"], "sensitivity": "confidential"}}, "agent-1")
        self.assertEqual(201, status)
        self.assertEqual("escalate", body["decision"])
        approval_id = body["approval_id"]

        status, pending = self.route("GET", "/approvals/pending")
        self.assertEqual(200, status)
        self.assertEqual([approval_id], [item["approval_id"] for item in pending["items"]])

        status, body = self.route("POST", "/approvals/resolve", {
            "request_id": "a1", "approval_id": approval_id, "decision": "approved",
            "reason": "限时放行", "valid_minutes": 20}, "ad1")
        self.assertEqual(200, status)
        self.assertIsNotNone(body["grant_id"])

        status, pending = self.route("GET", "/approvals/pending")
        self.assertEqual(0, len(pending["items"]))

    def test_grant_requires_privileged_role(self):
        self.route("POST", "/actors", {
            "request_id": "op", "new_actor_id": "op1", "display_name": "操作员",
            "role": "operator", "organization_id": "o1"}, "ad1")
        status, body = self.route("POST", "/grants", {
            "request_id": "gx", "effect": "allow", "grant_type": "standing",
            "model_id": "m1", "task_id": "t1", "actor_scope": "agent-1", "tool": "query",
            "data_scope": {"collections": ["docs"], "sensitivity": "internal"},
            "reason": "越权"}, "op1")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", body["error"])

    def test_list_grants_filters_and_hides_revoked_with_active_only(self):
        self.route("POST", "/grants", {
            "request_id": "gstand", "effect": "allow", "grant_type": "standing",
            "model_id": "m1", "task_id": "t1", "actor_scope": "agent-1", "tool": "query",
            "data_scope": {"collections": ["docs"], "sensitivity": "internal"},
            "reason": "长期"}, "ad1")
        _, second = self.route("POST", "/grants", {
            "request_id": "g2", "effect": "allow", "grant_type": "standing",
            "model_id": "m2", "task_id": "t2", "actor_scope": "agent-2", "tool": "export",
            "data_scope": {"collections": ["docs"], "sensitivity": "internal"},
            "reason": "待撤销"}, "ad1")
        self.route("POST", "/grants/revoke", {
            "request_id": "rev2", "grant_id": second["grant_id"], "reason": "收回"}, "ad1")
        status, body = self.route("GET", "/grants?active_only=true")
        self.assertEqual(200, status)
        self.assertEqual(1, len(body["items"]))
        status, body = self.route("GET", "/grants?model_id=m2")
        self.assertEqual(1, len(body["items"]))
        self.assertEqual("revoked", body["items"][0]["status"])

    def test_reconcile_endpoint(self):
        status, body = self.route("POST", "/grants/reconcile-expirations", {}, "ad1")
        self.assertEqual(200, status)
        self.assertIn("expired_grant_ids", body)

    def test_validation_error_returns_domain_status(self):
        status, body = self.route("POST", "/grants", {
            "request_id": "gbad", "effect": "allow", "grant_type": "temporary",
            "model_id": "m1", "task_id": "t1", "actor_scope": "agent-1", "tool": "query",
            "data_scope": {"collections": ["docs"], "sensitivity": "internal"},
            "reason": "缺到期时间"}, "ad1")
        self.assertEqual(400, status)
        self.assertEqual("validation_error", body["error"])


if __name__ == "__main__":
    unittest.main()

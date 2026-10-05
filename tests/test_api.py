import unittest

from ai_governance_foundation.api import route
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)

    def tearDown(self):
        self.database.close()

    def test_health_is_available_without_actor(self):
        status, payload = route(self.service, "GET", "/health", None)
        self.assertEqual(200, status)
        self.assertEqual("ok", payload["status"])

    def test_unknown_route_returns_404(self):
        status, payload = route(self.service, "GET", "/missing", None)
        self.assertEqual(404, status)
        self.assertEqual("route_not_found", payload["error"])

    def test_invalid_json_shape_returns_400(self):
        status, payload = route(self.service, "POST", "/organizations", {"request_id": "x"},
                                {"X-Actor-Id": "bootstrap"})
        self.assertEqual(400, status)
        self.assertEqual("invalid_request", payload["error"])

    def _bootstrap(self):
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="安全演练机构")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin1",
                                    display_name="主管", role="admin", organization_id="o1")
        self.service.register_actor(request_id="op", actor_id="admin1", new_actor_id="op1",
                                    display_name="操作员", role="operator", organization_id="o1")

    def test_grant_and_call_lifecycle_routes(self):
        self._bootstrap()
        status, _ = route(self.service, "POST", "/grants",
                          {"request_id": "g1", "model_id": "m1", "task_id": "t1",
                           "operator_id": "op1", "tool_name": "search", "data_scope": "dataset:*",
                           "effect": "allow", "priority": 0, "reason": "演练授权"},
                          {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        status, listing = route(self.service, "GET", "/grants", None, {"X-Actor-Id": "admin1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(listing["items"]))
        self.assertEqual("active", listing["items"][0]["status"])

        status, created = route(self.service, "POST", "/tool-calls",
                                {"request_id": "c1", "model_id": "m1", "task_id": "t1",
                                 "operator_id": "op1", "tool_name": "search",
                                 "data_scope": "dataset:images"},
                                {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("approved", created["call"]["status"])
        self.assertEqual("allow", created["call"]["decision"]["effect"])
        call_id = created["call"]["call_id"]

        status, replay = route(self.service, "GET", f"/tool-calls/{call_id}", None,
                               {"X-Actor-Id": "admin1"})
        self.assertEqual(200, status)
        self.assertEqual(["requested", "decided"],
                         [event["event_type"] for event in replay["timeline"]])

        status, done = route(self.service, "POST", f"/tool-calls/{call_id}/complete",
                             {"request_id": "c1-done", "outcome": "succeeded"},
                             {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("completed", done["call"]["status"])
        status, replay = route(self.service, "GET", f"/tool-calls/{call_id}", None,
                               {"X-Actor-Id": "admin1"})
        self.assertEqual(["requested", "decided", "completed"],
                         [event["event_type"] for event in replay["timeline"]])

    def test_denied_call_escalation_routes(self):
        self._bootstrap()
        status, created = route(self.service, "POST", "/tool-calls",
                                {"request_id": "c1", "model_id": "m1", "task_id": "t1",
                                 "operator_id": "op1", "tool_name": "delete",
                                 "data_scope": "dataset:images"},
                                {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("denied", created["call"]["status"])
        call_id = created["call"]["call_id"]
        status, escalated = route(self.service, "POST", f"/tool-calls/{call_id}/escalate",
                                  {"request_id": "e1", "reason": "需要人工复核"},
                                  {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("escalated", escalated["call"]["status"])
        status, payload = route(self.service, "POST", f"/tool-calls/{call_id}/intervene",
                                {"request_id": "i1", "decision": "reject", "note": "维持拒绝"},
                                {"X-Actor-Id": "admin1"})
        self.assertEqual(201, status)
        self.assertEqual("rejected", payload["call"]["status"])

    def test_unknown_call_action_returns_404(self):
        self._bootstrap()
        status, payload = route(self.service, "POST", "/tool-calls/abc/poke",
                                {"request_id": "x"}, {"X-Actor-Id": "admin1"})
        self.assertEqual(404, status)
        self.assertEqual("route_not_found", payload["error"])


if __name__ == "__main__":
    unittest.main()

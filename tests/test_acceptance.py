import unittest

from ai_governance_foundation.acceptance import run, run_permissions


class AcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertFalse(result["first_replayed"])
        self.assertTrue(result["second_replayed"])
        self.assertEqual(1, result["records"])

    def test_permissions_acceptance(self):
        result = run_permissions()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertEqual(5, result["timeline_events"])
        self.assertTrue(all(result["checks"].values()))


if __name__ == "__main__":
    unittest.main()

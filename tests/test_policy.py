import unittest

from ai_governance_foundation.errors import ValidationError
from ai_governance_foundation.policy import (
    CandidateGrant,
    SENSITIVITY_LEVELS,
    evaluate,
    normalize_scope,
    scope_covers,
    scopes_overlap,
)


def grant(grant_id="g1", effect="allow", model_id="m1", task_id="t1", actor_id="a1",
          tool="query", collections=None, sensitivity="internal", grant_type="standing",
          expires_at=None, created_at="2026-10-05T08:00:00Z", tags=None):
    scope = {"collections": collections or ["docs"], "tags": tags or [], "sensitivity": sensitivity}
    return CandidateGrant(grant_id=grant_id, effect=effect, model_id=model_id, task_id=task_id,
                          actor_id=actor_id, tool=tool, data_scope=scope, grant_type=grant_type,
                          expires_at=expires_at, created_at=created_at)


REQUEST_SCOPE = {"collections": ["docs"], "tags": [], "sensitivity": "internal"}


class ScopeTest(unittest.TestCase):
    def test_wildcard_collection_covers_everything(self):
        self.assertTrue(scope_covers({"collections": ["*"], "tags": [], "sensitivity": "internal"},
                                     {"collections": ["a", "b"], "tags": [], "sensitivity": "public"}))

    def test_sensitivity_must_be_at_least_as_high(self):
        for level_index, level in enumerate(SENSITIVITY_LEVELS):
            base = {"collections": ["*"], "tags": [], "sensitivity": level}
            for request_index, request_level in enumerate(SENSITIVITY_LEVELS):
                request = {"collections": ["x"], "tags": [], "sensitivity": request_level}
                self.assertEqual(scope_covers(base, request), level_index >= request_index)

    def test_tags_must_cover(self):
        wide = {"collections": ["*"], "tags": ["pii"], "sensitivity": "restricted"}
        self.assertFalse(scope_covers(wide, {"collections": ["x"], "tags": ["finance"],
                                             "sensitivity": "public"}))
        self.assertTrue(scope_covers(wide, {"collections": ["x"], "tags": ["pii"],
                                            "sensitivity": "public"}))

    def test_overlap_uses_intersection(self):
        left = {"collections": ["hr"], "tags": [], "sensitivity": "internal"}
        right = {"collections": ["finance"], "tags": [], "sensitivity": "internal"}
        self.assertFalse(scopes_overlap(left, right))
        self.assertTrue(scopes_overlap(left, {"collections": ["hr", "docs"], "tags": [],
                                              "sensitivity": "internal"}))

    def test_normalize_rejects_bad_shapes(self):
        with self.assertRaises(ValidationError):
            normalize_scope({}, field="data_scope")
        with self.assertRaises(ValidationError):
            normalize_scope({"collections": ["*", "x"], "sensitivity": "internal"}, field="s")
        with self.assertRaises(ValidationError):
            normalize_scope({"collections": ["x"], "sensitivity": "top-secret"}, field="s")

    def test_normalize_sorts_and_dedupes(self):
        scope = normalize_scope({"collections": ["b", "a", "a"], "tags": ["z"],
                                 "sensitivity": "restricted"}, field="s")
        self.assertEqual(["a", "b"], scope["collections"])


class EvaluateTest(unittest.TestCase):
    def test_allow_with_covering_grant(self):
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[grant()])
        self.assertEqual("allow", result["decision"])
        self.assertEqual("most_specific_allow", result["rule"])
        self.assertEqual("g1", result["winning_grant_id"])

    def test_explicit_deny_overrides_allow_when_scopes_overlap(self):
        allow = grant("allow-1")
        deny = grant("deny-1", effect="deny", sensitivity="restricted")
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[allow, deny])
        self.assertEqual("deny", result["decision"])
        self.assertEqual("explicit_deny_precedence", result["rule"])
        self.assertEqual(["deny-1"], result["matched_grant_ids"])

    def test_disjoint_deny_does_not_block_unrelated_allow(self):
        allow = grant("allow-1", collections=["docs"])
        deny = grant("deny-1", effect="deny", collections=["hr"])
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[allow, deny])
        self.assertEqual("allow", result["decision"])
        self.assertEqual("allow-1", result["winning_grant_id"])

    def test_insufficient_scope_grant_is_denied_with_reason(self):
        too_narrow = grant("g-narrow", collections=["other"])
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[too_narrow])
        self.assertEqual("deny", result["decision"])
        self.assertEqual("scope_not_granted", result["rule"])
        self.assertEqual("insufficient",
                         result["candidates_considered"][0]["scope_relation"])

    def test_insufficient_sensitivity_is_denied(self):
        low = grant("g-low", sensitivity="public")
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[low])
        self.assertEqual("deny", result["decision"])
        self.assertEqual("scope_not_granted", result["rule"])

    def test_no_dimension_match_escalates(self):
        other_tool = grant("g1", tool="other")
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[other_tool])
        self.assertEqual("escalate", result["decision"])
        self.assertEqual("no_matching_grant", result["rule"])

    def test_disjoint_deny_alone_escalates_rather_than_denies(self):
        deny = grant("deny-1", effect="deny", collections=["hr"])
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[deny])
        self.assertEqual("escalate", result["decision"])

    def test_most_specific_grant_wins(self):
        exact = grant("exact", model_id="m1", task_id="t1", actor_id="a1",
                      collections=["docs"], sensitivity="internal")
        broad = grant("broad", model_id="*", task_id="*", actor_id="*", tool="*",
                      collections=["*"], sensitivity="restricted")
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[broad, exact])
        self.assertEqual("exact", result["winning_grant_id"])
        self.assertEqual(["broad"], result["loser_grant_ids"])

    def test_wildcard_dimensions_match(self):
        wildcard = grant("w", model_id="*", task_id="*", actor_id="*", tool="*",
                         collections=["*"], sensitivity="restricted")
        result = evaluate(model_id="anything", task_id="anything", actor_id="anyone",
                          tool="anytool", data_scope=REQUEST_SCOPE, grants=[wildcard])
        self.assertEqual("allow", result["decision"])

    def test_temporary_grant_wins_tie_over_standing(self):
        scope = {"collections": ["*"], "tags": [], "sensitivity": "restricted"}
        standing = CandidateGrant(grant_id="standing", effect="allow", model_id="*", task_id="*",
                                  actor_id="*", tool="*", data_scope=scope, grant_type="standing",
                                  expires_at=None, created_at="2026-10-05T08:00:00Z")
        temporary = CandidateGrant(grant_id="temporary", effect="allow", model_id="*", task_id="*",
                                   actor_id="*", tool="*", data_scope=scope, grant_type="temporary",
                                   expires_at="2026-10-05T09:00:00Z",
                                   created_at="2026-10-05T08:30:00Z")
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[standing, temporary])
        self.assertEqual("temporary", result["winning_grant_id"])

    def test_report_is_explainable(self):
        result = evaluate(model_id="m1", task_id="t1", actor_id="a1", tool="query",
                          data_scope=REQUEST_SCOPE, grants=[])
        self.assertIn("reason", result)
        self.assertEqual([], result["candidates_considered"])


if __name__ == "__main__":
    unittest.main()

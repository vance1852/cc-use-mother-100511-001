"""实现数据范围比较与权限冲突裁决的纯函数。

裁决规则（全部体现在 :func:`evaluate` 的返回报告中，便于复盘解释）：

1. 维度匹配：授权的模型/任务/操作者/工具与请求精确相等，或授权侧使用 ``*`` 通配；
   已撤销或已到期的授权不参与裁决。
2. 显式 DENY 优先：只要存在维度匹配且数据范围与请求“相交”的 deny 授权，即拒绝，
   即使同时存在允许授权——禁止规则永远压倒允许规则。
3. 最窄 ALLOW 生效：在数据范围能够“完整覆盖”请求的 allow 授权中，选择主体维度绑定
   最多、工具精确匹配、数据范围最窄、临时授权优先、登记时间最早的一条。
4. 有维度匹配的授权但没有任何一条能覆盖请求数据范围 → 拒绝（scope_not_granted）。
5. 没有任何维度匹配的授权 → 升级人工审批（escalate）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import ValidationError

# 敏感级别由低到高，授权级别必须不低于请求级别才算覆盖。
SENSITIVITY_LEVELS = ("public", "internal", "confidential", "restricted")
WILDCARD = "*"


@dataclass(frozen=True)
class CandidateGrant:
    """裁决时使用的授权快照。"""

    grant_id: str
    effect: str
    model_id: str
    task_id: str
    actor_id: str
    tool: str
    data_scope: dict[str, Any]
    grant_type: str
    expires_at: str | None
    created_at: str


def normalize_scope(raw: Any, *, field: str, require_collections: bool = True) -> dict[str, Any]:
    """校验并规范化数据范围，返回键序稳定的字典。

    集合名/标签必须是标识符，``*`` 只能单独出现表示全域；敏感级别必须取自
    :data:`SENSITIVITY_LEVELS`。
    """

    if not isinstance(raw, dict) or not raw:
        raise ValidationError(f"{field} 必须是非空对象")
    normalized: dict[str, Any] = {}
    collections = _normalized_member_list(raw.get("collections"), f"{field}.collections",
                                          required=require_collections)
    normalized["collections"] = collections
    if "tags" in raw and raw["tags"] is not None:
        normalized["tags"] = _normalized_member_list(raw["tags"], f"{field}.tags", required=False)
    else:
        normalized["tags"] = []
    sensitivity = raw.get("sensitivity")
    if sensitivity is None:
        raise ValidationError(f"{field}.sensitivity 必须显式指定")
    if sensitivity not in SENSITIVITY_LEVELS:
        raise ValidationError(f"{field}.sensitivity 级别不合法")
    normalized["sensitivity"] = sensitivity
    unknown = set(raw) - {"collections", "tags", "sensitivity"}
    if unknown:
        raise ValidationError(f"{field} 含未知字段: {sorted(unknown)}")
    return normalized


def _normalized_member_list(value: Any, field: str, *, required: bool) -> list[str]:
    if value is None:
        if required:
            raise ValidationError(f"{field} 必须显式指定")
        return []
    if not isinstance(value, list):
        raise ValidationError(f"{field} 必须是数组")
    if required and not value:
        raise ValidationError(f"{field} 必须是非空数组")
    members = [str(item).strip() for item in value]
    if any(not item for item in members):
        raise ValidationError(f"{field} 不能包含空值")
    if WILDCARD in members and len(members) > 1:
        raise ValidationError(f"{field} 中通配符 * 只能单独使用")
    deduped = sorted(set(members))
    return deduped


def _members_cover(grant_members: list[str], request_members: list[str]) -> bool:
    if grant_members == [WILDCARD]:
        return True
    return set(request_members).issubset(set(grant_members))


def _members_overlap(left: list[str], right: list[str]) -> bool:
    if left == [WILDCARD] or right == [WILDCARD]:
        return True
    if not left or not right:
        # 未设置成员约束的一侧在该维度不构成限制，视为相交。
        return True
    return not set(left).isdisjoint(set(right))


def scope_covers(grant_scope: dict[str, Any], request_scope: dict[str, Any]) -> bool:
    """判断授权数据范围是否完整覆盖请求数据范围。"""

    if not _members_cover(grant_scope["collections"], request_scope["collections"]):
        return False
    # 授权未在标签维度做限制时等同全域。
    grant_tags = grant_scope.get("tags") or [WILDCARD]
    if not _members_cover(grant_tags, request_scope.get("tags", [])):
        return False
    grant_level = SENSITIVITY_LEVELS.index(grant_scope["sensitivity"])
    request_level = SENSITIVITY_LEVELS.index(request_scope["sensitivity"])
    return grant_level >= request_level


def scopes_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """判断两个数据范围是否存在交集（用于 deny 命中判定）。"""

    if not _members_overlap(left["collections"], right["collections"]):
        return False
    if not _members_overlap(left.get("tags", []), right.get("tags", [])):
        return False
    # 敏感级别区间自 public 起，两端总有交集，不影响相交判定。
    return True


def dimension_matches(grant: CandidateGrant, *, model_id: str, task_id: str,
                      actor_id: str, tool: str) -> dict[str, bool]:
    """返回四个维度的匹配情况，全 True 才表示该授权适用于请求。"""

    return {
        "model_id": grant.model_id == WILDCARD or grant.model_id == model_id,
        "task_id": grant.task_id == WILDCARD or grant.task_id == task_id,
        "actor_id": grant.actor_id == WILDCARD or grant.actor_id == actor_id,
        "tool": grant.tool == WILDCARD or grant.tool == tool,
    }


def specificity_key(grant: CandidateGrant) -> tuple[int, ...]:
    """构造排序键，值越大表示授权越具体、越应优先消耗。

    依次比较：精确绑定的主体维度数、工具精确匹配、集合数量少者更窄、
    敏感级低者更窄、标签限定多者更具体、临时授权优先。
    登记时间与编号的平局由 :func:`evaluate` 在外层处理。
    """

    exact_dimensions = sum((grant.model_id != WILDCARD, grant.task_id != WILDCARD,
                            grant.actor_id != WILDCARD))
    tool_exact = 1 if grant.tool != WILDCARD else 0
    collections = grant.data_scope["collections"]
    collection_score = 0 if collections == [WILDCARD] else 1_000_000 - len(collections)
    sensitivity_score = len(SENSITIVITY_LEVELS) - SENSITIVITY_LEVELS.index(grant.data_scope["sensitivity"])
    tag_score = len(grant.data_scope.get("tags", []))
    temporary_first = 1 if grant.grant_type == "temporary" else 0
    return (exact_dimensions, tool_exact, collection_score, sensitivity_score,
            tag_score, temporary_first)


def _candidate_view(grant: CandidateGrant, matches: dict[str, bool], relation: str) -> dict[str, Any]:
    return {
        "grant_id": grant.grant_id,
        "effect": grant.effect,
        "grant_type": grant.grant_type,
        "model_id": grant.model_id,
        "task_id": grant.task_id,
        "actor_id": grant.actor_id,
        "tool": grant.tool,
        "data_scope": grant.data_scope,
        "expires_at": grant.expires_at,
        "dimension_matches": matches,
        "scope_relation": relation,
        "specificity": specificity_key(grant),
    }


def evaluate(*, model_id: str, task_id: str, actor_id: str, tool: str,
             data_scope: dict[str, Any], grants: list[CandidateGrant]) -> dict[str, Any]:
    """对一次工具调用申请执行冲突裁决，返回包含决策与完整依据的报告。"""

    considered: list[dict[str, Any]] = []
    matched_allows: list[CandidateGrant] = []
    matched_denies: list[tuple[CandidateGrant, dict[str, bool]]] = []
    dimension_matched_allow = False

    for grant in grants:
        matches = dimension_matches(grant, model_id=model_id, task_id=task_id,
                                    actor_id=actor_id, tool=tool)
        if not all(matches.values()):
            continue
        if grant.effect == "deny":
            relation = "overlap" if scopes_overlap(grant.data_scope, data_scope) else "disjoint"
            considered.append(_candidate_view(grant, matches, relation))
            if relation == "overlap":
                matched_denies.append((grant, matches))
        else:
            dimension_matched_allow = True
            relation = "covers" if scope_covers(grant.data_scope, data_scope) else "insufficient"
            considered.append(_candidate_view(grant, matches, relation))
            if relation == "covers":
                matched_allows.append(grant)

    if matched_denies:
        denying = [grant.grant_id for grant, _ in matched_denies]
        return {
            "decision": "deny",
            "rule": "explicit_deny_precedence",
            "winning_grant_id": None,
            "matched_grant_ids": denying,
            "reason": "存在与请求数据范围相交的显式拒绝授权，拒绝优先于允许",
            "candidates_considered": considered,
        }

    if matched_allows:
        winner = min(
            matched_allows,
            key=lambda g: tuple(-score for score in specificity_key(g)) + (g.created_at, g.grant_id),
        )
        losers = [g.grant_id for g in matched_allows if g.grant_id != winner.grant_id]
        return {
            "decision": "allow",
            "rule": "most_specific_allow",
            "winning_grant_id": winner.grant_id,
            "matched_grant_ids": [g.grant_id for g in matched_allows],
            "reason": "在可覆盖请求范围的允许授权中，按维度最精确、范围最窄、临时优先选中胜出授权",
            "tie_broken_by": ["specificity", "temporary_first", "earliest_created_at", "grant_id"],
            "loser_grant_ids": losers,
            "grant_expires_at": winner.expires_at,
            "candidates_considered": considered,
        }

    if considered and dimension_matched_allow:
        return {
            "decision": "deny",
            "rule": "scope_not_granted",
            "winning_grant_id": None,
            "matched_grant_ids": [item["grant_id"] for item in considered
                                  if item["effect"] == "allow"],
            "reason": "存在维度匹配的允许授权，但其数据范围不能完整覆盖本次请求",
            "candidates_considered": considered,
        }

    return {
        "decision": "escalate",
        "rule": "no_matching_grant",
        "winning_grant_id": None,
        "matched_grant_ids": [],
        "reason": "没有任何与请求维度和数据范围相匹配的有效允许授权（不相关的拒绝授权不放行也不单独构成拒绝），升级人工审批",
        "candidates_considered": considered,
    }

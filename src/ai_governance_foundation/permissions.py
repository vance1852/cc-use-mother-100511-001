"""智能体工具调用的权限登记、调用前逐项核验与全过程审计。

裁决规则（确定性、可解释）：
1. 只对当前组织内状态为 active 的授权逐项核验模型、任务、操作者、工具和数据范围；
2. 没有全部命中的授权时默认拒绝（no_matching_grant）；
3. 多条授权命中时按优先级降序、数据范围具体度降序排列，取首位授权的效果
   （highest_priority，唯一命中时为 single_match）；
4. 最高位同时存在 allow 与 deny 时按失败安全原则拒绝（conflict_tie_deny）。
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .audit import append_event, canonical_json
from .base import ServiceBase
from .clock import Clock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import PermissionGrant
from .storage import Database


EFFECTS = frozenset({"allow", "deny"})
GRANT_STATUSES = frozenset({"active", "revoked", "expired"})
CALL_STATUSES = frozenset({"approved", "denied", "escalated", "approved_manual",
                           "rejected", "completed", "failed"})
INTERVENTIONS = frozenset({"approve", "reject"})
OUTCOMES = frozenset({"succeeded", "failed"})
MAX_PRIORITY = 1000
SCOPE_PATTERN = re.compile(r"^(\*|[A-Za-z0-9][A-Za-z0-9_.:-]{0,126}(?::\*)?)$")
SYSTEM_ACTOR = "system"


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise ValidationError(f"{field} 必须是 ISO 8601 时间") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} 必须包含时区")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def scope_covers(pattern: str, scope: str) -> bool:
    """判断授权的数据范围是否覆盖请求的数据范围。"""

    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        return scope == pattern[:-2] or scope.startswith(pattern[:-1])
    return pattern == scope


def scope_specificity(pattern: str) -> int:
    """数据范围的字面长度越长越具体，裁决排序越靠前。"""

    return len(pattern.rstrip("*"))


def _grant_from_row(row) -> PermissionGrant:
    return PermissionGrant(
        grant_id=row["grant_id"], organization_id=row["organization_id"],
        model_id=row["model_id"], task_id=row["task_id"], operator_id=row["operator_id"],
        tool_name=row["tool_name"], data_scope=row["data_scope"], effect=row["effect"],
        priority=row["priority"], status=row["status"], expires_at=row["expires_at"],
        reason=row["reason"], created_by=row["created_by"],
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


class PermissionService(ServiceBase):
    """按模型、任务、操作者与数据范围登记权限，并对工具调用逐项核验。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        super().__init__(database, clock)
        # 启动时先 reconciliate：把停机期间到期的临时授权标记失效，
        # 保证重启后有效授权与审计链都能还原。
        self.expire_due_grants()

    # ---------- 内部工具 ----------

    def _scope(self, value: str) -> str:
        value = str(value).strip()
        if not SCOPE_PATTERN.fullmatch(value):
            raise ValidationError("data_scope 格式无效")
        return value

    def _load_call(self, connection, call_id: str):
        row = connection.execute("SELECT * FROM tool_calls WHERE call_id=?", (call_id,)).fetchone()
        if row is None:
            raise NotFoundError("调用不存在")
        return row

    def _call_event(self, connection, *, call_id: str, event_type: str, actor_id: str,
                    detail: dict[str, Any], occurred_at: str) -> None:
        connection.execute(
            "INSERT INTO tool_call_events(call_id,event_type,actor_id,detail_json,occurred_at) "
            "VALUES(?,?,?,?,?)",
            (call_id, event_type, actor_id, canonical_json(detail), occurred_at),
        )

    def _call_view(self, connection, call_id: str) -> dict[str, Any]:
        row = self._load_call(connection, call_id)
        return {"call_id": row["call_id"], "organization_id": row["organization_id"],
                "model_id": row["model_id"], "task_id": row["task_id"],
                "operator_id": row["operator_id"], "tool_name": row["tool_name"],
                "data_scope": row["data_scope"], "status": row["status"],
                "decision": json.loads(row["decision_json"]),
                "requested_by": row["requested_by"], "requested_at": row["requested_at"],
                "updated_at": row["updated_at"], "completed_at": row["completed_at"]}

    def _expire_due(self, connection) -> int:
        """把已经到期的临时授权标记为 expired 并写入审计链。"""

        now = self.clock.now()
        rows = connection.execute(
            "SELECT grant_id, expires_at FROM permission_grants "
            "WHERE status='active' AND expires_at IS NOT NULL"
        ).fetchall()
        expired = 0
        for row in rows:
            if _parse_timestamp(row["expires_at"], "expires_at") <= now:
                stamp = self._now()
                connection.execute(
                    "UPDATE permission_grants SET status='expired', updated_at=? WHERE grant_id=?",
                    (stamp, row["grant_id"]),
                )
                append_event(connection, actor_id=SYSTEM_ACTOR, action="grant.expired",
                             resource_type="permission_grant", resource_id=row["grant_id"],
                             detail={"expires_at": row["expires_at"]}, occurred_at=stamp)
                expired += 1
        return expired

    def expire_due_grants(self) -> int:
        """对外暴露的到期扫描，返回本次失效的授权数量。"""

        with self.database.transaction(immediate=True) as connection:
            return self._expire_due(connection)

    # ---------- 权限登记 ----------

    def register_grant(self, *, request_id: str, actor_id: str, model_id: str, task_id: str,
                       operator_id: str, tool_name: str, data_scope: str, reason: str,
                       effect: str = "allow", priority: int = 0,
                       expires_at: str | None = None) -> Any:
        payload = {"actor_id": actor_id, "model_id": model_id, "task_id": task_id,
                   "operator_id": operator_id, "tool_name": tool_name, "data_scope": data_scope,
                   "effect": effect, "priority": priority, "expires_at": expires_at, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            operator = self._actor(connection, operator_id)
            if actor.role != "admin" and actor.organization_id != operator.organization_id:
                raise PermissionDenied("不能为其他组织的操作者登记权限")
            organization_id = operator.organization_id
            model_id = self._identifier(model_id, "model_id")
            task_id = self._identifier(task_id, "task_id")
            tool_name = self._identifier(tool_name, "tool_name")
            data_scope = self._scope(data_scope)
            if effect not in EFFECTS:
                raise ValidationError("effect 必须是 allow 或 deny")
            if isinstance(priority, bool) or not isinstance(priority, int) or abs(priority) > MAX_PRIORITY:
                raise ValidationError(f"priority 必须是 [-{MAX_PRIORITY}, {MAX_PRIORITY}] 内的整数")
            reason = self._text(reason, "reason")
            expires_norm = None
            if expires_at is not None:
                parsed = _parse_timestamp(expires_at, "expires_at")
                if parsed <= self.clock.now():
                    raise ValidationError("expires_at 必须晚于当前时间")
                expires_norm = _format_timestamp(parsed)

            def create() -> tuple[str, str, dict[str, Any]]:
                duplicate = connection.execute(
                    "SELECT grant_id FROM permission_grants WHERE organization_id=? AND model_id=? "
                    "AND task_id=? AND operator_id=? AND tool_name=? AND data_scope=? AND effect=? "
                    "AND status='active'",
                    (organization_id, model_id, task_id, operator_id, tool_name, data_scope, effect),
                ).fetchone()
                if duplicate:
                    raise ConflictError("相同范围的授权仍然有效，请先撤销再登记")
                grant_id = uuid.uuid4().hex
                stamp = self._now()
                connection.execute(
                    "INSERT INTO permission_grants(grant_id,organization_id,model_id,task_id,operator_id,"
                    "tool_name,data_scope,effect,priority,status,expires_at,reason,created_by,created_at,"
                    "updated_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?)",
                    (grant_id, organization_id, model_id, task_id, operator_id, tool_name, data_scope,
                     effect, priority, expires_norm, reason, actor_id, stamp, stamp),
                )
                append_event(connection, actor_id=actor_id, action="grant.registered",
                             resource_type="permission_grant", resource_id=grant_id,
                             detail={"organization_id": organization_id, "model_id": model_id,
                                     "task_id": task_id, "operator_id": operator_id,
                                     "tool_name": tool_name, "data_scope": data_scope,
                                     "effect": effect, "priority": priority,
                                     "expires_at": expires_norm, "reason": reason},
                             occurred_at=stamp)
                return "permission_grant", grant_id, {"grant_id": grant_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_grant", payload=payload, create=create)

    def revoke_grant(self, *, request_id: str, actor_id: str, grant_id: str, reason: str) -> Any:
        payload = {"actor_id": actor_id, "grant_id": grant_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            reason = self._text(reason, "reason")
            row = connection.execute("SELECT * FROM permission_grants WHERE grant_id=?",
                                     (grant_id,)).fetchone()
            if row is None:
                raise NotFoundError("授权不存在")
            if actor.role != "admin" and actor.organization_id != row["organization_id"]:
                raise PermissionDenied("不能撤销其他组织的授权")
            if row["status"] != "active":
                raise ConflictError("只能撤销仍然有效的授权")

            def create() -> tuple[str, str, dict[str, Any]]:
                stamp = self._now()
                connection.execute(
                    "UPDATE permission_grants SET status='revoked', updated_at=? WHERE grant_id=?",
                    (stamp, grant_id),
                )
                append_event(connection, actor_id=actor_id, action="grant.revoked",
                             resource_type="permission_grant", resource_id=grant_id,
                             detail={"reason": reason}, occurred_at=stamp)
                return "permission_grant", grant_id, {"grant_id": grant_id, "status": "revoked"}

            return self._idempotent(connection, request_id=request_id,
                                    action="revoke_grant", payload=payload, create=create)

    def list_grants(self, *, actor_id: str, organization_id: str | None = None,
                    status: str | None = None, model_id: str | None = None,
                    task_id: str | None = None, operator_id: str | None = None,
                    tool_name: str | None = None) -> list[PermissionGrant]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if organization_id and actor.role != "admin" and organization_id != actor.organization_id:
                raise PermissionDenied("不能查看其他组织的授权")
            organization_id = organization_id or actor.organization_id
            if status is not None and status not in GRANT_STATUSES:
                raise ValidationError("status 不在允许范围内")
            # 读取前先 reconciliate，保证列表中的状态与到期时间一致。
            self._expire_due(connection)
            clauses = ["organization_id=?"]
            parameters: list[Any] = [organization_id]
            for column, value in (("status", status), ("model_id", model_id), ("task_id", task_id),
                                  ("operator_id", operator_id), ("tool_name", tool_name)):
                if value is not None:
                    clauses.append(f"{column}=?")
                    parameters.append(value)
            rows = connection.execute(
                "SELECT * FROM permission_grants WHERE " + " AND ".join(clauses)
                + " ORDER BY created_at, grant_id",
                parameters,
            ).fetchall()
            return [_grant_from_row(row) for row in rows]

    # ---------- 调用前逐项核验与裁决 ----------

    def _adjudicate(self, connection, *, organization_id: str, model_id: str, task_id: str,
                    operator_id: str, tool_name: str, data_scope: str) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT * FROM permission_grants WHERE organization_id=?", (organization_id,)
        ).fetchall()
        excluded = {"expired": 0, "revoked": 0}
        failures = {"model": 0, "task": 0, "operator": 0, "tool": 0, "data_scope": 0}
        matched: list[Any] = []
        active = 0
        for row in rows:
            if row["status"] == "expired":
                excluded["expired"] += 1
                continue
            if row["status"] == "revoked":
                excluded["revoked"] += 1
                continue
            active += 1
            checks = {"model": row["model_id"] == model_id,
                      "task": row["task_id"] == task_id,
                      "operator": row["operator_id"] == operator_id,
                      "tool": row["tool_name"] == tool_name,
                      "data_scope": scope_covers(row["data_scope"], data_scope)}
            if all(checks.values()):
                matched.append(row)
            else:
                for key, passed in checks.items():
                    if not passed:
                        failures[key] += 1
        evaluated_at = self._now()
        if not matched:
            checks_summary = [
                {"item": key, "result": "fail" if count else "pass", "failed_grants": count}
                for key, count in failures.items()
            ]
            explanation = ("没有同时覆盖该模型、任务、操作者、工具和数据范围的有效授权"
                           if active else "该组织当前没有任何有效授权")
            return {"effect": "deny", "rule": "no_matching_grant", "conflict": False,
                    "winning_grant_id": None, "matched_grants": [], "checks": checks_summary,
                    "excluded": excluded, "evaluated_at": evaluated_at, "explanation": explanation}

        def sort_key(row) -> tuple:
            return (-row["priority"], -scope_specificity(row["data_scope"]),
                    row["created_at"], row["grant_id"])

        matched.sort(key=sort_key)
        winner = matched[0]
        top_key = sort_key(winner)[:2]
        tied = [row for row in matched if sort_key(row)[:2] == top_key]
        conflict = {row["effect"] for row in matched} == {"allow", "deny"}
        tied_effects = {row["effect"] for row in tied}
        if len(tied) > 1 and tied_effects == {"allow", "deny"}:
            effect = "deny"
            rule = "conflict_tie_deny"
            winning_grant_id = None
            tied_ids = "、".join(row["grant_id"] for row in tied)
            explanation = (f"最高优先级 {winner['priority']} 上同时存在允许与拒绝授权"
                           f"（{tied_ids}），按失败安全原则拒绝")
        else:
            effect = winner["effect"]
            winning_grant_id = winner["grant_id"]
            if len(matched) == 1:
                rule = "single_match"
                explanation = f"命中唯一有效授权 {winning_grant_id}（{effect}），逐项核验全部通过"
            else:
                rule = "highest_priority"
                note = "，其中允许与拒绝并存" if conflict else ""
                explanation = (f"命中 {len(matched)} 条有效授权{note}，按优先级与数据范围具体度"
                               f"采用授权 {winning_grant_id}（{effect}，优先级 {winner['priority']}）")
        checks = [
            {"item": "model", "result": "pass", "grant_value": winner["model_id"], "requested": model_id},
            {"item": "task", "result": "pass", "grant_value": winner["task_id"], "requested": task_id},
            {"item": "operator", "result": "pass", "grant_value": winner["operator_id"],
             "requested": operator_id},
            {"item": "tool", "result": "pass", "grant_value": winner["tool_name"], "requested": tool_name},
            {"item": "data_scope", "result": "pass", "grant_value": winner["data_scope"],
             "requested": data_scope},
            {"item": "expiry", "result": "pass", "expires_at": winner["expires_at"]},
        ]
        matched_view = [{"grant_id": row["grant_id"], "effect": row["effect"],
                         "priority": row["priority"], "data_scope": row["data_scope"],
                         "expires_at": row["expires_at"]} for row in matched]
        return {"effect": effect, "rule": rule, "conflict": conflict,
                "winning_grant_id": winning_grant_id, "matched_grants": matched_view,
                "checks": checks, "excluded": excluded, "evaluated_at": evaluated_at,
                "explanation": explanation}

    # ---------- 调用生命周期 ----------

    def request_tool_call(self, *, request_id: str, actor_id: str, model_id: str, task_id: str,
                          operator_id: str, tool_name: str, data_scope: str,
                          detail: dict[str, Any] | None = None) -> dict[str, Any]:
        if detail is not None and not isinstance(detail, dict):
            raise ValidationError("detail 必须是对象")
        payload = {"actor_id": actor_id, "model_id": model_id, "task_id": task_id,
                   "operator_id": operator_id, "tool_name": tool_name, "data_scope": data_scope,
                   "detail": detail or {}}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            operator = self._actor(connection, operator_id)
            if actor.role != "admin" and actor.actor_id != operator.actor_id:
                raise PermissionDenied("只能为本人发起工具调用核验")
            organization_id = operator.organization_id
            model_id = self._identifier(model_id, "model_id")
            task_id = self._identifier(task_id, "task_id")
            tool_name = self._identifier(tool_name, "tool_name")
            data_scope = self._scope(data_scope)
            # 裁决前先让到期的临时授权失效，保证核验基于最新状态。
            self._expire_due(connection)

            def create() -> tuple[str, str, dict[str, Any]]:
                decision = self._adjudicate(connection, organization_id=organization_id,
                                            model_id=model_id, task_id=task_id,
                                            operator_id=operator_id, tool_name=tool_name,
                                            data_scope=data_scope)
                status = "approved" if decision["effect"] == "allow" else "denied"
                call_id = uuid.uuid4().hex
                stamp = self._now()
                connection.execute(
                    "INSERT INTO tool_calls(call_id,organization_id,model_id,task_id,operator_id,"
                    "tool_name,data_scope,status,decision_json,requested_by,requested_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (call_id, organization_id, model_id, task_id, operator_id, tool_name, data_scope,
                     status, canonical_json(decision), actor.actor_id, stamp, stamp),
                )
                request_detail = {"model_id": model_id, "task_id": task_id, "operator_id": operator_id,
                                  "tool_name": tool_name, "data_scope": data_scope,
                                  "detail": detail or {}}
                self._call_event(connection, call_id=call_id, event_type="requested",
                                 actor_id=actor.actor_id, detail=request_detail, occurred_at=stamp)
                self._call_event(connection, call_id=call_id, event_type="decided",
                                 actor_id=actor.actor_id,
                                 detail={"effect": decision["effect"], "rule": decision["rule"],
                                         "explanation": decision["explanation"]},
                                 occurred_at=stamp)
                append_event(connection, actor_id=actor.actor_id, action="tool_call.requested",
                             resource_type="tool_call", resource_id=call_id,
                             detail=request_detail, occurred_at=stamp)
                append_event(connection, actor_id=actor.actor_id, action="tool_call.decided",
                             resource_type="tool_call", resource_id=call_id,
                             detail={"status": status, "decision": decision}, occurred_at=stamp)
                return "tool_call", call_id, {"call_id": call_id, "status": status}

            receipt = self._idempotent(connection, request_id=request_id,
                                       action="request_tool_call", payload=payload, create=create)
            return {"request_id": receipt.request_id, "replayed": receipt.replayed,
                    "call": self._call_view(connection, receipt.resource_id)}

    def escalate_tool_call(self, *, request_id: str, actor_id: str, call_id: str,
                           reason: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "call_id": call_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            replay = self._receipt_replay(connection, request_id=request_id,
                                          action="escalate_tool_call", payload=payload)
            if replay is None:
                actor = self._actor(connection, actor_id)
                reason = self._text(reason, "reason")
                row = self._load_call(connection, call_id)
                if row["requested_by"] != actor.actor_id:
                    raise PermissionDenied("只有调用申请人可以发起升级")
                if row["status"] != "denied":
                    raise ConflictError("只有被拒绝的调用可以升级")

                def create() -> tuple[str, str, dict[str, Any]]:
                    stamp = self._now()
                    connection.execute(
                        "UPDATE tool_calls SET status='escalated', updated_at=? WHERE call_id=?",
                        (stamp, call_id),
                    )
                    self._call_event(connection, call_id=call_id, event_type="escalated",
                                     actor_id=actor.actor_id, detail={"reason": reason},
                                     occurred_at=stamp)
                    append_event(connection, actor_id=actor.actor_id, action="tool_call.escalated",
                                 resource_type="tool_call", resource_id=call_id,
                                 detail={"reason": reason}, occurred_at=stamp)
                    return "tool_call", call_id, {"call_id": call_id, "status": "escalated"}

                replay = self._idempotent(connection, request_id=request_id,
                                          action="escalate_tool_call", payload=payload, create=create)
            return {"request_id": replay.request_id, "replayed": replay.replayed,
                    "call": self._call_view(connection, replay.resource_id)}

    def intervene_tool_call(self, *, request_id: str, actor_id: str, call_id: str,
                            decision: str, note: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "call_id": call_id, "decision": decision, "note": note}
        with self.database.transaction(immediate=True) as connection:
            replay = self._receipt_replay(connection, request_id=request_id,
                                          action="intervene_tool_call", payload=payload)
            if replay is None:
                actor = self._actor(connection, actor_id)
                self._require(actor, "admin", "reviewer")
                if decision not in INTERVENTIONS:
                    raise ValidationError("decision 必须是 approve 或 reject")
                note = self._text(note, "note")
                row = self._load_call(connection, call_id)
                if actor.role != "admin" and actor.organization_id != row["organization_id"]:
                    raise PermissionDenied("不能处理其他组织的调用")
                if row["requested_by"] == actor.actor_id:
                    raise PermissionDenied("申请人不能对自己的调用进行人工干预")
                if row["status"] != "escalated":
                    raise ConflictError("只有已升级的调用可以人工干预")
                new_status = "approved_manual" if decision == "approve" else "rejected"

                def create() -> tuple[str, str, dict[str, Any]]:
                    stamp = self._now()
                    connection.execute(
                        "UPDATE tool_calls SET status=?, updated_at=? WHERE call_id=?",
                        (new_status, stamp, call_id),
                    )
                    self._call_event(connection, call_id=call_id, event_type="intervened",
                                     actor_id=actor.actor_id,
                                     detail={"decision": decision, "note": note}, occurred_at=stamp)
                    append_event(connection, actor_id=actor.actor_id, action="tool_call.intervened",
                                 resource_type="tool_call", resource_id=call_id,
                                 detail={"decision": decision, "note": note, "status": new_status},
                                 occurred_at=stamp)
                    return "tool_call", call_id, {"call_id": call_id, "status": new_status}

                replay = self._idempotent(connection, request_id=request_id,
                                          action="intervene_tool_call", payload=payload, create=create)
            return {"request_id": replay.request_id, "replayed": replay.replayed,
                    "call": self._call_view(connection, replay.resource_id)}

    def complete_tool_call(self, *, request_id: str, actor_id: str, call_id: str,
                           outcome: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
        if detail is not None and not isinstance(detail, dict):
            raise ValidationError("detail 必须是对象")
        payload = {"actor_id": actor_id, "call_id": call_id, "outcome": outcome,
                   "detail": detail or {}}
        with self.database.transaction(immediate=True) as connection:
            replay = self._receipt_replay(connection, request_id=request_id,
                                          action="complete_tool_call", payload=payload)
            if replay is None:
                actor = self._actor(connection, actor_id)
                if outcome not in OUTCOMES:
                    raise ValidationError("outcome 必须是 succeeded 或 failed")
                row = self._load_call(connection, call_id)
                if actor.role != "admin" and actor.actor_id != row["requested_by"]:
                    raise PermissionDenied("只有申请人或管理员可以结束调用")
                if row["status"] not in ("approved", "approved_manual"):
                    raise ConflictError("只有已批准的调用可以登记结束")
                new_status = "completed" if outcome == "succeeded" else "failed"

                def create() -> tuple[str, str, dict[str, Any]]:
                    stamp = self._now()
                    connection.execute(
                        "UPDATE tool_calls SET status=?, updated_at=?, completed_at=? WHERE call_id=?",
                        (new_status, stamp, stamp, call_id),
                    )
                    self._call_event(connection, call_id=call_id, event_type="completed",
                                     actor_id=actor.actor_id,
                                     detail={"outcome": outcome, "detail": detail or {}},
                                     occurred_at=stamp)
                    append_event(connection, actor_id=actor.actor_id, action="tool_call.completed",
                                 resource_type="tool_call", resource_id=call_id,
                                 detail={"outcome": outcome, "status": new_status}, occurred_at=stamp)
                    return "tool_call", call_id, {"call_id": call_id, "status": new_status}

                replay = self._idempotent(connection, request_id=request_id,
                                          action="complete_tool_call", payload=payload, create=create)
            return {"request_id": replay.request_id, "replayed": replay.replayed,
                    "call": self._call_view(connection, replay.resource_id)}

    # ---------- 复盘查询 ----------

    def get_tool_call(self, *, actor_id: str, call_id: str) -> dict[str, Any]:
        """复盘一次调用从申请到结束的全过程：当前状态、裁决依据与完整时间线。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            row = self._load_call(connection, call_id)
            if actor.role != "admin" and actor.organization_id != row["organization_id"]:
                raise PermissionDenied("不能查看其他组织的调用")
            rows = connection.execute(
                "SELECT * FROM tool_call_events WHERE call_id=? ORDER BY sequence", (call_id,)
            ).fetchall()
            timeline = [{"sequence": item["sequence"], "event_type": item["event_type"],
                         "actor_id": item["actor_id"], "detail": json.loads(item["detail_json"]),
                         "occurred_at": item["occurred_at"]} for item in rows]
            return {"call": self._call_view(connection, call_id), "timeline": timeline}

    def list_tool_calls(self, *, actor_id: str, organization_id: str | None = None,
                        status: str | None = None, operator_id: str | None = None) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            if organization_id and actor.role != "admin" and organization_id != actor.organization_id:
                raise PermissionDenied("不能查看其他组织的调用")
            organization_id = organization_id or actor.organization_id
            if status is not None and status not in CALL_STATUSES:
                raise ValidationError("status 不在允许范围内")
            clauses = ["organization_id=?"]
            parameters: list[Any] = [organization_id]
            for column, value in (("status", status), ("operator_id", operator_id)):
                if value is not None:
                    clauses.append(f"{column}=?")
                    parameters.append(value)
            rows = connection.execute(
                "SELECT call_id FROM tool_calls WHERE " + " AND ".join(clauses)
                + " ORDER BY requested_at, call_id",
                parameters,
            ).fetchall()
            return [self._call_view(connection, row["call_id"]) for row in rows]

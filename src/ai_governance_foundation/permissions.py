"""提供智能体工具调用的权限登记、逐项核验、人工审批与审计复盘。"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .audit import append_event, canonical_json, digest, verify_chain
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import Approval, Grant, ToolCall
from .policy import CandidateGrant, evaluate, normalize_scope
from .storage import Database


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
EFFECTS = frozenset({"allow", "deny"})
GRANT_TYPES = frozenset({"standing", "temporary"})
APPROVER_ROLES = frozenset({"admin", "reviewer"})
# 调用终态与允许的状态迁移。
TERMINAL_STATUSES = frozenset({"denied", "rejected", "completed", "failed", "cancelled"})


class PermissionService:
    """协调授权登记、调用前裁决、临时授权生命周期和审计留痕。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    # ----- 基础辅助 -----------------------------------------------------

    def _now_dt(self) -> datetime:
        return self.clock.now().astimezone(timezone.utc)

    @staticmethod
    def _format_iso(value: datetime) -> str:
        """统一为秒级 UTC 的 ISO 串，保证时间戳可按字典序精确比较。"""

        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _now(self) -> str:
        return self._format_iso(self._now_dt())

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _dimension(self, value: str, field: str, *, wildcard: bool) -> str:
        value = str(value).strip()
        if wildcard and value == "*":
            return value
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int = 500) -> str:
        value = str(value or "").strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _iso(self, value: str, field: str) -> str:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是带时区的 ISO 8601 时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} 必须包含时区")
        return self._format_iso(parsed)

    def _staff(self, connection, actor_id: str) -> dict[str, Any]:
        """确认操作者存在、启用且具备登记/审批角色。"""

        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        if not row["active"]:
            raise PermissionDenied("操作者已停用")
        if row["role"] not in APPROVER_ROLES:
            raise PermissionDenied("当前角色不能登记权限或执行人工审批")
        return {"actor_id": row["actor_id"], "role": row["role"]}

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any],
                    create: Callable[[], tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return {"replayed": True, **json.loads(row["response_json"])}
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,"
            "resource_id,response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        return {"replayed": False, **response}

    def _sweep_expired(self, connection) -> list[str]:
        """把已到期的临时授权标记为 expired 并逐条留痕，返回失效编号。"""

        now = self._now()
        rows = connection.execute(
            "SELECT grant_id, model_id, task_id, actor_id, tool, expires_at FROM grants "
            "WHERE status='active' AND grant_type='temporary' AND expires_at IS NOT NULL AND expires_at<=?",
            (now,),
        ).fetchall()
        expired = [row["grant_id"] for row in rows]
        for row in rows:
            connection.execute("UPDATE grants SET status='expired', expired_at=? WHERE grant_id=?",
                               (now, row["grant_id"]))
            append_event(connection, actor_id="system", action="grant.expired",
                         resource_type="grant", resource_id=row["grant_id"],
                         detail={"model_id": row["model_id"], "task_id": row["task_id"],
                                 "actor_id": row["actor_id"], "tool": row["tool"],
                                 "expires_at": row["expires_at"], "expired_at": now},
                         occurred_at=now)
        return expired

    # ----- 授权登记 -----------------------------------------------------

    def register_grant(self, *, request_id: str, actor_id: str, effect: str, grant_type: str,
                       model_id: str, task_id: str, actor_scope: str, tool: str,
                       data_scope: dict[str, Any], reason: str,
                       expires_at: str | None = None) -> dict[str, Any]:
        """按模型、任务、操作者、工具和数据范围登记一条 allow/deny 授权。"""

        payload = {"actor_id": actor_id, "effect": effect, "grant_type": grant_type,
                   "model_id": model_id, "task_id": task_id, "actor_scope": actor_scope,
                   "tool": tool, "data_scope": data_scope, "reason": reason,
                   "expires_at": expires_at}
        with self.database.transaction(immediate=True) as connection:
            staff = self._staff(connection, actor_id)
            if effect not in EFFECTS:
                raise ValidationError("effect 只能是 allow 或 deny")
            if grant_type not in GRANT_TYPES:
                raise ValidationError("grant_type 只能是 standing 或 temporary")
            dimensions = {
                "model_id": self._dimension(model_id, "model_id", wildcard=True),
                "task_id": self._dimension(task_id, "task_id", wildcard=True),
                "actor_scope": self._dimension(actor_scope, "actor_scope", wildcard=True),
                "tool": self._dimension(tool, "tool", wildcard=True),
            }
            scope = normalize_scope(data_scope, field="data_scope")
            reason = self._text(reason, "reason")
            normalized_expiry: str | None = None
            if grant_type == "temporary":
                if not expires_at:
                    raise ValidationError("temporary 授权必须提供 expires_at")
                normalized_expiry = self._iso(expires_at, "expires_at")
                if normalized_expiry <= self._now():
                    raise ValidationError("expires_at 必须晚于当前时间")
            elif expires_at:
                raise ValidationError("standing 授权不能设置 expires_at")
            self._sweep_expired(connection)

            def create() -> tuple[str, str, dict[str, Any]]:
                grant_id = uuid.uuid4().hex
                now = self._now()
                connection.execute(
                    "INSERT INTO grants(grant_id,effect,grant_type,model_id,task_id,actor_id,tool,"
                    "scope_json,scope_hash,status,approved_by,approval_reason,source_approval_id,"
                    "expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (grant_id, effect, grant_type, dimensions["model_id"], dimensions["task_id"],
                     dimensions["actor_scope"], dimensions["tool"], canonical_json(scope),
                     digest(scope), "active", actor_id, reason, None, normalized_expiry, now),
                )
                append_event(connection, actor_id=actor_id, action="grant.registered",
                             resource_type="grant", resource_id=grant_id,
                             detail={"effect": effect, "grant_type": grant_type,
                                     "model_id": dimensions["model_id"],
                                     "task_id": dimensions["task_id"],
                                     "actor_id": dimensions["actor_scope"],
                                     "tool": dimensions["tool"], "data_scope": scope,
                                     "reason": reason, "expires_at": normalized_expiry,
                                     "approver_role": staff["role"]},
                             occurred_at=now)
                response = {"grant_id": grant_id, "effect": effect, "grant_type": grant_type,
                            "status": "active", **dimensions, "data_scope": scope,
                            "approved_by": actor_id, "reason": reason,
                            "expires_at": normalized_expiry, "created_at": now}
                return "grant", grant_id, response

            return self._idempotent(connection, request_id=request_id, action="register_grant",
                                    payload=payload, create=create)

    def revoke_grant(self, *, request_id: str, actor_id: str, grant_id: str,
                     reason: str) -> dict[str, Any]:
        """撤销一条仍然有效的授权。"""

        payload = {"actor_id": actor_id, "grant_id": grant_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            staff = self._staff(connection, actor_id)
            grant_id = self._identifier(grant_id, "grant_id")
            reason = self._text(reason, "reason")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
                if row is None:
                    raise NotFoundError("授权不存在")
                if row["status"] != "active":
                    raise ConflictError(f"授权当前状态为 {row['status']}，不能撤销")
                now = self._now()
                connection.execute(
                    "UPDATE grants SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=? "
                    "WHERE grant_id=?",
                    (now, actor_id, reason, grant_id),
                )
                append_event(connection, actor_id=actor_id, action="grant.revoked",
                             resource_type="grant", resource_id=grant_id,
                             detail={"effect": row["effect"], "model_id": row["model_id"],
                                     "task_id": row["task_id"], "actor_id": row["actor_id"],
                                     "tool": row["tool"], "reason": reason,
                                     "reviewer_role": staff["role"]},
                             occurred_at=now)
                response = {"grant_id": grant_id, "status": "revoked", "revoked_by": actor_id,
                            "reason": reason, "revoked_at": now}
                return "grant", grant_id, response

            return self._idempotent(connection, request_id=request_id, action="revoke_grant",
                                    payload=payload, create=create)

    def reconcile_expirations(self) -> dict[str, Any]:
        """供管理端在重启或巡检时主动清扫到期临时授权。"""

        with self.database.transaction(immediate=True) as connection:
            expired = self._sweep_expired(connection)
        return {"expired_grant_ids": expired, "count": len(expired), "swept_at": self._now()}

    # ----- 调用前核验 ---------------------------------------------------

    def request_tool_call(self, *, request_id: str, model_id: str, task_id: str,
                          actor_id: str, tool: str, data_scope: dict[str, Any],
                          arguments: dict[str, Any] | None = None,
                          reason: str | None = None) -> dict[str, Any]:
        """在工具实际执行前逐项核验权限，返回 allow/deny/escalate 裁决。"""

        payload = {"model_id": model_id, "task_id": task_id, "actor_id": actor_id,
                   "tool": tool, "data_scope": data_scope, "arguments": arguments,
                   "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            dimensions = {
                "model_id": self._dimension(model_id, "model_id", wildcard=False),
                "task_id": self._dimension(task_id, "task_id", wildcard=False),
                "actor_id": self._dimension(actor_id, "actor_id", wildcard=False),
                "tool": self._dimension(tool, "tool", wildcard=False),
            }
            scope = normalize_scope(data_scope, field="data_scope")
            if arguments is not None and not isinstance(arguments, dict):
                raise ValidationError("arguments 必须是对象")
            reason_text = str(reason or "").strip()[:500]
            self._sweep_expired(connection)

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                call_id = uuid.uuid4().hex
                arguments_hash = digest({"arguments": arguments or {}})
                append_event(connection, actor_id=dimensions["actor_id"],
                             action="tool_call.requested", resource_type="tool_call",
                             resource_id=call_id,
                             detail={"model_id": dimensions["model_id"],
                                     "task_id": dimensions["task_id"],
                                     "tool": dimensions["tool"], "data_scope": scope,
                                     "arguments_hash": arguments_hash, "reason": reason_text},
                             occurred_at=now)
                candidates = self._load_candidates(connection)
                report = evaluate(model_id=dimensions["model_id"], task_id=dimensions["task_id"],
                                  actor_id=dimensions["actor_id"], tool=dimensions["tool"],
                                  data_scope=scope, grants=candidates)
                decision = report["decision"]
                approval_id: str | None = None
                if decision == "allow":
                    status, decided_at = "allowed", now
                elif decision == "deny":
                    status, decided_at = "denied", now
                else:
                    status, decided_at = "escalated", None
                connection.execute(
                    "INSERT INTO tool_calls(call_id,request_id,model_id,task_id,actor_id,tool,"
                    "scope_json,arguments_hash,status,decision_rule,winning_grant_id,"
                    "decision_report_json,approval_id,created_at,decided_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (call_id, request_id, dimensions["model_id"], dimensions["task_id"],
                     dimensions["actor_id"], dimensions["tool"], canonical_json(scope),
                     arguments_hash, status, report["rule"], report["winning_grant_id"],
                     canonical_json(report), None, now, decided_at),
                )
                if decision == "escalate":
                    approval_id = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO approvals(approval_id,call_id,status,requested_at) "
                        "VALUES(?,?,?,?)",
                        (approval_id, call_id, "pending", now),
                    )
                    connection.execute(
                        "UPDATE tool_calls SET approval_id=? WHERE call_id=?",
                        (approval_id, call_id),
                    )
                append_event(connection, actor_id=dimensions["actor_id"],
                             action=f"tool_call.{decision}", resource_type="tool_call",
                             resource_id=call_id,
                             detail={"rule": report["rule"],
                                     "winning_grant_id": report["winning_grant_id"],
                                     "matched_grant_ids": report["matched_grant_ids"],
                                     "approval_id": approval_id,
                                     "rejected_scopes": [item["grant_id"]
                                                         for item in report["candidates_considered"]
                                                         if item["scope_relation"] == "insufficient"]},
                             occurred_at=decided_at or now)
                if approval_id:
                    append_event(connection, actor_id=dimensions["actor_id"],
                                 action="approval.requested", resource_type="approval",
                                 resource_id=approval_id,
                                 detail={"call_id": call_id, "rule": report["rule"]},
                                 occurred_at=now)
                response = {"call_id": call_id, "status": status, "decision": decision,
                            "rule": report["rule"], "winning_grant_id": report["winning_grant_id"],
                            "approval_id": approval_id, "report": report,
                            "data_scope": scope, "requested_at": now}
                return "tool_call", call_id, response

            return self._idempotent(connection, request_id=request_id,
                                    action="request_tool_call", payload=payload, create=create)

    def _load_candidates(self, connection) -> list[CandidateGrant]:
        now = self._now()
        rows = connection.execute("SELECT * FROM grants WHERE status='active'").fetchall()
        candidates = []
        for row in rows:
            if row["grant_type"] == "temporary" and row["expires_at"] and now >= row["expires_at"]:
                continue
            candidates.append(CandidateGrant(
                grant_id=row["grant_id"], effect=row["effect"], grant_type=row["grant_type"],
                model_id=row["model_id"], task_id=row["task_id"], actor_id=row["actor_id"],
                tool=row["tool"], data_scope=json.loads(row["scope_json"]),
                expires_at=row["expires_at"], created_at=row["created_at"]))
        return candidates

    # ----- 人工审批干预 -------------------------------------------------

    def resolve_approval(self, *, request_id: str, actor_id: str, approval_id: str,
                         decision: str, reason: str, valid_minutes: int | None = None,
                         data_scope: dict[str, Any] | None = None) -> dict[str, Any]:
        """对升级的调用执行人工裁决；批准时生成一条到期自动失效的临时授权。"""

        payload = {"actor_id": actor_id, "approval_id": approval_id, "decision": decision,
                   "reason": reason, "valid_minutes": valid_minutes, "data_scope": data_scope}
        with self.database.transaction(immediate=True) as connection:
            staff = self._staff(connection, actor_id)
            approval_id = self._identifier(approval_id, "approval_id")
            reason = self._text(reason, "reason")
            if decision not in ("approved", "rejected"):
                raise ValidationError("decision 只能是 approved 或 rejected")

            def create() -> tuple[str, str, dict[str, Any]]:
                approval = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id=?", (approval_id,)
                ).fetchone()
                if approval is None:
                    raise NotFoundError("审批单不存在")
                if approval["status"] != "pending":
                    raise ConflictError(f"审批单当前状态为 {approval['status']}")
                call = connection.execute(
                    "SELECT * FROM tool_calls WHERE call_id=?", (approval["call_id"],)
                ).fetchone()
                if call is None or call["status"] != "escalated":
                    raise ConflictError("关联调用不在待审批状态")
                now = self._now()
                grant_id: str | None = None
                expires_at: str | None = None
                granted_scope = json.loads(call["scope_json"])
                if decision == "approved":
                    if data_scope is not None:
                        granted_scope = normalize_scope(data_scope, field="data_scope")
                    else:
                        # 复用前确保形态仍合法。
                        granted_scope = normalize_scope(granted_scope, field="data_scope")
                    if valid_minutes is None or int(valid_minutes) <= 0 or int(valid_minutes) > 24 * 60 * 7:
                        raise ValidationError("批准时必须提供 1 到 10080 分钟之间的 valid_minutes")
                    expires_at = self._format_iso(
                        self._now_dt() + timedelta(minutes=int(valid_minutes)))
                    grant_id = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO grants(grant_id,effect,grant_type,model_id,task_id,actor_id,tool,"
                        "scope_json,scope_hash,status,approved_by,approval_reason,source_approval_id,"
                        "expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (grant_id, "allow", "temporary", call["model_id"], call["task_id"],
                         call["actor_id"], call["tool"], canonical_json(granted_scope),
                         digest(granted_scope), "active", actor_id, reason, approval_id,
                         expires_at, now),
                    )
                    call_status = "approved"
                else:
                    call_status = "rejected"
                connection.execute(
                    "UPDATE approvals SET status=?, decided_at=?, reviewer_id=?, decision=?, "
                    "reason=?, grant_id=?, expires_at=? WHERE approval_id=?",
                    (decision, now, actor_id, decision, reason, grant_id, expires_at, approval_id),
                )
                connection.execute(
                    "UPDATE tool_calls SET status=?, approval_id=?, decided_at=? WHERE call_id=?",
                    (call_status, approval_id, now, call["call_id"]),
                )
                append_event(connection, actor_id=actor_id, action="approval.resolved",
                             resource_type="approval", resource_id=approval_id,
                             detail={"call_id": call["call_id"], "decision": decision,
                                     "reason": reason, "grant_id": grant_id,
                                     "expires_at": expires_at, "reviewer_role": staff["role"]},
                             occurred_at=now)
                if grant_id:
                    append_event(connection, actor_id=actor_id, action="grant.registered",
                                 resource_type="grant", resource_id=grant_id,
                                 detail={"effect": "allow", "grant_type": "temporary",
                                         "model_id": call["model_id"], "task_id": call["task_id"],
                                         "actor_id": call["actor_id"], "tool": call["tool"],
                                         "data_scope": granted_scope, "reason": reason,
                                         "expires_at": expires_at, "source": "manual_approval",
                                         "call_id": call["call_id"], "approver_role": staff["role"]},
                                 occurred_at=now)
                append_event(connection, actor_id=actor_id, action=f"tool_call.{call_status}",
                             resource_type="tool_call", resource_id=call["call_id"],
                             detail={"approval_id": approval_id, "grant_id": grant_id,
                                     "manual_intervention": True, "reason": reason},
                             occurred_at=now)
                response = {"approval_id": approval_id, "call_id": call["call_id"],
                            "status": decision, "call_status": call_status,
                            "reviewer_id": actor_id, "reason": reason, "grant_id": grant_id,
                            "granted_scope": granted_scope if grant_id else None,
                            "expires_at": expires_at, "decided_at": now}
                return "approval", approval_id, response

            return self._idempotent(connection, request_id=request_id, action="resolve_approval",
                                    payload=payload, create=create)

    def finish_tool_call(self, *, request_id: str, actor_id: str, call_id: str,
                         outcome: str, result_summary: str) -> dict[str, Any]:
        """登记一次已放行调用的执行结果：completed 或 failed。"""

        payload = {"actor_id": actor_id, "call_id": call_id, "outcome": outcome,
                   "result_summary": result_summary}
        with self.database.transaction(immediate=True) as connection:
            call_id = self._identifier(call_id, "call_id")
            result_summary = self._text(result_summary, "result_summary", 1000)
            if outcome not in ("completed", "failed"):
                raise ValidationError("outcome 只能是 completed 或 failed")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT * FROM tool_calls WHERE call_id=?", (call_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError("工具调用不存在")
                if row["actor_id"] != actor_id and self._staff_optional(connection, actor_id) is None:
                    raise PermissionDenied("只能由调用申请者本人或管理人员结束调用")
                if row["status"] not in ("allowed", "approved"):
                    raise ConflictError(f"调用当前状态为 {row['status']}，不能登记执行结果")
                now = self._now()
                connection.execute(
                    "UPDATE tool_calls SET status=?, result_summary=?, finished_at=? WHERE call_id=?",
                    (outcome, result_summary, now, call_id),
                )
                append_event(connection, actor_id=actor_id, action=f"tool_call.{outcome}",
                             resource_type="tool_call", resource_id=call_id,
                             detail={"result_summary": result_summary}, occurred_at=now)
                response = {"call_id": call_id, "status": outcome,
                            "result_summary": result_summary, "finished_at": now}
                return "tool_call", call_id, response

            return self._idempotent(connection, request_id=request_id, action="finish_tool_call",
                                    payload=payload, create=create)

    def _staff_optional(self, connection, actor_id: str) -> dict[str, Any] | None:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None or not row["active"] or row["role"] not in APPROVER_ROLES:
            return None
        return {"actor_id": row["actor_id"], "role": row["role"]}

    # ----- 查询与复盘 ---------------------------------------------------

    def _grant_from_row(self, row) -> Grant:
        return Grant(
            grant_id=row["grant_id"], effect=row["effect"], grant_type=row["grant_type"],
            model_id=row["model_id"], task_id=row["task_id"], actor_id=row["actor_id"],
            tool=row["tool"], data_scope=json.loads(row["scope_json"]), status=row["status"],
            approved_by=row["approved_by"], approval_reason=row["approval_reason"],
            source_approval_id=row["source_approval_id"], expires_at=row["expires_at"],
            created_at=row["created_at"], revoked_at=row["revoked_at"],
            revoked_by=row["revoked_by"], revoke_reason=row["revoke_reason"],
            expired_at=row["expired_at"])

    def get_grant(self, grant_id: str) -> Grant:
        row = self.database.connection.execute(
            "SELECT * FROM grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("授权不存在")
        return self._grant_from_row(row)

    def list_grants(self, *, active_only: bool = False, **filters: str | None) -> list[Grant]:
        """按模型、任务、操作者、工具维度列出授权；active_only 仅返回当前有效授权。"""

        query = "SELECT * FROM grants WHERE 1=1"
        parameters: list[Any] = []
        for column in ("effect", "status", "model_id", "task_id", "actor_id", "tool", "grant_type"):
            value = filters.get(column)
            if value is not None:
                query += f" AND {column}=?"
                parameters.append(value)
        query += " ORDER BY created_at, grant_id"
        grants = [self._grant_from_row(row)
                  for row in self.database.connection.execute(query, parameters)]
        if active_only:
            now = self._now()
            grants = [grant for grant in grants if grant.is_active(now)]
        return grants

    def _call_from_row(self, row) -> ToolCall:
        return ToolCall(
            call_id=row["call_id"], request_id=row["request_id"], model_id=row["model_id"],
            task_id=row["task_id"], actor_id=row["actor_id"], tool=row["tool"],
            data_scope=json.loads(row["scope_json"]), arguments_hash=row["arguments_hash"],
            status=row["status"], decision_rule=row["decision_rule"],
            winning_grant_id=row["winning_grant_id"],
            decision_report=json.loads(row["decision_report_json"]),
            approval_id=row["approval_id"], result_summary=row["result_summary"],
            created_at=row["created_at"], decided_at=row["decided_at"],
            finished_at=row["finished_at"])

    def get_tool_call(self, call_id: str) -> ToolCall:
        row = self.database.connection.execute(
            "SELECT * FROM tool_calls WHERE call_id=?", (call_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("工具调用不存在")
        return self._call_from_row(row)

    def list_tool_calls(self, *, task_id: str | None = None, actor_id: str | None = None,
                        model_id: str | None = None, tool: str | None = None,
                        status: str | None = None, limit: int = 100) -> list[ToolCall]:
        query = "SELECT * FROM tool_calls WHERE 1=1"
        parameters: list[Any] = []
        for field, value in (("task_id", task_id), ("actor_id", actor_id),
                             ("model_id", model_id), ("tool", tool), ("status", status)):
            if value is not None:
                query += f" AND {field}=?"
                parameters.append(value)
        query += " ORDER BY created_at DESC, call_id DESC LIMIT ?"
        parameters.append(min(max(int(limit), 1), 500))
        return [self._call_from_row(row)
                for row in self.database.connection.execute(query, parameters)]

    def get_approval(self, approval_id: str) -> Approval:
        row = self.database.connection.execute(
            "SELECT * FROM approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("审批单不存在")
        return self._approval_from_row(row)

    def list_pending_approvals(self) -> list[Approval]:
        rows = self.database.connection.execute(
            "SELECT * FROM approvals WHERE status='pending' ORDER BY requested_at, approval_id"
        ).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def _approval_from_row(self, row) -> Approval:
        return Approval(
            approval_id=row["approval_id"], call_id=row["call_id"], status=row["status"],
            requested_at=row["requested_at"], decided_at=row["decided_at"],
            reviewer_id=row["reviewer_id"], decision=row["decision"], reason=row["reason"],
            grant_id=row["grant_id"], expires_at=row["expires_at"])

    def call_timeline(self, call_id: str) -> dict[str, Any]:
        """复盘一次调用从申请到结束的完整过程：裁决报告、审批干预与审计时间线。"""

        call_row = self.database.connection.execute(
            "SELECT * FROM tool_calls WHERE call_id=?", (call_id,)
        ).fetchone()
        if call_row is None:
            raise NotFoundError("工具调用不存在")
        call = self._call_from_row(call_row)
        approval = None
        if call.approval_id:
            row = self.database.connection.execute(
                "SELECT * FROM approvals WHERE approval_id=?", (call.approval_id,)
            ).fetchone()
            approval = self._approval_from_row(row)
        event_rows = self.database.connection.execute(
            "SELECT * FROM audit_events WHERE resource_id=? "
            "OR resource_id=? OR json_extract(detail_json,'$.call_id')=? "
            "ORDER BY sequence",
            (call.call_id, call.approval_id, call.call_id),
        ).fetchall()
        events = [{"sequence": row["sequence"], "event_id": row["event_id"],
                   "actor_id": row["actor_id"], "action": row["action"],
                   "resource_type": row["resource_type"], "resource_id": row["resource_id"],
                   "detail": json.loads(row["detail_json"]),
                   "previous_hash": row["previous_hash"], "event_hash": row["event_hash"],
                   "occurred_at": row["occurred_at"]} for row in event_rows]
        winning_grant = None
        if call.winning_grant_id:
            row = self.database.connection.execute(
                "SELECT * FROM grants WHERE grant_id=?", (call.winning_grant_id,)
            ).fetchone()
            if row:
                winning_grant = self._grant_view(self._grant_from_row(row))
        return {"call": self._call_view(call), "approval": self._approval_view(approval),
                "winning_grant": winning_grant, "events": events, "event_count": len(events)}

    def verify_audit(self) -> tuple[bool, int]:
        return verify_chain(self.database.connection)

    @staticmethod
    def _call_view(call: ToolCall) -> dict[str, Any]:
        return {**call.__dict__, "terminal": call.status in TERMINAL_STATUSES}

    @staticmethod
    def _approval_view(approval: Approval | None) -> dict[str, Any] | None:
        return approval.__dict__ if approval else None

    @staticmethod
    def _grant_view(grant: Grant) -> dict[str, Any]:
        return grant.__dict__

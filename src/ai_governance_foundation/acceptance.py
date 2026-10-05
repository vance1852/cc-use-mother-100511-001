"""运行基础服务与智能体工具权限域的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import Clock
from .permissions import PermissionService
from .service import DomainService
from .storage import Database


class MutableClock(Clock):
    """可在验收中途推进的 UTC 时钟。"""

    def __init__(self, value: datetime) -> None:
        self._value = value.astimezone(timezone.utc)

    def advance(self, **delta) -> None:
        from datetime import timedelta

        self._value = self._value + timedelta(**delta)

    def now(self) -> datetime:
        return self._value


def run() -> dict[str, object]:
    """执行登记链与权限裁决链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database_path = Path(directory) / "acceptance.sqlite3"
        clock = MutableClock(datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
        database = Database(database_path)
        service = DomainService(database, clock)
        permissions = PermissionService(database, clock)

        # ----- 既有治理登记链 -----
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-reviewer", actor_id="admin-001", new_actor_id="reviewer-001",
                               display_name="安全审查员", role="reviewer", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="项目负责人", role="operator", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="institution_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="institution_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})

        # ----- 按模型/任务/操作者/工具/数据范围登记最小权限 -----
        allow_grant = permissions.register_grant(
            request_id="grant-search", actor_id="admin-001", effect="allow", grant_type="standing",
            model_id="opus-agent", task_id="task-research", actor_scope="agent-001",
            tool="web_search",
            data_scope={"collections": ["docs", "papers"], "sensitivity": "internal"},
            reason="科研检索任务最小权限")
        deny_grant = permissions.register_grant(
            request_id="grant-hr-deny", actor_id="admin-001", effect="deny", grant_type="standing",
            model_id="opus-agent", task_id="task-research", actor_scope="agent-001",
            tool="web_search",
            data_scope={"collections": ["hr"], "sensitivity": "confidential"},
            reason="HR 数据禁止智能体检索")

        # ----- 调用前逐项核验 -----
        in_scope = permissions.request_tool_call(
            request_id="call-in-scope", model_id="opus-agent", task_id="task-research",
            actor_id="agent-001", tool="web_search",
            data_scope={"collections": ["docs"], "sensitivity": "public"},
            arguments={"query": "治理框架"}, reason="检索公开资料")
        denied = permissions.request_tool_call(
            request_id="call-hr", model_id="opus-agent", task_id="task-research",
            actor_id="agent-001", tool="web_search",
            data_scope={"collections": ["hr"], "sensitivity": "confidential"})
        escalated = permissions.request_tool_call(
            request_id="call-db", model_id="opus-agent", task_id="task-research",
            actor_id="agent-001", tool="database_query",
            data_scope={"collections": ["metrics"], "sensitivity": "confidential"},
            reason="临时需要查询指标库")

        # ----- 升级与人工干预：批准并生成 30 分钟临时授权 -----
        approval = permissions.resolve_approval(
            request_id="approve-db", actor_id="reviewer-001",
            approval_id=escalated["approval_id"], decision="approved",
            reason="演练期间限时放行指标查询", valid_minutes=30)
        clock.advance(minutes=10)
        within_window = permissions.request_tool_call(
            request_id="call-db-repeat", model_id="opus-agent", task_id="task-research",
            actor_id="agent-001", tool="database_query",
            data_scope={"collections": ["metrics"], "sensitivity": "confidential"})

        # ----- 临时授权到期自动失效 -----
        clock.advance(minutes=25)
        swept = permissions.reconcile_expirations()
        after_expiry = permissions.request_tool_call(
            request_id="call-db-expired", model_id="opus-agent", task_id="task-research",
            actor_id="agent-001", tool="database_query",
            data_scope={"collections": ["metrics"], "sensitivity": "confidential"})

        # ----- 撤销长期授权 -----
        permissions.revoke_grant(request_id="revoke-search", actor_id="admin-001",
                                 grant_id=allow_grant["grant_id"], reason="演练结束收回检索权限")
        after_revoke = permissions.request_tool_call(
            request_id="call-after-revoke", model_id="opus-agent", task_id="task-research",
            actor_id="agent-001", tool="web_search",
            data_scope={"collections": ["docs"], "sensitivity": "public"})
        permissions.finish_tool_call(request_id="finish-in-scope", actor_id="agent-001",
                                     call_id=in_scope["call_id"], outcome="completed",
                                     result_summary="返回 3 条检索结果")

        timeline_before = permissions.call_timeline(escalated["call_id"])
        database.close()

        # ----- 服务重启：还原有效授权与完整审计链 -----
        restarted = Database(database_path)
        service_restart = DomainService(restarted, clock)
        permissions_restart = PermissionService(restarted, clock)
        permissions_restart.reconcile_expirations()
        valid, event_count = permissions_restart.verify_audit()
        active_grants = permissions_restart.list_grants(active_only=True)
        timeline_after = permissions_restart.call_timeline(escalated["call_id"])
        restored_call = permissions_restart.get_tool_call(in_scope["call_id"])
        pending = permissions_restart.list_pending_approvals()
        record_count = len(service_restart.list_domain_data("site-001"))
        restarted.close()

        result = {
            "status": "ok",
            "records": record_count,
            "audit_events": event_count,
            "audit_valid": valid,
            "first_replayed": first.replayed,
            "second_replayed": replay.replayed,
            "in_scope_decision": in_scope["decision"],
            "in_scope_rule": in_scope["rule"],
            "denied_decision": denied["decision"],
            "denied_rule": denied["rule"],
            "denied_winner_is_deny_grant": denied["report"]["matched_grant_ids"] == [deny_grant["grant_id"]],
            "escalated_decision": escalated["decision"],
            "escalated_rule": escalated["rule"],
            "approval_status": approval["status"],
            "approval_created_temporary_grant": approval["grant_id"] is not None,
            "within_window_decision": within_window["decision"],
            "within_window_grant": within_window["winning_grant_id"] == approval["grant_id"],
            "after_expiry_decision": after_expiry["decision"],
            "swept_expired_count": swept["count"],
            "after_revoke_decision": after_revoke["decision"],
            "restored_active_grants": len(active_grants),
            "restored_call_status": restored_call.status,
            "timeline_events_before_restart": timeline_before["event_count"],
            "timeline_events_after_restart": timeline_after["event_count"],
            "timeline_preserved": timeline_before["event_count"] == timeline_after["event_count"],
            "timeline_actions": [event["action"] for event in timeline_after["events"]],
            "pending_approvals": len(pending),
        }
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    success = result["status"] == "ok" and result["audit_valid"]
    required = {
        "in_scope_decision": "allow",
        "denied_decision": "deny",
        "denied_rule": "explicit_deny_precedence",
        "escalated_decision": "escalate",
        "approval_status": "approved",
        "within_window_decision": "allow",
        "after_expiry_decision": "escalate",
        "after_revoke_decision": "escalate",
        "restored_call_status": "completed",
    }
    for key, expected in required.items():
        success = success and result[key] == expected  # type: ignore[literal-required]
    success = success and bool(result["denied_winner_is_deny_grant"])
    success = success and bool(result["approval_created_temporary_grant"])
    success = success and bool(result["within_window_grant"])
    success = success and bool(result["timeline_preserved"])
    success = success and result["restored_active_grants"] == 1
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())

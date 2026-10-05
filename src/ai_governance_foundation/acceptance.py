"""运行基础服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .service import DomainService
from .storage import Database


def run() -> dict[str, object]:
    """执行一条完整登记链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        service = DomainService(database, FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)))
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
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
        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed}
        database.close()
        return result


def run_permissions() -> dict[str, object]:
    """演练权限登记、调用核验、冲突裁决、升级干预、到期失效与重启还原。"""

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "permissions.sqlite3"
        database = Database(path)
        service = DomainService(database, FixedClock(datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)))
        service.register_organization(request_id="p-org", actor_id="bootstrap",
                                      organization_id="org-safe", name="安全演练机构")
        service.register_actor(request_id="p-admin", actor_id="bootstrap", new_actor_id="admin-1",
                               display_name="平台主管", role="admin", organization_id="org-safe")
        service.register_actor(request_id="p-op", actor_id="admin-1", new_actor_id="op-1",
                               display_name="智能体操作员", role="operator", organization_id="org-safe")
        service.register_actor(request_id="p-rev", actor_id="admin-1", new_actor_id="rev-1",
                               display_name="值班复核员", role="reviewer", organization_id="org-safe")
        permissions = service.permissions
        # 登记：临时允许检索（一小时后到期）、一律拒绝删除、导出上 allow/deny 冲突。
        permissions.register_grant(request_id="g-search", actor_id="op-1", model_id="model-a",
                                   task_id="task-drill", operator_id="op-1", tool_name="search",
                                   data_scope="dataset:public:*", effect="allow", priority=0,
                                   expires_at="2026-10-01T09:00:00Z", reason="演练期间允许检索公开数据")
        permissions.register_grant(request_id="g-delete", actor_id="op-1", model_id="model-a",
                                   task_id="task-drill", operator_id="op-1", tool_name="delete",
                                   data_scope="dataset:public:*", effect="deny", priority=0,
                                   reason="删除操作一律拒绝")
        permissions.register_grant(request_id="g-export-allow", actor_id="op-1", model_id="model-a",
                                   task_id="task-drill", operator_id="op-1", tool_name="export",
                                   data_scope="dataset:public:*", effect="allow", priority=0,
                                   reason="常规导出")
        permissions.register_grant(request_id="g-export-deny", actor_id="admin-1", model_id="model-a",
                                   task_id="task-drill", operator_id="op-1", tool_name="export",
                                   data_scope="dataset:public:*", effect="deny", priority=10,
                                   reason="演练期间禁止导出")
        # 调用前逐项核验：批准并完成检索；删除被拒后升级，由复核员人工放行并完成。
        allowed = permissions.request_tool_call(request_id="c-search", actor_id="op-1",
                                                model_id="model-a", task_id="task-drill",
                                                operator_id="op-1", tool_name="search",
                                                data_scope="dataset:public:images")
        permissions.complete_tool_call(request_id="c-search-done", actor_id="op-1",
                                       call_id=allowed["call"]["call_id"], outcome="succeeded")
        blocked = permissions.request_tool_call(request_id="c-delete", actor_id="op-1",
                                                model_id="model-a", task_id="task-drill",
                                                operator_id="op-1", tool_name="delete",
                                                data_scope="dataset:public:images")
        permissions.escalate_tool_call(request_id="c-delete-esc", actor_id="op-1",
                                       call_id=blocked["call"]["call_id"],
                                       reason="演练需要临时删除样本")
        intervened = permissions.intervene_tool_call(request_id="c-delete-fix", actor_id="rev-1",
                                                     call_id=blocked["call"]["call_id"],
                                                     decision="approve", note="值班复核员人工放行")
        permissions.complete_tool_call(request_id="c-delete-done", actor_id="op-1",
                                       call_id=blocked["call"]["call_id"], outcome="succeeded")
        conflict = permissions.request_tool_call(request_id="c-export", actor_id="op-1",
                                                 model_id="model-a", task_id="task-drill",
                                                 operator_id="op-1", tool_name="export",
                                                 data_scope="dataset:public:images")
        database.close()
        # 模拟两小时后重启：临时授权自动失效，有效授权与审计链完整还原。
        restored_database = Database(path)
        restored = DomainService(restored_database,
                                 FixedClock(datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)))
        expired_call = restored.permissions.request_tool_call(
            request_id="c-search-2", actor_id="op-1", model_id="model-a", task_id="task-drill",
            operator_id="op-1", tool_name="search", data_scope="dataset:public:images")
        replay = restored.permissions.get_tool_call(actor_id="admin-1",
                                                    call_id=blocked["call"]["call_id"])
        valid, event_count = restored.verify_audit()
        checks = {
            "allowed": allowed["call"]["status"] == "approved",
            "blocked": blocked["call"]["status"] == "denied",
            "intervened": intervened["call"]["status"] == "approved_manual",
            "conflict_denied": (conflict["call"]["status"] == "denied"
                                and conflict["call"]["decision"]["rule"] == "highest_priority"
                                and conflict["call"]["decision"]["conflict"]),
            "expired": (expired_call["call"]["status"] == "denied"
                        and expired_call["call"]["decision"]["rule"] == "no_matching_grant"),
            "timeline": [event["event_type"] for event in replay["timeline"]] == [
                "requested", "decided", "escalated", "intervened", "completed"],
            "audit": valid,
        }
        result = {"status": "ok" if all(checks.values()) else "failed", "checks": checks,
                  "audit_events": event_count, "audit_valid": valid,
                  "timeline_events": len(replay["timeline"])}
        restored_database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    foundation = run()
    permissions = run_permissions()
    print(json.dumps({"foundation": foundation, "permissions": permissions},
                     ensure_ascii=False, sort_keys=True))
    ok = (foundation["status"] == "ok" and foundation["audit_valid"]
          and permissions["status"] == "ok" and permissions["audit_valid"])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

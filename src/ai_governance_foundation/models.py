"""定义基础服务在模块边界使用的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Actor:
    """表示具有明确角色的后台操作者。"""

    actor_id: str
    display_name: str
    role: str
    organization_id: str
    active: bool


@dataclass(frozen=True)
class Site:
    """表示科研创新机构下的业务场所。"""

    site_id: str
    organization_id: str
    name: str
    timezone_name: str
    version: int


@dataclass(frozen=True)
class DomainRecord:
    """表示已经持久化的领域资料记录。"""

    record_id: str
    site_id: str
    category: str
    external_key: str
    payload: dict[str, Any]
    created_by: str
    created_at: str


@dataclass(frozen=True)
class WriteReceipt:
    """描述一次幂等写入的稳定结果。"""

    request_id: str
    resource_type: str
    resource_id: str
    replayed: bool


@dataclass(frozen=True)
class Grant:
    """表示一条按模型、任务、操作者、工具和数据范围登记的权限。"""

    grant_id: str
    effect: str
    grant_type: str
    model_id: str
    task_id: str
    actor_id: str
    tool: str
    data_scope: dict[str, Any]
    status: str
    approved_by: str
    approval_reason: str
    source_approval_id: str | None
    expires_at: str | None
    created_at: str
    revoked_at: str | None
    revoked_by: str | None
    revoke_reason: str | None
    expired_at: str | None

    def is_active(self, now_iso: str) -> bool:
        """是否仍为有效授权：未撤销且临时授权未到期。"""

        if self.status != "active":
            return False
        if self.grant_type == "temporary" and self.expires_at is not None and now_iso >= self.expires_at:
            return False
        return True


@dataclass(frozen=True)
class ToolCall:
    """记录一次工具调用从申请到结束的完整状态。"""

    call_id: str
    request_id: str
    model_id: str
    task_id: str
    actor_id: str
    tool: str
    data_scope: dict[str, Any]
    arguments_hash: str
    status: str
    decision_rule: str | None
    winning_grant_id: str | None
    decision_report: dict[str, Any]
    approval_id: str | None
    result_summary: str | None
    created_at: str
    decided_at: str | None
    finished_at: str | None


@dataclass(frozen=True)
class Approval:
    """表示一次升级后的人工审批干预记录。"""

    approval_id: str
    call_id: str
    status: str
    requested_at: str
    decided_at: str | None
    reviewer_id: str | None
    decision: str | None
    reason: str | None
    grant_id: str | None
    expires_at: str | None

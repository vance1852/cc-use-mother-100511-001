# 智能体工具权限登记与审计服务

本项目提供人工智能治理协作的服务端基础能力：登记主体、任务、权限、风险事件和结构化证据，
并通过角色权限、请求幂等、SQLite 事务与审计链保持业务状态一致。

在此之上，服务面向**智能体工具调用**提供权限登记与审计能力，覆盖以下场景：

- 按**模型、任务、操作者、工具、数据范围**登记 allow/deny 授权，支持优先级与到期时间；
- 工具调用前**逐项核验**每个维度，拒绝、批准都生成可解释的裁决依据；
- 权限冲突时按确定性规则裁决：优先级降序 → 数据范围具体度降序 → 平级冲突失败安全拒绝；
- 被拒绝的调用可**升级**，由复核员或管理员**人工干预**（申请人不能自批）；
- 临时授权到期后**自动失效**（启动 reconciliate + 核验/查询前惰性扫描），并写入审计链；
- 服务重启后有效授权与完整哈希审计链均可还原，管理人员可通过 API **复盘**一次调用
  从申请到结束的全过程。

## 角色与职责

| 角色 | 能力 |
| --- | --- |
| admin | 全部能力，可跨组织；不能干预自己申请的调用 |
| operator | 登记/撤销本组织授权，为本人发起调用核验、升级与结束 |
| reviewer | 对已升级的调用进行人工干预（approve/reject） |
| auditor | 只读复盘本组织调用与授权 |

## 裁决规则（可解释）

每次调用核验都会生成不可变的裁决快照（`decision`），包含：

- `checks`：逐项核验结果（model / task / operator / tool / data_scope / expiry）；
- `matched_grants`：全部命中的有效授权及其效果、优先级、数据范围；
- `rule`：裁决规则 —— `single_match`（唯一命中）、`highest_priority`
  （按优先级与数据范围具体度取首位）、`conflict_tie_deny`（最高位 allow/deny
  平级，失败安全拒绝）、`no_matching_grant`（无匹配，默认拒绝）；
- `conflict`：命中集合中是否同时存在 allow 与 deny；
- `excluded`：因过期、撤销被排除的授权数量；
- `explanation`：人类可读的裁决说明。

## 调用生命周期

```
request_tool_call ──► approved ──► complete_tool_call ──► completed / failed
                 └─► denied ──► escalate ──► intervene ──► approved_manual ──► completed / failed
                                              └──────────► rejected（终态）
```

每个状态变迁都会写入 `tool_call_events` 时间线和哈希串联的 `audit_events`
（`grant.registered/revoked/expired`、`tool_call.requested/decided/escalated/intervened/completed`）。

## HTTP API

写操作与敏感读操作需要 `X-Actor-Id` 请求头；所有写操作支持 `request_id` 幂等重试。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/grants` | 登记授权（model_id/task_id/operator_id/tool_name/data_scope/effect/priority/expires_at/reason） |
| GET | `/grants` | 列出授权（可按 status、model_id、task_id、operator_id、tool_name 过滤） |
| POST | `/grants/{id}/revoke` | 撤销授权（需 reason） |
| POST | `/tool-calls` | 调用前逐项核验，返回裁决依据；拒绝也是成功登记的结果 |
| GET | `/tool-calls` | 列出调用（可按 status、operator_id 过滤） |
| GET | `/tool-calls/{id}` | 复盘：当前状态 + 裁决快照 + 完整时间线 |
| POST | `/tool-calls/{id}/escalate` | 申请人对被拒绝的调用发起升级 |
| POST | `/tool-calls/{id}/intervene` | reviewer/admin 人工干预（decision=approve/reject，需 note） |
| POST | `/tool-calls/{id}/complete` | 登记调用结束（outcome=succeeded/failed） |
| GET | `/audit-events` | 哈希串联审计日志 |
| GET | `/health` | 健康检查（含审计链校验结果） |

数据范围支持精确值（`dataset:public:images`）与前缀通配（`dataset:public:*`、`*`）。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

验收覆盖：登记链幂等重放、授权批准/拒绝、冲突裁决、升级与人工干预、
临时授权到期自动失效、重启后有效授权与审计链还原、调用全过程复盘。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的状态与审计历史继续保留。

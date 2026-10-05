# 智能体工具调用权限登记与审计服务

面向智能体（Agent）工具调用的最小权限治理服务。团队可以按**模型、任务、操作者、工具和数据范围**
登记可用权限，在每次工具调用前进行逐项核验；临时授权到期自动失效；拒绝、升级和人工干预全程留痕；
权限冲突时给出可解释的裁决依据；服务重启后仍能还原有效授权与完整审计链。

## 核心能力

- **权限登记（Grant）**：五维定位 `model_id / task_id / actor_id / tool / data_scope`，
  `effect=allow|deny`，`grant_type=standing|temporary`，记录批准人、理由与时间（谁在何时批准）。
- **调用前逐项核验**：对每次工具调用申请执行维度匹配 + 数据范围覆盖判断，返回
  `allow / deny / escalate` 及完整裁决报告。
- **可解释冲突裁决**：
  1. 维度匹配（精确相等或授权侧 `*` 通配）；
  2. **显式 DENY 优先**：与请求数据范围相交的拒绝授权压倒一切允许授权；
  3. 在能完整覆盖请求的 ALLOW 中，选“维度最精确、工具精确、范围最窄、临时优先、登记最早”的一条；
  4. 有匹配的 ALLOW 但范围不足 → `deny(scope_not_granted)`；无任何匹配授权 → `escalate(no_matching_grant)`。
  裁决报告 `candidates_considered` 逐条给出维度匹配情况与范围关系（covers/insufficient/overlap/disjoint）。
- **临时授权自动失效**：临时授权必须带 `expires_at`；核验时惰性清扫，管理端也可主动
  `reconcile-expirations`；到期后授权标记为 `expired` 并写入审计。
- **升级与人工干预**：无授权的调用生成待审批单；审查人批准时可指定授权范围与有效时长（1–10080
  分钟），系统自动生成临时授权；拒绝则调用终结。审批人、理由、结论全部保留。
- **全链路复盘**：调用状态机 `requested → allowed/denied/escalated → approved/rejected →
  completed/failed`，`/tool-calls/{id}/timeline` 返回裁决报告、审批单、胜出授权与哈希链审计时间线。
- **可校验审计链**：所有动作（登记、撤销、到期、申请、裁决、审批、结束）进入 SHA-256 哈希链，
  `/health` 与 `verify_audit()` 可离线验证未被篡改；状态持久化在 SQLite，重启即可还原。

## HTTP API

所有写操作都携带幂等键 `request_id`；管理/审批类接口通过请求头 `X-Actor-Id` 标识操作者
（需 admin 或 reviewer 角色）。工具调用的 `actor_id` 是智能体身份，放在请求体中。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/grants` | 登记一条 allow/deny 授权（临时授权需 `expires_at`） |
| POST | `/grants/revoke` | 撤销授权 |
| POST | `/grants/reconcile-expirations` | 主动清扫到期临时授权 |
| GET | `/grants` | 按 effect/status/model_id/task_id/actor_id/tool/grant_type 过滤，`active_only=true` 仅看有效授权 |
| GET | `/grants/{grant_id}` | 查看单条授权 |
| POST | `/tool-calls` | 调用前核验，返回 allow/deny/escalate 与裁决报告 |
| POST | `/tool-calls/finish` | 登记已放行调用的执行结果 completed/failed |
| GET | `/tool-calls` | 按任务/操作者/模型/工具/状态列出调用 |
| GET | `/tool-calls/{call_id}` | 查看单次调用 |
| GET | `/tool-calls/{call_id}/timeline` | **复盘一次调用从申请到结束的全过程** |
| POST | `/approvals/resolve` | 人工批准（生成临时授权）或拒绝 |
| GET | `/approvals/pending` | 待审批队列 |
| GET | `/approvals/{approval_id}` | 查看审批单 |
| GET | `/audit-events?after_sequence=N` | 拉取哈希链审计事件 |
| GET | `/health` | 健康检查与审计链校验结果 |

数据范围 `data_scope` 形如：

```json
{ "collections": ["orders"], "tags": ["pii"], "sensitivity": "confidential" }
```

`sensitivity` 取值 `public < internal < confidential < restricted`；`collections/tags` 为标识符
数组，`["*"]` 表示全域且只能单独出现。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

覆盖最小授权放行、DENY 优先、范围不足拒绝、无授权升级、人工批准生成临时授权、到期失效、
撤销、重启还原与全链路时间线：

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务启动时会先清扫到期临时授权；重启后 SQLite 中的授权、调用、审批状态与审计历史继续保留。

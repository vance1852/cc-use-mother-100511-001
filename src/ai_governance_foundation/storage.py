"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
    grant_type TEXT NOT NULL CHECK(grant_type IN ('standing', 'temporary')),
    model_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    scope_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'expired')),
    approved_by TEXT NOT NULL,
    approval_reason TEXT NOT NULL,
    source_approval_id TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT,
    revoke_reason TEXT,
    expired_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_grants_lookup
    ON grants(effect, status, model_id, task_id, actor_id, tool);
CREATE TABLE IF NOT EXISTS tool_calls (
    call_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    model_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    arguments_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('requested', 'allowed', 'denied', 'escalated',
                                          'approved', 'rejected', 'completed', 'failed', 'cancelled')),
    decision_rule TEXT,
    winning_grant_id TEXT,
    decision_report_json TEXT NOT NULL,
    approval_id TEXT,
    result_summary TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_timeline ON tool_calls(created_at, call_id);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL REFERENCES tool_calls(call_id),
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'cancelled')),
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    reviewer_id TEXT,
    decision TEXT CHECK(decision IS NULL OR decision IN ('approved', 'rejected')),
    reason TEXT,
    grant_id TEXT REFERENCES grants(grant_id),
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, requested_at);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()

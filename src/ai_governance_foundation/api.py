"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .permissions import PermissionService
from .service import DomainService
from .storage import Database


def _truthy(value: str | None) -> bool:
    return str(value or "").lower() in ("1", "true", "yes", "on")


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None,
          permissions: PermissionService | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    actor_id = headers.get("X-Actor-Id", "")
    permissions = permissions or PermissionService(service.database, service.clock)
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}

        # ----- 智能体工具权限域 -----
        if method == "POST" and parsed.path == "/grants":
            result = permissions.register_grant(actor_id=actor_id, **body)
            return 200 if result["replayed"] else 201, result
        if method == "POST" and parsed.path == "/grants/revoke":
            result = permissions.revoke_grant(actor_id=actor_id, **body)
            return 200 if result["replayed"] else 200, result
        if method == "POST" and parsed.path == "/grants/reconcile-expirations":
            return 200, permissions.reconcile_expirations()
        if method == "GET" and parsed.path == "/grants":
            filters = {name: query.get(name, [None])[0]
                       for name in ("effect", "status", "model_id", "task_id", "grant_type")}
            actor_filter = query.get("actor_id", [None])[0]
            if actor_filter:
                filters["actor_id"] = actor_filter
            grants = permissions.list_grants(active_only=_truthy(query.get("active_only", [None])[0]),
                                             **filters)
            return 200, {"items": [grant.__dict__ for grant in grants]}
        if method == "GET" and parsed.path.startswith("/grants/"):
            grant_id = parsed.path.split("/", 2)[2]
            return 200, permissions.get_grant(grant_id).__dict__

        if method == "POST" and parsed.path == "/tool-calls":
            # 工具调用的 actor_id（智能体身份）是请求载荷字段，而非审批头。
            result = permissions.request_tool_call(**body)
            return 200 if result["replayed"] else 201, result
        if method == "POST" and parsed.path == "/tool-calls/finish":
            result = permissions.finish_tool_call(**body)
            return 200, result
        if method == "GET" and parsed.path == "/tool-calls":
            calls = permissions.list_tool_calls(
                task_id=query.get("task_id", [None])[0],
                actor_id=query.get("actor_id", [None])[0],
                model_id=query.get("model_id", [None])[0],
                tool=query.get("tool", [None])[0],
                status=query.get("status", [None])[0],
                limit=int(query.get("limit", ["100"])[0]))
            return 200, {"items": [call.__dict__ for call in calls]}
        if method == "GET" and parsed.path.endswith("/timeline"):
            parts = parsed.path.strip("/").split("/")
            # /tool-calls/{call_id}/timeline
            if len(parts) == 3 and parts[0] == "tool-calls":
                return 200, permissions.call_timeline(parts[1])
        if method == "GET" and parsed.path.startswith("/tool-calls/"):
            call_id = parsed.path.split("/", 2)[2]
            return 200, permissions.get_tool_call(call_id).__dict__

        if method == "POST" and parsed.path == "/approvals/resolve":
            result = permissions.resolve_approval(actor_id=actor_id, **body)
            return 200, result
        if method == "GET" and parsed.path == "/approvals/pending":
            items = permissions.list_pending_approvals()
            return 200, {"items": [item.__dict__ for item in items]}
        if method == "GET" and parsed.path.startswith("/approvals/"):
            approval_id = parsed.path.split("/", 2)[2]
            return 200, permissions.get_approval(approval_id).__dict__

        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService
    permissions: PermissionService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")},
                                self.permissions)
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def build_services(database: Database) -> tuple[DomainService, PermissionService]:
    """构造共享数据库的两个服务，并在启动时清扫到期临时授权。"""

    domain = DomainService(database)
    permissions = PermissionService(database, domain.clock)
    permissions.reconcile_expirations()
    return domain, permissions


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动智能体工具权限登记与审计服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service, Handler.permissions = build_services(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

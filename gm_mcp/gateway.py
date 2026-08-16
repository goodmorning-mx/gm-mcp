"""Reusable HTTP MCP gateway for GoodMorning products.

The gateway deliberately contains no product logic. Products register adapters
whose handlers call their existing application services and receive a trusted
``RequestContext`` from the product's authentication layer.
"""

from __future__ import annotations

import inspect
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .context import RequestContext
from .registry import ToolCall, ToolRegistry
from .security import PermissionDenied


class ContextResolver(Protocol):
    def __call__(self, request: Request) -> RequestContext | Awaitable[RequestContext]: ...


class AuditSink(Protocol):
    def __call__(self, event: dict[str, Any]) -> None | Awaitable[None]: ...


class GatewayAuthError(Exception):
    """Raised by a product authenticator when the bearer token is invalid."""


def _rpc_error(request_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": error})


async def _resolve(resolver: ContextResolver, request: Request) -> RequestContext:
    value = resolver(request)
    if inspect.isawaitable(value):
        value = await value
    if not isinstance(value, RequestContext):
        raise GatewayAuthError("Context resolver did not return RequestContext")
    return value


def create_gateway_app(
    registry: ToolRegistry,
    *,
    context_resolver: ContextResolver,
    audit_sink: AuditSink | None = None,
    name: str = "GoodMorning MCP Gateway",
) -> FastAPI:
    """Create a standards-compatible Streamable HTTP MCP application.

    Supported JSON-RPC methods are ``initialize``, ``notifications/initialized``,
    ``tools/list`` and ``tools/call``. The legacy ``/tools`` endpoints remain
    available for existing GoodMorning clients during migration.
    """

    app = FastAPI(title=name)

    async def audit(event: dict[str, Any]) -> None:
        if audit_sink is not None:
            result = audit_sink(event)
            if inspect.isawaitable(result):
                await result

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": name, "tools": len(registry.list())}

    async def authenticated(request: Request) -> RequestContext:
        try:
            return await _resolve(context_resolver, request)
        except GatewayAuthError as exc:
            raise exc
        except Exception as exc:  # product auth may use HTTPException or JWT errors
            raise GatewayAuthError(str(exc)) from exc

    @app.get("/tools")
    async def tools(request: Request) -> Any:
        try:
            await authenticated(request)
        except GatewayAuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        return registry.list()

    @app.post("/tools/call")
    async def legacy_call(request: Request) -> Any:
        try:
            context = await authenticated(request)
            body = await request.json()
            call = ToolCall(str(body["name"]), dict(body.get("arguments", {})), bool(body.get("confirmed", False)))
            result = await invoke(call, context)
            return {"content": result.content, "isError": result.is_error, "requiresConfirmation": result.requires_confirmation}
        except GatewayAuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        except (KeyError, TypeError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def invoke(call: ToolCall, context: RequestContext):
        request_id = context.request_id or str(uuid.uuid4())
        base = {"request_id": request_id, "tool": call.name, "user_id": context.user_id,
                "organization_id": context.organization_id, "product_id": context.product_id,
                "confirmed": call.confirmed}
        await audit({**base, "event": "mcp.tool.started", "argument_keys": sorted(call.arguments)})
        try:
            result = await registry.invoke(call, context)
        except PermissionDenied as exc:
            await audit({**base, "event": "mcp.tool.denied", "status": "denied", "error": str(exc)})
            raise
        except Exception as exc:
            await audit({**base, "event": "mcp.tool.failed", "status": "error", "error": str(exc)})
            raise
        await audit({**base, "event": "mcp.tool.completed", "status": "confirmation_required" if result.requires_confirmation else "ok"})
        return result

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> JSONResponse:
        try:
            body = await request.json()
            request_id = body.get("id")
            method = body.get("method")
            if method == "notifications/initialized":
                return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": {}})
            context = await authenticated(request)
            if method == "initialize":
                return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": {
                    "protocolVersion": body.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": name, "version": "0.2.0"},
                }})
            if method == "tools/list":
                return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": {"tools": registry.list()}})
            if method == "tools/call":
                params = body.get("params", {})
                call = ToolCall(str(params["name"]), dict(params.get("arguments", {})), bool(params.get("confirmed", False)))
                result = await invoke(call, context)
                content = result.content if isinstance(result.content, list) else [{"type": "text", "text": json.dumps(result.content, ensure_ascii=False, default=str)}]
                return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": {
                    "content": content, "isError": result.is_error,
                    **({"_meta": {"requiresConfirmation": True}} if result.requires_confirmation else {}),
                }})
            return _rpc_error(request_id, -32601, f"Unsupported method: {method}")
        except GatewayAuthError as exc:
            return _rpc_error(body.get("id") if isinstance(body, dict) else None, -32001, "Unauthorized", {"detail": str(exc)})
        except PermissionDenied as exc:
            return _rpc_error(body.get("id"), -32003, "Permission denied", {"detail": str(exc)})
        except Exception as exc:
            return _rpc_error(body.get("id"), -32000, "Tool request failed", {"detail": str(exc)})

    return app

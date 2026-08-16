"""Reusable HTTP MCP gateway for GoodMorning products.

The gateway deliberately contains no product logic. Products register adapters
whose handlers call their existing application services and receive a trusted
``RequestContext`` from the product's authentication layer.
"""

from __future__ import annotations

from html import escape
import inspect
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .context import RequestContext
from .oauth import OAuthProvider, OAuthProtocolError
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


def _tool_call(body: dict[str, Any], *, params: bool = False) -> ToolCall:
    source = body.get("params", {}) if params else body
    return ToolCall(
        str(source["name"]),
        dict(source.get("arguments", {})),
        bool(source.get("confirmed", False)),
        source.get("intent_id") or source.get("intentId"),
        source.get("confirmation_token") or source.get("confirmationToken"),
        source.get("idempotency_key") or source.get("idempotencyKey"),
    )


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
    context_resolver: ContextResolver | None = None,
    audit_sink: AuditSink | None = None,
    name: str = "GoodMorning MCP Gateway",
    oauth: OAuthProvider | None = None,
    oauth_product_id: str = "goodmorning-product",
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
        authorization = request.headers.get("authorization", "")
        if oauth is not None and authorization.lower().startswith("bearer "):
            context = await oauth.context(authorization.split(" ", 1)[1].strip(), product_id=oauth_product_id, request_id=request.headers.get("x-request-id"))
            if context is not None:
                return context
        if context_resolver is None:
            raise GatewayAuthError("Bearer OAuth access token required")
        try:
            return await _resolve(context_resolver, request)
        except GatewayAuthError as exc:
            raise exc
        except Exception as exc:  # product auth may use HTTPException or JWT errors
            raise GatewayAuthError(str(exc)) from exc

    if oauth is not None:
        @app.get("/.well-known/oauth-authorization-server")
        async def oauth_metadata(request: Request) -> Any:
            return oauth.metadata(f"{oauth.issuer_url}/oauth/register")

        @app.get("/.well-known/oauth-protected-resource")
        async def protected_resource() -> Any:
            return oauth.protected_resource_metadata()

        @app.post("/oauth/register")
        async def register(request: Request) -> Any:
            try:
                return JSONResponse(oauth.register(await request.json()), status_code=201)
            except OAuthProtocolError as exc:
                return JSONResponse({"error": exc.error, "error_description": exc.description}, status_code=400)

        @app.get("/oauth/authorize")
        async def authorize(request: Request) -> Any:
            try:
                request_id = oauth.begin_authorization(dict(request.query_params))
                return RedirectResponse(f"/oauth/login?request_id={request_id}", status_code=303)
            except OAuthProtocolError as exc:
                return JSONResponse({"error": exc.error, "error_description": exc.description}, status_code=400)

        @app.get("/oauth/login")
        async def login_form(request_id: str) -> Any:
            if oauth.pending(request_id) is None:
                return HTMLResponse("Authorization request expired.", status_code=400)
            safe_request_id = escape(request_id, quote=True)
            return HTMLResponse("""<html><body><h1>GoodMorning MCP authorization</h1><form method='post'><input type='hidden' name='request_id' value='""" + safe_request_id + """'><label>Email <input name='email' type='email' required></label><label>Password <input name='password' type='password' required></label><button type='submit'>Authorize</button></form></body></html>""")

        @app.post("/oauth/login")
        async def login_submit(request: Request) -> Any:
            from urllib.parse import parse_qs
            values = parse_qs((await request.body()).decode(), keep_blank_values=True)
            try:
                redirect = await oauth.approve(values.get("request_id", [""])[0], values.get("email", [""])[0], values.get("password", [""])[0])
                return RedirectResponse(redirect, status_code=303)
            except OAuthProtocolError as exc:
                return HTMLResponse(exc.description, status_code=403)

        @app.post("/oauth/token")
        async def token(request: Request) -> Any:
            from urllib.parse import parse_qs
            values = parse_qs((await request.body()).decode(), keep_blank_values=True)
            get = lambda key: values.get(key, [""])[0]
            try:
                if get("grant_type") == "authorization_code":
                    result = await oauth.exchange_code(client_id=get("client_id"), code=get("code"), redirect_uri=get("redirect_uri"), verifier=get("code_verifier"))
                elif get("grant_type") == "refresh_token":
                    result = await oauth.refresh(client_id=get("client_id"), refresh_token=get("refresh_token"), scope=get("scope") or None)
                else:
                    raise OAuthProtocolError("unsupported_grant_type", "Only authorization_code and refresh_token are supported.")
                return JSONResponse(result)
            except OAuthProtocolError as exc:
                return JSONResponse({"error": exc.error, "error_description": exc.description}, status_code=400)

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
            call = _tool_call(body)
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
                call = _tool_call(body, params=True)
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

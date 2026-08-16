from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

from .context import RequestContext
from .intents import IntentStore
from .security import Permission, PermissionDenied

ServiceCallable = Callable[..., Any]
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ServiceCallable
    permission: Permission = Permission.READ
    write: bool = False
    requires_confirmation: bool = False
    output_schema: dict[str, Any] | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            **({"outputSchema": self.output_schema} if self.output_schema is not None else {}),
            "metadata": {
                "permission": self.permission.value,
                "readOnly": not self.write,
                "requiresConfirmation": self.requires_confirmation,
                "scopes": sorted(self.scopes),
                "roles": sorted(self.roles),
                "permissions": sorted(self.permissions or {self.permission.value}),
            },
        }


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    confirmed: bool = False
    intent_id: str | None = None
    confirmation_token: str | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class ToolResult:
    content: Any
    is_error: bool = False
    requires_confirmation: bool = False


class ToolRegistry:
    """Registry that adapts tools to existing product service functions."""

    def __init__(self, intent_store: IntentStore | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        self._intent_store = intent_store

    def register(self, item: Tool) -> Tool:
        if item.name in self._tools:
            raise ValueError(f"Tool already registered: {item.name}")
        if not item.name or "." not in item.name:
            raise ValueError("Tool names must use a product namespace, e.g. billing.list_invoices")
        self._tools[item.name] = item
        return item

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"Unknown MCP tool: {name}") from exc

    def list(self) -> list[dict[str, Any]]:
        return [self._tools[name].metadata() for name in sorted(self._tools)]

    async def invoke(self, call: ToolCall, context: RequestContext) -> ToolResult:
        item = self.get(call.name)
        if not context.can(item.permission.value):
            raise PermissionDenied(f"Missing {item.permission.value} permission for {call.name}")
        required_permissions = item.permissions or frozenset({item.permission.value})
        if not required_permissions.issubset(context.permissions) and "*" not in context.permissions:
            raise PermissionDenied(f"Missing required permissions for {call.name}")
        if item.scopes and not item.scopes.issubset(context.scopes) and "*" not in context.scopes:
            raise PermissionDenied(f"Missing required scopes for {call.name}")
        if item.roles and not item.roles.intersection(context.roles) and "*" not in context.roles:
            raise PermissionDenied(f"Missing required role for {call.name}")
        if item.requires_confirmation and self._intent_store is not None:
            if not call.confirmed:
                preview = self._intent_store.preview(context=context, tool_name=call.name, arguments=call.arguments, idempotency_key=call.idempotency_key)
                if inspect.isawaitable(preview):
                    preview = await preview
                return ToolResult(content=preview, requires_confirmation=True)
            if not call.intent_id or not call.confirmation_token:
                raise PermissionDenied(f"Confirmation token required for {call.name}")
            value = self._intent_store.confirm(context=context, tool_name=call.name, intent_id=call.intent_id, confirmation_token=call.confirmation_token, execute=lambda: item.handler(context=context, **call.arguments))
            if inspect.isawaitable(value):
                value = await value
            return ToolResult(content=value)
        if item.requires_confirmation and not call.confirmed:
            return ToolResult(content={"tool": call.name, "arguments": call.arguments}, requires_confirmation=True)
        value = item.handler(context=context, **call.arguments)
        if inspect.isawaitable(value):
            value = await value
        return ToolResult(content=value)


def tool(
    *,
    name: str,
    description: str,
    input_schema: dict[str, Any],
    permission: Permission = Permission.READ,
    write: bool = False,
    requires_confirmation: bool = False,
    output_schema: dict[str, Any] | None = None,
    scopes: set[str] | frozenset[str] | None = None,
    roles: set[str] | frozenset[str] | None = None,
    permissions: set[str] | frozenset[str] | None = None,
) -> Callable[[ServiceCallable], Tool]:
    """Decorate a product service adapter as an MCP tool definition."""
    def decorator(handler: ServiceCallable) -> Tool:
        return Tool(name, description, input_schema, handler, permission, write, requires_confirmation, output_schema, frozenset(scopes or ()), frozenset(roles or ()), frozenset(permissions or ()))
    return decorator

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

from .context import RequestContext
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
            },
        }


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    confirmed: bool = False


@dataclass(frozen=True, slots=True)
class ToolResult:
    content: Any
    is_error: bool = False
    requires_confirmation: bool = False


class ToolRegistry:
    """Registry that adapts tools to existing product service functions."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

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
) -> Callable[[ServiceCallable], Tool]:
    """Decorate a product service adapter as an MCP tool definition."""
    def decorator(handler: ServiceCallable) -> Tool:
        return Tool(name, description, input_schema, handler, permission, write, requires_confirmation, output_schema)
    return decorator

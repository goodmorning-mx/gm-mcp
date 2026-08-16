"""Protocol for product-owned durable preview/confirm write intents."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from .context import RequestContext

Executor = Callable[[], Any | Awaitable[Any]]


class IntentStore(Protocol):
    """Persistence boundary for exactly-once product mutations."""

    def preview(self, *, context: RequestContext, tool_name: str, arguments: dict[str, Any], idempotency_key: str | None) -> Any | Awaitable[Any]: ...

    def confirm(self, *, context: RequestContext, tool_name: str, intent_id: str | None, confirmation_token: str | None, execute: Executor) -> Any | Awaitable[Any]: ...

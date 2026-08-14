from __future__ import annotations

from typing import Any

import httpx

from .context import RequestContext
from .registry import ToolCall, ToolResult


class MCPError(RuntimeError):
    pass


class MCPClient:
    """Small MCP-compatible client for a remote tool server."""

    def __init__(self, base_url: str, *, token: str | None = None, timeout: float = 20.0, client: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client = client

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    async def list_tools(self) -> list[dict[str, Any]]:
        close = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        try:
            response = await client.get(f"{self.base_url}/tools", headers=self._headers())
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, list):
                raise MCPError("MCP server returned an invalid tools list")
            return value
        except httpx.HTTPError as exc:
            raise MCPError(f"MCP tools request failed: {exc}") from exc
        finally:
            if close:
                await client.aclose()

    async def call_tool(self, call: ToolCall, context: RequestContext) -> ToolResult:
        close = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        payload = {"name": call.name, "arguments": call.arguments, "confirmed": call.confirmed, "context": {
            "userId": context.user_id, "organizationId": context.organization_id, "productId": context.product_id,
            "requestId": context.request_id, "permissions": sorted(context.permissions),
        }}
        try:
            response = await client.post(f"{self.base_url}/tools/call", json=payload, headers=self._headers())
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise MCPError("MCP server returned an invalid tool result")
            return ToolResult(value.get("content"), bool(value.get("isError")), bool(value.get("requiresConfirmation")))
        except httpx.HTTPError as exc:
            raise MCPError(f"MCP tool request failed: {exc}") from exc
        finally:
            if close:
                await client.aclose()

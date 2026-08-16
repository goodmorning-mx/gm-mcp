# gm-mcp

`gm-mcp` is the shared Operations MCP Gateway for GoodMorning products. It
supports embedded registries and a remote Streamable HTTP gateway without
duplicating product business logic.

Products register namespaced adapters with `ToolRegistry` and create an ASGI
app using `create_gateway_app`. The product supplies authentication/context
resolution and an audit sink; every handler receives the trusted
`RequestContext`.

The remote endpoint implements `initialize`, `tools/list`, and `tools/call` at
`POST /mcp`, plus temporary `/tools` compatibility endpoints. Gateways can
enable OAuth 2.1 Authorization Code + S256 PKCE with dynamic client
registration, resource-bound short-lived access tokens, and rotating refresh
tokens. Writes can be marked `requires_confirmation=True`; products may attach
a durable intent store so the first call previews an intent and the confirmed
call is audited with user, organization, product,
request, tool, and outcome metadata. `/health` is unauthenticated.

Reusable MCP primitives for GoodMorning products. Product code registers
adapters around existing services; the registry never accesses a product
database directly. The intended path is:

`MCP tool → product service → PostgreSQL`

The package supplies namespaced tool metadata, JSON input schemas, user/org/
product context, read/write permissions, explicit confirmation gates, and a
small HTTP client for remote MCP servers.

```python
from gm_mcp import Permission, RequestContext, ToolRegistry, tool

registry = ToolRegistry()

@tool(name="students.find", description="Find students", input_schema={"type": "object"})
async def find_students(*, context: RequestContext, query: str):
    return await student_service.search(context.organization_id, query)

registry.register(find_students)
```

Install with `pip install gm-mcp`. See `tests/` for the service-adapter and
confirmation contracts.

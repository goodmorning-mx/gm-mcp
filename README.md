# gm-mcp

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

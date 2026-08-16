import json

from fastapi.testclient import TestClient

from gm_mcp import RequestContext, ToolRegistry, create_gateway_app, tool


def test_streamable_http_lists_and_calls_tools_with_product_context():
    registry = ToolRegistry()

    @tool(name="students.find", description="Find students", input_schema={"type": "object"})
    def find(*, context, query):
        return {"organization": context.organization_id, "query": query}

    registry.register(find)
    events = []
    app = create_gateway_app(
        registry,
        context_resolver=lambda request: RequestContext("user-1", "org-1", "balletpourtous", frozenset({"read"})),
        audit_sink=events.append,
    )
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    listing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert listing.status_code == 200
    assert listing.json()["result"]["tools"][0]["name"] == "students.find"
    response = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "students.find", "arguments": {"query": "Ana"}},
    })
    assert json.loads(response.json()["result"]["content"][0]["text"]) == {"organization": "org-1", "query": "Ana"}
    assert events[-1]["event"] == "mcp.tool.completed"

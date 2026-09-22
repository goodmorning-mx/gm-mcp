import json
import unittest

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
    initialized = client.post("/mcp", json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}, headers={"authorization": "Bearer test"})
    assert initialized.json()["result"]["serverInfo"]["version"] == "0.3.2"
    listing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert listing.status_code == 200
    assert listing.json()["result"]["tools"][0]["name"] == "students.find"
    response = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "students.find", "arguments": {"query": "Ana"}},
    })
    assert json.loads(response.json()["result"]["content"][0]["text"]) == {"organization": "org-1", "query": "Ana"}
    assert events[-1]["event"] == "mcp.tool.completed"


class GatewayContentBlockTests(unittest.TestCase):
    def _call(self, result):
        registry = ToolRegistry()

        @tool(name="academy.list", description="List academy data", input_schema={"type": "object"})
        def list_data(*, context):
            return result

        registry.register(list_data)
        app = create_gateway_app(
            registry,
            context_resolver=lambda request: RequestContext("user-1", "org-1", "academy", frozenset({"read"})),
        )
        response = TestClient(app).post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "academy.list", "arguments": {}},
        })
        self.assertEqual(response.status_code, 200)
        return response.json()["result"]["content"]

    def test_product_list_is_wrapped_as_json_text_content(self):
        rows = [{"id": 4, "nombre": "Grupo Rosa"}, {"id": 9, "nombre": "Grupo Ballet"}]

        content = self._call(rows)

        self.assertEqual(content, [{"type": "text", "text": json.dumps(rows, ensure_ascii=False)}])
        self.assertEqual(json.loads(content[0]["text"]), rows)

    def test_empty_product_list_is_wrapped_as_json_text_content(self):
        self.assertEqual(self._call([]), [{"type": "text", "text": "[]"}])

    def test_valid_mcp_content_blocks_are_preserved(self):
        blocks = [{"type": "text", "text": "Already formatted"}]
        self.assertEqual(self._call(blocks), blocks)

    def test_list_with_non_content_items_is_serialized_as_product_data(self):
        rows = [{"type": "group", "id": 4, "nombre": "Grupo Rosa"}]
        content = self._call(rows)
        self.assertEqual(content, [{"type": "text", "text": json.dumps(rows, ensure_ascii=False)}])

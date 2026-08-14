import asyncio
import unittest

from gm_mcp import Permission, PermissionDenied, RequestContext, ToolCall, ToolRegistry, tool


class RegistryTests(unittest.TestCase):
    def test_tool_calls_existing_service_and_context(self):
        registry = ToolRegistry()

        @tool(name="students.find", description="Find students", input_schema={"type": "object"})
        def find(*, context, query):
            return {"product": context.product_id, "query": query}

        registry.register(find)
        result = asyncio.run(registry.invoke(ToolCall("students.find", {"query": "Ana"}), RequestContext("u1", "o1", "academy", frozenset({"read"}))))
        self.assertEqual(result.content, {"product": "academy", "query": "Ana"})
        self.assertEqual(registry.list()[0]["metadata"]["readOnly"], True)

    def test_permissions_and_confirmation_are_enforced(self):
        registry = ToolRegistry()

        @tool(name="students.archive", description="Archive", input_schema={"type": "object"}, permission=Permission.WRITE, write=True, requires_confirmation=True)
        def archive(*, context, student_id):
            return student_id

        registry.register(archive)
        context = RequestContext("u1", "o1", "academy", frozenset({"write"}))
        pending = asyncio.run(registry.invoke(ToolCall("students.archive", {"student_id": 4}), context))
        self.assertTrue(pending.requires_confirmation)
        done = asyncio.run(registry.invoke(ToolCall("students.archive", {"student_id": 4}, confirmed=True), context))
        self.assertEqual(done.content, 4)
        with self.assertRaises(PermissionDenied):
            asyncio.run(registry.invoke(ToolCall("students.archive", {"student_id": 4}), RequestContext("u1", "o1", "academy", frozenset({"read"}))))

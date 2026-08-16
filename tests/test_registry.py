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

    def test_durable_intent_store_receives_actor_and_confirmation_metadata(self):
        class Store:
            def __init__(self):
                self.calls = []

            def preview(self, **kwargs):
                self.calls.append(("preview", kwargs))
                return {"intent_id": "intent-1", "confirmation_token": "token-1"}

            def confirm(self, **kwargs):
                self.calls.append(("confirm", kwargs))
                return kwargs["execute"]()

        store = Store()
        registry = ToolRegistry(intent_store=store)

        @tool(name="students.create", description="Create", input_schema={"type": "object"}, permission=Permission.WRITE, write=True, requires_confirmation=True)
        def create(*, context, name):
            return {"created": name}

        registry.register(create)
        context = RequestContext("user-1", "org-1", "demo", frozenset({"write"}), oauth_client_id="client-1")
        pending = asyncio.run(registry.invoke(ToolCall("students.create", {"name": "Ana"}, idempotency_key="key-1"), context))
        self.assertTrue(pending.requires_confirmation)
        done = asyncio.run(registry.invoke(ToolCall("students.create", {"name": "Ana"}, confirmed=True, intent_id="intent-1", confirmation_token="token-1"), context))
        self.assertEqual(done.content, {"created": "Ana"})
        self.assertEqual(store.calls[0][1]["context"].oauth_client_id, "client-1")

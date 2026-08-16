import json
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi.testclient import TestClient

from gm_mcp import OAuthIdentity, OAuthProvider, Permission, ToolRegistry, create_gateway_app, pkce_challenge, tool


def test_oauth_pkce_registration_code_exchange_refresh_and_tool_authorization():
    identity = OAuthIdentity("user-1", "org-1", frozenset({"admin"}), frozenset({"read", "write"}), "Admin")

    def authenticate(email, password):
        return identity if email == "admin@example.test" and password == "correct" else None

    def load(subject, resource):
        return identity if subject == identity.user_id and resource.endswith("/mcp") else None

    oauth = OAuthProvider(
        issuer_url="https://mcp.example.test",
        resource_url="https://mcp.example.test/mcp",
        signing_secret="oauth-test-secret-with-at-least-32-characters",
        scopes={"mcp:read": "Read operations", "mcp:write": "Write operations"},
        authenticate_user=authenticate,
        load_identity=load,
    )
    registry = ToolRegistry()

    @tool(name="demo.read", description="Read", input_schema={"type": "object"}, scopes={"mcp:read"}, permissions={"read"})
    def read(*, context):
        return {"user": context.user_id, "client": context.oauth_client_id}

    registry.register(read)
    app = create_gateway_app(registry, oauth=oauth, oauth_product_id="demo")
    client = TestClient(app)

    metadata = client.post("/oauth/register", json={
        "client_name": "Test MCP client",
        "redirect_uris": ["http://127.0.0.1:8765/callback"],
        "scope": "mcp:read",
        "token_endpoint_auth_method": "none",
    })
    assert metadata.status_code == 201
    client_id = metadata.json()["client_id"]
    verifier = "a" * 64
    authorization = client.get("/oauth/authorize", params={
        "client_id": client_id,
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "response_type": "code",
        "scope": "mcp:read",
        "state": "state-1",
        "resource": "https://mcp.example.test/mcp",
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    assert authorization.status_code == 303
    request_id = parse_qs(urlparse(authorization.headers["location"]).query)["request_id"][0]
    login = client.post(authorization.headers["location"], data={"request_id": request_id, "email": "admin@example.test", "password": "correct"}, follow_redirects=False)
    assert login.status_code == 303
    callback = urlparse(login.headers["location"])
    callback_values = parse_qs(callback.query)
    assert callback_values["state"] == ["state-1"]

    token = client.post("/oauth/token", data=urlencode({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": callback_values["code"][0],
        "redirect_uri": "http://127.0.0.1:8765/callback",
        "code_verifier": verifier,
    }), headers={"content-type": "application/x-www-form-urlencoded"})
    assert token.status_code == 200
    tokens = token.json()
    assert tokens["expires_in"] <= 600 and tokens["refresh_token"]

    listed = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"authorization": f"Bearer {tokens['access_token']}"})
    assert listed.status_code == 200
    assert listed.json()["result"]["tools"][0]["metadata"]["scopes"] == ["mcp:read"]
    called = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "demo.read", "arguments": {}}}, headers={"authorization": f"Bearer {tokens['access_token']}"})
    assert json.loads(called.json()["result"]["content"][0]["text"])["client"] == client_id

    refreshed = client.post("/oauth/token", data=urlencode({"grant_type": "refresh_token", "client_id": client_id, "refresh_token": tokens["refresh_token"]}), headers={"content-type": "application/x-www-form-urlencoded"})
    assert refreshed.status_code == 200 and refreshed.json()["refresh_token"] != tokens["refresh_token"]
    rotated = client.post("/oauth/token", data=urlencode({"grant_type": "refresh_token", "client_id": client_id, "refresh_token": tokens["refresh_token"]}), headers={"content-type": "application/x-www-form-urlencoded"})
    assert rotated.status_code == 400 and rotated.json()["error"] == "invalid_grant"


def test_oauth_rejects_wrong_resource_and_unsafe_redirect():
    identity = OAuthIdentity("user-1", "org-1")
    oauth = OAuthProvider(
        issuer_url="https://mcp.example.test",
        resource_url="https://mcp.example.test/mcp",
        signing_secret="oauth-test-secret-with-at-least-32-characters",
        scopes={"mcp:read": "Read operations"},
        authenticate_user=lambda email, password: identity,
        load_identity=lambda subject, resource: identity,
    )
    assert oauth.register({"redirect_uris": ["https://client.example/callback"], "scope": "mcp:read"})["client_id"]
    try:
        oauth.register({"redirect_uris": ["http://evil.example/callback"], "scope": "mcp:read"})
    except ValueError as exc:
        assert "redirect" in str(exc)
    else:
        raise AssertionError("unsafe redirect URI was accepted")

"""Small, product-neutral OAuth 2.1 provider for remote MCP gateways.

The provider owns protocol state and token validation only. Products supply
the identity callbacks, so gm-auth remains the source of truth for users,
organizations, roles, and permissions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode, urlsplit

from .context import RequestContext

_PKCE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")


@dataclass(frozen=True, slots=True)
class OAuthIdentity:
    user_id: str
    organization_id: str
    roles: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset()
    name: str | None = None
    email: str | None = None


@dataclass(frozen=True, slots=True)
class OAuthClient:
    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str
    scopes: frozenset[str]
    token_endpoint_auth_method: str = "none"


@dataclass(frozen=True, slots=True)
class OAuthGrant:
    subject: str
    organization_id: str
    client_id: str
    scopes: frozenset[str]
    roles: frozenset[str]
    permissions: frozenset[str]
    resource: str
    expires_at: int


IdentityAuthenticator = Callable[[str, str], OAuthIdentity | None | Awaitable[OAuthIdentity | None]]
IdentityLoader = Callable[[str, str], OAuthIdentity | None | Awaitable[OAuthIdentity | None]]
RedirectValidator = Callable[[str], bool]


def _default_redirect_validator(uri: str) -> bool:
    parsed = urlsplit(uri)
    if parsed.fragment or parsed.query or not parsed.netloc:
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass(slots=True)
class _Pending:
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    scope: frozenset[str]
    resource: str
    expires_at: float


@dataclass(slots=True)
class _Code:
    code: str
    client_id: str
    subject: str
    redirect_uri: str
    code_challenge: str
    scopes: frozenset[str]
    resource: str
    expires_at: float


@dataclass(slots=True)
class _Refresh:
    token_hash: str
    client_id: str
    subject: str
    scopes: frozenset[str]
    resource: str
    expires_at: float


class OAuthProtocolError(ValueError):
    def __init__(self, error: str, description: str):
        super().__init__(description)
        self.error = error
        self.description = description


class OAuthProvider:
    """OAuth 2.1 Authorization Code + S256 PKCE provider.

    State is intentionally bounded and fail-closed. A product can replace
    these callbacks with durable storage later without changing the gateway
    protocol or tool registry.
    """

    def __init__(
        self,
        *,
        issuer_url: str,
        resource_url: str,
        signing_secret: str,
        scopes: dict[str, str],
        authenticate_user: IdentityAuthenticator,
        load_identity: IdentityLoader,
        access_token_ttl_seconds: int = 600,
        refresh_token_ttl_seconds: int = 2_592_000,
        redirect_validator: RedirectValidator | None = None,
        legacy_token_resolver: IdentityAuthenticator | None = None,
    ) -> None:
        if not signing_secret or len(signing_secret) < 32:
            raise ValueError("OAuth signing secret must contain at least 32 characters.")
        parsed = urlsplit(resource_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("OAuth resource_url must be an HTTPS origin or endpoint without query/fragment.")
        if not scopes:
            raise ValueError("At least one OAuth scope is required.")
        self.issuer_url = issuer_url.rstrip("/")
        self.resource_url = resource_url.rstrip("/")
        self.scopes = dict(scopes)
        self._authenticate_user = authenticate_user
        self._load_identity = load_identity
        self._legacy_token_resolver = legacy_token_resolver
        self._access_ttl = max(60, access_token_ttl_seconds)
        self._refresh_ttl = max(300, refresh_token_ttl_seconds)
        self._key = hmac.new(signing_secret.encode(), b"gm-mcp-oauth-v1", hashlib.sha256).digest()
        self._redirect_validator = redirect_validator or _default_redirect_validator
        self._clients: OrderedDict[str, OAuthClient] = OrderedDict()
        self._pending: dict[str, _Pending] = {}
        self._codes: dict[str, _Code] = {}
        self._access: dict[str, OAuthGrant] = {}
        self._refresh: OrderedDict[str, _Refresh] = OrderedDict()

    def _cleanup(self) -> None:
        now = time.time()
        self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at > now}
        self._access = {k: v for k, v in self._access.items() if v.expires_at > now}
        for key, value in list(self._refresh.items()):
            if value.expires_at <= now:
                self._refresh.pop(key, None)

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    async def _maybe(self, value: Any) -> Any:
        return await value if inspect.isawaitable(value) else value

    def metadata(self, registration_endpoint: str) -> dict[str, Any]:
        return {
            "issuer": self.issuer_url,
            "authorization_endpoint": f"{self.issuer_url}/oauth/authorize",
            "token_endpoint": f"{self.issuer_url}/oauth/token",
            "registration_endpoint": registration_endpoint,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": sorted(self.scopes),
            "token_endpoint_auth_methods_supported": ["none"],
        }

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {"resource": self.resource_url, "authorization_servers": [self.issuer_url], "scopes_supported": sorted(self.scopes)}

    def register(self, metadata: dict[str, Any]) -> dict[str, Any]:
        redirect_uris = tuple(str(value) for value in metadata.get("redirect_uris", []))
        if not redirect_uris or len(redirect_uris) > 10 or any(not self._redirect_validator(uri) for uri in redirect_uris):
            raise OAuthProtocolError("invalid_client_metadata", "redirect_uris must be approved HTTPS or loopback URLs.")
        auth_method = str(metadata.get("token_endpoint_auth_method", "none"))
        if auth_method != "none":
            raise OAuthProtocolError("invalid_client_metadata", "This gateway accepts public PKCE clients only.")
        requested = frozenset(str(metadata.get("scope", "")).split()) or frozenset(self.scopes)
        if not requested.issubset(self.scopes):
            raise OAuthProtocolError("invalid_scope", "Requested scope is not supported by this gateway.")
        client_id = secrets.token_urlsafe(24)
        client = OAuthClient(client_id, redirect_uris, str(metadata.get("client_name") or "MCP client")[:120], requested, auth_method)
        self._clients[client_id] = client
        while len(self._clients) > 512:
            self._clients.popitem(last=False)
        return {
            "client_id": client_id,
            "client_name": client.client_name,
            "redirect_uris": list(client.redirect_uris),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": " ".join(sorted(client.scopes)),
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
        }

    def client(self, client_id: str) -> OAuthClient:
        self._cleanup()
        value = self._clients.get(client_id)
        if value is None:
            raise OAuthProtocolError("invalid_client", "Unknown OAuth client.")
        return value

    def begin_authorization(self, params: dict[str, str]) -> str:
        client = self.client(params.get("client_id", ""))
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri not in client.redirect_uris or params.get("response_type") != "code":
            raise OAuthProtocolError("invalid_request", "The client and redirect URI do not match.")
        challenge = params.get("code_challenge", "")
        if params.get("code_challenge_method") != "S256" or not _PKCE.fullmatch(challenge):
            raise OAuthProtocolError("invalid_request", "S256 PKCE is required.")
        requested = frozenset(params.get("scope", "").split()) or client.scopes
        if not requested.issubset(client.scopes) or not requested.issubset(self.scopes):
            raise OAuthProtocolError("invalid_scope", "The requested scope is not allowed for this client.")
        request_id = secrets.token_urlsafe(32)
        self._pending[request_id] = _Pending(client.client_id, redirect_uri, params.get("state"), challenge, requested, params.get("resource", self.resource_url), time.time() + 300)
        if self._pending[request_id].resource != self.resource_url:
            self._pending.pop(request_id, None)
            raise OAuthProtocolError("invalid_target", "The requested resource does not match this gateway.")
        return request_id

    def pending(self, request_id: str) -> _Pending | None:
        self._cleanup()
        return self._pending.get(request_id)

    async def approve(self, request_id: str, email: str, password: str) -> str:
        pending = self.pending(request_id)
        if pending is None:
            raise OAuthProtocolError("invalid_request", "The authorization request expired.")
        identity = await self._maybe(self._authenticate_user(email, password))
        if identity is None:
            raise OAuthProtocolError("access_denied", "Invalid credentials or MCP access is not allowed.")
        if self._pending.pop(request_id, None) is None:
            raise OAuthProtocolError("invalid_request", "The authorization request was already used.")
        code = secrets.token_urlsafe(32)
        self._codes[code] = _Code(code, pending.client_id, identity.user_id, pending.redirect_uri, pending.code_challenge, pending.scope, pending.resource, time.time() + 300)
        values = {"code": code}
        if pending.state:
            values["state"] = pending.state
        return f"{pending.redirect_uri}{'&' if '?' in pending.redirect_uri else '?'}{urlencode(values)}"

    def deny(self, request_id: str) -> str | None:
        pending = self._pending.pop(request_id, None)
        if pending is None:
            return None
        values = {"error": "access_denied"}
        if pending.state:
            values["state"] = pending.state
        return f"{pending.redirect_uri}{'&' if '?' in pending.redirect_uri else '?'}{urlencode(values)}"

    async def exchange_code(self, *, client_id: str, code: str, redirect_uri: str, verifier: str) -> dict[str, Any]:
        client = self.client(client_id)
        stored = self._codes.pop(code, None)
        if stored is None or stored.client_id != client.client_id or stored.redirect_uri != redirect_uri or pkce_challenge(verifier) != stored.code_challenge:
            raise OAuthProtocolError("invalid_grant", "The authorization code is invalid, expired, or already used.")
        identity = await self._maybe(self._load_identity(stored.subject, stored.resource))
        if identity is None:
            raise OAuthProtocolError("invalid_grant", "The account is no longer authorized.")
        return self._issue(identity, client.client_id, stored.scopes, stored.resource)

    async def refresh(self, *, client_id: str, refresh_token: str, scope: str | None = None) -> dict[str, Any]:
        client = self.client(client_id)
        stored = self._refresh.pop(self._hash(refresh_token), None)
        if stored is None or stored.client_id != client.client_id:
            raise OAuthProtocolError("invalid_grant", "The refresh token is invalid or has already been rotated.")
        scopes = frozenset((scope or " ".join(stored.scopes)).split())
        if not scopes or not scopes.issubset(stored.scopes):
            raise OAuthProtocolError("invalid_scope", "Refresh cannot grant additional scopes.")
        identity = await self._maybe(self._load_identity(stored.subject, stored.resource))
        if identity is None:
            raise OAuthProtocolError("invalid_grant", "The account is no longer authorized.")
        return self._issue(identity, client.client_id, scopes, stored.resource)

    def _issue(self, identity: OAuthIdentity, client_id: str, scopes: frozenset[str], resource: str) -> dict[str, Any]:
        now = int(time.time())
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(64)
        self._access[access] = OAuthGrant(identity.user_id, identity.organization_id, client_id, scopes, identity.roles, identity.permissions, resource, now + self._access_ttl)
        self._refresh[self._hash(refresh)] = _Refresh(self._hash(refresh), client_id, identity.user_id, scopes, resource, time.time() + self._refresh_ttl)
        while len(self._refresh) > 1024:
            self._refresh.popitem(last=False)
        return {"access_token": access, "token_type": "Bearer", "expires_in": self._access_ttl, "refresh_token": refresh, "scope": " ".join(sorted(scopes))}

    async def resolve(self, token: str) -> OAuthGrant | None:
        self._cleanup()
        grant = self._access.get(token)
        if grant is not None and grant.expires_at > int(time.time()) and grant.resource == self.resource_url:
            identity = await self._maybe(self._load_identity(grant.subject, grant.resource))
            if identity is None or identity.organization_id != grant.organization_id:
                return None
            return OAuthGrant(identity.user_id, identity.organization_id, grant.client_id, grant.scopes, identity.roles, identity.permissions, grant.resource, grant.expires_at)
        if self._legacy_token_resolver is not None:
            identity = await self._maybe(self._legacy_token_resolver(token, self.resource_url))
            if identity is not None:
                return OAuthGrant(identity.user_id, identity.organization_id, "legacy-bearer", frozenset(self.scopes), identity.roles, identity.permissions, self.resource_url, int(time.time()) + self._access_ttl)
        return None

    async def context(self, token: str, *, product_id: str, request_id: str | None = None) -> RequestContext | None:
        grant = await self.resolve(token)
        if grant is None:
            return None
        return RequestContext(grant.subject, grant.organization_id, product_id, grant.permissions, request_id=request_id, roles=grant.roles, scopes=grant.scopes, oauth_client_id=grant.client_id, metadata={"oauth_client_id": grant.client_id, "resource": grant.resource})

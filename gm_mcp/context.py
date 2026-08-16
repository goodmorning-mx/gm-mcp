from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Identity and product boundary passed to every tool invocation."""

    user_id: str
    organization_id: str
    product_id: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    request_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    roles: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    oauth_client_id: str | None = None

    def can(self, permission: str) -> bool:
        return permission in self.permissions or "*" in self.permissions

    def has_role(self, role: str) -> bool:
        return role in self.roles or "*" in self.roles

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes

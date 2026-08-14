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

    def can(self, permission: str) -> bool:
        return permission in self.permissions or "*" in self.permissions

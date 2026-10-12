"""HTTP login audit adapter backed by the policy-enforced engine."""
from __future__ import annotations

from ..engine import BruteForceEngine, CredentialAuditResult
from .base import UnsupportedProtocolError


class Adapter:
    protocol = "http"

    def __init__(self, engine: BruteForceEngine | None = None) -> None:
        self.engine = engine or BruteForceEngine()

    async def audit(
        self, login_url: str, username: str = "", **options,
    ) -> CredentialAuditResult:
        """Run a guarded HTTP audit; requires explicit preflight confirmation."""
        return await self.engine.run(login_url, username, **options)

    async def connect(self, *args, **kwargs):
        """Preserve the old capability probe with a clear API migration hint."""
        del args, kwargs
        raise UnsupportedProtocolError(
            "HTTP authentication uses Adapter.audit(login_url, ..., preflight_confirmed=True)."
        )

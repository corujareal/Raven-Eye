from __future__ import annotations
from dataclasses import dataclass

@dataclass(slots=True)
class CredentialAuditPolicy:
    """Safe policy surface for credential auditing.

    RavenEye does not perform password guessing, spraying, credential stuffing,
    evasion, or authentication bypasses. Integrators may use this policy to
    describe an externally controlled, authorized test without embedding attack
    automation in the core platform.
    """
    max_attempts: int = 0
    lockout_threshold: int = 0
    enabled: bool = False

class BruteForceEngine:
    def __init__(self, *_, **__): self.policy=CredentialAuditPolicy()
    async def run(self, *_, **__):
        raise RuntimeError('Credential-guessing automation is disabled in the safe RavenEye build.')

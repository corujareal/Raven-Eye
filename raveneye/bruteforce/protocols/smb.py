"""Protocol capability declaration for RavenEye 6.6.6.

This module intentionally does not implement credential-guessing/attack logic.
It exposes a clear capability failure so the UI cannot mistake a stub for a
working protocol engine.
"""
from .base import unavailable

class Adapter:
    protocol = "smb"

    async def connect(self, *args, **kwargs):
        unavailable(self.protocol)

class UnsupportedProtocolError(RuntimeError):
    """Raised when an optional protocol adapter is not installed/implemented."""


def unavailable(protocol: str) -> None:
    raise UnsupportedProtocolError(
        f"Protocol adapter '{protocol}' is not available in this build. "
        "Install a supported adapter or use the safe enumeration/audit features."
    )

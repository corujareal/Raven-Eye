"""Policy-enforced async facade for RavenEye's guarded HTTP login audit.

This increment connects the newer package API to the maintained HTTP flow. It
does not enable the other protocol stubs or expose credentials in its result.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import TypeVar
from urllib.parse import urlsplit

_Result = TypeVar("_Result")


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} must be an integer") from None
    if normalized != value or not minimum <= normalized <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return normalized


@dataclass(frozen=True, slots=True)
class CredentialAuditPolicy:
    """Hard local limits for an explicitly confirmed authentication audit."""

    max_attempts: int = 100
    lockout_threshold: int = 5
    enabled: bool = True
    min_delay_seconds: float = 1.0
    max_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        _bounded_int("max_attempts", self.max_attempts, 1, 100)
        _bounded_int("lockout_threshold", self.lockout_threshold, 1, 100)
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a boolean")
        if not 1.0 <= float(self.min_delay_seconds) <= 60.0:
            raise ValueError("min_delay_seconds must be between 1 and 60 seconds")
        if not 1.0 <= float(self.max_timeout_seconds) <= 30.0:
            raise ValueError("max_timeout_seconds must be between 1 and 30 seconds")


@dataclass(frozen=True, slots=True)
class CredentialAuditResult:
    """Redacted outcome; credential values and request URLs are excluded."""

    status: str
    target_origin: str
    attempts: int
    elapsed_seconds: float
    attempts_per_second: float
    match_confidence: str | None = None


def _safe_origin(target: str) -> str:
    try:
        parsed = urlsplit(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = parsed.hostname.lower().rstrip(".")
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return f"{parsed.scheme.lower()}://{host}:{port}"
    except (ValueError, UnicodeError):
        raise ValueError("target must be an HTTP(S) URL without embedded credentials") from None


def _run_in_daemon_thread(
    loop: asyncio.AbstractEventLoop,
    function: Callable[[], _Result],
    finished: threading.Event,
) -> asyncio.Future[_Result]:
    """Bridge a blocking legacy operation without executor shutdown hangs."""
    completed = loop.create_future()

    def settle(value=None, error: BaseException | None = None) -> None:
        if completed.done():
            return
        if error is not None:
            completed.set_exception(error)
        else:
            completed.set_result(value)

    def worker() -> None:
        try:
            value = function()
        except BaseException as exc:
            try:
                loop.call_soon_threadsafe(settle, None, exc)
            except RuntimeError:
                pass
        else:
            try:
                loop.call_soon_threadsafe(settle, value, None)
            except RuntimeError:
                pass
        finally:
            finished.set()

    threading.Thread(target=worker, name="raveneye-http-audit", daemon=True).start()
    return completed


class BruteForceEngine:
    """Async facade over the guarded, serial HTTP audit implementation.

    A caller must confirm the exact target before this method can make a
    request. Cancellation is cooperative: it stops before the next credential
    POST and waits for any in-flight request to finish or time out.
    """

    def __init__(self, policy: CredentialAuditPolicy | None = None, *, wordlist_manager=None):
        self.policy = policy or CredentialAuditPolicy()
        self.wordlist_manager = wordlist_manager

    async def run(
        self,
        login_url: str,
        username: str = "",
        *,
        preflight_confirmed: bool = False,
        username_field: str = "username",
        password_field: str = "password",
        wordlist_path: str | None = None,
        userlist_path: str | None = None,
        combo_mode: bool = False,
        success_marker: str = "",
        delay: float | None = None,
        timeout: float | None = None,
        max_attempts: int | None = None,
        per_user_limit: int | None = None,
        resumable: bool = False,
        resume: bool = False,
        threads: int = 1,
    ) -> CredentialAuditResult:
        if not self.policy.enabled:
            raise RuntimeError("Credential auditing is disabled by policy.")
        if not preflight_confirmed:
            raise ValueError("explicit target confirmation is required before authentication")

        target_origin = _safe_origin(login_url)
        if _bounded_int("threads", threads, 1, 1) != 1:
            raise ValueError("this policy permits one authentication request at a time")
        requested_cap = self.policy.max_attempts if max_attempts is None else _bounded_int(
            "max_attempts", max_attempts, 1, self.policy.max_attempts,
        )
        if not 1 <= requested_cap <= self.policy.max_attempts:
            raise ValueError("max_attempts exceeds the configured audit policy")
        account_cap = self.policy.lockout_threshold if per_user_limit is None else _bounded_int(
            "per_user_limit", per_user_limit, 1, self.policy.lockout_threshold,
        )
        if not 1 <= account_cap <= self.policy.lockout_threshold:
            raise ValueError("per_user_limit exceeds the configured lockout threshold")
        delay_value = self.policy.min_delay_seconds if delay is None else float(delay)
        timeout_value = min(8.0, self.policy.max_timeout_seconds) if timeout is None else float(timeout)
        if delay_value < self.policy.min_delay_seconds or delay_value > 60.0:
            raise ValueError("delay must respect the policy minimum and stay at or below 60 seconds")
        if not 1.0 <= timeout_value <= self.policy.max_timeout_seconds:
            raise ValueError("timeout exceeds the configured audit policy")

        # Late imports keep package discovery light and avoid a module cycle:
        # the legacy implementation owns wordlist normalization, DNS pinning,
        # checkpoint integrity, lockout handling, and the protected HTTP client.
        from raveneye_pkg.bruteforce import bruteforce_login, get_wordlist_manager

        manager = self.wordlist_manager or get_wordlist_manager()
        cancelled = threading.Event()
        worker_finished = threading.Event()
        started = time.monotonic()
        loop = asyncio.get_running_loop()
        work = _run_in_daemon_thread(loop, partial(
            bruteforce_login,
            login_url,
            username,
            username_field,
            password_field,
            wordlist_path=wordlist_path,
            use_extra_passwords=False,
            userlist_path=userlist_path,
            combo_mode=combo_mode,
            delay=delay_value,
            timeout=timeout_value,
            stop_on_success=True,
            resumable=resumable,
            resume=resume,
            threads=1,
            max_attempts=requested_cap,
            per_user_limit=account_cap,
            success_marker=success_marker,
            preflight_confirmed=True,
            _wordlist_manager=manager,
            _cancel_event=cancelled,
        ), worker_finished)
        try:
            found, attempts = await asyncio.shield(work)
        except asyncio.CancelledError:
            cancelled.set()
            current = asyncio.current_task()
            # Python 3.11+ keeps a cancellation count after the exception is
            # caught. Clear pending requests while we drain the in-flight
            # request; the original cancellation is re-raised below.
            uncancel = getattr(current, "uncancel", None)
            cancelling = getattr(current, "cancelling", None)
            if callable(uncancel) and callable(cancelling):
                while cancelling():
                    uncancel()
            while not worker_finished.is_set():
                await asyncio.sleep(0.01)
            # Consume a worker exception after cancellation; cancellation
            # remains the public outcome and the worker emits sanitized state.
            work.add_done_callback(
                lambda future: None if future.cancelled() else future.exception()
            )
            raise

        elapsed = max(0.001, time.monotonic() - started)
        return CredentialAuditResult(
            status="possible_match" if found else "completed" if attempts else "no_attempts",
            target_origin=target_origin,
            attempts=int(attempts),
            elapsed_seconds=elapsed,
            attempts_per_second=float(attempts) / elapsed,
            match_confidence="possible" if found else None,
        )

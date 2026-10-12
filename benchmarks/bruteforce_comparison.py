"""Local, labeled HTTP-login comparison between RavenEye and THC Hydra.

The fixture binds only to 127.0.0.1. It accepts no user-supplied target,
username, password, or wordlist, and writes aggregate metrics only. Example:

    python benchmarks/bruteforce_comparison.py --hydra /tmp/raveneye-hydra-source/hydra
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_HOST = "127.0.0.1"
FIXTURE_USER = "raveneye-fixture-user"
VALID_PASSWORD = "raveneye-fixture-valid-only"
SUCCESS_MARKER = "RAVENEYE_FIXTURE_AUTHENTICATED"
INVALID_MARKER = "RAVENEYE_FIXTURE_REJECTED"
POSITIVE_CANDIDATES = ("raveneye-fixture-wrong-one", VALID_PASSWORD, "raveneye-fixture-wrong-two")
NEGATIVE_CANDIDATES = (
    "raveneye-fixture-wrong-one",
    "raveneye-fixture-wrong-two",
    "raveneye-fixture-wrong-three",
)


class FixtureState:
    """Track classifications only; discard submitted credentials and tokens."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.csrf_enabled = False
        self.reset()

    def reset(self, *, csrf_enabled: bool | None = None) -> None:
        with self.lock:
            if csrf_enabled is not None:
                self.csrf_enabled = csrf_enabled
            self.posts = 0
            self.accepted = 0
            self.rejected = 0
            self.csrf_rejected = 0
            self.csrf_generation = 1
            self.csrf_token = self._token(1) if self.csrf_enabled else ""

    @staticmethod
    def _token(generation: int) -> str:
        return f"raveneye-fixture-csrf-{generation}"

    def check_and_rotate_csrf(self, token: str) -> bool:
        with self.lock:
            valid = not self.csrf_enabled or token == self.csrf_token
            if self.csrf_enabled and valid:
                self.csrf_generation += 1
                self.csrf_token = self._token(self.csrf_generation)
            return valid

    def csrf_form(self) -> str:
        with self.lock:
            token = self.csrf_token
        return (
            '<form method="post" action="/login">'
            '<input name="username"><input name="password">'
            f'<input type="hidden" name="csrf_token" value="{token}"></form>'
        )

    def record(self, accepted: bool, *, csrf_valid: bool) -> None:
        with self.lock:
            self.posts += 1
            self.accepted += int(accepted)
            self.rejected += int(not accepted)
            self.csrf_rejected += int(not csrf_valid)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "authentication_posts": self.posts,
                "accepted_posts": self.accepted,
                "rejected_posts": self.rejected,
                "csrf_rejected_posts": self.csrf_rejected,
            }


def make_fixture(state: FixtureState) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            if urlsplit(self.path).path != "/login":
                self.send_error(404)
                return
            body = state.csrf_form().encode("ascii") if state.csrf_enabled else (
                b'<form method="post"><input name="username"><input name="password"></form>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/login":
                self.send_error(404)
                return
            length = min(8192, int(self.headers.get("Content-Length", "0") or 0))
            values = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            csrf_valid = state.check_and_rotate_csrf(values.get("csrf_token", [""])[0])
            accepted = (
                values.get("username", [""])[0] == FIXTURE_USER
                and values.get("password", [""])[0] == VALID_PASSWORD
                and csrf_valid
            )
            state.record(accepted, csrf_valid=csrf_valid)
            marker = SUCCESS_MARKER if accepted else INVALID_MARKER
            body = (
                f"{marker}{state.csrf_form()}".encode("ascii")
                if state.csrf_enabled else marker.encode("ascii")
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)

        def log_message(self, _format: str, *_args) -> None:
            return

    server = ThreadingHTTPServer((FIXTURE_HOST, 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="raveneye-login-fixture", daemon=True)
    thread.start()
    server.fixture_thread = thread
    return server


def summarize_run(tool: str, case: str, elapsed: float, detected: bool, expected: bool,
                  reported_correct_credential: bool | None, snapshot: dict) -> dict:
    true_positive = bool(expected and detected and reported_correct_credential is True)
    false_positive = bool(not expected and detected)
    false_negative = bool(expected and not detected)
    true_negative = bool(not expected and not detected)
    return {
        "tool": tool,
        "case": case,
        "expected_match": expected,
        "detected_match": detected,
        "reported_expected_credential": reported_correct_credential,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "authentication_posts": snapshot["authentication_posts"],
        "accepted_posts": snapshot["accepted_posts"],
        "rejected_posts": snapshot["rejected_posts"],
        "elapsed_seconds": round(elapsed, 6),
        "authentication_posts_per_second": round(snapshot["authentication_posts"] / elapsed, 6) if elapsed else None,
    }


def run_raveneye(base_url: str, case: str, candidates: tuple[str, ...], state: FixtureState,
                 wordlist_path: Path, manager, per_user_limit: int) -> dict:
    # Imports are intentionally local so `--help` doesn't initialize RavenEye.
    from raveneye.bruteforce.engine import BruteForceEngine, CredentialAuditPolicy

    state.reset()
    expected = "positive" in case
    started = time.perf_counter()
    result = asyncio.run(BruteForceEngine(
        CredentialAuditPolicy(max_attempts=len(candidates), lockout_threshold=per_user_limit),
        wordlist_manager=manager,
    ).run(
        f"{base_url}/login",
        FIXTURE_USER,
        preflight_confirmed=True,
        wordlist_path=str(wordlist_path),
        success_marker=SUCCESS_MARKER,
        delay=1.0,
        timeout=4.0,
        max_attempts=len(candidates),
        per_user_limit=per_user_limit,
    ))
    elapsed = time.perf_counter() - started
    snapshot = state.snapshot()
    detected = result.status == "possible_match"
    # The public engine result deliberately does not contain the password.
    correct_credential = bool(snapshot["accepted_posts"] == 1) if detected else None
    return summarize_run("RavenEye", case, elapsed, detected, expected, correct_credential, snapshot)


def run_hydra(binary: Path, version: str, base_url: str, case: str,
              candidates: tuple[str, ...], state: FixtureState, temp_root: Path,
              *, profile: str) -> dict:
    password_file = temp_root / f"{case}-hydra-passwords.txt"
    password_file.write_text("\n".join(candidates) + "\n", encoding="utf-8")
    parsed = urlsplit(base_url)
    if parsed.hostname != FIXTURE_HOST:
        raise RuntimeError("The local comparison fixture must use the literal loopback address.")
    csrf_mode = case.startswith("csrf-")
    csrf_parameter = "&csrf_token=raveneye-fixture-csrf-1" if csrf_mode else ""
    module_options = (
        f"/login:username=^USER^&password=^PASS^{csrf_parameter}:S={SUCCESS_MARKER}"
    )
    if profile == "matched-serial":
        concurrency_options = ["-t", "1", "-c", "1"]
        tool_name = "Hydra (1 task, -c 1s)"
    elif profile == "default-parallel":
        concurrency_options = ["-t", "16"]
        tool_name = "Hydra (16 tasks)"
    else:
        raise ValueError("Unknown Hydra comparison profile.")
    command = [
        str(binary), "-4", "-I", "-f", *concurrency_options, "-w", "4",
        "-s", str(parsed.port), "-l", FIXTURE_USER, "-P", str(password_file),
        FIXTURE_HOST, "http-post-form", module_options,
    ]
    hydra_home = temp_root / "hydra-home"
    hydra_home.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update({
        "HOME": str(hydra_home),
        "XDG_CONFIG_HOME": str(hydra_home / ".config"),
        "XDG_DATA_HOME": str(hydra_home / ".local" / "share"),
        "XDG_CACHE_HOME": str(hydra_home / ".cache"),
    })
    state.reset()
    started = time.perf_counter()
    process = subprocess.run(
        command, cwd=temp_root, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=20, check=False,
    )
    elapsed = time.perf_counter() - started
    snapshot = state.snapshot()
    combined = process.stdout + "\n" + process.stderr
    # Read the captured credentials only to compare with fixture truth; never
    # return or persist Hydra's raw output, which may include a match.
    match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", combined)
    detected = match is not None
    correct_credential = (
        None if not match else bool(match.group(1) == FIXTURE_USER and match.group(2) == VALID_PASSWORD)
    )
    if process.returncode not in (0, 255) and not detected:
        raise RuntimeError(f"Hydra fixture run failed with exit status {process.returncode}; captured output omitted.")
    if snapshot["authentication_posts"] == 0:
        raise RuntimeError(f"Hydra did not reach the local fixture (version {version}); captured output omitted.")
    return summarize_run(tool_name, case, elapsed, detected, "positive" in case, correct_credential, snapshot)


def aggregate(rows: list[dict]) -> dict:
    output = {}
    for tool in ("RavenEye", "Hydra (1 task, -c 1s)", "Hydra (16 tasks)"):
        selected = [row for row in rows if row["tool"] == tool]
        rates = [row["authentication_posts_per_second"] for row in selected]
        true_positives = sum(row["true_positive"] for row in selected)
        false_positives = sum(row["false_positive"] for row in selected)
        true_negatives = sum(row["true_negative"] for row in selected)
        false_negatives = sum(row["false_negative"] for row in selected)
        output[tool] = {
            "runs": len(selected),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": round(true_positives / (true_positives + false_positives), 6)
            if true_positives + false_positives else None,
            "recall": round(true_positives / (true_positives + false_negatives), 6)
            if true_positives + false_negatives else None,
            "specificity": round(true_negatives / (true_negatives + false_positives), 6)
            if true_negatives + false_positives else None,
            "median_authentication_posts_per_second": round(statistics.median(rates), 6) if rates else None,
        }
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare RavenEye and Hydra on loopback-only labeled login fixtures, including rotating CSRF."
    )
    parser.add_argument("--hydra", required=True, type=Path, help="path to a locally built Hydra executable")
    parser.add_argument(
        "--runs", type=int, default=3,
        help="repetitions per positive, negative, and rotating-CSRF case (1-10)",
    )
    parser.add_argument("--hydra-source-revision", default="not-recorded",
                        help="source revision used to build the local Hydra executable")
    parser.add_argument("--output", type=Path, default=None, help="optional path for sanitized aggregate JSON")
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("--runs must be between 1 and 10")
    binary = args.hydra.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--hydra must point to an executable Hydra binary")
    version_result = subprocess.run([str(binary), "-h"], capture_output=True, text=True, timeout=5, check=False)
    version_line = next((line.strip() for line in (version_result.stdout + version_result.stderr).splitlines()
                         if line.startswith("Hydra v")), "unknown")

    from raveneye.wordlists import WordlistManager
    from raveneye_pkg import state as raveneye_state

    raveneye_state.config = {"bf_attempts": 100, "bf_attempts_per_user": 100, "scope_file": ""}
    rows: list[dict] = []
    fixture_state = FixtureState()
    server = make_fixture(fixture_state)
    base_url = f"http://{FIXTURE_HOST}:{server.server_port}"
    try:
        with tempfile.TemporaryDirectory(prefix="raveneye-hydra-fixture-") as temp_dir:
            temp_root = Path(temp_dir)
            list_path = temp_root / "raveneye-passwords.txt"
            manager = WordlistManager(temp_root / "raveneye-data" / "wordlists")
            for run_number in range(args.runs):
                for case, candidates in (
                    ("positive", POSITIVE_CANDIDATES),
                    ("negative", NEGATIVE_CANDIDATES),
                    ("csrf-positive", POSITIVE_CANDIDATES),
                    ("csrf-negative", NEGATIVE_CANDIDATES),
                ):
                    fixture_state.reset(csrf_enabled=case.startswith("csrf-"))
                    list_path.write_text("\n".join(candidates) + "\n", encoding="utf-8")
                    rows.append(run_raveneye(base_url, case, candidates, fixture_state, list_path, manager, len(candidates)))
                    rows.append(run_hydra(binary, version_line, base_url, case, candidates, fixture_state, temp_root, profile="matched-serial"))
                    rows.append(run_hydra(binary, version_line, base_url, case, candidates, fixture_state, temp_root, profile="default-parallel"))
            report = {
                "fixture": "RavenEye local login fixture, bound only to 127.0.0.1",
                "hydra_version": version_line,
                "hydra_source_revision": args.hydra_source_revision,
                "runs_per_case_per_tool": args.runs,
                "authentication_policy": {
                    "raveneye_threads": 1,
                    "raveneye_delay_seconds": 1,
                    "hydra_profiles": {
                        "matched": "-t 1 -c 1 (one task, one-second per-attempt wait)",
                        "default": "-t 16 (Hydra documented default task concurrency)",
                    },
                    "target_limit": "one ephemeral loopback HTTP origin",
                    "candidates_per_case": 3,
                    "positive_candidate_position": 2,
                    "negative_case_contains_valid_credential": False,
                    "csrf_scenarios": (
                        "single-use CSRF token rotates in each rejected POST response; "
                        "Hydra receives the initially observed token as a static form value"
                    ),
                    "output_contains_credentials": False,
                },
                "timing_method": (
                    "Wall clock around the BruteForceEngine call or Hydra subprocess. "
                    "RavenEye imports are warm; Hydra process startup is included, "
                    "so this short-list measurement is conservative for Hydra."
                ),
                "summary": aggregate(rows),
                "runs": rows,
                "interpretation": "Synthetic fixture evidence only; does not establish performance or accuracy on arbitrary real-world login forms.",
            }
    finally:
        server.shutdown()
        server.server_close()
        server.fixture_thread.join(timeout=2)

    encoded = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        output_path = args.output.expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()

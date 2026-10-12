"""Fair, local-only RavenEye/Katana crawler comparison on a labeled fixture.

Usage: python benchmarks/katana_comparison.py --runs 5 --pages 2000
Add --include-headless to measure optional browser runs separately.
Katana is invoked from PATH. The RavenEye run grants loopback access only to
this fixture's exact IP:port; no public or other private address is allowed.
The static and headless modes are measured independently for both tools.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def current_rss_kib(pid: int | None = None) -> int:
    target = pid or os.getpid()
    try:
        for line in Path(f"/proc/{target}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0


def high_water_rss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0


class FixtureState:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.success = 0
        self.pages: set[str] = set()
        self.methods: Counter[str] = Counter()
        self.path_counts: Counter[str] = Counter()
        self.path_status_counts: dict[str, Counter[int]] = {}

    def reset(self):
        with self.lock:
            self.requests = self.success = 0
            self.pages.clear()
            self.methods.clear()
            self.path_counts.clear()
            self.path_status_counts.clear()

    def snapshot(self) -> tuple[int, int, set[str]]:
        with self.lock:
            return self.requests, self.success, set(self.pages)

    def method_snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.methods)

    def path_count_snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.path_counts)

    def path_status_snapshot(self) -> dict[str, dict[int, int]]:
        with self.lock:
            return {path: dict(counts) for path, counts in self.path_status_counts.items()}


def fixture_body(path: str, origin: str, stress_urls: int = 0) -> tuple[int, str, bytes]:
    if path == "/robots.txt":
        return 200, "text/plain", b"User-agent: *\nDisallow: /blocked/\nSitemap: /sitemap.xml\n"
    if path == "/sitemap.xml":
        return 200, "application/xml", b"<urlset><url><loc>/pages/form/000</loc></url></urlset>"
    if path == "/.well-known/security.txt":
        return 200, "text/plain", b"Contact: mailto:security@example.test\n"
    if path == "/.well-known/assetlinks.json":
        return 404, "text/plain", b"not found"
    if path == "/":
        links = [f'<a href="/pages/{kind}/{i:03d}">{kind}-{i}</a>'
                 for kind in ("login", "error", "listing", "form") for i in range(50)]
        links += [f'<a href="/duplicates/a/{i:03d}">dup-a-{i}</a><a href="/duplicates/b/{i:03d}">dup-b-{i}</a>' for i in range(100)]
        links += [f'<a href="/api/item/{i:03d}">api-{i}</a>' for i in range(100)]
        links.append('<a href="/spa">runtime SPA</a>')
        links += [f'<a href="/stress/{i:05d}">stress-{i}</a>' for i in range(stress_urls)]
        body = ("<!doctype html><html><head><title>Fixture</title>"
                "<script type='module' src='/assets/app.js'></script></head><body>" + "".join(links) + "</body></html>").encode()
        return 200, "text/html; charset=utf-8", body
    if path == "/spa":
        body = b"""<!doctype html><html><body><div id=\"root\"></div><script>
          const suffix = [\"runtime\", \"fetch\"].join(\"-\");
          fetch(\"/api/\" + suffix);
          const xhr = new XMLHttpRequest();
          xhr.open(\"GET\", \"/api/\" + [\"runtime\", \"xhr\"].join(\"-\")); xhr.send();
          const postPath = [\"runtime\", \"post\"].join(\"-\");
          fetch(\"/api/\" + postPath, {method: \"POST\", body: \"fixture-only\"});
        </script></body></html>"""
        return 200, "text/html; charset=utf-8", body
    parts = path.strip("/").split("/")
    if len(parts) == 3 and parts[0] == "pages" and parts[1] in {"login", "error", "listing", "form"}:
        kind, index = parts[1], parts[2]
        title = {"login": "Sign in", "error": "Internal Server Error", "listing": f"Index of /archive/{index}", "form": "Contact"}[kind]
        number = int(index)
        kind_salt = {"login": 11, "error": 101, "listing": 1009, "form": 10007}[kind]
        unique_text = " ".join(f"signal{(number * 97 + slot * 53 + kind_salt) % 1_000_003}" for slot in range(12))
        form = '<form><input type="text" name="email"><button>Send</button></form>'
        if kind == "login":
            form = '<form><input type="password" name="password"></form>'
        body = f"<!doctype html><title>{title}</title><h1>{title}</h1><p>{unique_text}</p>{form}".encode()
        return (500 if kind == "error" else 200), "text/html; charset=utf-8", body
    if len(parts) == 3 and parts[0] == "duplicates":
        pair = int(parts[2])
        unique_text = " ".join(f"pair{(pair * 137 + slot * 61) % 1_000_033}" for slot in range(12))
        body = f"<!doctype html><title>Shared page {pair}</title><main><h1>Shared content</h1><p>Identical document body used to measure duplicate detection. {unique_text}</p></main>".encode()
        return 200, "text/html; charset=utf-8", body
    if path == "/assets/app.js":
        body = ("import './chunk.js'; fetch('/api/js-endpoint'); "
                "new WebSocket('ws://" + urlsplit(origin).netloc + "/socket');"
                "//# sourceMappingURL=/assets/app.js.map").encode()
        return 200, "application/javascript", body
    if path == "/assets/chunk.js":
        return 200, "application/javascript", b"fetch('/api/module-endpoint');"
    if path == "/assets/app.js.map":
        content = "fetch('/api/map-endpoint');"
        return 200, "application/json", json.dumps({"version": 3, "sources": ["app.ts"], "sourcesContent": [content]}).encode()
    if path in {"/api/js-endpoint", "/api/map-endpoint", "/api/module-endpoint",
                "/api/runtime-fetch", "/api/runtime-xhr", "/api/runtime-post"} or (len(parts) == 3 and parts[:2] == ["api", "item"]):
        return 200, "application/json", b'{"ok":true}'
    if path.startswith("/blocked/"):
        return 200, "text/html", b"blocked fixture page"
    if path.startswith("/stress/"):
        token = int(path.rsplit("/", 1)[-1])
        unique = " ".join(f"noise{(token * 131 + slot * 71) % 1_000_033}" for slot in range(12))
        return 404, "text/html; charset=utf-8", f"<!doctype html><title>Not found</title><p>{path} {unique}</p>".encode()
    # Give every unknown path a distinct body so a generic 404 template cannot
    # masquerade as a duplicate-detection true positive.
    token = int.from_bytes(hashlib.sha256(path.encode("utf-8")).digest()[:8], "big")
    unique = " ".join(f"unknown{(token * 131 + slot * 71) % 1_000_033}" for slot in range(12))
    return 404, "text/html; charset=utf-8", f"<!doctype html><title>Not found</title><p>{path} {unique}</p>".encode()


def make_server(state: FixtureState, stress_urls: int = 0) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self._respond("GET")
        def do_POST(self):
            # This endpoint is an isolated local fixture; it never changes state.
            self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
            self._respond("POST")
        def _respond(self, method: str):
            path = urlsplit(self.path).path
            status, content_type, body = fixture_body(path, self.server.origin, self.server.stress_urls)
            with state.lock:
                state.requests += 1
                state.methods[method] += 1
                state.path_counts[path] += 1
                state.path_status_counts.setdefault(path, Counter())[status] += 1
                if 200 <= status < 300:
                    state.success += 1
                state.pages.add(path)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            return
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.stress_urls = stress_urls
    server.origin = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._fixture_thread = thread
    return server


def row_url(row: dict) -> str:
    """Read URLs from RavenEye and Katana JSONL without favoring one schema."""
    request = row.get("request") if isinstance(row.get("request"), dict) else {}
    raw = row.get("url") or request.get("endpoint") or request.get("url")
    return str(raw or "").split("#", 1)[0]


def fixture_request_metrics(state: FixtureState) -> dict:
    counts = state.path_count_snapshot()
    status_counts = state.path_status_snapshot()
    repeated = {path: count for path, count in counts.items() if count > 1}
    server_error_retries = sum(
        count - 1 for path, count in repeated.items()
        if any(500 <= status <= 599 for status in status_counts.get(path, {}))
    )
    return {
        "fixture_duplicate_requests": sum(count - 1 for count in counts.values()),
        "fixture_duplicate_request_paths": len(repeated),
        "fixture_server_error_retry_requests": server_error_retries,
        "fixture_other_duplicate_requests": sum(count - 1 for count in counts.values()) - server_error_retries,
        "fixture_duplicate_request_examples": [
            {
                "path": path,
                "requests": count,
                "statuses": status_counts.get(path, {}),
                "classification": (
                    "server_error_retry"
                    if any(500 <= status <= 599 for status in status_counts.get(path, {}))
                    else "other_repeat"
                ),
            }
            for path, count in sorted(repeated.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
    }


def metric_scores(rows: list[dict], origin: str, stress_urls: int = 0,
                  requested_paths: set[str] | None = None) -> dict:
    urls = {url for row in rows if (url := row_url(row))}
    api_truth = {f"{origin}/api/item/{i:03d}" for i in range(100)}
    page_truth = {
        f"{origin}/pages/{kind}/{index:03d}": kind
        for kind in ("login", "error", "listing", "form") for index in range(50)
    }
    page_truth.update({f"{origin}/stress/{index:05d}": "error" for index in range(stress_urls)})
    # These deterministic fixture routes return 404. They are labeled error
    # pages so valid status-based classifications do not inflate false positives.
    for path in (
        "/.well-known/assetlinks.json", "/openapi.json", "/swagger.json",
        "/swagger/v1/swagger.json", "/api-docs", "/graphql", "/api/",
    ):
        page_truth[f"{origin}{path}"] = "error"
    rows_by_url = {url: item for item in rows if (url := row_url(item))}
    runtime_truth = {"/api/runtime-fetch", "/api/runtime-xhr", "/api/runtime-post"}
    runtime_observed: set[str] = set()
    runtime_methods: set[tuple[str, str]] = set()
    for row in rows:
        request = row.get("request") if isinstance(row.get("request"), dict) else {}
        request_url = request.get("endpoint") or request.get("url") or row.get("url")
        request_method = str(request.get("method") or row.get("method") or "").upper()
        if request_url:
            request_path = urlsplit(str(request_url)).path
            if request_path in runtime_truth:
                runtime_observed.add(request_path)
                if request_method:
                    runtime_methods.add((request_path, request_method))
        for event in row.get("runtime_requests", []):
            if not isinstance(event, dict) or not event.get("url"):
                continue
            request_path = urlsplit(str(event["url"])).path
            if request_path in runtime_truth:
                runtime_observed.add(request_path)
                runtime_methods.add((request_path, str(event.get("method", "")).upper()))
    # The fixture server also confirms what actually reached it; this is useful
    # for proving that RavenEye observed but did not send the synthetic POST.
    runtime_observed.update(urlsplit(url).path for url in urls
                            if urlsplit(url).path in runtime_truth)
    per_class = {}
    for kind in ("login", "error", "listing", "form"):
        tp = sum(1 for url, truth in page_truth.items()
                 if truth == kind and rows_by_url.get(url, {}).get("type") == kind)
        fp = sum(1 for url, row in rows_by_url.items()
                 if row.get("type") == kind and page_truth.get(url) != kind)
        fn = sum(1 for url, truth in page_truth.items()
                 if truth == kind and rows_by_url.get(url, {}).get("type") != kind)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        false_positive_examples = sorted(
            url for url, row in rows_by_url.items()
            if row.get("type") == kind and page_truth.get(url) != kind
        )[:10]
        per_class[kind] = {
            "precision": precision,
            "recall": recall,
            "f1": (2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
            "false_positive_examples": false_positive_examples,
        }
    api_truth_paths = {urlsplit(url).path for url in api_truth}
    js_api_truth_paths = {
        "/api/js-endpoint", "/api/map-endpoint", "/api/module-endpoint",
    }
    observed_paths = {urlsplit(url).path for url in urls}
    requested_paths = requested_paths or set()
    duplicate_truth = {f"{origin}/duplicates/b/{i:03d}" for i in range(100)}
    duplicate_pred = {url for row in rows if row.get("duplicate") and (url := row_url(row))}
    tp = len(duplicate_pred & duplicate_truth)
    fp = len(duplicate_pred - duplicate_truth)
    fn = len(duplicate_truth - duplicate_pred)
    return {
        "jsonl_unique_urls": len(urls),
        "jsonl_rows": len(rows),
        "jsonl_known_api_coverage": len({urlsplit(url).path for url in urls} & api_truth_paths) / len(api_truth_paths),
        "known_js_endpoint_request_coverage": len(requested_paths & js_api_truth_paths) / len(js_api_truth_paths),
        "known_js_endpoint_jsonl_coverage": len(observed_paths & js_api_truth_paths) / len(js_api_truth_paths),
        "runtime_endpoint_capture_coverage": len(runtime_observed & runtime_truth) / len(runtime_truth),
        "runtime_methods_observed": sorted(
            {method for path, method in runtime_methods if path in runtime_truth and method}
        ),
        "runtime_post_observed": float(("/api/runtime-post", "POST") in runtime_methods),
        "module_script_request_coverage": float("/assets/chunk.js" in requested_paths),
        "jsonl_api_path_examples": sorted(
            urlsplit(url).path for url in urls if "/api/item/" in urlsplit(url).path
        )[:5],
        "page_class_macro_f1": sum(x["f1"] for x in per_class.values()) / len(per_class),
        "page_class_metrics": per_class,
        "duplicate_precision": tp / (tp + fp) if tp + fp else 0.0,
        "duplicate_recall": tp / (tp + fn) if tp + fn else 0.0,
        "duplicate_flagged": len(duplicate_pred),
        "duplicate_false_positive_examples": sorted(duplicate_pred - duplicate_truth)[:10],
        "duplicate_false_negative_examples": sorted(duplicate_truth - duplicate_pred)[:10],
    }


def raveneye_run(origin: str, output: Path, pages: int, state: FixtureState,
                 stress_urls: int = 0, *, headless: bool = False) -> tuple[dict, int]:
    worker = ROOT / "benchmarks" / "raveneye_worker.py"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    started = time.perf_counter()
    process = subprocess.Popen(
        [sys.executable, str(worker), origin, str(output), str(pages), "1" if headless else "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
        env=environment,
    )
    ready_line = process.stdout.readline() if process.stdout else ""
    try:
        ready = json.loads(ready_line)
    except json.JSONDecodeError:
        diagnostic = process.stderr.read() if process.stderr else ""
        process.wait()
        return {"error": f"RavenEye worker failed to start: {diagnostic[-1200:]}"}, 0
    rss_start = int(ready.get("rss_kib", 0))
    peak_rss = max(rss_start, high_water_rss_kib(process.pid))
    timeout_seconds = max(60, min(1800, int(pages / 20) + 60))
    while process.poll() is None:
        if time.perf_counter() - started > timeout_seconds:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            return {"error": f"RavenEye exceeded {timeout_seconds}s fixture timeout"}, 0
        peak_rss = max(peak_rss, current_rss_kib(process.pid), high_water_rss_kib(process.pid))
        time.sleep(0.01)
    elapsed = time.perf_counter() - started
    stdout_tail = process.stdout.read().splitlines() if process.stdout else []
    diagnostic = process.stderr.read() if process.stderr else ""
    if process.returncode != 0 or not stdout_tail:
        return {"error": f"RavenEye worker exited with status {process.returncode}: {diagnostic[-1200:]}"}, 0
    try:
        worker_result = json.loads(stdout_tail[-1])
    except json.JSONDecodeError:
        return {"error": f"RavenEye worker returned invalid metrics: {diagnostic[-1200:]}"}, 0
    peak_rss = max(peak_rss, int(worker_result.get("rss_peak_kib", 0)))
    fixture_requests, fixture_success, requested_paths = state.snapshot()
    fixture_pages = len(requested_paths)
    rows = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
    metrics = metric_scores(rows, origin, stress_urls, requested_paths)
    known_api_paths = {f"/api/item/{i:03d}" for i in range(100)}
    known_page_paths = {
        f"/pages/{kind}/{index:03d}"
        for kind in ("login", "error", "listing", "form") for index in range(50)
    }
    metrics.update({
        "elapsed_seconds": elapsed,
        "crawl_execution_seconds": worker_result.get("elapsed_seconds"),
        "fixture_http_responses": fixture_requests,
        "fixture_pages_requested": fixture_pages,
        "urls_seen": fixture_pages,
        "stress_urls_expected": stress_urls,
        "stress_urls_seen": sum(1 for path in requested_paths if path.startswith("/stress/")),
        "stress_url_coverage": (
            sum(1 for path in requested_paths if path.startswith("/stress/")) / stress_urls
            if stress_urls else 1.0
        ),
        "known_api_coverage": len(requested_paths & known_api_paths) / len(known_api_paths),
        "known_page_coverage": len(requested_paths & known_page_paths) / len(known_page_paths),
        "responses_per_second": fixture_requests / max(elapsed, 1e-9),
        "unique_pages_per_second": fixture_pages / max(elapsed, 1e-9),
        "2xx_per_second": fixture_success / max(elapsed, 1e-9),
        "rss_peak_kib": peak_rss,
        "rss_start_kib": rss_start,
        "rss_increment_kib": max(0, peak_rss - rss_start),
        "rss_peak_kib_per_10k_urls": peak_rss * 10_000 / max(1, fixture_pages),
        "rss_increment_kib_per_10k_urls": (
            max(0, peak_rss - rss_start) * 10_000 / max(1, fixture_pages)
        ),
        "frontier_peak_capacity": worker_result.get("frontier_peak_capacity", 0),
        "queue_ram_limit": worker_result.get("queue_ram_limit", 128),
        "headless_rendering": headless,
        "fixture_method_counts": state.method_snapshot(),
        "fixture_post_requests_sent": state.method_snapshot().get("POST", 0),
        "schema_version_rows": len(rows),
    })
    metrics.update(fixture_request_metrics(state))
    return metrics, fixture_requests


def katana_run(binary: str, origin: str, output: Path, pages: int, state: FixtureState,
               stress_urls: int = 0, *, headless: bool = False) -> dict:
    command = [binary, "-u", origin + "/", "-d", "3", "-c", "20", "-p", "1",
               "-rl", "200", "-kf", "robotstxt", "-jc", "-jsl",
               "-fx", "-ndef", "-mdp", str(pages),
               "-j", "-silent", "-nc", "-duc", "-duf", "-or", "-ob",
               "-o", str(output)]
    if headless:
        command.extend(["-hl", "-xhr"])
    started = time.perf_counter()
    katana_home = output.parent / f"{output.stem}-home"
    katana_home.mkdir(parents=True, exist_ok=True)
    katana_env = os.environ.copy()
    # Katana initializes its default per-user config even in non-interactive
    # runs. Isolate that write inside this temporary benchmark workspace.
    katana_env["HOME"] = str(katana_home)
    katana_env["XDG_CONFIG_HOME"] = str(katana_home / ".config")
    katana_env["XDG_DATA_HOME"] = str(katana_home / ".local" / "share")
    katana_env["XDG_CACHE_HOME"] = str(katana_home / ".cache")
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=katana_env)
    # Katana exposes no readiness event; an immediate RSS sample is often
    # taken during Go startup, so compare absolute peak RSS only.
    peak_rss = max(current_rss_kib(process.pid), high_water_rss_kib(process.pid))
    timeout_seconds = max(60, min(1800, int(pages / 20) + 60))
    while process.poll() is None:
        if time.perf_counter() - started > timeout_seconds:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            return {"error": f"Katana exceeded {timeout_seconds}s fixture timeout", "elapsed_seconds": time.perf_counter() - started}
        peak_rss = max(peak_rss, current_rss_kib(process.pid), high_water_rss_kib(process.pid))
        time.sleep(0.01)
    elapsed = time.perf_counter() - started
    diagnostic = process.stderr.read() if process.stderr else ""
    fixture_requests, fixture_success, requested_paths = state.snapshot()
    fixture_pages = len(requested_paths)
    if process.returncode != 0:
        return {"error": f"Katana exited with status {process.returncode}", "elapsed_seconds": elapsed}
    rows = []
    if output.exists():
        for line in output.read_text(errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    urls = {row_url(row) for row in rows if row_url(row)}
    api_truth = {f"/api/item/{i:03d}" for i in range(100)}
    pages_truth = {
        f"/pages/{kind}/{index:03d}"
        for kind in ("login", "error", "listing", "form") for index in range(50)
    }
    js_api_truth = {"/api/js-endpoint", "/api/map-endpoint", "/api/module-endpoint"}
    row_paths = {urlsplit(url).path for url in urls}
    return {
        "urls_seen": fixture_pages,
        "stress_urls_expected": stress_urls,
        "stress_urls_seen": sum(1 for path in requested_paths if path.startswith("/stress/")),
        "stress_url_coverage": (
            sum(1 for path in requested_paths if path.startswith("/stress/")) / stress_urls
            if stress_urls else 1.0
        ),
        "jsonl_unique_urls": len(urls),
        "jsonl_rows": len(rows),
        "known_api_coverage": len(requested_paths & api_truth) / len(api_truth),
        "jsonl_known_api_coverage": len({urlsplit(url).path for url in urls} & api_truth) / len(api_truth),
        "jsonl_api_path_examples": sorted(
            urlsplit(url).path for url in urls if "/api/item/" in urlsplit(url).path
        )[:5],
        "known_page_coverage": len(requested_paths & pages_truth) / len(pages_truth),
        "known_js_endpoint_request_coverage": len(requested_paths & js_api_truth) / len(js_api_truth),
        "known_js_endpoint_jsonl_coverage": len(row_paths & js_api_truth) / len(js_api_truth),
        "module_script_request_coverage": float("/assets/chunk.js" in requested_paths),
        "runtime_endpoint_capture_coverage": len({urlsplit(url).path for url in urls} & {
            "/api/runtime-fetch", "/api/runtime-xhr", "/api/runtime-post"
        }) / 3,
        "elapsed_seconds": elapsed,
        "fixture_http_responses": fixture_requests,
        "fixture_pages_requested": fixture_pages,
        "headless_rendering": headless,
        "fixture_method_counts": state.method_snapshot(),
        "fixture_post_requests_sent": state.method_snapshot().get("POST", 0),
        "responses_per_second": fixture_requests / max(elapsed, 1e-9),
        "unique_pages_per_second": fixture_pages / max(elapsed, 1e-9),
        "2xx_per_second": fixture_success / max(elapsed, 1e-9),
        "rss_peak_kib": peak_rss,
        "rss_peak_kib_per_10k_urls": peak_rss * 10_000 / max(1, fixture_pages),
        "diagnostic": diagnostic[-1200:] if fixture_requests == 0 else "",
        **fixture_request_metrics(state),
    }


def summarize(runs: list[dict]) -> dict:
    keys = sorted({
        key for run in runs for key, value in run.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    })
    result = {}
    for key in keys:
        values = sorted(
            run[key] for run in runs
            if isinstance(run.get(key), (int, float)) and not isinstance(run.get(key), bool)
        )
        if values:
            p95_index = max(0, math.ceil(0.95 * len(values)) - 1)
            result[key] = {"median": statistics.median(values), "p95": values[p95_index]}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--pages", type=int, default=2000,
                        help="Maximum pages; use at least stress-urls + 1000 to avoid capping the labeled fixture.")
    parser.add_argument("--stress-urls", type=int, default=0,
                        help="Add this many labeled unique 404 endpoints to the fixture for bounded-memory stress runs.")
    parser.add_argument("--include-headless", action="store_true",
                        help="Also run optional browser mode; may be slow or fail if Katana/Chrome does not exit cleanly.")
    parser.add_argument("--output", default="output/benchmarks/katana-comparison.json")
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or args.pages < 1 or args.stress_urls < 0:
        parser.error("--runs/--pages precisam ser positivos; --warmups/--stress-urls não podem ser negativos")
    state = FixtureState()
    server = make_server(state, args.stress_urls)
    katana = shutil.which("katana")
    raven_runs: list[dict] = []
    raven_headless_runs: list[dict] = []
    katana_runs: list[dict] = []
    katana_headless_runs: list[dict] = []
    katana_version = "unknown"
    with tempfile.TemporaryDirectory(prefix="raveneye-katana-bench-") as temporary:
        temp = Path(temporary)
        for index in range(args.runs + args.warmups):
            # Warm-up runs are explicit and may be disabled for expensive stress fixtures.
            state.reset()
            raven_result, _ = raveneye_run(
                server.origin, temp / f"raven-{index}.jsonl", args.pages, state, args.stress_urls,
            )
            if index >= args.warmups:
                raven_runs.append(raven_result)
            state.reset()
            if args.include_headless:
                raven_headless_result, _ = raveneye_run(
                    server.origin, temp / f"raven-headless-{index}.jsonl", args.pages,
                    state, args.stress_urls, headless=True,
                )
                if index >= args.warmups:
                    raven_headless_runs.append(raven_headless_result)
            if katana:
                state.reset()
                kata_result = katana_run(katana, server.origin, temp / f"katana-{index}.jsonl", args.pages, state, args.stress_urls)
                if index >= args.warmups:
                    katana_runs.append(kata_result)
                if args.include_headless:
                    state.reset()
                    kata_headless_result = katana_run(
                        katana, server.origin, temp / f"katana-headless-{index}.jsonl",
                        args.pages, state, args.stress_urls, headless=True,
                    )
                    if index >= args.warmups:
                        katana_headless_runs.append(kata_headless_result)
        if katana:
            version_home = temp / "katana-version-home"
            version_home.mkdir(parents=True, exist_ok=True)
            version_env = os.environ.copy()
            version_env["HOME"] = str(version_home)
            version_env["XDG_CONFIG_HOME"] = str(version_home / ".config")
            version_env["XDG_DATA_HOME"] = str(version_home / ".local" / "share")
            version_env["XDG_CACHE_HOME"] = str(version_home / ".cache")
            version_result = subprocess.run([katana, "-version"], capture_output=True, text=True, env=version_env)
            version_match = re.search(r"Current version:\s*(v\S+)", version_result.stdout + version_result.stderr)
            if version_match:
                katana_version = version_match.group(1)
    server.shutdown()
    report = {
        "environment": {
            "os": platform.system(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "fixture": {"origin": server.origin, "labeled_pages": 200, "known_endpoints": 100,
                    "known_javascript_endpoints": 3, "runtime_only_endpoints": 3,
                    "runtime_post_is_local_and_state_free": True,
                    "module_imports": 1, "duplicate_pairs": 100,
                    "stress_urls": args.stress_urls,
                    "categories": ["login", "error", "listing", "form"], "private_network_access": "exact loopback IP:port only"},
        "settings": {"runs": args.runs, "warmups": args.warmups, "depth": 3, "max_pages": args.pages,
                     "rps": 200, "global_concurrency": 20,
                     "process_isolation": "Both crawlers run in separate processes; fixture server remains in parent.",
                     "rss_method": "Peak RSS divided by requested unique URLs and scaled to 10,000 is an absolute normalized process cost, not marginal growth. On small fixtures the fixed process baseline dominates; use a >=10k-URL stress fixture for memory comparisons. Incremental RSS is reported only for RavenEye, whose worker emits an initialized-process readiness baseline.",
                     "katana_static_controls": ["-c 20", "-rl 200", f"-mdp {args.pages}", "-d 3", "-jc", "-jsl (deeper JS parser)", "-fx", "-ndef (allow static JS resources)", "-j", "-or", "-ob", "-duf (disable response-body dedup so endpoint coverage is comparable)"],
                     "katana_headless_controls": ["-hl", "-xhr", "-c 20", "-rl 200", f"-mdp {args.pages}", "-d 3", "-jc", "-jsl", "-j", "-or", "-ob", "-duf"]},
        "raveneye": {"median_p95": summarize(raven_runs), "runs": raven_runs},
        "headless_included": args.include_headless,
        "raveneye_headless": ({"median_p95": summarize(raven_headless_runs), "runs": raven_headless_runs}
                               if args.include_headless else {"skipped": "pass --include-headless to run browser mode"}),
        "katana": ({"median_p95": summarize(katana_runs), "runs": katana_runs,
                    "version": katana_version}
                   if katana else {"error": "Katana binary not installed or unavailable on PATH"}),
        "katana_headless": ({"median_p95": summarize(katana_headless_runs), "runs": katana_headless_runs,
                             "version": katana_version}
                            if katana and args.include_headless else
                            {"skipped": "pass --include-headless to run browser mode", "version": katana_version}
                            if katana else
                            {"error": "Katana binary not installed or unavailable on PATH"}),
    }
    if katana and "median_p95" in report["raveneye"] and "median_p95" in report["katana"]:
        raven_medians = report["raveneye"]["median_p95"]
        katana_medians = report["katana"]["median_p95"]
        comparisons = {}
        for metric in ("unique_pages_per_second", "known_api_coverage", "known_page_coverage",
                       "known_js_endpoint_request_coverage", "known_js_endpoint_jsonl_coverage",
                       "runtime_endpoint_capture_coverage",
                       "module_script_request_coverage", "stress_url_coverage",
                       "rss_peak_kib_per_10k_urls"):
            raven_value = raven_medians.get(metric, {}).get("median")
            katana_value = katana_medians.get(metric, {}).get("median")
            if raven_value is not None and katana_value is not None:
                comparisons[metric] = {
                    "raveneye_median": raven_value,
                    "katana_median": katana_value,
                    "ratio_raveneye_over_katana": raven_value / katana_value if katana_value else None,
                }
        raven_api_values = [run["jsonl_known_api_coverage"] for run in raven_runs
                            if "jsonl_known_api_coverage" in run]
        katana_api_values = [run["jsonl_known_api_coverage"] for run in katana_runs
                             if "jsonl_known_api_coverage" in run]
        if raven_api_values and katana_api_values:
            comparisons["jsonl_known_api_coverage"] = {
                "raveneye_median": statistics.median(raven_api_values),
                "katana_median": statistics.median(katana_api_values),
            }
        report["comparison"] = comparisons
    if (katana and args.include_headless and "median_p95" in report["raveneye_headless"]
            and "median_p95" in report["katana_headless"]):
        raven_medians = report["raveneye_headless"]["median_p95"]
        katana_medians = report["katana_headless"]["median_p95"]
        report["comparison_headless"] = {
            metric: {
                "raveneye_median": raven_medians[metric]["median"],
                "katana_median": katana_medians[metric]["median"],
                "ratio_raveneye_over_katana": (
                    raven_medians[metric]["median"] / katana_medians[metric]["median"]
                    if katana_medians[metric]["median"] else None
                ),
            }
            for metric in ("unique_pages_per_second", "known_api_coverage", "known_page_coverage",
                           "runtime_endpoint_capture_coverage", "module_script_request_coverage",
                           "rss_peak_kib_per_10k_urls")
            if metric in raven_medians and metric in katana_medians
        }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Saved: {output}")


if __name__ == "__main__":
    main()

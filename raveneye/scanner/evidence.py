"""Structured, privacy-preserving evidence for scanner findings.

Only hashes and response metadata are serialized. Request URLs, response bodies,
cookies, and probe values are never copied into this evidence record.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

STAGES = frozenset({"POSSIBLE", "PROBABLE", "CONFIRMED"})
_BASE_SCORE = {"POSSIBLE": 20, "PROBABLE": 50, "CONFIRMED": 75}
_FACTOR_WEIGHT = {
    "direct_observation": 15,
    "baseline_compared": 10,
    "differential_signal": 15,
    "unique_marker": 10,
    "repeatable": 10,
    "high_quality_fingerprint": 5,
    "heuristic_only": -10,
    "lexical_only": -15,
    "unresolved_context": -10,
    "partial_response": -5,
}


def sanitize_url(url: str) -> str:
    """Keep endpoint and parameter names while removing query values/userinfo."""
    try:
        p = urlsplit(str(url))
        if not p.scheme or not p.hostname:
            return ""
        host = p.hostname.lower()
        authority_host = f"[{host}]" if ":" in host else host
        port = p.port
        netloc = authority_host if port is None else f"{authority_host}:{port}"
        query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(p.query, keep_blank_values=True)])
        return urlunsplit((p.scheme.lower(), netloc, p.path or "/", query, ""))
    except (TypeError, ValueError):
        return ""


def request_sha256(method: str, url: str) -> str:
    raw = f"{str(method).upper()}\n{str(url)}".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()


def response_sha256(status: int | None, headers, body: str) -> str:
    normalized = {
        str(k).lower(): str(v)
        for k, v in (headers or {}).items()
    }
    raw = json.dumps(
        {"status": status, "headers": sorted(normalized.items()), "body": str(body)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()


def body_sha256(body: str) -> str:
    return hashlib.sha256(str(body).encode("utf-8", "replace")).hexdigest()


def stage_for_finding(finding_id: str, *, default: str = "POSSIBLE") -> str:
    """Conservative policy: confirm only directly observable configuration facts."""
    key = str(finding_id or "").lower()
    if key in {
        "headers.csp", "headers.xcto", "tls.hsts", "headers.referrer-policy",
        "csp-missing", "security header ausente", "headers-security",
        "headers_security", "ssl_tls",
        "cookie.prefix-secure", "cookie.prefix-host",
        "cookie.samesite-none-secure",
        "cors.invalid-credentialed-wildcard",
    }:
        return "CONFIRMED"
    if key in {"sqli.error-differential", "server-error-detail-confirmed"}:
        return "PROBABLE"
    if key.startswith("cve.") or "cve" in key or key == "vulnerable_components":
        return "POSSIBLE"
    if key in {
        "directory-listing", "server-disclosure", "x-powered-by-disclosure",
        "directory_listing", "open_redirect", "cors", "information_disclosure",
    }:
        return "PROBABLE"
    if key in {"potential-secret-disclosure", "possible-secret-disclosure"}:
        return "POSSIBLE"
    return default if default in STAGES else "POSSIBLE"


def score_finding(stage: str, factors: dict | None = None) -> tuple[int, dict[str, int]]:
    """Return a deterministic evidence-strength score, not a probability."""
    stage = stage if stage in STAGES else "POSSIBLE"
    applied: dict[str, int] = {}
    for name, enabled in (factors or {}).items():
        if enabled and name in _FACTOR_WEIGHT:
            applied[name] = _FACTOR_WEIGHT[name]
    score = max(0, min(100, _BASE_SCORE[stage] + sum(applied.values())))
    return score, applied


def make_evidence(
    *,
    method: str,
    url: str,
    status: int | None,
    headers,
    body: str,
    source: str,
    stage: str,
    factors: dict | None = None,
    baseline: dict | None = None,
    truncated: bool = False,
) -> dict:
    """Build serializable evidence without retaining raw HTTP data."""
    stage = stage if stage in STAGES else "POSSIBLE"
    score, applied = score_finding(stage, factors)
    current_body_hash = body_sha256(body)
    current_response_hash = response_sha256(status, headers, body)
    if baseline is None:
        baseline_record = {
            "status": status,
            "body_sha256": current_body_hash,
            "response_sha256": current_response_hash,
            "body_length": len(str(body).encode("utf-8", "replace")),
        }
        delta = {"compared": False}
    else:
        baseline_body = str(baseline.get("body", ""))
        baseline_status = baseline.get("status")
        baseline_headers = baseline.get("headers", {})
        baseline_record = {
            "status": baseline_status,
            "body_sha256": body_sha256(baseline_body),
            "response_sha256": response_sha256(baseline_status, baseline_headers, baseline_body),
            "body_length": len(baseline_body.encode("utf-8", "replace")),
        }
        delta = {
            "compared": True,
            "status_changed": baseline_status != status,
            "body_hash_changed": baseline_record["body_sha256"] != current_body_hash,
            "body_length_delta": len(str(body).encode("utf-8", "replace")) - baseline_record["body_length"],
        }
    return {
        "schema_version": "1.0",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "source": str(source),
        "request": {"method": str(method).upper(), "sha256": request_sha256(method, url)},
        "response": {
            "status": status,
            "body_length": len(str(body).encode("utf-8", "replace")),
            "body_sha256": current_body_hash,
            "sha256": current_response_hash,
            "truncated": bool(truncated),
        },
        "baseline": baseline_record,
        "delta": delta,
        "stage": stage,
        "confidence_score": score,
        "score_factors": applied,
        "score_note": "Força da evidência observada; não é probabilidade estatística.",
    }

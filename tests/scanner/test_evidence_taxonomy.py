from datetime import datetime

from raveneye.scanner.evidence import make_evidence, sanitize_url, score_finding, stage_for_finding
from raveneye.scanner.fingerprint import fingerprint


def test_query_values_are_redacted_without_losing_parameter_names():
    assert sanitize_url("https://example.test/search?q=secret&token=abc#frag") == (
        "https://example.test/search?q=%5Bredacted%5D&token=%5Bredacted%5D"
    )


def test_url_sanitizer_drops_userinfo_and_preserves_nondefault_port():
    assert sanitize_url("https://scanner:secret@example.test:8443/path?token=private") == (
        "https://example.test:8443/path?token=%5Bredacted%5D"
    )


def test_evidence_metadata_contains_hashes_and_differential_but_no_body():
    baseline = {"status": 200, "headers": {"content-type": "text/plain"}, "body": "baseline"}
    result = make_evidence(
        method="GET",
        url="https://example.test/search?q=probe-secret",
        status=500,
        headers={"content-type": "text/plain", "set-cookie": "sid=secret-value"},
        body="database parser error",
        source="active-safe:test",
        stage="PROBABLE",
        factors={"baseline_compared": True, "differential_signal": True},
        baseline=baseline,
    )

    assert len(result["request"]["sha256"]) == 64
    assert len(result["response"]["sha256"]) == 64
    assert result["delta"] == {
        "compared": True,
        "status_changed": True,
        "body_hash_changed": True,
        "body_length_delta": 13,
    }
    assert result["stage"] == "PROBABLE"
    assert 0 <= result["confidence_score"] <= 100
    assert "probe-secret" not in repr(result)
    assert "secret-value" not in repr(result)
    assert "database parser error" not in repr(result)
    datetime.fromisoformat(result["observed_at"])


def test_banner_fingerprint_is_not_high_confidence_proof():
    observed = fingerprint({"Server": "nginx/1.24.0"})
    nginx = next(row for row in observed if row["name"].lower() == "nginx")
    assert nginx["version"] == "1.24.0"
    assert nginx["confidence"] == "MEDIUM"


def test_stage_and_score_are_explicit_and_deterministic():
    assert stage_for_finding("xss.reflection") == "POSSIBLE"
    assert stage_for_finding("cve.local-correlation.CVE-2024-0001") == "POSSIBLE"
    assert stage_for_finding("cookie_security") == "POSSIBLE"
    first = score_finding("POSSIBLE", {"unique_marker": True, "heuristic_only": True})
    assert first == score_finding("POSSIBLE", {"unique_marker": True, "heuristic_only": True})

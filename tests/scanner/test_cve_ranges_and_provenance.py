from raveneye.scanner.cve_correlator import (
    correlate_exact,
    correlate_technologies,
    records_from_nvd_json,
    version_matches,
)


def test_nvd_inclusive_and_exclusive_version_bounds():
    record = {
        "version_start_including": "1.2.0",
        "version_end_excluding": "1.4.0",
    }
    assert version_matches("1.2.0", record)
    assert version_matches("1.3.9", record)
    assert not version_matches("1.1.9", record)
    assert not version_matches("1.4.0", record)


def test_nvd_normalizer_preserves_range_vendor_and_context():
    data = {
        "version": "2.0",
        "timestamp": "2026-10-01T00:00:00.000",
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "test"}],
                "configurations": [{
                    "nodes": [{
                        "operator": "AND",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.2.0",
                            "versionEndExcluding": "1.4.0",
                        }],
                    }]
                }],
            }
        }],
    }
    row = records_from_nvd_json(data)[0]
    assert row["vendor"] == "acme"
    assert row["version_start_including"] == "1.2.0"
    assert row["version_end_excluding"] == "1.4.0"
    assert row["context_required"] is True


def test_banner_to_cve_correlation_never_confirms_deployment():
    record = {
        "vendor": "acme",
        "product": "widget",
        "version": "*",
        "version_start_including": "1.2.0",
        "version_end_excluding": "1.4.0",
        "cve": "CVE-2024-1234",
        "vulnerable": True,
        "context_required": False,
    }
    tech = [{"name": "widget", "version": "1.3.0", "confidence": "MEDIUM", "source": "header:server"}]
    results = correlate_technologies(
        tech, [record], url="https://example.test/", source_metadata={
            "source": "NVD", "schema_version": "NVD-2.0", "retrieved_at": "2026-10-01",
            "sha256": "a" * 64,
        }
    )
    assert results[0]["stage"] == "POSSIBLE"
    assert results[0]["confidence"] == "LOW"
    assert results[0]["cve_source"] == "NVD"
    assert results[0]["cve_dataset_sha256"] == "a" * 64


def test_banner_correlation_skips_unresolved_nvd_boolean_context():
    record = {
        "vendor": "acme", "product": "widget", "version": "*",
        "version_start_including": "1.2.0", "version_end_excluding": "1.4.0",
        "cve": "CVE-2024-1234", "vulnerable": True, "context_required": True,
    }
    tech = [{"name": "widget", "version": "1.3.0", "confidence": "MEDIUM", "source": "header:server"}]
    assert correlate_technologies(tech, [record], url="https://example.test/") == []


def test_legacy_exact_correlator_refuses_versions_outside_range():
    rows = [{
        "product": "widget",
        "version": "*",
        "version_start_excluding": "1.2.0",
        "version_end_including": "1.3.0",
        "cve": "CVE-2024-1111",
    }]
    assert [x.cve for x in correlate_exact("widget", "1.3.0", rows)] == ["CVE-2024-1111"]
    assert correlate_exact("widget", "1.2.0", rows) == []

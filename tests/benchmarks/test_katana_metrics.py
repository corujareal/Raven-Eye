from collections import Counter

from benchmarks.katana_comparison import (
    FixtureState,
    fixture_body,
    fixture_request_metrics,
    metric_scores,
    summarize,
)


def test_comparison_fixture_declares_its_es_module_script_correctly():
    status, content_type, body = fixture_body("/", "http://127.0.0.1:12345")

    assert status == 200
    assert content_type.startswith("text/html")
    assert b"<script type='module' src='/assets/app.js'>" in body


def test_comparison_metrics_read_nested_katana_request_endpoint_schema():
    origin = "http://127.0.0.1:12345"
    rows = [
        {"request": {"endpoint": f"{origin}/api/item/{index:03d}"}}
        for index in range(100)
    ]
    rows += [
        {"request": {"endpoint": f"{origin}/pages/login/{index:03d}"}, "type": "login"}
        for index in range(50)
    ]

    metrics = metric_scores(rows, origin)

    assert metrics["jsonl_unique_urls"] == 150
    assert metrics["jsonl_known_api_coverage"] == 1.0
    assert metrics["jsonl_api_path_examples"] == [
        "/api/item/000", "/api/item/001", "/api/item/002", "/api/item/003", "/api/item/004",
    ]
    assert metrics["page_class_metrics"]["login"]["recall"] == 1.0


def test_404_fixture_routes_are_labeled_and_unexpected_error_classification_is_auditable():
    origin = "http://127.0.0.1:12345"
    rows = [
        {"url": f"{origin}/openapi.json", "type": "error"},
        {"url": f"{origin}/unexpected", "type": "error"},
    ]

    metrics = metric_scores(rows, origin)

    assert metrics["page_class_metrics"]["error"]["precision"] == 0.5
    assert metrics["page_class_metrics"]["error"]["false_positive_examples"] == [
        f"{origin}/unexpected",
    ]


def test_benchmark_summary_uses_available_samples_and_excludes_boolean_flags():
    summary = summarize([
        {"pages_per_second": 10.0, "headless_rendering": False},
        {"pages_per_second": 20.0, "headless_rendering": True},
        {"pages_per_second": 30.0},
    ])

    assert summary["pages_per_second"] == {"median": 20.0, "p95": 30.0}
    assert "headless_rendering" not in summary


def test_fixture_duplicate_request_metrics_explain_repeated_fetches():
    state = FixtureState()
    with state.lock:
        state.path_counts.update({"/": 2, "/page": 3, "/api": 1})
        state.path_status_counts.update({
            "/": Counter({200: 2}),
            "/page": Counter({500: 3}),
            "/api": Counter({200: 1}),
        })

    metrics = fixture_request_metrics(state)

    assert metrics["fixture_duplicate_requests"] == 3
    assert metrics["fixture_duplicate_request_paths"] == 2
    assert metrics["fixture_server_error_retry_requests"] == 2
    assert metrics["fixture_other_duplicate_requests"] == 1
    assert metrics["fixture_duplicate_request_examples"] == [
        {"path": "/page", "requests": 3, "statuses": {500: 3}, "classification": "server_error_retry"},
        {"path": "/", "requests": 2, "statuses": {200: 2}, "classification": "other_repeat"},
    ]

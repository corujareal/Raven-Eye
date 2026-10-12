import pytest

from raveneye.scanner.template_engine import TemplateEngine, TemplateValidationError, _validate_template


VALID = {
    "schema_version": "1.0",
    "id": "debug-marker",
    "info": {
        "name": "Debug marker",
        "severity": "medium",
        "confidence": "low",
        "stage": "POSSIBLE",
        "tags": ["passive"],
    },
    "matchers-condition": "and",
    "matchers": [
        {"type": "status", "status": [500]},
        {"type": "word", "words": ["Traceback"], "part": "body"},
    ],
}


def test_schema_v1_matches_a_collected_response_only():
    rule = _validate_template(dict(VALID))
    found = TemplateEngine().match(rule, "Traceback", {}, "https://example.test/", 500)
    assert found[0].stage == "POSSIBLE"
    assert found[0].confidence_score <= 100
    assert "Traceback" not in found[0].evidence


@pytest.mark.parametrize("mutate", [
    lambda data: data.update({"http": [{"method": "GET"}]}),
    lambda data: data.update({"id": "debug marker"}),
    lambda data: data.update({"matchers": []}),
    lambda data: data.update({"matchers": [{"type": "regex", "regex": ["("]}]}),
    lambda data: data.update({"matchers": [{"type": "word", "words": ["x"], "part": "raw"}]}),
    lambda data: data["info"].update({"stage": "CONFIRMED"}),
])
def test_schema_rejects_unknown_or_unsafe_fields(mutate):
    import copy

    candidate = copy.deepcopy(VALID)
    mutate(candidate)
    with pytest.raises(TemplateValidationError):
        _validate_template(candidate)


def test_yaml_duplicate_id_and_duplicate_keys_are_reported(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "schema_version: '1.0'\nid: dup\nid: other\ninfo: {name: x}\nmatchers: [{type: word, words: [x]}]\n",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        "schema_version: '1.0'\nid: dup\ninfo: {name: x}\nmatchers: [{type: word, words: [x]}]\n",
        encoding="utf-8",
    )
    (tmp_path / "c.yaml").write_text(
        "schema_version: '1.0'\nid: dup\ninfo: {name: x}\nmatchers: [{type: word, words: [y]}]\n",
        encoding="utf-8",
    )
    engine = TemplateEngine(tmp_path)
    loaded = engine.load()
    assert len(loaded) == 1
    assert loaded[0]["id"] == "dup"
    assert len(engine.errors) == 2


def test_extractors_redact_secret_values():
    rule = {
        **VALID,
        "matchers-condition": "or",
        "matchers": [{"type": "word", "words": ["token="]}],
        "extractors": [{"type": "regex", "regex": [r"token=([A-Za-z0-9_-]+)"]}],
    }
    found = TemplateEngine().match(rule, "token=secretvalue123", {}, "https://example.test", 200)
    assert found
    assert "secretvalue123" not in found[0].evidence
    assert "redacted" in found[0].evidence

from types import SimpleNamespace

import pytest

from raveneye_pkg.vuln_scanner import RavenVulnScanner


@pytest.mark.parametrize(
    ("form_markup", "meta_markup", "expected_candidate"),
    [
        ('<input name="title">', "", True),
        ('<input type="hidden" name="__RequestVerificationToken" value="v">', "", False),
        ('<input type="hidden" name="_token" value="v">', "", False),
        ('<input type="hidden" name="nonce" value="v">', "", False),
        ('<input name="title">', '<meta name="csrf-token" content="v">', False),
        ('<input name="title">', '<meta name="csrf-param" content="authenticity_token">', True),
        ('<input type="hidden" name="remember_token" value="v">', "", True),
    ],
)
def test_csrf_form_fixture_classification(form_markup, meta_markup, expected_candidate, monkeypatch):
    scanner = RavenVulnScanner("https://fixture.test/", active=False)
    body = (
        "<html><head>" + meta_markup + "</head><body>"
        f'<form method="post" action="/update">{form_markup}</form>'
        "</body></html>"
    )
    response = SimpleNamespace(
        headers={"Content-Type": "text/html; charset=utf-8"},
        text=body,
    )
    monkeypatch.setattr(scanner, "_request", lambda _url: response)

    scanner._check_csrf()

    findings = [item for item in scanner.findings if item.category == "csrf"]
    assert bool(findings) is expected_candidate
    if findings:
        assert findings[0].severity == "BAIXO"
        assert findings[0].confidence == "LOW"
        assert findings[0].stage == "POSSIBLE"

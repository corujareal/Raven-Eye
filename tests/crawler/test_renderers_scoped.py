from raveneye.crawler.filters import Scope
from raveneye.crawler.renderers import (
    ScopedPlaywrightRenderer,
    _render_method_is_safe,
    looks_like_spa,
)


def test_spa_detection_uses_shell_signals_instead_of_vendor_names():
    assert looks_like_spa("<main id='root'></main>")
    assert looks_like_spa("<app-root></app-root>")
    assert looks_like_spa('<div id="app"></div>')
    assert not looks_like_spa('<div id="app">' + "visible content " * 30 + "</div>")
    assert not looks_like_spa("<title>Built with Vite</title><p>ordinary server page</p>")
    assert not looks_like_spa("<main id='root'></main>" + "x" * 200_000)


def test_headless_scope_checks_host_path_regex_and_exclusions_for_websockets():
    scope = Scope(
        domains={"example.test"},
        paths=["/app"],
        excludes={"/app/private/*"},
    )
    renderer = ScopedPlaywrightRenderer(scope)

    assert renderer._allows("https://example.test/app/home")
    assert not renderer._allows("https://example.test/application/home")
    assert renderer._allows("wss://example.test/app/socket")
    assert not renderer._allows("https://example.test/private")
    assert not renderer._allows("wss://example.test/app/private/secret")
    assert not renderer._allows("https://outside.test/app/home")
    assert not renderer._allows("file:///etc/passwd")


def test_headless_blocks_state_changing_http_methods():
    assert _render_method_is_safe("GET")
    assert _render_method_is_safe("HEAD")
    for method in ("OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"):
        assert not _render_method_is_safe(method)

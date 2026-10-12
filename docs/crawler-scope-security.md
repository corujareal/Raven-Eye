# Crawler scope and DNS protections

This page records where the crawler accepts or rejects a request. It covers the
async engine and the legacy CLI crawler; it does not claim that every scanner
or third-party service in RavenEye has the same request path.

## Scope rules

- The async engine with no explicit domain scope pins the crawl to the exact
  host or hosts in the seed URLs. It does not expand to sibling subdomains.
- The legacy crawler also defaults to the exact seed host. Explicit domain
  rules use the shared matcher: `example.test` includes its subdomains, while
  `*.example.test` includes subdomains but not the apex.
- Both crawlers accept only HTTP(S) URLs without URL userinfo. The legacy
  `request_url()` applies that check before DNS resolution and again to every
  redirect.
- Links from HTML, JavaScript, module imports, workers, robots, sitemaps, and
  redirects are checked before they enter the request queue. The legacy
  crawler's baseline, parameter probes, JavaScript reads, and robots/sitemap
  preflight pass the same host and exclusion rules to `request_url()`.
- Configured path scopes match the exact path or descendants separated by `/`;
  `/api` includes `/api/v1` but not the sibling path `/apiary`.

## Redirects and DNS

- The async engine disables automatic redirects. A `Location` is treated as a
  discovered URL and must pass scope, robots, depth, page-count, SSRF, and DNS
  checks before a later request.
- The async engine follows up to five `robots.txt` redirects manually because
  robots rules apply to the original authority. Every hop must remain inside
  the configured scope and pass the same SSRF/DNS checks; an out-of-scope
  redirect or redirect loop fails closed for that origin.
- The legacy HTTP client follows redirects manually. Each destination must
  pass the same host/exclusion checks and a fresh safe-IP check; the validated
  address is pinned for the request.
- The async client validates all resolved addresses as public and pins the
  validated results in its resolver. A mixed public/private DNS response is
  rejected.
- Async Playwright rendering uses a loopback-only SOCKS proxy that enforces the
  host allowlist and resolves the destination itself. The async CLI rejects a
  configured external proxy instead of bypassing it; this browser path has no
  upstream proxy mode.

## Remaining proxy boundary

The legacy synchronous HTTP client can use a configured forward proxy. RavenEye
checks the requested URL and resolves it before sending the request, but an
HTTP proxy or `socks5h` proxy can resolve the target hostname on the proxy
server, outside RavenEye's DNS pin. Treat such a proxy as a trusted network
boundary. For strict DNS-rebinding protection, run without a forward proxy;
the crawler's built-in browser proxy is locally enforced. A later change can
make unsupported proxy types fail closed, but that would change the existing
proxy option's behavior and needs an explicit compatibility decision.

## Evidence

Scope checks for JavaScript imports and redirects are covered by
`tests/crawler/test_js_module_crawl.py`,
`tests/crawler/test_legacy_js_crawl.py`, and
`tests/security/test_browser_egress.py`. Direct legacy preflight, baseline, and
parameter-probe scope checks are covered by
`tests/security/test_crawler_scope_network.py`. Robots redirect handling,
including an out-of-scope destination and the five-hop cap, is covered by
`tests/crawler/test_robots_sitemap_jsonl.py`.

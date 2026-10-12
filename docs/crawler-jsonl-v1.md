# Crawler JSONL schema 1.0

The asynchronous crawler writes each completed page record as soon as the worker finishes it. Every row has `schema_version: "1.0"`. The forms sidecar uses the output filename stem, for example `crawl.jsonl` produces `crawl_forms.jsonl`; form records carry the same schema version.

The frontier normalizes scheme, hostname, default port, and fragment. It keeps
the query string verbatim: parameter order, repeated keys, and encoding can be
application data, so the crawler does not merge those URLs without evidence.

Page rows may include:

- `url`, `status`, `content_type`, `location`, `depth`, `truncated`, and `retries` for the HTTP result.
- `retry_deferred` and `retry_after_seconds` when a server asked the crawler to wait longer than the configured crawl deadline.
- `duplicate`, `type`, `discovered`, `forms_found`, `scripts`, and `websockets` for extracted content signals. `scripts` includes external HTML script references and bounded literal module or worker imports found in JavaScript. Imported URLs pass through the crawler's ordinary scope, robots, depth, and page-limit checks before a request is scheduled.
- Static JavaScript endpoint extraction tokenizes source before classifying URL literals, so commented code and code examples nested inside strings do not become requests. Inline executable scripts and external scripts use the same bounded parser; JSON script blocks and scripts inside `<template>` are ignored.
- `js_route_templates` records path-only observations for dynamic `fetch`, axios, XHR, and URL configuration literals, such as `/api/users/{param}`. Inline executable code, external scripts, and embedded `sourcesContent` use the same bounded parser. These are evidence for review only: RavenEye does not guess their runtime values, schedule the template, or retain query strings. The legacy CLI exposes the same templates in scan event logs and the PDF appendix.
- `robots_allow`, `robots_disallow`, `sitemaps`, or `robots_policy` for the preflight robots.txt response. Disallowed URLs are catalogued and not requested. `robots_redirects` and `robots_final_url` describe scoped redirects; the engine follows at most five and fails closed if a redirect leaves the configured scope.
- `telemetry` with cumulative counts and bounded latency samples.
- `rendered`, `rendered_url`, `render_status`, `render_error`, and `blocked_browser_requests` when optional headless rendering is used.
- `runtime_requests` for in-scope browser-observed XHR/fetch calls. Entries contain method, resource type, status, and URL with query values redacted; request bodies, cookies, and headers are not recorded. Only GET runtime URLs are scheduled for ordinary crawling. Other methods remain observations and are never replayed by RavenEye.
- `websockets` may include runtime-discovered URLs. WebSocket connections are mocked by the headless renderer and are not opened against the target.

These headless fields are additive to schema 1.0; rows produced without headless rendering retain their previous shape. The return value of `Crawler.crawl()` remains a list for existing Python callers. Files are still written incrementally. Pass `append_output=True` only when deliberately combining multiple target runs into one JSONL file.

## Retry behavior

Idempotent crawler GET requests retry timeouts and HTTP 408, 425, 429, 502,
503, and 504 responses, subject to the crawl deadline and configured attempt
limit. `Retry-After` is honored and shared across workers for the host; local
backoff is exponential with jitter and capped at 30 seconds. A generic 500 is
recorded and parsed on its first response because it does not establish that
the error is temporary, and its body can still contain useful links. This
avoids repeatedly fetching a stable application error page while preserving
retries for throttling and temporary gateway failures.

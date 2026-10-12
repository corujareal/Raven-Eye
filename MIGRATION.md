# RavenEye 6.6.6 — migration notes

This release line remains **6.6.6** and preserves the `I see you` identity.

## Completed architecture work
- Async HTTP session with centralized timeout, rate limiting, SSRF validation and scope enforcement.
- Scope DSL supports domains/wildcards, path prefixes, regular expressions and exclusions.
- Crawler pipeline includes HTML/form/API/WebSocket discovery, robots/sitemap/.well-known seeds, SimHash deduplication and JSONL output.
- Scanner uses safe, non-destructive checks for the requested vulnerability categories, OpenAPI/GraphQL analysis and technology fingerprinting.
- Reports provide TXT/JSON/HTML/CSV/Markdown output with risk scoring and evidence redaction.
- Async SQLite persistence uses `aiosqlite` for the core database path.
- Plugin discovery is available through the `raveneye.plugins` entry-point group.
- Logs are JSONL/SIEM-friendly and redact common credential/token fields.

## Safety boundary
The production-safe build deliberately does **not** automate password guessing/spraying,
credential stuffing, authentication bypass, exploit payload injection, destructive fuzzing,
or out-of-band exploit callbacks. The scanner reports evidence requiring authorized manual
validation instead. This keeps the platform suitable for controlled defensive assessment
while retaining clear extension points for separately governed integrations.

## Compatibility
The legacy `raveneye_pkg/` package remains in the archive and continues to back the
canonical `RavenEye.py` launcher (installed as the `raven` command). The old
`raveneye.py` compatibility shim (a one-line forwarder to `RavenEye.py`) was removed
during the installer cleanup — it added nothing beyond the real launcher and only
caused confusion between two near-identical filenames. New development belongs under
`raveneye/` and the Poetry entry points.

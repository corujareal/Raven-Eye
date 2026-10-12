# Scan event log schema 1.0

Each integrated scan writes `<base>_events.jsonl` next to its other report files.
The file is replaced atomically at completion and uses owner-only permissions
where POSIX file modes are available. Each line is one JSON object with:

- `schema_version`: `"1.0"`
- `timestamp`: UTC event time
- `event`: the event type
- `target`: target authority only; path and query are omitted
- `scan_id`: database scan ID when the caller provided one
- `data`: fields for that event

## Event types

- `scan.summary`: duration, crawl counts, findings by severity and evidence
  stage, URL-path heuristic counts, dork search counts, and API integration status.
- `crawl.summary`: request/error totals, JavaScript and endpoint counts, dynamic
  JavaScript route-template count, and up to 50 sanitized examples. Templates
  contain only paths, omit query values, and are explicitly marked as
  observations that were not requested.
- `surface.hint`: a path matched a legacy URL heuristic. It is explicitly
  unverified and is kept separate from vulnerability findings.
- `javascript.secret_hint`: a secret-like pattern was found in a JavaScript
  file. The event keeps its type, file URL, and severity, never the value.
- `vulnerability.confirmed`: scanner finding promoted to `CONFIRMED` by its
  evidence policy.
- `vulnerability.candidate`: `PROBABLE` or `POSSIBLE` finding. These remain
  explicitly separate from confirmed results.
- `search.summary`: provider and result counts from automated search.
- `search.response`: an in-scope, unique response returned by the selected
  search provider. It contains the sanitized title, URL, snippet, engine names,
  and classification signals.
- `integration.status`: compact status, HTTP code, and redacted message for an
  API integration.

Scanner events retain evidence timestamps, request/response hashes, response
status, and baseline deltas. They omit response bodies, request bodies, cookies,
headers, and query values. A search result never becomes a confirmed
vulnerability solely because an engine returned it.

The event log does not store generated dork strings. SearXNG requests use the
form body; only filtered responses and aggregate counts are retained. The local
instance can still forward a search query to its enabled external engines, so
this file describes RavenEye's storage behavior, not upstream engine retention.

`raven logs --watch <file>` renders these events as readable lines. The
interactive Leitor de Logs lists the per-scan JSONL files and formats each row
for reading. Category exports recognize `scanner`, `dorks`/`search`, `api`, and
`crawler`; PDF exports keep search, route hints, and integration events in
their own report sections instead of counting them as vulnerability findings.
PDF exports include observed JavaScript route templates in a separate appendix
and label them as not requested.
Older message-only JSONL files remain supported by the log viewer.

# RavenEye passive scanner templates — schema 1.0

Templates are local YAML rules over an HTTP response the scanner has already
collected. They do not create requests, inject values, execute code, call
out-of-band services, or read files. The supported dialect is intentionally
smaller than Nuclei's request-capable template DSL.

## Example

~~~yaml
schema_version: '1.0'
id: exposed-debug
info:
  name: Exposed Debug Indicator
  severity: medium
  confidence: low
  stage: POSSIBLE
  description: A debug signature appeared in a collected response.
  remediation: Disable public debug output and retain diagnostics in protected logs.
  tags: [exposure, passive]
  cwe: CWE-209
matchers-condition: and
matchers:
  - type: status
    status: [500]
  - type: word
    words: ['Traceback (most recent call last)']
    part: body
~~~

## Supported fields

- Root: schema_version (required, 1.0), id (required and unique), info
  (required), matchers (1–12 required), optional matchers-condition
  (and/or, default or), optional extractors (0–4).
- info: name (required), severity (CRITICAL, HIGH, MEDIUM, LOW, INFO),
  confidence (HIGH, MEDIUM, LOW, default LOW), stage (POSSIBLE or PROBABLE,
  default POSSIBLE), optional description, remediation, tags, cwe, cve, and
  references.
- Matchers: word, regex, or status. A matcher may set part to body, header, or
  all (default), condition to and/or (default or), and negative to a boolean.
  Each matcher accepts 1–12 values.
- Extractors: regex (1–4 patterns) or kval (1–8 keys). Extracted values pass
are never emitted as plaintext; the finding reports only their length and
SHA-256 digest.

The loader rejects unknown request/execution fields, duplicate YAML keys,
duplicate IDs, empty matchers, invalid types, and unsupported stages. Templates
cannot mark a vulnerability CONFIRMED; a response match alone does not meet
the scanner's confirmation criteria. File size is limited to 64 KiB, response
matching to 200 KiB, and regular expressions to 256 characters. Quantified
groups/alternations are rejected because Python's standard regex engine has no
execution timeout.

Every template rejection is returned in template_errors with filename and a
bounded diagnostic. A missing template directory means no local templates;
missing PyYAML raises an explicit dependency error instead of silently skipping
the rule set.

## Evidence and privacy

Findings include stage, an explainable 0–100 evidence-strength score, UTC
observation time, response/baseline hashes, status/length delta, and source.
These scores are not calibrated probabilities. Raw bodies, headers containing
secrets, query values, and probe values are not included in evidence metadata.

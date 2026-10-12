# Scanner quality notes

## Result stages and evidence

- `POSSIBLE` means a heuristic or a safe probe found a signal that needs review.
- `PROBABLE` requires repeatable differential evidence for the current SQL error check.
- `CONFIRMED` is reserved for directly observed configuration facts; the score is an
  evidence-strength score, not a statistical probability.
- Reports retain response hashes, timestamps, status, body length, and baseline deltas.
  They do not retain request bodies or query values.

The reflected-input check sends a unique benign canary and reports reflection only;
it does not claim that browser JavaScript execution was verified. The report keeps
the parameter name but redacts its value. This follows the test objective of
separately assessing reflection and the encoding applied on return, rather than
treating any reflected string as confirmed XSS ([OWASP WSTG, Reflected XSS](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/)).

## Changes in this iteration

- CSRF form review recognizes common hidden fields such as `_token` and
  `__RequestVerificationToken`, plus populated CSRF meta tokens used by
  JavaScript headers. A missing recognizable marker is now reported only as
  `BAIXO` / `LOW` / `POSSIBLE`; its absence does not prove a CSRF vulnerability.
  The labeled fixture also checks that `csrf-param` and unrelated
  `remember_token` names do not suppress the candidate.
- Debug disclosure detection no longer treats a framework name such as `Laravel`
  as a debug page by itself. It still recognizes stack traces and explicit debug
  settings.
- Private-address disclosure requires a valid IPv4 address in an RFC 1918 range;
  malformed values such as `192.168.999.999` are ignored.
- A PHP configuration page is reported only when the response has the exact
  `phpinfo()` title plus both the `PHP Version` and `Loaded Configuration File`
  table markers. The report stores a fixed description, not the configuration
  output.
- Passive SQL, command, traversal, and LDAP checks require specific parser/system
  error or file-content signatures. Framework names, tool names, `DOCTYPE`, generic
  path errors, and ordinary script tags no longer count by themselves.
- The DOM XSS candidate requires both a recognized browser input source and an HTML
  sink in the response. The check does not claim that data flows between them.
- Repeated signals for CSP absence, secret-like response data, and version-bearing
  server headers collapse when their endpoint and response hash are identical.
  The earlier, more conservative record is kept.
- Generic cookie flag omissions remain review candidates. A common session-like
  cookie name raises the signal to medium confidence; a generic name such as
  `analytics` stays informational/low confidence because the scanner cannot infer
  its contents. Exact `__Secure-`, `__Host-`, and `SameSite=None` attribute
  violations are confirmed configuration facts; evidence contains only the cookie
  ordinal and failed rule, never the cookie name or value.
- Directory-listing findings require both a generated index heading and a
  parent-directory link. A documentation page mentioning “Index of /” is not enough.
- Duplicate `X-Content-Type-Options` findings from two passive check paths collapse
  when they refer to the same response hash.
- A wildcard `Access-Control-Allow-Origin` paired with credentials is recorded as
  a low-severity configuration fact, not an exposure: browsers reject credentialed
  access for that combination. A plain wildcard without credentials remains an
  informational review candidate because public resources may intentionally use it.
- A seed URL is accepted with implicit target-host scope in both scanner paths.
  Explicit scope files continue to filter by their configured rules.
- CVE matches based on a remote fingerprint remain `POSSIBLE`. NVD applicability
  can depend on version ranges and boolean CPE context, while a banner cannot
  verify the deployed package, backports, or build; the report asks for inventory
  verification instead of presenting correlation as an affected installation.

OWASP describes debug exposure in terms of reachable debug pages, verbose errors,
stack traces, and exposed runtime settings, rather than framework names alone
([OWASP WSTG, Application Platform Configuration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/02-Application_Platform_Configuration/)).
Cookie-prefix constraints follow the browser rules documented for
[`Set-Cookie`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).
Credentialed CORS wildcard behavior follows the [MDN CORS guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS).
The scanner's conservative CPE handling follows [NVD applicability guidance](https://nvd.nist.gov/general/faq-sections/cpe-faqs).

## Fixture measurements and limits

`tests/scanner/test_passive_false_positive_fixtures.py` contains positive and
negative labeled examples for debug, private-IP, PHP configuration-page, and
directory-listing checks.
`tests/scanner/test_safe_category_signatures.py` does the same for SQL, command,
traversal, XXE, DOM XSS source/sink, and LDAP signals. Each check has precision 1.0
and recall 1.0 on its two-example fixture. These are regression checks, not
estimates of real-world accuracy; the fixtures are too small and synthetic to
support that claim.

Local scanner fixtures also verify that:

- the benign reflection canary is sent to the mock response handler but does not
  appear in serialized findings;
- query values are redacted from the finding URL;
- an unconfigured scope accepts the requested seed host;
- same-response aliases do not produce duplicate findings;
- generic cookie flag omissions remain review candidates, while exact prefix and
  `SameSite=None` violations are direct configuration observations;
- cookie values and names stay out of the new prefix finding evidence.
- CSRF fixtures cover unprotected forms, `_token`, ASP.NET request verification
  tokens, nonce fields, populated meta tokens, meta parameter names, and unrelated
  `remember_token` fields.

## Remaining measurement work

- Expand labeled fixtures for each vulnerability class, including safe and
  ambiguous pages, redirects, framework error variants, and API responses.
- Keep lexical indicators such as generic SQL/runtime error signatures at low
  confidence until a baseline and repeatable differential signal exist.
- Measure precision, recall, latency, and evidence strength against a larger
  labeled corpus before raising severity or adding more templates.
- Check that every scanner entry point asks for consent before any network request.

# Passive asset API integrations

RavenEye checks only providers with a configured key. Keys can come from the
application settings, exported environment variables, or the nearest `.env`
file. Environment variables take precedence:

- `CENSYS_API_KEY` (Personal Access Token); `CENSYS_ORGANIZATION_ID` is optional.
- `NETLAS_API_KEY`.
- `LEAKIX_API_KEY`.

The integrations make one bounded request per configured provider. They do not
follow redirects or retry rate-limited requests. Reports include only compact,
allowlisted metadata; raw banners, response bodies, leak contents, and API keys
are not retained.

## Statuses

| Status | Meaning |
| --- | --- |
| `authentication_failed` | The provider rejected the credential (HTTP 401). |
| `plan_limit` | The account plan or balance does not permit the request (HTTP 402). |
| `permission_denied` | The credential lacks access to the requested resource (HTTP 403). |
| `asset_not_found` | The provider has no record for the queried asset (HTTP 404). |
| `no_content` | The provider accepted the request but returned no response body (HTTP 204); no asset metadata is claimed. |
| `invalid_request` | The provider rejected the request parameters (HTTP 422). |
| `rate_limited` | The provider asked the client to slow down; RavenEye does not retry automatically. |
| `redirect_blocked` | The API attempted to redirect the request; RavenEye did not follow it. |

## Provider references

- [Censys Platform API: Get a host](https://docs.censys.com/reference/v3-globaldata-asset-host) accepts a Personal Access Token; the organization ID can be supplied in a header or query parameter and is optional for this endpoint.
- [Netlas API reference](https://docs.netlas.io/api-reference/) documents host lookup by IP or domain using a Bearer token.
- [LeakIX domain details](https://docs.leakix.net/docs/api/domain/) documents `GET /domain/:domain`, the `api-key` header, and its approximately one-request-per-second API limit.

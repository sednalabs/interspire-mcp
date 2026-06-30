# Interspire XML Compatibility Profile

This document records the XML API surface that `interspire-mcp` relies on. It
is a behavioural compatibility profile derived from observed Interspire XML
request and response behaviour.

The profile exists so the MCP router, live backend, fixtures, documentation,
and operator expectations stay aligned when Interspire versions differ.

## Envelope

All supported XML calls use this envelope shape:

```xml
<xmlrequest>
  <username>...</username>
  <usertoken>...</usertoken>
  <requesttype>...</requesttype>
  <requestmethod>...</requestmethod>
  <details>...</details>
</xmlrequest>
```

When a method does not need details, the MCP sends a non-empty whitespace body
inside `<details>`. Older Interspire builds can reject an empty details node.

## Officially Documented Baseline

Interspire's public XML API documentation describes a POST-only XML endpoint,
per-user XML enablement, an XML username/token pair, and the common
`SUCCESS`/`ERROR` response shape. It also documents contact/list methods that
are suitable for fixture coverage of the MCP's safe read surface:

- `authentication/xmlapitest` for token checks;
- `GetLists` samples and related list-summary response fields;
- `lists/GetCustomFields` for custom-field metadata;
- `subscribers/GetSubscribers` for bounded subscriber discovery;
- `subscribers/IsSubscriberOnList` for contact presence checks.

The public documentation also describes subscriber mutation methods. The MCP
does not expose those as operational tools; audience mutation remains outside
the current public write scope.

## Supported Read Methods

| Purpose | requesttype | requestmethod | details | MCP interpretation |
| --- | --- | --- | --- | --- |
| Auth probe | `authentication` | `XmlApiTest` | Blank details | Read-only proof that the XML username/token is accepted before list/contact methods are trusted. |
| List summary | `lists` | `GetLists` | Blank details | Source for list ids, names, and aggregate list counts. |
| Contact presence | `subscribers` | `IsSubscriberOnList` | `emailaddress`, `listid`, and legacy `listids` | Positive presence is strong list-presence evidence. Absence evidence is labelled by confidence and corroborated where send-readiness depends on it. |
| Audience hygiene export | `subscribers` | `GetSubscribers` | Top-level `listid` plus `searchinfo.List`, `Status=a`, `Confirmed=1`, and bounded email query | Candidate discovery for private hygiene artifacts, followed by separate suppression and eligibility gates before send decisions. |

## Candidate Write Methods

Some Interspire deployments may expose XML methods that look suitable for list
or newsletter scaffolding. The MCP does not treat those methods as operational
write tools just because they are present in a deployment.

Before any XML write candidate can be used, add a dedicated preview/apply/proof
contract, synthetic fixtures for the XML request and response shape, route and
permission negative tests, redaction checks, and live no-send proof on the
target Interspire version. Until then, write candidates are compatibility
research only.

## Response Fields Parsed

The MCP parses only the fields required for redacted operator tools:

- status and error message fields for API success/failure;
- list id, list name, owner id, and available aggregate counts from list
  summaries;
- subscriber id, email address, subscribe date, confirmation status,
  unsubscribe status, and bounce status from subscriber reads.

Outputs redact or aggregate these values according to the public tool contract,
with raw response handling reserved for private operator evidence.

## Version Notes

Interspire 8.x exposes list summary reads as `lists/GetLists`. The MCP uses
that request type for list summary evidence.

Interspire authenticates the XML username and token before dispatching the
requested method. An error such as `Unable to check user details` therefore
means the XML credentials, user XML API enablement, or XML API policy need
attention before the method-specific result can be trusted. The MCP classifies
these responses as `xml_auth_error` instead of treating them as ordinary list
or subscriber read failures.

Subscriber XML methods can have two parameter layers: a top-level field used by
access checks and legacy method parameters used by the underlying API call. The
MCP includes both forms only for reviewed read methods where compatibility
requires it.

## Fixture Policy

Tests use synthetic XML fixtures that preserve the field shape while keeping
recipient data, credentials, cookies, and source text out of the repository.

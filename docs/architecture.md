# Architecture

`interspire-6-mcp` is a curated stdio MCP server. It wraps legacy Interspire
Email Marketer 6.2.3 state in typed, redacted, operator-oriented tools.

## Shape

- Transport: stdio.
- Toolkit: `sednalabs/mcp-toolkit-rs`.
- Authority order: Interspire XML API first, authenticated admin HTML fallback
  only for explicitly allowlisted pages.
- Output: compact JSON strings shaped for MCP clients and agent workflows.
- Safety posture: read-only by default, with guarded queue cancel/delete plus
  guarded no-send campaign, list, user, and non-secret settings apply paths.

## Module Boundaries

| Module | Responsibility |
| --- | --- |
| `lib.rs` | MCP server, tool inventory, trait boundary, tool handlers. |
| `config.rs` | Environment and secret-file configuration without exposing values. |
| `live.rs` | Thin backend root that keeps the trait surface stable while delegating to domain modules. |
| `live/reads.rs` | Read-only backend handlers for status, list/contact readback, settings, queue stats, and campaign readback. |
| `live/guarded.rs` | Guarded queue-control and no-send form-write preview/apply handlers. |
| `live/audience.rs` | Warm-up readiness and audience-hygiene handler orchestration. |
| `live/support.rs` | Shared list caps, source-list filtering, and local helper utilities for the live backend. |
| `xml_api.rs` | Interspire XML API reads and XML parsing. |
| `admin_html.rs` | Authenticated admin HTML reads, queue-control extraction, and redacted parsing helpers. |
| `admin_html/forms.rs` | Guarded form snapshotting, allowlisted field updates, preview/apply plan binding, and field-scoped POST construction. |
| `safety.rs` | URL allowlists for read pages and guarded queue/form write routes. |
| `guarded_write.rs` | Shared plan-id and runtime enablement checks. |
| `audience_hygiene.rs` | Private audience artifact construction outside git. |
| `audience_hygiene_checkpoint.rs` | Checkpointed begin/resume/status flow for bounded audience export progress. |
| `response/common.rs` | Shared request/response contracts, fixtures, caps, and redacted error serialization. |
| `response/queue.rs` | Queue preview/apply request and report contracts. |
| `response/forms.rs` | Guarded campaign/list/user/settings write request and report contracts. |
| `response/audience.rs` | Warm-up readiness and audience-hygiene request/report contracts. |
| `response.rs` | Thin re-export module for the response contract tree. |
| `redact.rs` | Redaction helpers for emails, hosts, URLs, and secret-shaped text. |

## Source Authority

The XML API is preferred for list and subscriber evidence because it has a more
stable contract than legacy admin HTML. Admin HTML is used where the XML API is
missing important operational state:

- list owner and reply/bounce metadata;
- global email, bounce, and cron settings;
- user-level SMTP override state;
- campaign edit summaries;
- schedule and stats rows;
- queue-control preview/action links;
- persisted form state for guarded campaign, list, user, and settings edits.

The server does not treat provider delivery events, external validation results,
or private artifact exports as Interspire state. Those may be useful inputs for
separate workflows, but Interspire remains the source of list/campaign/contact
readback in this repository.

The checkpointed audience export flow is deliberately transport-local rather
than a generic background-task framework. It persists bounded progress under an
approved private output root, advances only a limited number of subscriber XML
queries per call, and lets operators resume safely after MCP/client timeouts.

## Contract Tests

The test suite protects both the MCP boundary and domain output:

- schema snapshot for exported tools;
- stdio runtime smoke test against the real binary;
- domain contract tests for redaction, caps, no-send flags, and output shape;
- parser tests for XML and HTML fixtures;
- safety tests for blocked admin paths and guarded queue/form routes.

Tool schema changes should be deliberate and reviewed. Use:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tool_schema_snapshot_contract_is_stable
```

Then inspect the JSON diff before committing.

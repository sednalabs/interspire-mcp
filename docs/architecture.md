# Architecture

`interspire-mcp` is a curated stdio MCP server. It wraps Interspire Email
Marketer state in typed, redacted, operator-oriented tools.

## Shape

- Transport: stdio.
- Toolkit: `sednalabs/mcp-toolkit-rs`.
- Authority order: Interspire XML API first, authenticated admin HTML fallback
  only for explicitly allowlisted pages.
- Output: compact JSON strings shaped for MCP clients and agent workflows.
- Safety posture: read-only by default, with guarded queue cancel/delete,
  guarded campaign, list, user, non-secret settings, semantic template, private
  artifact, and explicit guarded-send apply paths.
- No-mutation proof posture: selected admin wizard pages may be rendered for
  evidence without submitting a send. The final send form is available only to
  the separate guarded-send apply tools.
- Sensitive read posture: toolkit-owned metadata and policy preflight, with
  Interspire-owned target/field allowlists.

## Legacy Adapter Pattern

This repository is both a service implementation for Interspire Email Marketer
installs and a reference implementation of a careful admin-control-plane MCP
adapter. The useful pattern is not "scrape an admin UI"; it is to build a
narrow source-authority map over a split operational control plane:

- use the stable API first;
- reach authenticated admin HTML only where the API is incomplete;
- allowlist the exact admin pages, query shapes, actions, and fields that have
  a reviewed operator purpose;
- convert upstream state into redacted, typed, task-shaped MCP output;
- bind every mutation to preview/apply plan ids, runtime gates, and post-apply
  readback;
- treat unredacted setup values as explicit sensitive reads, not as ordinary
  readback;
- publish private recipient or validation artifacts only through private local
  files, with aggregate MCP evidence.

The generalized pattern lives in
[`mcp-toolkit-rs`](https://github.com/sednalabs/mcp-toolkit-rs/blob/main/docs/legacy-system-adapter-pattern.md).
Product-specific route allowlists, Interspire XML semantics, admin-form
parsers, and operator wording stay in this repository.

## Module Boundaries

| Module | Responsibility |
| --- | --- |
| `lib.rs` | MCP server, tool inventory, trait boundary, tool handlers. |
| `config.rs` | Environment and secret-file configuration without exposing values. |
| `live.rs` | Thin backend root that keeps the trait surface stable while delegating to domain modules. |
| `live/reads.rs` | Read-only backend handlers for status, list/contact readback, settings, queue stats, and campaign readback. |
| `live/guarded.rs` | Guarded queue-control and form-write preview/apply handlers. |
| `live/send.rs` | Guarded seed and production send apply handlers. |
| `live/audience.rs` | Warm-up readiness and audience-hygiene handler orchestration. |
| `live/support.rs` | Shared list caps, source-list filtering, and local helper utilities for the live backend. |
| `xml_api.rs` | Interspire XML API reads and XML parsing. |
| `admin_html.rs` | Authenticated admin HTML reads, queue-control extraction, and redacted parsing helpers. |
| `admin_html/forms.rs` | Guarded form snapshotting, allowlisted field updates, preview/apply plan binding, and field-scoped POST construction. |
| `admin_html/proof.rs` | No-mutation admin proof reads plus guarded final-send form capture for admin reachability, campaign body audit, render artifacts, Send wizard readback, seed-readiness gates, seed sends, and production sends. |
| `private_artifacts.rs` | Private local artifact root validation and atomic artifact writes outside the repository. |
| `safety.rs` | URL allowlists for read pages, proof posts, guarded send posts, and guarded queue/form write routes. |
| `guarded_write.rs` | Shared plan-id and runtime enablement checks. |
| `audience_hygiene.rs` | Private audience artifact construction outside git. |
| `audience_hygiene_checkpoint.rs` | Checkpointed begin/resume/status flow for bounded audience export progress. |
| `response/common.rs` | Shared request/response contracts, fixtures, caps, and redacted error serialization. |
| `response/queue.rs` | Queue preview/apply request and report contracts. |
| `response/render.rs` | Private campaign render artifact request and report contracts. |
| `response/template.rs` | Semantic EDM campaign template update request helpers. |
| `response/seed_send.rs` | Guarded seed-send apply request and report contracts. |
| `response/production_send.rs` | Guarded production-send apply request and report contracts. |
| `response/forms.rs` | Guarded campaign/list/user/settings write request and report contracts. |
| `response/audience.rs` | Warm-up readiness and audience-hygiene request/report contracts. |
| `response/send_wizard.rs` | Admin-session, campaign-body, Send wizard, and seed-readiness proof contracts. |
| `response.rs` | Thin re-export module for the response contract tree. |
| `redact.rs` | Redaction helpers for emails, hosts, URLs, and secret-shaped text. |

## Source Authority

The XML API is preferred for list and subscriber evidence because it has a more
stable contract than admin HTML. It is the first authority for positive
list-presence readback wherever it can answer the question. A negative
`IsSubscriberOnList` response is not treated as authoritative absence unless
another source corroborates it; the tool reports low-confidence absence so
operators do not mistake API-scope gaps for send-readiness proof. Admin HTML is
treated as a brittle substrate and is used only where the XML API is missing
important operational state:

- list owner and reply/bounce metadata;
- global email, bounce, and cron settings;
- user-level SMTP override state;
- campaign edit summaries;
- schedule and stats rows;
- queue-control preview/action links;
- persisted form state for guarded campaign, list, user, and settings edits.
- Send wizard proof state for selected campaign/list readiness, with the final
  editable form parsed but not submitted by proof tools.

Admin HTML access is therefore route-shaped, not browser-shaped. The backend
does not expose a general fetch tool, a click tool, arbitrary query strings, or
raw upstream pages. Parsers extract only the reviewed state required for the
public tool contract, and responses carry readback evidence rather than raw
HTML dumps.

The server does not treat provider delivery events, external validation results,
or private artifact exports as Interspire state. Those may be useful inputs for
separate workflows, but Interspire remains the source of list/campaign/contact
readback in this repository.

The checkpointed audience export flow is deliberately transport-local rather
than a generic background-task framework. It persists bounded progress under an
approved private output root, advances only a limited number of subscriber XML
queries per call, and lets operators resume safely after MCP/client timeouts.
Checkpoint resume/status resolves jobs as direct children of that approved root
and normalizes loaded state back to the resolved directory before any later
checkpoint read or write.

Sensitive field reads use the MCP Toolkit sensitive-read posture and policy
decision helper for the generic runtime/acknowledgement/boundary checks.
Interspire-specific route selection and field allowlists stay in
`admin_html.rs`. Guarded form writes remain target-specific for campaign, list,
user, and setup sections; normal readback tools continue to redact values.

No-mutation Send proof uses the MCP Toolkit no-mutation-proof posture and
Interspire route allowlists together. The generic toolkit metadata describes
the proof boundary for MCP clients, while this repository owns the Step2-only
route classifier, parser, queue/stat invariant checks, and negative send flags.

Campaign body resolution uses the same approach for Interspire 8 editor
screens: the initial campaign edit page is read first, and if body controls are
absent the adapter can render the Step2 body form through an allowlisted
no-save Step1 POST. Render artifacts and semantic template preview share that
resolver. Template apply still uses a separate guarded campaign Complete/save
route and the preview/apply plan-id model.

Guarded form apply mutates the requested controls in a captured form snapshot,
then replays the resulting current form state through the matched save route.
Blank password controls are still omitted. This preserves ordinary unchanged
fields such as subject lines and tracking checkboxes while keeping the requested
change list, route classifier, plan id, and post-apply readback narrow.

Guarded send apply tools deliberately sit outside the no-mutation proof family.
They re-run the same campaign-body and Send wizard proof immediately, capture
the live final send form, and post only through the guarded final-send route
classifier. Seed sends require a bounded recipient count. Production sends also
require the production runtime gate, exact expected count, From, Reply-To,
subject, HTML SHA-256, and confirmation phrase.

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

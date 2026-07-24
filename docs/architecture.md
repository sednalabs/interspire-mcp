# Architecture

`interspire-mcp` is a curated stdio MCP server. It wraps Interspire Email
Marketer state in typed, redacted, operator-oriented tools.

## Shape

- Transport: stdio.
- Toolkit: `sednalabs/mcp-toolkit-rs`.
- Authority order: Interspire XML API first, authenticated admin HTML fallback
  only for explicitly allowlisted pages.
- Output: compact JSON strings shaped for MCP clients and agent workflows.
- Safety posture: read-only by default, with guarded queue
  cancel/delete/pause/resume, guarded campaign, list, user, non-secret
  settings, list creation, campaign copy, semantic template, private artifact,
  aggregate CSV import preflight, and explicit guarded-send apply paths.
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
parsers, and operator wording stay in this repository. The supported XML
request/response profile is maintained in
[`interspire-xml-compatibility.md`](interspire-xml-compatibility.md).

## Module Boundaries

| Module | Responsibility |
| --- | --- |
| `lib.rs` | MCP server, tool inventory, trait boundary, tool handlers. |
| `config.rs` | Environment and secret-file configuration without exposing values. |
| `live.rs` | Thin backend root that keeps the trait surface stable while delegating to domain modules. |
| `live/reads.rs` | Read-only backend handlers for status, list/contact readback, settings, queue stats, send-job status, cron readiness, stop-gate readiness, and campaign readback. |
| `live/guarded.rs` | Guarded queue-control and form-write preview/apply handlers. |
| `live/scaffold.rs` | Guarded list/campaign scaffold handlers plus aggregate CSV import preflight. |
| `live/send.rs` | Guarded seed and production send apply handlers. |
| `live/audience.rs` | Warm-up readiness and audience-hygiene handler orchestration. |
| `live/support.rs` | Shared list caps, source-list filtering, and local helper utilities for the live backend. |
| `xml_api.rs` | Interspire XML API reads and XML parsing. |
| `admin_html.rs` | Authenticated admin HTML reads, queue-control extraction, and redacted parsing helpers. |
| `admin_html/send_ops.rs` | Structured send-job status, cron readiness, and stop-gate decision parsing over allowlisted Schedule/newsletter Manage/Stats/Settings reads. |
| `admin_html/forms.rs` | Guarded form snapshotting, allowlisted field updates, preview/apply plan binding, list-create apply, and field-scoped POST construction. |
| `admin_html/scaffold.rs` | Campaign-copy route discovery and before/after draft detection. |
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
| `response/oci_ledger.rs` | OCI send-ledger preflight request and redacted proof contracts. |
| `response/seed_send.rs` | Guarded seed-send apply request and report contracts. |
| `response/production_send.rs` | Guarded production-send apply request and report contracts. |
| `response/send_outcome.rs` | Shared post-send reconciliation status and aggregate proof contracts. |
| `response/send_ops.rs` | Structured send-job status, cron-readiness, stop-gate, action-plan, and queued-follow-up contracts. |
| `response/forms.rs` | Guarded campaign/list/user/settings write request and report contracts. |
| `response/scaffold.rs` | List-create, campaign-copy, and CSV preflight request/report contracts. |
| `response/audience.rs` | Warm-up readiness and audience-hygiene request/report contracts. |
| `response/send_wizard.rs` | Admin-session, campaign-body, Send wizard, and seed-readiness proof contracts. |
| `response.rs` | Thin re-export module for the response contract tree. |
| `redact.rs` | Redaction helpers for emails, hosts, URLs, and secret-shaped text. |

## Source Authority

The XML API is preferred for list and subscriber evidence because it has a more
stable contract than admin HTML. It is the first authority for positive
list-presence readback wherever it can answer the question. If
`IsSubscriberOnList` returns false, contact-state proof immediately performs a
bounded `GetSubscribers` exact-email search and treats only an active,
confirmed, non-bounced, non-unsubscribed exact match as presence. A remaining
negative XML result is not treated as authoritative absence unless another
source corroborates it; the tool reports low-confidence absence so operators do
not mistake API-scope gaps for send-readiness proof. Admin HTML is treated as a
brittle substrate and is used only where the XML API is missing important
operational state:

- exact contact-state corroboration when XML cannot prove presence, using an
  internally generated `Subscribers&Action=Manage` exact-search read that
  targets one list and one email, returns only redacted/hash evidence, and does
  not expose a generic subscriber export or admin URL surface;
- list owner and reply/bounce metadata;
- global email, bounce, and cron settings;
- user-level SMTP override state;
- campaign edit summaries;
- schedule and stats rows;
- queue-control preview/action links;
- persisted form state for guarded campaign, list, user, settings, and
  list-create edits.
- exact Copy-route discovery and before/after draft detection for campaign
  copy.
- aggregate-only CSV import preflight under configured private roots.
- Send wizard proof state for selected campaign/list readiness, with the final
  editable form parsed but not submitted by proof tools.

Interspire 8 compatibility note: list summary XML uses `lists/GetLists`.
Subscriber XML methods have two layers of
parameter semantics. The XML security layer checks a top-level `listid`, while
some underlying subscriber APIs still accept legacy method parameters such as
`listids` or nested `searchinfo`. Curated XML reads include both forms only
where required so ownership checks and legacy method invocation agree. The
admin contact-state fallback likewise uses Interspire 8's `emailaddress` plus
`search_rule=exact` search parameters, with route safety blocking broad search
rules.

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
Checkpoint resume/status resolves jobs to deterministic direct children of that
approved root from the validated `job_id`, not by scanning operator-controlled
directory names, and normalizes loaded state back to the resolved directory
before any later checkpoint read or write. A resume/status request may provide
the old `artifact_prefix` only to recover a pre-existing legacy
`<artifact_prefix>-<job_id>` child. The fallback uses the same prefix
normalization as begin/export, automatically tries the default legacy prefix,
and does not reintroduce sibling directory scanning.

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
Plan ids use stable route/form content and requested changes while excluding
volatile CSRF/session token values; apply still refreshes and submits the
current token from the live form.

Campaign active-state changes are deliberately separate from generic campaign
form edits. They read the campaign manager page, infer state from exactly one
visible Activate or Deactivate action for the target campaign id, execute only
that allowlisted state route when the plan id matches, and then prove the
requested state from a fresh manager-page readback.

List creation uses the same form-write gate but has create-specific readback:
apply rereads list summary before and after submission and accepts the result
only when exactly one new list id appears, then reads that new list edit page
and internally verifies the requested fields persisted.

Campaign copy is route-follow scaffolding, not generic admin browsing. Preview
discovers the exact Copy link for the requested source campaign on the manage
page and binds the plan id to that stable route. Apply rereads the manage page
before and after following that route, accepts the result only when exactly one
new campaign id appears, and confirms both source and copied campaign edit
pages are readable. Full body/settings equivalence remains a campaign
readback/body-audit gate.

CSV import preflight is intentionally outside the write path. It reads only a
local CSV under configured private roots and returns generic column labels plus
aggregate file evidence. Explicit expected-count mismatches and preflight caps
block the proof; there is no import apply handler in this public build.

Guarded send apply tools deliberately sit outside the no-mutation proof family.
They re-run the same campaign-body and Send wizard proof immediately, capture
the live final send form, and post only through the guarded final-send route
classifier. Seed sends require a bounded recipient count. Production sends also
require the production runtime gate, exact expected count, From, Reply-To,
subject, HTML SHA-256, and confirmation phrase.
When OCI ledger enforcement is enabled, both send apply paths first verify the
configured private ledger has the expected Interspire campaign/batch rows, then
refuse before the final send form if that proof is missing, incomplete, or tied
to a different campaign id than the one being sent.

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

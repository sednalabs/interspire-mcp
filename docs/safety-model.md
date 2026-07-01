# Safety Model

This repository is built around one rule: a tool should answer an operational
question without creating an uncontrolled way to send mail or corrupt list
state.

## Defaults

- Read-only tools are enabled by default.
- Guarded writes are disabled by default.
- Queue-control writes are separately disabled by default.
- Form-write controls are separately disabled by default.
- Guarded apply defaults to `preview_apply`, not direct mutation.
- No-mutation proof tools may render allowlisted read/proof pages, but they
  must not submit a send, schedule, import, contact, or suppression action.
- Sensitive reads are disabled by default and require explicit acknowledgement.
- Private audience exports require an explicit private artifact root.
- CSV import preflight requires an explicit private artifact root and returns
  aggregate evidence only.
- Tool output is redacted and aggregate wherever raw recipient or credential
  data might appear.

## Blocked Operations

The MCP server intentionally does not provide tools for:

- generic or unreviewed sending;
- scheduling;
- cron triggering;
- contact-import apply;
- generic raw contact exports;
- contact delete/edit operations;
- unsubscribe or resubscribe mutation;
- suppression mutation;
- SMTP password mutation;
- bounce password mutation;
- provider API mutation;
- DNS mutation.

Allowlisted writes are limited to queue cancel/delete, guarded campaign, list,
user, and non-secret settings edits, list creation, campaign copy, semantic
template edits, private artifact creation, and explicit guarded send apply
tools. CSV import preflight is read-only and aggregate-only. Anything outside
those targets stays blocked.

## Negative Tool Surface

The absence of broad tools is a deliberate safety feature. The server does not
offer a generic XML call tool, raw SQL tool, generic admin URL fetcher, browser
automation bridge, contact dump, or provider-management surface. Operators get
named intent tools that answer reviewed operational questions; unreviewed admin
actions stay unavailable even when the Interspire admin account itself could
perform them in a browser.

Private audience artifacts and CSV preflight reports are also not send
authorization. They can support hygiene review outside the repository, but the
MCP response exposes aggregate evidence only and does not convert exported
recipients into a send-ready list.

## Admin HTML Allowlist

Legacy Interspire admin pages are brittle. The HTML adapter admits only known
paths:

- lists and list edit pages;
- selected settings tabs;
- users and user edit pages;
- newsletter manage and edit pages;
- newsletter Copy routes discovered from the manage page for exact campaign ids;
- the list create page and form;
- schedule and stats pages;
- the Send page for the reviewed no-send Step2 proof boundary and the
  separately gated guarded-send final form boundary.

Extra query parameters, duplicate query keys, path escapes, cross-origin URLs,
and send/import/export/contact mutation paths are blocked before HTTP requests
are made.

Admin HTML is an unsafe substrate, not a trusted API. The adapter keeps it
behind allowlisted routes and parsers, redacts extracted values, and avoids
returning raw pages to the MCP client. Hidden fields, selected options, and
checked state are captured only for guarded preview/apply form workflows, then
re-read after apply to prove what persisted.

The Send page allowlist is narrower than the ordinary read-page allowlist.
No-mutation tools use it only so `interspire_send_wizard_readback` can render
the Step2/final editable wizard state and then stop before the final send
boundary. Guarded send apply tools have a separate final-form POST classifier
for Send Step3/Step4/Send actions captured from the freshly proven page.
Schedule, contact-import apply, export, cron, and contact/suppression paths
stay blocked.

## Preview/Apply As Transaction Guard

Every current write path is a two-step transaction guard. Preview captures the
current upstream state, normalizes the intended change, and returns a
deterministic plan id. Apply requires the matching plan id, the specific
runtime enablement flag for that write family, a fresh upstream re-read, and a
post-apply readback. This prevents a preview for one page, row, or form state
from becoming a general mutation token.

## Guarded Queue Controls

Queue control has two phases.

Preview:

- reads the Schedule page;
- finds cancel/delete links inside bounded table rows;
- validates that each link is a Schedule-page cancel/delete route with a
  numeric identifier;
- returns a deterministic plan id, redacted row summary, action, and route
  fingerprint.

Apply:

- requires `INTERSPIRE_GUARDED_WRITES=1`;
- requires `INTERSPIRE_QUEUE_WRITE_CONTROLS=1`;
- requires the exact plan id and action from preview;
- re-reads the Schedule page before apply;
- applies only the matching Schedule cancel route or one-job Schedule delete
  form post;
- sends Schedule referer/origin context and accepted CSRF token headers for
  guarded queue applies;
- for delete candidates, may first follow a same-row, same-job Schedule
  `Pause` route when Interspire exposes one, then applies the selected delete
  plan;
- re-reads the Schedule page after apply;
- returns before/after counts and evidence.

Queue apply does not authorize sending and does not mutate lists, contacts,
suppression state, Interspire settings, provider APIs, DNS, or secrets.

## Guarded Form Writes

Form writes and scaffold writes also have preview/apply phases.

Preview:

- reads the allowlisted edit form;
- captures hidden fields, selected options, and checked state;
- restricts requested changes to an allowlisted field set for that target;
- returns a deterministic plan id, available fields, summarized requested
  changes, and warnings.

Apply:

- requires `INTERSPIRE_GUARDED_WRITES=1`;
- requires `INTERSPIRE_FORM_WRITE_CONTROLS=1`;
- requires the exact preview-generated `plan_id`;
- derives the plan id from stable route/form content and requested changes,
  excluding volatile CSRF/session token values that are refreshed at apply time;
- posts only to an allowlisted campaign, list, user, settings, or list-create
  route, or follows the exact allowlisted campaign-copy route;
- sends the current form page as Referer plus the admin Origin and accepted
  CSRF token header when the form exposes a token, matching Interspire 8's
  browser-side POST expectations;
- mutates the requested controls in the captured form snapshot, then submits
  the resulting current form state plus safe hidden controls and the save submit
  control;
- re-reads the edited page after apply;
- returns redacted field readback evidence.

For Interspire 8.x campaign body forms, campaign preview/readback may first
render the campaign editor's Step2 body form through the same allowlisted
no-save Step1 POST used by body audit. The actual apply route remains separate:
only the matching campaign edit Complete/save form is accepted as a guarded
campaign write route.

Unchanged ordinary controls are replayed to preserve Interspire edit-form
semantics, including campaign subject lines and checked tracking flags. Blank
password controls are omitted so a routine metadata save cannot silently clear
or echo an unrelated secret. Secret updates remain out of scope for this public
phase.

Form apply can change non-secret delivery and cron configuration inside
Interspire, including SMTP host/username/port, bounce host/username/IMAP mode,
hourly throttle, cron toggles, and the Interspire test-mode send toggle. It
does not reach provider APIs, DNS, password fields, contact state, or
suppression state.

Form apply does not authorize sending and does not mutate contacts,
suppression state, contact-import state, export state, provider APIs, or DNS.

List creation is the only create-style form write in this public build. It
requires the same runtime gates and preview plan id as other guarded form
writes, then rereads list summary and the new list edit page. Apply is
confirmed only when exactly one new list id appears and the requested fields
match the persisted form values internally.
On Interspire 8.x, the create route may ignore visible Bounce Email unless
local bounce processing is selected. The MCP must not enable local bounce
polling just to persist metadata. Instead, list-create apply may immediately
re-save the newly created list through the normal list edit route, using the
same guarded metadata update model, then prove the final edit-form values.
Existing list updates must preserve source-defined webhook and multi-select
state, including `total_webhooks`, `WebhookUrl_*`, `webhook_event_*`,
`AvailableFields[]`, and `VisibleFields[]`.

Campaign copy is the only route-follow scaffold write. Preview reads the
campaign manage page, finds the exact Copy link for the requested source
campaign id, and binds the plan id to the stable current route. Apply rereads
the manage page before and after the Copy route and is confirmed only when
exactly one new campaign id appears and both source and copied campaign edit
pages are readable. It does not claim full copied body/settings equivalence;
use campaign readback/body audit before treating the copy as send-ready.

CSV import preflight is not a write. It constrains the file path to configured
private roots, requires a `.csv` extension, rejects parent-directory path
components, and returns only generic column labels, aggregate counts, duplicate
and invalid-looking counts, the selected email column position, and SHA-256. It
blocks on explicit expected-count mismatches or hard byte/row/unique-email caps.
It has no apply tool and returns no raw rows, raw headers, or email addresses.

## No-Mutation Send Proof

The send-readiness tools deliberately sit between ordinary readback and
guarded writes:

- `interspire_admin_session_probe` checks authenticated admin reachability
  through allowlisted read pages.
- `interspire_campaign_body_audit` counts redacted campaign-body signals such
  as unsubscribe tokens, link protocol mix, image-alt coverage, and visible
  tracking-pixel text without returning raw HTML. On Interspire 8.x it may
  render the editor Step2 body form through an allowlisted no-save Step1 POST
  when the initial edit page only contains campaign metadata; it never posts
  the final Complete/save form.
- `interspire_send_wizard_readback` posts only to the allowlisted Send Step2
  proof route, parses the resulting final editable wizard page, and never posts
  that final form. Interspire 8.x may render the requested campaign as an
  available campaign option instead of a selected value and may echo only the
  resulting recipient count rather than the selected list ids; when an operator
  supplied an expected recipient count, the proof can record that as list-session
  evidence while still treating the next form as a blocked send boundary.
- `interspire_seed_readiness_gate` combines campaign-body and wizard evidence
  into review gates without approving a seed or production send.
- `interspire_campaign_test_send_preview` and
  `interspire_campaign_test_send_apply` use Interspire's native
  `Newsletters/SendPreview` route for one explicit reviewer address. Preview
  reads the persisted campaign subject and body hashes, binds them to the exact
  recipient and caller-supplied preview sender, and verifies queue/stat
  invariants without posting, then returns a preview digest.
  Apply requires guarded writes, send controls, `acknowledge_test_send=true`,
  the exact preview digest, the preview report's public subject, and the exact
  preview HTML SHA-256. The digest binds the raw subject without returning it.
  This path does not create lists, import contacts, schedule mail, trigger cron,
  or authorize production mail. It also does not prove list-specific
  unsubscribe, custom fields, contact merge behavior, tracking behavior, or
  production audience metadata.
- `interspire_seed_send_apply` repeats those gates immediately before posting
  the final send form and is bounded to an acknowledged seed-recipient count
  of 1-20.
- `interspire_production_send_apply` repeats those gates immediately before
  posting the final send form and additionally requires production send runtime
  enablement plus exact expected recipient count, From, Reply-To, subject, HTML
  SHA-256, and the required confirmation phrase.
- When `INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=1`, both guarded send apply tools
  also require `oci_ledger_preflight` to match the expected campaign/batch row
  count in the configured private OCI send ledger before the final send form is
  posted. Matched rows must include recipient keys, trace keys, and valid UTC
  `submitted_at`/timestamp values that are fresh enough for the immediate send
  boundary. Rows older than 15 minutes, missing timestamps, invalid timestamps,
  or timestamps more than 5 minutes in the future are ignored and counted in
  `stale_rows_ignored`. The preflight `campaign_id` must equal the
  Interspire campaign id in the send request. The ledger path is
  environment-configured only; tool callers cannot supply arbitrary file paths.
- `interspire_oci_send_ledger_prepare_preview` and
  `interspire_oci_send_ledger_prepare_apply` can prepare that private ledger
  from a private JSONL manifest. Preview computes sanitized rows and a plan id
  without writing. Apply requires guarded writes, send controls, the exact plan
  id, and `acknowledge_ledger_write=true`, then writes only hashed recipient and
  trace values with an apply-time UTC `submitted_at` and reruns preflight. The
  prepare tools do not contact OCI and do not perform an Interspire send,
  schedule, queue, import, contact, list, or suppression mutation.
- OCI ledger preparation and preflight reject non-private Unix permissions on
  the ledger directory, manifest file, and existing ledger file because the
  manifest can contain raw recipient or provider trace identifiers before the
  tool hashes them.

The wizard proof records Schedule and Stats rows before and after the Step2
render. Output includes invariant evidence and explicit negative flags such as
`send_performed: false`, `scheduled: false`, and
`production_send_authorized: false`.

The send apply tools are deliberately narrower than Interspire's native admin
surface. They do not accept arbitrary admin URLs, do not schedule mail, and do
not trigger cron. They post only the final Send-page form captured from the
freshly proven wizard page, and only when the relevant runtime controls are
enabled.

OCI ledger preparation and preflight are not delivery proof. They prove only
that a private local send ledger can contain, and does contain, the expected
Interspire campaign/batch rows, timestamped when the ledger apply occurred and
still fresh at the Interspire final send boundary.
Provider acceptance, bounces, complaints, suppression reconciliation, and
recipient rendering still require OCI and recipient-side readback after an
explicitly approved send.

Posting the final form is not considered proof of a send. Apply responses carry
a post-send reconciliation object with the explicit status vocabulary
`posted`, `queued`, `processed`, `transport_failed`, `delivered_unverified`,
and `seed_proven`. After the final form post, the MCP follows only allowlisted
Interspire popup send continuations of `Page=Send&Action=Send` with a numeric
job identifier, including `Started=1` continuation routes, then rereads
Schedule and Stats. `sent=true` is reserved for terminal reconciliation states,
not for HTTP 200 or 302 alone.

## EDM Template Editing And Render Artifacts

The semantic template tools are wrappers over the guarded campaign form-write
surface. They provide easier fields for EDM work, but still preserve the
preview/apply plan-id model, current-form readback, approved field allowlist,
current-form preservation, hidden control preservation, and post-apply
verification used by the generic campaign apply tools.

On Interspire 8.x, semantic `html_body` and `text_body` updates resolve against
the editor controls exposed on the Step2 body form, such as
`myDevEditControl_html`, instead of assuming those fields exist on the initial
campaign metadata page.

Some Interspire 8 editor shapes omit the plain-text editor control when the
campaign is currently HTML-only. For a semantic `text_body` update, the adapter
must render the body Step2 page through the allowlisted Step1 proof route with
the Text+HTML format selected, then post the resulting Step2 `TextContent`
control through the normal guarded Complete/Save boundary. Apply proof must
re-read the campaign body and show non-zero text bytes before the campaign can
be treated as multipart-ready.

`interspire_campaign_render_artifact` is read-only against Interspire and writes
private local artifacts outside the repository. Its output is artifact
metadata, not visual proof. Operators or agents must open the generated preview
HTML in a browser and inspect desktop/mobile screenshots before making visual
claims.

## Sensitive Field Query

The sensitive field query is a special read-only setup tool. It exists for
cases where redacted readbacks are not enough to configure or migrate a server,
but it deliberately avoids becoming a broad secret-viewing surface.

Controls:

- requires `INTERSPIRE_SENSITIVE_READS=1`;
- requires `acknowledge_sensitive_output=true` on every call;
- requires exact field names instead of dumping whole forms;
- uses toolkit policy-core boundary checks before any admin read;
- uses Interspire-owned allowlists for each settings/list target;
- denies password, token, license, cookie, API-key, private-key, credential,
  and similar fields even when the runtime gate is enabled;
- marks the MCP descriptor as model-only, sensitive-output, approval-required,
  and read-only.

The current allowlist is limited to setup and migration-critical settings plus
list sender/reply/bounce email fields. User and campaign targets reveal no
fields; adding them would be a separate public contract change.

This tool does not mutate Interspire, provider APIs, DNS, contact state, list
state, suppression state, or send state. Normal readback tools remain redacted.

## Private Audience Artifacts

Audience hygiene exports can contain raw recipient addresses. They must be
written outside the repository under an explicitly approved private root:

```bash
export INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private
```

The output directory must be an absolute subdirectory under one of those roots.
Repository paths, relative paths, dot components, symlinks, root directories,
and unresolved escapes are rejected.

MCP output reports aggregate counts, warnings, file paths, sizes, and SHA-256
hashes only. The private files themselves must not be committed or pasted into
issue trackers, tickets, or chat.

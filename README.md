# interspire-mcp

[![Rust baseline](https://github.com/sednalabs/interspire-mcp/actions/workflows/rust.yml/badge.svg)](https://github.com/sednalabs/interspire-mcp/actions/workflows/rust.yml)
[![CodeQL](https://github.com/sednalabs/interspire-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/sednalabs/interspire-mcp/actions/workflows/codeql.yml)

`interspire-mcp` is a safety-first Rust MCP server and reference
implementation for wrapping newsletter operations in a narrow, auditable,
least-privilege tool surface. It targets Interspire Email Marketer 6.x and 8.x
installs that need operational care without exposing the full admin control
plane to agents. The original hardening target was an older Interspire 6.2.3
deployment; newer admin surfaces should be configured explicitly with
`INTERSPIRE_VERSION=8.x` where possible.

It gives agents and operators structured answers to the questions that matter
before newsletter work goes wrong:

- What lists, campaigns, queue rows, and sender settings does Interspire show?
- Which user-level SMTP overrides might affect a campaign owner?
- Which audience exports are only private candidate artifacts, not send-ready
  proof?
- If something dangerous is queued, can we preview a cancel/delete/pause/resume plan and
  apply only that narrow plan with explicit write gates?
- Can we stage a no-send campaign, list, user, or non-secret settings edit
  with preview/apply proof instead of clicking through the brittle admin UI?
- Can we scaffold a new list, copy a known campaign into a draft, and preflight
  a cleaned CSV candidate without importing contacts?
- Can we update EDM body fields, generate private render artifacts, and inspect
  desktop/mobile previews before sending?
- Can we send a one-recipient Interspire campaign preview to a reviewer without
  creating a seed list, while clearly marking what that preview does not prove?
- Can we prepare a private OCI send-ledger file from a sanitized manifest before
  a guarded send, without contacting the provider or exposing raw recipients?
- Can we apply a seed or production send only after fresh proof, exact expected
  values, runtime send gates, and explicit acknowledgement?
- When server setup requires a saved admin value, can we query one exact
  approved field without turning normal readbacks into secret dumps?

The server is read-only by default. Its write-class capabilities are limited to
guarded queue cancel/delete/pause/resume, guarded campaign/list/user/settings/template
edits, guarded list creation, guarded campaign copy, private render artifacts,
aggregate-only import preflight, private OCI send-ledger preparation, and
separately gated seed or production send apply tools. All apply paths stay
disabled unless the runtime explicitly
enables guarded writes and the matching control flags. Import preflight is a
read tool and never imports contacts.
The narrow sensitive-read tool is also disabled by default and requires both a
runtime gate and per-call acknowledgement before it can return unredacted setup
values.

## What Makes This Different

This is not a generic Interspire API wrapper and it is not a browser automation
server. It is a curated MCP facade over a split newsletter control plane:

- the XML API is preferred wherever it has stable source authority;
- authenticated admin HTML is used only for specific gaps the XML API cannot
  answer;
- admin routes, query shapes, and form fields are allowlisted instead of
  exposing a generic fetch or click surface;
- write paths require preview plans, exact plan ids, runtime gates, fresh
  readback, and redacted apply evidence;
- private recipient artifacts stay outside git and MCP output remains
  aggregate-only;
- generic send, schedule, import, contact mutation, suppression mutation,
  secret, provider, DNS, and generic admin tools are intentionally absent.

The result is a concrete example of the constrained adapter pattern described
in [`mcp-toolkit-rs`](https://github.com/sednalabs/mcp-toolkit-rs/blob/main/docs/legacy-system-adapter-pattern.md):
wrap a high-impact admin control plane with a small set of operator-intent tools,
strong negative surface area, and auditable preview/apply boundaries.

## Why This Exists

Older Interspire deployments and long-running newsletter installations often
carry important lists, suppression history, campaign drafts, and operational
state. The usual way to inspect that state is an admin UI designed for humans,
not agents. The usual way to automate it is worse: broad API calls, raw HTML
scraping, or direct database access.

This project takes a narrower route. It exposes first-class MCP intent tools
with compact, redacted JSON output. The tools are designed for operator
questions, not for generic administrative access.

Operational tools also have to prove the live workflow they claim to support.
For new or materially changed capabilities, use
[`docs/live-proof-matrix.md`](docs/live-proof-matrix.md): compile, docs, schema,
tool listing, hosted binary install, and restart are not enough until the exact
target workflow has fixture coverage, negative tests, and live no-send proof on
the intended Interspire major version.
For source-derived compatibility work, use
[`docs/source-compatibility-regression.md`](docs/source-compatibility-regression.md)
and the private source checker. Public tests must use synthetic fixtures rather
than proprietary Interspire source snippets.

For agent/operator discipline around ledger-first discovery, secret-safe
automation, narrow source harvesting, and no-send proof, use
[`docs/operator-workflow.md`](docs/operator-workflow.md).

## Tool Surface

| Tool | Class | Purpose |
| --- | --- | --- |
| `interspire_status` | Read | Report configuration, safety posture, and available capabilities. |
| `interspire_xml_auth_probe` | Read | Probe XML API authentication with `authentication/XmlApiTest` before using list or contact reads. |
| `interspire_list_summary` | Read | Summarize lists and aggregate subscriber-state counts. |
| `interspire_contact_state` | Read | Check one redacted contact's list presence with XML first, exact XML subscriber-search corroboration after a negative presence probe, and exact admin-HTML fallback, while keeping uncorroborated negative absence low confidence. |
| `interspire_contact_import_preflight` | Read | Preflight a local cleaned CSV candidate with aggregate counts and SHA-256 only; no contacts are imported. |
| `interspire_list_owner_readback` | Read | Read list owner, reply-to, and bounce metadata. |
| `interspire_settings_audit` | Read | Read redacted global email, bounce, and cron settings. |
| `interspire_settings_inventory` | Read | Inventory redacted settings form fields across allowlisted tabs, with capped omitted secret/hidden/blank controls reported by name and reason. |
| `interspire_admin_session_probe` | Read | Probe authenticated admin reachability through allowlisted read pages. |
| `interspire_user_smtp_readback` | Read | Read redacted per-user SMTP override state. |
| `interspire_queue_stats_readback` | Read | Read scheduled queue and stats rows without triggering cron. |
| `interspire_queue_control_preview` | Read preview | Build plan IDs for cancel/delete/pause/resume actions found on the schedule page. |
| `interspire_queue_control_apply` | Guarded apply | Apply one previously previewed queue cancel/delete/pause/resume plan when write gates are enabled. |
| `interspire_send_job_status_readback` | Read | Read structured Schedule/Stats status for one expected send job, including redacted row summaries, progress counters when present, queue-control action plans, and explicit unproven table-counter gaps. |
| `interspire_cron_readiness` | Read | Compare Interspire cron settings with Schedule-page cron detection without triggering `cron.php`. |
| `interspire_send_stop_gate_readiness` | No-mutation proof | Combine send-job status and optional OCI ledger preflight into a hold/continue/pause recommendation; any pause still requires separate queue-control apply. |
| `interspire_campaign_readback` | Read | Read campaign manage rows with structured campaign ids/action flags, or one campaign edit-page summary. |
| `interspire_campaign_body_audit` | Read | Audit redacted campaign body safety signals without returning raw HTML. |
| `interspire_campaign_copy_preview` | Read preview | Preview a guarded copy plan for creating a draft from a known campaign, including off-page source campaigns. |
| `interspire_campaign_copy_apply` | Guarded apply | Apply one previously previewed campaign-copy plan and return the detected new draft id. |
| `interspire_campaign_render_artifact` | Private artifact | Write private persisted-campaign render artifacts for native-browser screenshot inspection without returning raw HTML. |
| `interspire_campaign_test_send_preview` | No-mutation proof | Preview a one-recipient Interspire campaign preview/test send without posting the SendPreview route. |
| `interspire_campaign_test_send_apply` | Guarded test send | Apply one explicitly acknowledged campaign preview/test send to one recipient after exact preview digest, public preview subject, HTML hash, and send-control runtime gates. The digest also binds raw subject, text/preheader hashes, and the caller-supplied preview sender. |
| `interspire_oci_send_ledger_prepare_preview` | No-mutation proof | Preview sanitized private OCI send-ledger rows from a private JSONL manifest without writing the ledger or sending. |
| `interspire_oci_send_ledger_prepare_apply` | Guarded local apply | Write sanitized private OCI send-ledger rows from an acknowledged preview plan, then rerun OCI ledger preflight. This does not contact OCI or perform an Interspire send. |
| `interspire_send_wizard_readback` | No-mutation proof | Render the Send wizard through the no-send proof boundary and verify queue/stat invariants, including Interspire 8 wizard shapes that echo recipient count rather than selected list ids. |
| `interspire_seed_readiness_gate` | No-mutation proof | Combine campaign body audit and Send wizard readback into seed-readiness gates. |
| `interspire_seed_send_apply` | Guarded send | Apply one explicitly acknowledged bounded seed send after immediate readiness proof and send-control runtime gates. |
| `interspire_production_send_apply` | Guarded send | Apply an explicitly acknowledged production send after strict readiness proof, exact expected count/sender/subject/hash, and production-send runtime gates. |
| `interspire_campaign_template_update_preview` | Read preview | Preview semantic EDM template edits such as subject, HTML body, text body, and tracking flags. |
| `interspire_campaign_template_update_apply` | Guarded apply | Apply one previously previewed semantic EDM template edit. |
| `interspire_campaign_template_artifact_update_preview` | Read preview | Preview applying a fixed private render artifact to a draft campaign without returning raw HTML. |
| `interspire_campaign_template_artifact_update_apply` | Guarded apply | Apply one previously previewed fixed private render artifact and prove the persisted body hash. |
| `interspire_campaign_update_preview` | Read preview | Preview guarded campaign content or sender-metadata edits, including the documented Archive checkbox. |
| `interspire_campaign_update_apply` | Guarded apply | Apply one previously previewed campaign edit when guarded form-write gates are enabled. |
| `interspire_list_update_preview` | Read preview | Preview guarded list metadata edits. |
| `interspire_list_update_apply` | Guarded apply | Apply one previously previewed list metadata edit when guarded form-write gates are enabled. |
| `interspire_list_create_preview` | Read preview | Preview guarded list creation with sender/reply/bounce metadata. |
| `interspire_list_create_apply` | Guarded apply | Apply one previously previewed list creation plan and return the detected new list id. |
| `interspire_user_update_preview` | Read preview | Preview guarded user profile, footer, or non-secret SMTP override edits. |
| `interspire_user_update_apply` | Guarded apply | Apply one previously previewed user edit when guarded form-write gates are enabled. |
| `interspire_settings_update_preview` | Read preview | Preview guarded non-secret application, email, bounce, or cron settings edits. |
| `interspire_settings_update_apply` | Guarded apply | Apply one previously previewed non-secret settings edit when guarded form-write gates are enabled. |
| `interspire_sensitive_field_query` | Sensitive read | Query exact approved setup fields with unredacted values after `INTERSPIRE_SENSITIVE_READS=1` and `acknowledge_sensitive_output=true`. |
| `interspire_warmup_audience_readiness` | Read | Report specified-list warm-up universe coverage and warnings. |
| `interspire_audience_hygiene_export` | Private artifact | Export candidate audience artifacts outside git with aggregate MCP output only. |
| `interspire_audience_hygiene_export_begin` | Private artifact | Start a checkpointed audience export job and advance a bounded number of subscriber queries. |
| `interspire_audience_hygiene_export_resume` | Private artifact | Resume a checkpointed audience export job without repeating completed shards. |
| `interspire_audience_hygiene_export_status` | Read | Read aggregate status for a checkpointed audience export job. |

There is intentionally no generic admin URL fetch tool, raw contact dump tool,
generic send tool, schedule tool, contact-import apply tool, unsubscribe
mutation tool, suppression mutation tool, SMTP password tool, provider tool, or
DNS tool.

## Quick Start

For operational installs, use the hosted GitHub Actions binary artifact:

- Run the manual `binary-build` workflow on the branch or SHA you want.
- Download the `interspire-mcp-linux-x86_64` artifact from the run.
- Verify the downloaded checksum before installing or running the binary.
- Extract `interspire-mcp` from `interspire-mcp-linux-x86_64.tar.gz`.

```bash
sha256sum -c interspire-mcp-linux-x86_64.tar.gz.sha256
tar -xzf interspire-mcp-linux-x86_64.tar.gz interspire-mcp
install -m 0755 interspire-mcp /opt/interspire-mcp/interspire-mcp
```

Local `cargo build` is fine for development and tests, but do not use a local
release build as the operator handoff binary.

Run as a stdio MCP server through a private launcher outside this repository.
Do not paste real credentials into shell commands, transcripts, PRs, or public
docs. The launcher should load secrets from the operator's private mechanism and
then exec the verified binary:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Export INTERSPIRE_* variables from your private secret store here.
exec /opt/interspire-mcp/interspire-mcp
```

Register it with an MCP client by pointing the client at the verified hosted
artifact binary and passing credentials through the client's secret/environment
mechanism. The JSON below is shape-only; keep real values in the client's
private secret store where supported:

```json
{
  "mcpServers": {
    "interspire": {
      "command": "/opt/interspire-mcp/interspire-mcp",
      "env": {
        "INTERSPIRE_XML_ENDPOINT": "https://example.invalid/xml.php",
        "INTERSPIRE_XML_USERNAME": "xml-user",
        "INTERSPIRE_XML_TOKEN": "redacted-token",
        "INTERSPIRE_ADMIN_BASE_URL": "https://example.invalid/admin/",
        "INTERSPIRE_ADMIN_USERNAME": "admin-user",
        "INTERSPIRE_ADMIN_PASSWORD": "redacted-password"
      }
    }
  }
}
```

First smoke test: call `interspire_status`. A healthy default posture should
report configured read capabilities, `safe_mode: true`,
`guarded_writes_enabled: false`, and `queue_controls_enabled: false`.
For a default runtime it should also report `form_write_controls_enabled: false`
and `write_execution_mode: "preview_apply"`. If the Interspire admin or XML API
is behind Cloudflare Access, `cloudflare_access_configured: true` confirms that
the service-token header values were loaded without revealing those values.
Then call `interspire_xml_auth_probe`. It uses Interspire's
`authentication/XmlApiTest` route and performs no list, contact, queue, form,
or send action. A `xml_auth_error` means the XML username, XML token, XML API
enablement, or admin-only policy should be fixed before relying on XML list or
contact evidence.

For real deployments, load credentials through environment variables populated
outside the repository. Do not commit credentials, cookies, raw exports, saved
admin HTML, provider payloads, or recipient artifacts.

## Configuration

Core XML API variables:

```bash
INTERSPIRE_VERSION=auto
INTERSPIRE_XML_ENDPOINT='https://example.invalid/xml.php'
INTERSPIRE_XML_USERNAME='xml-user'
INTERSPIRE_XML_TOKEN='redacted-token'
```

`INTERSPIRE_VERSION` accepts `auto`, `6.2.3`, and `8.x`. The default is
`auto`. Set `6.2.3` for older installations and `8.x` for newer admin login
surfaces that expose JavaScript CSRF tokens such as `IEM_CSRF_TOKEN`.
The supported XML request profile is documented in
[`docs/interspire-xml-compatibility.md`](docs/interspire-xml-compatibility.md).
Use the Interspire XML API token for `INTERSPIRE_XML_TOKEN`; it is not the
admin-login password. Keep a separate XML credential set per Interspire
instance so a legacy install and a new install cannot silently share the wrong
token.

Admin HTML fallback variables:

```bash
INTERSPIRE_ADMIN_BASE_URL='https://example.invalid/admin/'
INTERSPIRE_ADMIN_USERNAME='admin-user'
INTERSPIRE_ADMIN_PASSWORD='redacted-password'
INTERSPIRE_HTML_LIST_ENRICH_LIMIT=25
```

The MCP reads credentials from direct environment variables only. If an
installation stores secrets in files, keep that file handling in a private
launcher or secrets manager that exports these environment variables before
starting the MCP binary.

Cloudflare Access service-token variables for protected admin/XML origins:

```bash
INTERSPIRE_CF_ACCESS_CLIENT_ID='service-token-client-id'
INTERSPIRE_CF_ACCESS_CLIENT_SECRET='redacted-service-token-secret'
```

When both Access values are configured, the MCP attaches
`CF-Access-Client-Id` and `CF-Access-Client-Secret` to the existing Interspire
XML and admin HTML requests. These values are never returned by status or
readback tools.

Guarded write variables, all disabled by default:

```bash
INTERSPIRE_GUARDED_WRITES=1
INTERSPIRE_QUEUE_WRITE_CONTROLS=1
INTERSPIRE_FORM_WRITE_CONTROLS=1
INTERSPIRE_CONTACT_WRITE_CONTROLS=0
INTERSPIRE_SEND_CONTROLS=0
INTERSPIRE_PRODUCTION_SEND_CONTROLS=0
```

Sensitive read variable, disabled by default:

```bash
INTERSPIRE_SENSITIVE_READS=1
```

`interspire_sensitive_field_query` is for setup/debugging cases where an
operator explicitly needs one saved non-password value such as an SMTP host,
reply-to address, or bounce mailbox. It requires exact field names, a reviewed
target, `INTERSPIRE_SENSITIVE_READS=1`, and
`acknowledge_sensitive_output=true`. Password, token, license, cookie, API-key,
and similar fields are denied even when this gate is enabled.

Private audience artifact variables:

```bash
INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private
INTERSPIRE_AUDIENCE_HYGIENE_OUTPUT_DIR=/secure/private/interspire-audience-hygiene
```

See [Configuration](docs/configuration.md) for the complete contract.

## Guarded Write Workflow

All write paths use the same safety pattern:

1. Read the current state with the matching readback tool.
2. Call the matching `*_preview` tool with only the intended field changes.
3. Review the returned `plan_id`, allowed fields, summarized changes, and
   warnings.
4. Enable only the matching guarded-write flags for the session that should
   apply the change.
5. Call the matching `*_apply` tool with the exact `plan_id`.
6. Review the post-apply readback evidence before taking any next step.

### Queue Controls

Queue apply remains limited to Schedule-page cancel/delete/pause/resume actions.

The apply route is limited to Interspire Schedule-page cancel, pause, and
resume links plus the built-in Schedule delete form for one selected job.
Plan ids bind the previewed action, numeric row/job identity, route
fingerprint, and redacted row summary. Post-apply readback requires
cancel/delete targets to disappear from allowlisted queue controls; pause and
resume must remove the requested action and expose the expected opposite action
for the same job.
It does not use Interspire's queue controls to send, schedule, import, export,
edit contacts, edit suppressions, change provider APIs, DNS, or secrets, or
authorize any later send.

### Guarded Form Writes

Campaign, list, user, settings, list-creation, and campaign-copy writes stay
no-send and no-contact by design:

- they only target allowlisted edit forms;
- they require `INTERSPIRE_GUARDED_WRITES=1` and
  `INTERSPIRE_FORM_WRITE_CONTROLS=1`;
- they produce a deterministic preview plan before apply;
- they require the exact preview-generated `plan_id` during apply while
  excluding volatile CSRF/session token values from the plan hash;
- they re-fetch the page after apply, verify the requested fields persisted,
  and then report redacted readback;
- they omit blank password fields from the submitted payload so unrelated
  secrets are not cleared by accident.

Within that boundary, the public phase does allow non-secret Interspire
delivery and cron configuration edits such as SMTP host/username/port, bounce
host/username/IMAP mode, hourly throttle, cron toggles, and the Interspire
test-mode send toggle. Cron settings are changed through
`interspire_settings_update_preview` / `interspire_settings_update_apply` with
`section="cron"` and the current guarded allowlist:
`cron_enabled`, `cron_send`, `cron_bounce`, `cron_autoresponder`,
`cron_triggeremails_s`, and `cron_maintenance`. It still does not expose provider APIs, DNS,
password/secret fields, contact mutations, suppression mutations, cron
execution, or generic send execution controls.

### Scaffold And Import Preflight

`interspire_list_create_preview` and `interspire_list_create_apply` create a
new Interspire list only through the captured list-create form. The apply step
requires the preview plan id, the guarded-write runtime gates, and a before/after
list readback that detects exactly one new list id and internally verifies the
requested fields persisted.
For Interspire 8.x, the native create route can ignore the visible Bounce Email
unless local bounce polling is selected. The apply path therefore creates the
list first, then proves and, if needed, re-saves the new list through the normal
edit route so non-secret sender/reply/bounce metadata can persist without
turning on local bounce polling.

`interspire_campaign_copy_preview` and `interspire_campaign_copy_apply` copy a
known campaign by following only an allowlisted Copy route. If the requested
source campaign is not visible on the current campaign-manager page, the tool
may construct the same allowlisted Copy route from another visible Copy link,
then re-run the exact campaign-copy safety classifier against the requested
source id. The apply step reports the detected new draft id, confirms the
source and copied campaign edit pages can be read back, and states that full
body/settings equivalence still needs campaign readback/body audit before any
send decision. It does not send, schedule, trigger cron, import contacts, or
alter provider state.

`interspire_campaign_readback` returns compact redacted campaign-row summaries
for human review and a structured `campaign_manage_rows` array with campaign
ids plus action availability flags. It does not return admin URLs, CSRF tokens,
raw links, or recipient data.

`interspire_contact_import_preflight` is deliberately not an import tool. It
accepts a local CSV path only under configured private roots, computes generic
column labels, aggregate row counts, duplicate/invalid-looking counts, selected
email column position, and SHA-256, then returns no raw rows, raw headers, or
email addresses. Explicit expected-count mismatches and hard safety caps are
blocking errors, not warnings. Use it to prove a candidate file before a
separate, explicitly approved import path exists.

```bash
export INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS=/secure/private/imports
```

### EDM Template And Render Artifacts

`interspire_campaign_template_update_preview` and
`interspire_campaign_template_update_apply` are friendly wrappers around the
guarded campaign edit surface. They accept semantic fields such as `subject`,
`html_body`, `text_body`, `track_opens`, `track_links`, `send_multipart`, and
`embed_images`, then map those to the actual Interspire form controls present
on the current campaign, including Interspire 8 editor fields such as
`myDevEditControl_html`.

`interspire_campaign_render_artifact` fetches the persisted campaign body and
writes private local files outside the repository. The response contains file
paths, hashes, byte counts, and a native-browser next step; it does not return
raw campaign HTML. Visual signoff still requires opening the preview artifact
with a browser and inspecting desktop/mobile screenshots.

`interspire_campaign_test_send_preview` and
`interspire_campaign_test_send_apply` use Interspire's native campaign preview
route for one explicit recipient. Preview reads the persisted campaign subject
and body hashes, binds them to one exact recipient and the caller-supplied
preview sender, verifies queue/stat invariants without sending, then returns a
preview digest. Apply requires `INTERSPIRE_GUARDED_WRITES=1`,
`INTERSPIRE_SEND_CONTROLS=1`, `acknowledge_test_send=true`, the exact preview
digest, the preview report's public subject, and the exact preview HTML SHA-256 before
posting `Newsletters/SendPreview`. It does not create seed lists, import
contacts, schedule mail, trigger cron, or authorize production mail. It also
does not prove list-specific unsubscribe, custom fields, contact merge
behavior, tracking behavior, or production audience metadata; use a seed-list
send when those properties are the proof target. A denied apply response omits
campaign-body proof entirely; body audit data is returned only after the tool
has re-read the target campaign as part of an accepted preview/send path.

`interspire_campaign_template_artifact_update_preview` and
`interspire_campaign_template_artifact_update_apply` transfer campaign HTML from
that fixed private render-artifact directory into another draft without placing
the raw HTML in the MCP transcript. Preview reads the artifact privately,
verifies optional expected byte and SHA-256 values, and returns only the
filename, hash, byte count, and guarded write preview. Apply repeats the
artifact read, saves through the guarded campaign edit surface, and fails unless
the post-apply body audit matches the artifact hash. These tools do not send,
schedule, import contacts, or authorize production mail.

Render artifacts require a private output root:

```bash
export INTERSPIRE_RENDER_ARTIFACT_ROOTS=/secure/private
```

Then pass `output_dir` as a subdirectory under that root, or set
`INTERSPIRE_RENDER_ARTIFACT_OUTPUT_DIR`.

### Guarded Send Apply

The MCP exposes two explicit send tools. They are not generic admin POST tools;
both re-run the campaign body audit and Send wizard proof immediately before
posting the final send form captured from the live Interspire page.

`interspire_seed_send_apply` is bounded to small seed sends. It requires:

- `INTERSPIRE_GUARDED_WRITES=1`
- `INTERSPIRE_SEND_CONTROLS=1`
- `acknowledge_seed_send=true`
- an explicit list id set and `expected_recipient_count` from 1 to 20
- when `INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=1`, an `oci_ledger_preflight`
  object whose `campaign_id` matches the Interspire campaign being sent and
  whose batch id, sender domain, and expected row count match rows already
  present in the configured private OCI send ledger, including valid UTC
  `submitted_at`/timestamp values on matched rows. Otherwise matching rows
  older than 15 minutes, missing timestamps, invalid timestamps, or timestamps
  more than 5 minutes in the future are ignored and reported through
  `stale_rows_ignored`.

`interspire_oci_send_ledger_prepare_preview` and
`interspire_oci_send_ledger_prepare_apply` can prepare those private ledger
rows before a guarded send request. Preview reads a private JSONL manifest from
the configured ledger directory and returns a plan id without writing. Apply
requires `INTERSPIRE_GUARDED_WRITES=1`, `INTERSPIRE_SEND_CONTROLS=1`, the exact
plan id, and `acknowledge_ledger_write=true`, then writes only sanitized ledger
rows with an apply-time UTC `submitted_at` and reruns the same preflight gate.
If exact matching rows already exist but are stale or lack a valid timestamp,
apply appends fresh timestamped rows instead of claiming idempotence. The
prepare tools do not contact OCI and do not perform an Interspire send.

`interspire_production_send_apply` is the full-send boundary. It requires:

- `INTERSPIRE_GUARDED_WRITES=1`
- `INTERSPIRE_SEND_CONTROLS=1`
- `INTERSPIRE_PRODUCTION_SEND_CONTROLS=1`
- `acknowledge_production_send=true`
- `confirmation_phrase="SEND_PRODUCTION_CAMPAIGN"`
- exact expected recipient count, From email, Reply-To email, subject, and
  campaign HTML SHA-256
- when `INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=1`, a verified
  `oci_ledger_preflight` object, with `campaign_id` equal to the Interspire
  campaign id, before the final Interspire send form is posted.

Both tools return redacted aggregate evidence plus a post-send reconciliation
object. HTTP success from the final form post is reported only as `posted`.
When Interspire 8.x renders the final Step4 page without echoing selected
campaign/list controls, the send tools bind the final POST to the already
proven request campaign id and list ids rather than trusting stale form values.
The tools then follow the allowlisted Interspire popup send loop, reread
Schedule and Stats, and classify the result as `posted`, `queued`, `processed`,
`transport_failed`, `delivered_unverified`, or `seed_proven`. The legacy
`sent` boolean is true only when reconciliation reaches a terminal success
state and an Interspire job id was proven. A final form HTTP 200 without a job
id plus queue/stats movement remains non-successful `posted-unproven` evidence.
When Interspire creates a job but completion is not yet proven, the
reconciliation object can include a `follow_up_contract` containing the job id,
campaign id, list ids, expected queue total, and status tool name for
`interspire_send_job_status_readback`.
Production sending should still be paired with provider-side monitoring and an
Ops work item reference.

The OCI ledger path is configured only by `INTERSPIRE_OCI_SEND_LEDGER_PATH`.
Send requests cannot choose arbitrary ledger files, and the preflight campaign
token must match the Interspire campaign id in the send request. Ledger
preflight output returns hashes and counts only; it does not return raw
recipients, raw campaign identifiers, private file paths, or provider payloads.
The ledger directory, private manifest, and any existing ledger file must not be
readable, writable, or executable by group or other users on Unix systems.

### No-Mutation Send Proof

The send-readiness tools are proof tools, not send tools. They can inspect an
admin session, audit a redacted campaign body, and render the Send wizard only
through the reviewed no-send Step2 boundary. The final editable send form may
be parsed to prove selected campaign/list metadata, recipient estimates,
tracking checkboxes, sender fields, and form fingerprints, but it is never
submitted.

For Interspire 8.x campaign drafts, `interspire_campaign_body_audit` may render
the campaign editor's Step2 body form through an allowlisted no-save Step1 POST
when the initial edit page only contains metadata fields. It parses the Step2
HTML body controls such as `myDevEditControl_html`, then stops before the
Complete/save form.

`interspire_send_wizard_readback` records Schedule and Stats rows before and
after the proof render and reports whether those invariants changed.
`interspire_seed_readiness_gate` combines that proof with campaign-body safety
signals so an operator can decide what still needs review before a guarded
seed or production send. Both tools report `send_performed: false`,
`scheduled: false`, and `production_send_authorized: false`.

See [Safety Model](docs/safety-model.md).

## Private Audience Hygiene Export

The private artifact lane is for controlled list-hygiene preparation. It reads
the explicit list IDs you provide through Interspire XML, filters out
unconfirmed, unsubscribed, and bounced rows as reported by Interspire, dedupes
by normalized email, and writes private files outside the repository.

Example:

```bash
export INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private

interspire-mcp audience-hygiene-export \
  --source-list-ids 7,8,9 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --artifact-prefix example-run
```

MCP and CLI output stays aggregate: counts, warnings, artifact paths, hashes,
and file sizes. Private artifacts may contain raw recipient addresses and must
stay out of git, issue trackers, tickets, and chat.

An audience hygiene export is candidate evidence. It is not validation proof,
suppression proof, engagement proof, or send authorization.

For large list exports, prefer the checkpointed flow so one MCP call does not
have to finish the full XML traversal:

```bash
interspire-mcp audience-hygiene-export-begin \
  --source-list-ids 7,8 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --artifact-prefix example-run \
  --max-queries-per-call 4

interspire-mcp audience-hygiene-export-status \
  --job-id iah_123 \
  --output-dir /secure/private/interspire-audience-hygiene

interspire-mcp audience-hygiene-export-resume \
  --job-id iah_123 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --max-queries-per-call 4
```

Checkpoint state is written privately under the approved output root and the
MCP response stays aggregate and redacted. Resume and status calls resolve the
job to a deterministic child directory derived from the validated `job_id`,
then rewrite loaded state to that resolved directory, so checkpoint state
cannot redirect later file reads or writes. `artifact_prefix` still controls
export artifact naming; it is not used for new checkpoint lookup. Older
checkpoint directories created as `<artifact_prefix>-<job_id>` still work
without scanning the output directory: default-prefix jobs are tried
automatically, and non-default legacy jobs can be recovered by passing the same
original `artifact_prefix` on resume or status. This is a resumable export
helper, not a background send or task runner.

## Development

Required local checks:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Schema updates are intentional changes. To refresh the MCP tool snapshot after
reviewing a tool-surface change:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tool_schema_snapshot_contract_is_stable
```

Then review and commit `spec/tool_schema_snapshot.v1.json`.

Dependency governance:

```bash
./scripts/dependency_governance_check.sh
```

Hosted checks include:

- Rust baseline: format, clippy, metadata, and test shards run as parallel
  fanout jobs with a final aggregate `Run Rust baseline` gate.
- CodeQL Advanced: Rust and GitHub Actions workflow security.
- Code Quality: Cobertura artifact on every run, with best-effort GitHub Code
  Quality upload when the repository-side feature is enabled.
- Dependency governance: `cargo-deny`, `cargo-audit`, and direct dependency
  stale-risk reporting run as parallel fanout jobs with a final aggregate
  `dependency-governance` gate.

CI uses `.github/actions/setup-rust-ci` for the shared Rust toolchain and Cargo
cache policy. Keep future CI reruns on this rapid fanout path. Reuse small
artifacts that shorten later jobs, such as metadata and coverage reports, but do
not upload large `target/` directories between jobs unless measured evidence
shows that artifact transfer is faster than the shared Cargo cache.

## Architecture

The server follows the curated stdio intent-server pattern from
[`mcp-toolkit-rs`](https://github.com/sednalabs/mcp-toolkit-rs). Domain logic
stays in this repository; MCP protocol inventory, stdio serving, schema
snapshotting, and contract-test helpers come from the toolkit.

Read the full [Architecture](docs/architecture.md) for module boundaries and
source authority.

## License

Apache-2.0. See [LICENSE](LICENSE).

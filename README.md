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
- If something dangerous is queued, can we preview a cancel/delete plan and
  apply only that narrow plan with explicit write gates?
- Can we stage a no-send campaign, list, user, or non-secret settings edit
  with preview/apply proof instead of clicking through the brittle admin UI?
- When server setup requires a saved admin value, can we query one exact
  approved field without turning normal readbacks into secret dumps?

The server is read-only by default. Its write-class capabilities are limited to
guarded queue cancel/delete plus guarded no-send campaign, list, user, and
non-secret settings edits. All apply paths stay disabled unless the runtime
explicitly enables guarded writes and the matching control flags.
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
- send, schedule, import, contact mutation, suppression mutation, secret,
  provider, DNS, and generic admin tools are intentionally absent.

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

## Tool Surface

| Tool | Class | Purpose |
| --- | --- | --- |
| `interspire_status` | Read | Report configuration, safety posture, and available capabilities. |
| `interspire_list_summary` | Read | Summarize lists and aggregate subscriber-state counts. |
| `interspire_contact_state` | Read | Check one redacted contact's XML list presence, with low-confidence warnings for uncorroborated absence. |
| `interspire_list_owner_readback` | Read | Read list owner, reply-to, and bounce metadata. |
| `interspire_settings_audit` | Read | Read redacted global email, bounce, and cron settings. |
| `interspire_user_smtp_readback` | Read | Read redacted per-user SMTP override state. |
| `interspire_queue_stats_readback` | Read | Read scheduled queue and stats rows without triggering cron. |
| `interspire_queue_control_preview` | Read preview | Build plan IDs for cancel/delete actions found on the schedule page. |
| `interspire_queue_control_apply` | Guarded apply | Apply one previously previewed queue cancel/delete plan when write gates are enabled. |
| `interspire_campaign_readback` | Read | Read campaign rows or one campaign edit-page summary. |
| `interspire_campaign_update_preview` | Read preview | Preview guarded campaign content or sender-metadata edits. |
| `interspire_campaign_update_apply` | Guarded apply | Apply one previously previewed campaign edit when guarded form-write gates are enabled. |
| `interspire_list_update_preview` | Read preview | Preview guarded list metadata edits. |
| `interspire_list_update_apply` | Guarded apply | Apply one previously previewed list metadata edit when guarded form-write gates are enabled. |
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
send tool, schedule tool, import tool, unsubscribe mutation tool, suppression
mutation tool, SMTP password tool, provider tool, or DNS tool.

## Quick Start

Build from source:

```bash
git clone https://github.com/sednalabs/interspire-mcp.git
cd interspire-mcp
cargo build --release
```

Run as a stdio MCP server:

```bash
INTERSPIRE_XML_ENDPOINT='https://example.invalid/xml.php' \
INTERSPIRE_XML_USERNAME='xml-user' \
INTERSPIRE_XML_TOKEN='redacted-token' \
INTERSPIRE_ADMIN_BASE_URL='https://example.invalid/admin/' \
INTERSPIRE_ADMIN_USERNAME='admin-user' \
INTERSPIRE_ADMIN_PASSWORD='redacted-password' \
target/release/interspire-mcp
```

Register it with an MCP client by pointing the client at the built binary and
passing credentials through the client's secret/environment mechanism:

```json
{
  "mcpServers": {
    "interspire": {
      "command": "/path/to/interspire-mcp/target/release/interspire-mcp",
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
and `write_execution_mode: "preview_apply"`.

For real deployments, load credentials from environment variables or secret
files outside the repository. Do not commit credentials, cookies, raw exports,
saved admin HTML, provider payloads, or recipient artifacts.

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

Admin HTML fallback variables:

```bash
INTERSPIRE_ADMIN_BASE_URL='https://example.invalid/admin/'
INTERSPIRE_ADMIN_USERNAME='admin-user'
INTERSPIRE_ADMIN_PASSWORD='redacted-password'
INTERSPIRE_HTML_LIST_ENRICH_LIMIT=25
```

Secret-file variables:

```bash
INTERSPIRE_XML_CREDENTIALS_FILE=/secure/secrets/interspire-xml.env
INTERSPIRE_ADMIN_CREDENTIALS_FILE=/secure/secrets/interspire-admin.env
```

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

Queue apply remains limited to Schedule-page cancel/delete actions.

The apply route is limited to Interspire Schedule-page cancel actions and the
built-in Schedule delete form for one selected job.
It does not send, schedule, import, export, edit contacts, edit suppressions,
change provider APIs, DNS, or secrets, or authorize any later send.

### Guarded Form Writes

Campaign, list, user, and settings form writes stay no-send and no-contact by
design:

- they only target allowlisted edit forms;
- they require `INTERSPIRE_GUARDED_WRITES=1` and
  `INTERSPIRE_FORM_WRITE_CONTROLS=1`;
- they produce a deterministic preview plan before apply;
- they require the exact preview-generated `plan_id` during apply;
- they re-fetch the page after apply, verify the requested fields persisted,
  and then report redacted readback;
- they omit blank password fields from the submitted payload so unrelated
  secrets are not cleared by accident.

Within that boundary, the public phase does allow non-secret Interspire
delivery and cron configuration edits such as SMTP host/username/port, bounce
host/username/IMAP mode, hourly throttle, and cron toggles. It still does not
expose provider APIs, DNS, password/secret fields, contact mutations,
suppression mutations, or send controls.

This phase intentionally does not expose send, schedule, cron-trigger,
contact-mutation, suppression-mutation, SMTP password, bounce password,
provider APIs, or DNS tools.

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
target/release/interspire-mcp audience-hygiene-export-begin \
  --source-list-ids 7,8 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --artifact-prefix example-run \
  --max-queries-per-call 4

target/release/interspire-mcp audience-hygiene-export-status \
  --job-id iah_123 \
  --output-dir /secure/private/interspire-audience-hygiene

target/release/interspire-mcp audience-hygiene-export-resume \
  --job-id iah_123 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --max-queries-per-call 4
```

Checkpoint state is written privately under the approved output root and the
MCP response stays aggregate and redacted. Resume and status calls resolve the
job from the approved output root and rewrite loaded state to that resolved
directory, so checkpoint state cannot redirect later file reads or writes. This
is a resumable export helper, not a background send or task runner.

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

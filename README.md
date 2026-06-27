# interspire-6-mcp

[![Rust baseline](https://github.com/sednalabs/interspire-6-mcp/actions/workflows/rust.yml/badge.svg)](https://github.com/sednalabs/interspire-6-mcp/actions/workflows/rust.yml)
[![CodeQL](https://github.com/sednalabs/interspire-6-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/sednalabs/interspire-6-mcp/actions/workflows/codeql.yml)

`interspire-6-mcp` is a small Rust MCP server for teams that still need to
operate Interspire Email Marketer 6.2.3 with modern safety expectations.

It gives agents and operators structured answers to the questions that matter
before newsletter work goes wrong:

- What lists, campaigns, queue rows, and sender settings does Interspire show?
- Which user-level SMTP overrides might affect a campaign owner?
- Which audience exports are only private candidate artifacts, not send-ready
  proof?
- If something dangerous is queued, can we preview a cancel/delete plan and
  apply only that narrow plan with explicit write gates?

The server is read-only by default. Its only write-class capability is a
guarded queue cancel/delete apply path, disabled unless the runtime explicitly
enables guarded writes and queue controls.

## Why This Exists

Interspire 6.2.3 is legacy software, but many installs still carry important
newsletter lists, suppression history, campaign drafts, and operational state.
The usual way to inspect it is a brittle admin UI. The usual way to automate it
is worse: broad API calls, raw HTML scraping, or direct database access.

This project takes a narrower route. It exposes first-class MCP intent tools
with compact, redacted JSON output. The tools are designed for operator
questions, not for generic administrative access.

## Tool Surface

| Tool | Class | Purpose |
| --- | --- | --- |
| `interspire_status` | Read | Report configuration, safety posture, and available capabilities. |
| `interspire_list_summary` | Read | Summarize lists and aggregate subscriber-state counts. |
| `interspire_contact_state` | Read | Check one redacted contact's XML list presence. |
| `interspire_list_owner_readback` | Read | Read list owner, reply-to, and bounce metadata. |
| `interspire_settings_audit` | Read | Read redacted global email, bounce, and cron settings. |
| `interspire_user_smtp_readback` | Read | Read redacted per-user SMTP override state. |
| `interspire_queue_stats_readback` | Read | Read scheduled queue and stats rows without triggering cron. |
| `interspire_queue_control_preview` | Read preview | Build plan IDs for cancel/delete actions found on the schedule page. |
| `interspire_queue_control_apply` | Guarded apply | Apply one previously previewed queue cancel/delete plan when write gates are enabled. |
| `interspire_campaign_readback` | Read | Read campaign rows or one campaign edit-page summary. |
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
git clone https://github.com/sednalabs/interspire-6-mcp.git
cd interspire-6-mcp
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
target/release/interspire-6-mcp
```

Register it with an MCP client by pointing the client at the built binary and
passing credentials through the client's secret/environment mechanism:

```json
{
  "mcpServers": {
    "interspire-6": {
      "command": "/path/to/interspire-6-mcp/target/release/interspire-6-mcp",
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

For real deployments, load credentials from environment variables or secret
files outside the repository. Do not commit credentials, cookies, raw exports,
saved admin HTML, provider payloads, or recipient artifacts.

## Configuration

Core XML API variables:

```bash
INTERSPIRE_XML_ENDPOINT='https://example.invalid/xml.php'
INTERSPIRE_XML_USERNAME='xml-user'
INTERSPIRE_XML_TOKEN='redacted-token'
```

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

Guarded write variables, both disabled by default:

```bash
INTERSPIRE_GUARDED_WRITES=1
INTERSPIRE_QUEUE_WRITE_CONTROLS=1
```

Private audience artifact variables:

```bash
INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private
INTERSPIRE_AUDIENCE_HYGIENE_OUTPUT_DIR=/secure/private/interspire-audience-hygiene
```

See [Configuration](docs/configuration.md) for the complete contract.

## Guarded Queue Controls

Queue controls are a preview/apply workflow.

1. Call `interspire_queue_control_preview`.
2. Review the returned `plan_id`, action, row summary, and warnings.
3. Enable both guarded-write environment flags only for the session that should
   apply the action.
4. Call `interspire_queue_control_apply` with the exact `plan_id` and action.
5. Review the before/after queue counts and post-apply evidence.

The apply route is limited to Interspire Schedule-page cancel/delete actions.
It does not send, schedule, import, export, edit contacts, edit suppressions,
change settings, change SMTP, change provider configuration, or authorize any
later send.

See [Safety Model](docs/safety-model.md).

## Private Audience Hygiene Export

The private artifact lane is for controlled list-hygiene preparation. It reads
the explicit list IDs you provide through Interspire XML, filters out
unconfirmed, unsubscribed, and bounced rows as reported by Interspire, dedupes
by normalized email, and writes private files outside the repository.

Example:

```bash
export INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private

interspire-6-mcp audience-hygiene-export \
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
target/release/interspire-6-mcp audience-hygiene-export-begin \
  --source-list-ids 7,8 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --artifact-prefix example-run \
  --max-queries-per-call 4

target/release/interspire-6-mcp audience-hygiene-export-status \
  --job-id iah_123 \
  --output-dir /secure/private/interspire-audience-hygiene

target/release/interspire-6-mcp audience-hygiene-export-resume \
  --job-id iah_123 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --max-queries-per-call 4
```

Checkpoint state is written privately under the approved output root and the
MCP response stays aggregate and redacted. This is a resumable export helper,
not a background send or task runner.

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

- Rust baseline: format, clippy, tests, metadata.
- CodeQL Advanced: Rust and GitHub Actions workflow security.
- Code Quality: Cobertura artifact on every run, with best-effort GitHub Code
  Quality upload when the repository-side feature is enabled.
- Dependency governance: `cargo-deny`, `cargo-audit`, and direct dependency
  stale-risk reporting.

## Architecture

The server follows the curated stdio intent-server pattern from
[`mcp-toolkit-rs`](https://github.com/sednalabs/mcp-toolkit-rs). Domain logic
stays in this repository; MCP protocol inventory, stdio serving, schema
snapshotting, and contract-test helpers come from the toolkit.

Read the full [Architecture](docs/architecture.md) for module boundaries and
source authority.

## License

Apache-2.0. See [LICENSE](LICENSE).

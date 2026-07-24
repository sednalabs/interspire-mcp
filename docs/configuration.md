# Configuration

All credentials are supplied at runtime. The repository should remain useful
without containing secrets, cookies, saved HTML, or live recipient data.

## XML API

```bash
INTERSPIRE_VERSION=auto
INTERSPIRE_XML_ENDPOINT='https://example.invalid/xml.php'
INTERSPIRE_XML_USERNAME='xml-user'
INTERSPIRE_XML_TOKEN='redacted-token'
```

`INTERSPIRE_VERSION` accepts `auto`, `6.2.3`, and `8.x`. The default is
`auto`. Use `6.2.3` for older installations and `8.x` for newer admin login
surfaces that emit JavaScript CSRF tokens.

The MCP reads credentials from direct environment variables only. If an
installation stores these values in files, use a private launcher or secrets
manager to export the variables before starting the MCP binary.

`INTERSPIRE_XML_TOKEN` is the user's XML API token, not the admin-login
password. Keep XML credentials separate from admin HTML credentials, and keep
one XML credential set per Interspire instance. Reusing a new-instance XML token
against an older installation can make list/contact reads fail at the
authentication layer before the requested method is reached.

The supported XML calls are documented in
[`interspire-xml-compatibility.md`](interspire-xml-compatibility.md). In
particular, list summary reads use `lists/GetLists`; subscriber reads use the
`subscribers` request type.

## Admin HTML

```bash
INTERSPIRE_ADMIN_BASE_URL='https://example.invalid/admin/'
INTERSPIRE_ADMIN_USERNAME='admin-user'
INTERSPIRE_ADMIN_PASSWORD='redacted-password'
INTERSPIRE_HTML_LIST_ENRICH_LIMIT=25
```

The MCP reads credentials from direct environment variables only. If an
installation stores these values in files, use a private launcher or secrets
manager to export the variables before starting the MCP binary.

## Cloudflare Access Protected Origins

If the Interspire admin or XML API is protected by Cloudflare Access, provide a
service token through environment variables:

```bash
INTERSPIRE_CF_ACCESS_CLIENT_ID='service-token-client-id'
INTERSPIRE_CF_ACCESS_CLIENT_SECRET='redacted-service-token-secret'
```

When both values are configured, all Interspire XML and admin HTML HTTP
requests include the `CF-Access-Client-Id` and `CF-Access-Client-Secret`
headers. Status readback reports only the boolean
`cloudflare_access_configured` value and does not expose the token values.

## Guarded Writes

Guarded writes are off unless the runtime enables them explicitly:

```bash
INTERSPIRE_GUARDED_WRITES=1
INTERSPIRE_QUEUE_WRITE_CONTROLS=1
INTERSPIRE_FORM_WRITE_CONTROLS=1
INTERSPIRE_CONTACT_WRITE_CONTROLS=0
INTERSPIRE_SEND_CONTROLS=0
INTERSPIRE_PRODUCTION_SEND_CONTROLS=0
INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=0
INTERSPIRE_OCI_SEND_LEDGER_PATH=/secure/private/oci-send-ledger.jsonl
```

Current public behavior:

- `INTERSPIRE_QUEUE_WRITE_CONTROLS=1` enables guarded queue
  cancel/delete/pause/resume apply. Each apply also requires
  `acknowledge_queue_mutation=true`.
- `interspire_send_job_status_readback` and `interspire_cron_readiness` are
  read-only admin-HTML tools. They require only the admin HTML configuration
  above and do not need write-control flags.
- `interspire_send_stop_gate_readiness` is also read-only. It can evaluate an
  optional `oci_ledger_preflight` against the configured
  `INTERSPIRE_OCI_SEND_LEDGER_PATH`, but any recommended pause still requires a
  separate guarded queue-control apply.
- `INTERSPIRE_FORM_WRITE_CONTROLS=1` enables guarded campaign, list, user,
  non-secret settings, list-create, and campaign-copy apply.
  Cron setting changes use the same preview/apply contract with
  `section="cron"` and only the guarded cron fields `cron_enabled`,
  `cron_send`, `cron_bounce`, `cron_autoresponder`, `cron_triggeremails_s`,
  and `cron_maintenance`.
- `INTERSPIRE_SEND_CONTROLS=1` enables explicitly acknowledged one-recipient
  campaign preview/test sends through `interspire_campaign_test_send_apply`
  and bounded seed sends through `interspire_seed_send_apply`. It also enables
  `interspire_oci_send_ledger_prepare_apply`, which writes only a private local
  ledger file and does not send.
- `INTERSPIRE_PRODUCTION_SEND_CONTROLS=1` additionally enables
  `interspire_production_send_apply`, which requires exact expected recipient
  count, From, Reply-To, subject, HTML SHA-256, and confirmation phrase.
- `INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=1` makes both guarded send apply tools
  refuse before the final Interspire send form unless `oci_ledger_preflight`
  verifies the expected Interspire campaign/batch row count in the configured
  private ledger, with recipient keys, trace keys, and valid UTC
  `submitted_at`/timestamp values on each matched row. Matched rows also must
  be fresh: older than 15 minutes, invalid/missing timestamps, or timestamps
  more than 5 minutes in the future are ignored and counted in
  `stale_rows_ignored`. The preflight `campaign_id` must equal the Interspire
  `campaign_id` in the send request.
- `INTERSPIRE_OCI_SEND_LEDGER_PATH` is the only ledger file path source. Send
  requests cannot provide a per-call file path.
- `INTERSPIRE_CONTACT_WRITE_CONTROLS` is reserved for later phases and should
  remain disabled.
- The public build always requires preview/apply with an exact `plan_id`.

Use write flags only for the process that should apply an already-reviewed
plan. Preview remains available without them.

### OCI Send Ledger Preparation

`interspire_oci_send_ledger_prepare_preview` and
`interspire_oci_send_ledger_prepare_apply` are generic local-file helpers for
operators who require a private OCI send ledger before a guarded Interspire send
may proceed.

The prepare tools:

- read a private JSONL manifest supplied by `manifest_path`;
- require the manifest to be a direct child of the configured ledger directory;
- require the configured ledger path to come from
  `INTERSPIRE_OCI_SEND_LEDGER_PATH`;
- require the ledger directory, manifest file, and any existing ledger file to
  be private on Unix, with no group/other permissions;
- hash raw recipient, message, correlation, and header values before writing
  ledger rows;
- stamp appended rows with an apply-time UTC `submitted_at` value so monitoring
  tools can bind the ledger evidence to an explicit send window;
- return only hashes, counts, trace-key classification, plan state, and
  preflight proof;
- never contact OCI and never perform an Interspire send, schedule, queue,
  import, contact, list, or suppression mutation.

Each manifest line must be a JSON object with one recipient identifier or hash
and one provider trace identifier or hash. Accepted recipient fields include
`recipient_hash`, `recipient_id_hash`, `recipient_address_hash`,
`recipient_email`, `recipient_id`, `subscriber_id`, `contact_id`, and `email`.
Accepted trace fields include `message_id`, `provider_message_id`,
`message_id_hash`, `correlation_id`, `correlation_id_hash`, `header_value`,
and `header_value_hash`. Fields named `*_hash` must contain a 20- or
64-character hexadecimal digest; put raw values in the non-hash fields so the
prepare tool can hash them before writing.

Prepare reports classify trace inputs as `message_id_trace_rows`,
`correlation_id_trace_rows`, and `header_value_trace_rows`. The
`provider_visible_trace_candidate_rows` count includes message-id and
header-value rows because those are the trace shapes operators can attempt to
join against provider-visible evidence. `local_correlation_only_rows` are valid
private ledger trace keys, but they do not by themselves prove that provider
logs will expose the same join key; live provider-log proof is still required
before claiming exact message traceability.

Preview computes a deterministic `plan_id`. Apply requires the same manifest,
`expected_plan_id`, `acknowledge_ledger_write=true`,
`INTERSPIRE_GUARDED_WRITES=1`, and `INTERSPIRE_SEND_CONTROLS=1`. Apply appends
sanitized timestamped rows when the current ledger does not already contain the
same fresh prepared rows. Old or timestampless matching rows are ignored for
current-send proof and a new apply appends fresh timestamped rows instead of
claiming idempotence. Partial fresh matching rows for the same campaign and
batch still block so operators do not accidentally double-write a split ledger
batch.

## Import Preflight

CSV import preflight is read-only and aggregate-only. It never imports contacts
or mutates Interspire. Configure one or more private roots before using
`interspire_contact_import_preflight`:

```bash
INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS=/secure/private/imports
```

Multiple roots can be supplied with colon or comma separators:

```bash
INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS=/secure/private/imports:/mnt/private-imports
```

The requested CSV path must already exist, must end in `.csv`, must not contain
parent-directory components, and must canonicalize under one configured root.
The tool returns only generic column labels, row counts, duplicate and
invalid-looking counts, the selected email column position, and SHA-256. It
does not return raw rows, raw headers, or email addresses. It blocks if an
operator-supplied expected unique count does not match the file, or if the file
exceeds the built-in byte, data-row, or unique-email safety caps. It has no
apply companion in this public build.

## Private Render Artifacts

Render artifacts are private local files used for native-browser screenshot
inspection. The public build writes them under a fixed local directory:

```bash
/tmp/interspire-mcp-render-artifacts
```

Per-request `output_dir` and `artifact_prefix` values are rejected for render
artifacts in the public build. Filenames are generated from a fixed prefix and
timestamp, and the directory is checked for symlinks before permissions are
applied. Responses return paths, hashes, and byte counts, not raw campaign HTML.

## Sensitive Reads

Sensitive reads are off unless the runtime enables them explicitly:

```bash
INTERSPIRE_SENSITIVE_READS=1
```

`interspire_sensitive_field_query` is read-only but can return unredacted saved
admin form values. It is intended for setup/debugging cases where an operator
needs one exact approved setup field, such as a saved SMTP host, list sender
address, reply-to address, or bounce mailbox.

Each call must provide:

- a reviewed target, such as a settings section or list;
- exact field names;
- `acknowledge_sensitive_output=true`.

The policy-core preflight denies calls when the runtime gate is disabled, the
acknowledgement is missing, or the requested field list exceeds toolkit
boundary limits. Interspire-specific allowlists then deny fields outside the
target contract. Password, token, license, cookie, API-key, private-key,
credential, and similar field names are never revealed by this tool family.
User and campaign targets currently reveal no fields; exposing those values
would require a deliberately documented tool-family expansion.

## Audience Hygiene Artifacts

Private audience artifacts require an approved root:

```bash
INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private
```

The CLI and MCP request may provide the output directory:

```bash
interspire-mcp audience-hygiene-export \
  --source-list-ids 7,8,9 \
  --output-dir /secure/private/interspire-audience-hygiene \
  --artifact-prefix example-run
```

Or use an environment default:

```bash
INTERSPIRE_AUDIENCE_HYGIENE_OUTPUT_DIR=/secure/private/interspire-audience-hygiene
```

Multiple approved roots can be supplied as a colon-separated list:

```bash
INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private:/mnt/private-artifacts
```

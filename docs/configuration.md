# Configuration

All credentials are supplied at runtime. The repository should remain useful
without containing secrets, cookies, saved HTML, or live recipient data.

## XML API

```bash
INTERSPIRE_XML_ENDPOINT='https://example.invalid/xml.php'
INTERSPIRE_XML_USERNAME='xml-user'
INTERSPIRE_XML_TOKEN='redacted-token'
```

Supported secret file:

```bash
INTERSPIRE_XML_CREDENTIALS_FILE=/secure/secrets/interspire-xml.env
```

The XML secret file supports:

```text
INTERSPIRE_XML_ENDPOINT=https://example.invalid/xml.php
INTERSPIRE_XML_USERNAME=xml-user
INTERSPIRE_XML_TOKEN=redacted-token
```

Explicit environment variables take precedence over file values.

## Admin HTML

```bash
INTERSPIRE_ADMIN_BASE_URL='https://example.invalid/admin/'
INTERSPIRE_ADMIN_USERNAME='admin-user'
INTERSPIRE_ADMIN_PASSWORD='redacted-password'
INTERSPIRE_HTML_LIST_ENRICH_LIMIT=25
```

Supported secret file:

```bash
INTERSPIRE_ADMIN_CREDENTIALS_FILE=/secure/secrets/interspire-admin.env
```

The admin secret file supports key/value format:

```text
INTERSPIRE_ADMIN_BASE_URL=https://example.invalid/admin/
INTERSPIRE_ADMIN_USERNAME=admin-user
INTERSPIRE_ADMIN_PASSWORD=redacted-password
```

For compatibility with simple secret stores, it may also contain username on
line 1 and password on line 2. Set `INTERSPIRE_ADMIN_BASE_URL` separately when
using that format.

## Guarded Writes

Guarded writes are off unless the runtime enables them explicitly:

```bash
INTERSPIRE_GUARDED_WRITES=1
INTERSPIRE_QUEUE_WRITE_CONTROLS=1
INTERSPIRE_FORM_WRITE_CONTROLS=1
INTERSPIRE_CONTACT_WRITE_CONTROLS=0
INTERSPIRE_SEND_CONTROLS=0
INTERSPIRE_PRODUCTION_SEND_CONTROLS=0
```

Current public behavior:

- `INTERSPIRE_QUEUE_WRITE_CONTROLS=1` enables guarded queue cancel/delete apply.
- `INTERSPIRE_FORM_WRITE_CONTROLS=1` enables guarded campaign, list, user, and
  non-secret settings apply.
- `INTERSPIRE_CONTACT_WRITE_CONTROLS`, `INTERSPIRE_SEND_CONTROLS`, and
  `INTERSPIRE_PRODUCTION_SEND_CONTROLS` are reserved for later phases and
  should remain disabled.
- The public build always requires preview/apply with an exact `plan_id`.

Use write flags only for the process that should apply an already-reviewed
plan. Preview remains available without them.

## Audience Hygiene Artifacts

Private audience artifacts require an approved root:

```bash
INTERSPIRE_AUDIENCE_HYGIENE_ROOTS=/secure/private
```

The CLI and MCP request may provide the output directory:

```bash
interspire-6-mcp audience-hygiene-export \
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

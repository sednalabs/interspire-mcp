# Source Compatibility Regression

`interspire-mcp` can be checked against a private Interspire source tree without
committing proprietary source. The public repository stores only interoperability
contracts that are needed to operate the public admin/XML interface: route
names, request field names, workflow boundaries, redaction rules, and synthetic
fixtures.

Do not commit copied Interspire source, saved admin pages from a real instance,
template bodies, comments, implementation excerpts, private source-root paths,
credentials, license material, cookies, recipient rows, provider payloads, or
live message headers.

## Public Regression Layer

Public tests use synthetic HTML/XML fixtures that preserve the shape of
Interspire admin forms and XML responses. They must not contain live admin HTML,
recipient rows, credentials, cookies, license values, provider payloads, or
verbatim proprietary source blocks.

The most important fixture rule is whole-form semantics. Guarded form tests
should prove that the MCP:

- matches the reviewed Interspire route/action for the target operation;
- preserves hidden CSRF/session controls that are safe to replay;
- preserves checked checkbox/radio state;
- preserves every selected option from multi-select controls;
- refuses multi-select updates unless a tool explicitly models them;
- omits blank password controls;
- proves apply results through authoritative readback.

## Private Source Contract Check

Use `scripts/private_interspire_source_contract_check.py` for local/private
source checks. It scans a local Interspire source tree for reviewed contract
markers and prints aggregate JSON only. Its output must not include the local
source root, proprietary snippets, or raw checker patterns.

```bash
python3 scripts/private_interspire_source_contract_check.py \
  --source-root /private/path/to/interspire \
  --pretty
```

The checker is not a public CI gate because the Interspire source is private.
It is a local compatibility guard before release work:

1. run the private checker against the source tree;
2. convert any discovered contract drift into synthetic public fixtures;
3. patch the MCP and run the focused tests;
4. build installable binaries through GitHub Actions;
5. install the hosted artifact by checksum;
6. run `mcp_probe` against configured Interspire instances before operational
   use.

## Public Output Rule

Do not paste proprietary source snippets into public issues, PRs, docs, tests,
or tool output. If a private source check fails, report only the contract area,
missing behavioural contract label, relative source-area path, and next public
synthetic fixture to add.

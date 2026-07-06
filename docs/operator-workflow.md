# Operator Workflow Guardrails

This project exists to make legacy newsletter operations safer for agents and
operators. The MCP can only help if the surrounding workflow is also narrow,
ledger-first, and secret-safe.

Use this guide before Interspire, EDM, CommsWire, or similar newsletter work
that involves live configuration, private artifacts, list state, or send-adjacent
proof.

## Ledger-First Discovery

Before running discovery commands, opening private files, or asking an operator
for information, read the current work item, ticket, issue, or operations ledger
entry and its parent/container notes. Treat that ledger as the source of current
operational facts.

Capture or refresh a concise checkpoint before deeper work:

```text
Discovery checkpoint
Known facts:
- MCP alias or binary path:
- Interspire major version:
- Current branch/PR/run/artifact:
- Installed binary checksum:
- Safe campaign/list ids for readback:

Known blockers:
- Restart required:
- Credential/session owner action required:
- Live proof still missing:

Next lookup before shell:
- Exact repo/path/doc to read:
- Exact tool or MCP readback to try first:

Private evidence pointer:
- Private artifact location or ledger ref, no raw secret values:
```

When a fact changes, append a superseding checkpoint. Do not rely on chat
memory, shell history, or local scratch files as the only record of current
state.

## Narrow Discovery

Start from named facts in the ledger:

- use the named repository, worktree, PR, workflow run, binary checksum, or
  document path first;
- use the configured MCP alias and read tools before lower-level shell or HTTP
  fallbacks;
- search the implicated files or modules first, not the whole workstation;
- stop when the needed evidence is found, then write the result back to the
  ledger.

If wider discovery is unavoidable, record the reason first and cap the scope.
Use explicit roots and exclude generated, build, cache, dependency, transcript,
and unrelated private-evidence directories. Do not run broad recursive searches
over home, workspace, staging, or private roots just to rediscover facts that a
ledger or nearby repo document should already contain.

## Secret-Safe Automation

Secrets must enter the MCP through runtime environment or the operator's
private launcher, not through command lines, public docs, fixtures, PR bodies,
or transcripts.

Do:

- inspect configuration by key name and boolean capability only;
- use `interspire_status`, scoped readbacks, and redacted reports for normal
  proof;
- keep raw HTML, cookies, credentials, provider payloads, and recipient
  artifacts under private roots outside the repository;
- use private render artifacts for browser inspection and report only paths,
  hashes, byte counts, and visual proof status;
- keep sensitive-read tools disabled unless an operator explicitly enables the
  runtime gate and acknowledges the exact field requested.

Do not:

- print environment values to prove configuration;
- commit saved admin HTML, cookies, credentials, raw exports, provider payloads,
  or recipient examples;
- paste raw recipient addresses, headers, bounces, cookies, or secret-bearing
  error text into public issues, PRs, docs, or general work item comments;
- add generic admin URL, generic XML, raw SQL, browser-click, provider, DNS,
  unsubscribe, resubscribe, suppression, contact-import apply, or password
  mutation tools as shortcuts.

## No-Send Proof Discipline

Tool listing, a green build, a downloaded binary, and a restart prove only that
the MCP process can start. They do not prove that a live newsletter workflow is
ready.

For a changed operational capability, require the relevant row in
[`live-proof-matrix.md`](live-proof-matrix.md):

- fixture coverage for the expected page/API shape;
- negative tests for unsafe, stale, omitted, or misleading proof;
- schema/tool inventory coverage when the public contract changes;
- hosted binary build and checksum verification for operator install;
- target-version live no-send smoke when the tool touches Interspire admin
  state, campaign/list proof, queue/stat readback, or send-adjacent workflows.

No-send proof must stop before final send, schedule, cron, import, contact, or
suppression boundaries. When queue or stats tables are relevant, prove the
before/after invariant and record only redacted aggregate evidence.

## When A Tool Misleads

If an MCP report suggests readiness while an adjacent readback fails, or if a
refused/denied path returns synthetic-looking proof, stop operational use of
that capability. File or update the owning work item/friction record, add a
fixture or regression test for the misleading shape, patch the MCP, rebuild via
hosted compute, reinstall from the hosted artifact, and repeat the proof path.

Do not work around misleading proof by clicking the admin UI, using a generic
HTTP client, or manually reconstructing send readiness unless the operator has
explicitly approved a one-off emergency path and the result is recorded in the
ledger.


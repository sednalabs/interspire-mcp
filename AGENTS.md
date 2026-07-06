# AGENTS.md - interspire-mcp

This repository contains a public Rust MCP server for Interspire Email Marketer
6.x and 8.x operational surfaces. It follows the curated stdio intent-server pattern from
`sednalabs/mcp-toolkit-rs`.

## Engineering Rules

- Keep the MCP surface small and operator-shaped. Prefer focused intent tools
  over generic XML, SQL, HTTP, or admin escape hatches.
- Prefer small domain modules over growth in place. When a file starts owning
  multiple responsibilities such as read parsing, guarded writes, safety
  policy, and render helpers, split the new seam into a dedicated sibling or
  submodule in the same change.
- Read-only tools are the default. Mutating tools require an explicit safety
  design, runtime enablement, preview/apply semantics, redacted output, and
  post-apply readback.
- Current public write scope is intentionally narrow: guarded queue
  cancel/delete, guarded campaign/list/user/settings edits, guarded list
  creation, guarded campaign copy, semantic EDM template edits, private
  render-artifact generation, bounded seed sends, and strictly gated production
  sends. CSV import preflight is read-only and aggregate-only.
- Sensitive reads are exceptional read-only tools, not ordinary readback.
  Preserve the toolkit sensitive-read posture, runtime gate, per-call
  acknowledgement, exact field list, and Interspire-owned allowlists.
- Do not add generic send, schedule, cron-trigger, contact-import apply, raw
  contact export, unsubscribe/resubscribe, suppression mutation, SMTP password,
  bounce password, provider APIs, DNS, or generic admin URL tools. Any send
  tool must remain an explicit guarded-send surface with runtime gates, fresh
  no-send proof, exact expected recipient count, redacted output, and no
  arbitrary admin URL input.
- Fixtures must be synthetic or redacted. Never commit credentials, cookies,
  raw recipient exports, saved admin HTML from a live system, provider payloads,
  private headers, or local operator files.
- Public docs and examples must use placeholder hosts and paths.
- Start Interspire, EDM, or CommsWire operational work from the current work
  item, ticket, issue, or operations ledger before discovery. Capture known
  facts, blockers, exact next lookup, and private-evidence pointers there. Do
  not rely on chat memory or broad workspace searches to rediscover facts that
  have already been recorded.
- Keep discovery narrow: read named docs, paths, PRs, workflow runs, and MCP
  aliases first. If a wider search is genuinely required, record the reason,
  cap the explicit roots, exclude generated/cache/dependency/transcript/private
  evidence directories, and stop once the needed evidence is found.
- For secret-safe operating rules and the reusable discovery checkpoint shape,
  follow `docs/operator-workflow.md` before touching live Interspire,
  newsletter, or send-adjacent state.
- Keep dependencies shallow and consistent with `mcp-toolkit-rs`.
- Do not let `admin_html.rs`, `live.rs`, or `response.rs` become catch-all
  files. New capability slices should land in named modules with clear
  ownership boundaries and tests near the seam they protect.
- Preserve the rapid GitHub Actions fanout model. Rust baseline and dependency
  governance should stay split into parallel jobs with final aggregate gates,
  and Rust jobs should use `.github/actions/setup-rust-ci` for shared toolchain
  and cache policy. Reuse compact artifacts such as metadata and coverage
  reports; do not pass large `target/` artifacts between jobs unless measured
  evidence proves it is faster than the shared Cargo cache.
- Build installable binaries only on GitHub Actions. Do not compile or install
  a local release binary from this workstation for handoff. Use the manual
  `binary-build` workflow, download the artifact, verify the checksum, then
  install that hosted artifact locally if needed.
- Do not release or operationally use a new MCP capability from this repo
  merely because it compiles, appears in the tool list, has docs, or was
  installed from a hosted binary. For every new or materially changed
  operational capability, update `docs/live-proof-matrix.md` before coding and
  record the exact fixture tests, negative tests, and live no-send proof needed
  for the target Interspire major version.
- Do not drip-feed contract tests after failures appear. Before patching a new
  tool or operational capability, list the full affected contract surface
  first: router inventory, backend path, schema snapshot, fixture tests,
  negative tests, stdio smoke, docs, live-proof matrix, formatting, clippy, and
  workspace tests. Patch against that matrix and run it as a complete focused
  gate before release or install.
- The minimum usable proof for Interspire 8 operational prep is a successful
  live no-send smoke of the exact tool on the target instance. Tool listing,
  binary checksum verification, and Codex restart prove only installation, not
  workflow readiness.
- If a live smoke exposes a mismatch between the advertised tool and actual
  Interspire behavior, stop operational work, file/update Ops friction, patch
  the MCP with a fixture/regression test for that shape, and repeat the full
  affected matrix row before using the tool.
- Keep the manual `binary-build` workflow lean and predictable. It should
  produce a release binary artifact plus checksum for operator installation,
  use the shared Rust setup action, and avoid turning a one-off install lane
  into another broad validation workflow.

## Required Checks

Run focused checks before committing behavior changes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

For dependency changes, also run:

```bash
./scripts/dependency_governance_check.sh
```

## Documentation

Update README and docs when behavior, tool contracts, configuration, security
posture, or workflow expectations change. Documentation quality is part of the
release contract for this public repository.

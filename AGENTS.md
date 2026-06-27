# AGENTS.md - interspire-6-mcp

This repository contains a public Rust MCP server for Interspire Email Marketer
6.2.3. It follows the curated stdio intent-server pattern from
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
  cancel/delete plus guarded no-send campaign, list, user, and non-secret
  settings edits, including non-secret delivery and cron configuration that is
  stored inside Interspire forms.
- Do not add send, schedule, cron-trigger, import, raw contact export,
  unsubscribe/resubscribe, suppression mutation, SMTP password, bounce
  password, provider APIs, DNS, or generic admin URL tools.
- Fixtures must be synthetic or redacted. Never commit credentials, cookies,
  raw recipient exports, saved admin HTML from a live system, provider payloads,
  private headers, or local operator files.
- Public docs and examples must use placeholder hosts and paths.
- Keep dependencies shallow and consistent with `mcp-toolkit-rs`.
- Do not let `admin_html.rs`, `live.rs`, or `response.rs` become catch-all
  files. New capability slices should land in named modules with clear
  ownership boundaries and tests near the seam they protect.

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

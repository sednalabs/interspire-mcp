# Dependency Governance

This document defines dependency selection and upgrade policy for
`interspire-6-mcp`.

## Goal

Keep the server secure, maintainable, and release-friendly by preferring
well-maintained crates with clear operational risk signals.

## Go/No-Go Criteria

All new direct crates and major upgrades must meet every hard gate below.

1. `security`: No unresolved RustSec advisory for the selected version.
2. `license`: License is allowlisted by `deny.toml`.
3. `source`: Registry source is trusted. Public git dependencies must be
   explicitly allowlisted.
4. `maintenance`: Evidence of active maintenance.
5. `adoption/reputation`: Evidence the crate is broadly used or maintained by
   a trusted project.
6. `fit`: Clear justification that existing dependencies or the standard
   library cannot solve the need with lower risk.

If a hard gate fails, the dependency change is a no-go unless an explicit,
time-bounded exception is approved and documented.

## Required Evidence

Every dependency change should include a policy note in the associated pull
request:

```text
Dependency change note
- crate: <name> <old -> new>
- change type: <new | upgrade | removal>
- purpose: <why needed>
- alternatives considered: <stdlib/existing crates/other crates>
- maintenance evidence: <release recency + repo activity>
- adoption/reputation evidence: <reverse-deps/downloads/known users or maintainer org>
- security status: <cargo deny + cargo audit result>
- license status: <allowlisted license(s)>
- startup impact: <expected effect on cold start/steady state>
- rollback plan: <how to revert safely>
- exception (if any): <risk accepted, owner, expiry date>
```

## Enforcement

Install the local tool set:

```bash
cargo install --locked cargo-deny cargo-audit cargo-outdated
```

Run:

```bash
./scripts/dependency_governance_check.sh
```

The script enforces:

- advisory, license, ban, and source policy via `cargo-deny`;
- RustSec vulnerability checks via `cargo-audit`;
- direct dependency stale-risk reporting via `cargo-outdated`.

Outdated direct dependencies are report-only by default. To make them blocking:

```bash
STRICT_OUTDATED=1 ./scripts/dependency_governance_check.sh
```

## Current Exceptions

- `RUSTSEC-2025-0057` (`fxhash`): maintenance-status advisory inherited through
  `scraper -> selectors`. This is not a known vulnerability, but it is still
  dependency debt. Keep the exception visible in both `deny.toml` and
  `scripts/dependency_governance_check.sh`, and revisit it when replacing the
  HTML parsing stack or when `selectors` moves away from `fxhash`.

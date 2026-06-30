# Live Proof Matrix

This repository wraps newsletter control planes. A tool is not operationally
ready just because it compiles, appears in the MCP tool list, or was installed
from a hosted binary. For every new or materially changed capability, update
this matrix before coding and record the exact proof before handoff.

## Acceptance Rule

Each operational capability needs all of the following:

- a named workflow row below;
- fixture or unit coverage for the parser, route gate, redaction, and output
  contract;
- negative coverage for the most likely unsafe or misleading state;
- public docs and schema snapshot updates when the tool contract changes;
- hosted GitHub Actions validation for release candidates;
- hosted binary artifact plus checksum verification for installable binaries;
- configured-alias startup proof after install;
- live no-send proof on the target Interspire major version before operational
  use.

Tool listing, successful initialization, and checksum install are installation
proof only. They do not prove that the workflow is usable.

## Interspire 8 CommsWire Prep Matrix

| Workflow | Tool | Class | Required Proof | Negative Tests | Live No-Send Proof |
| --- | --- | --- | --- | --- | --- |
| Runtime posture | `interspire_status` | Read | Reports admin/XML configuration, gates, blocked operations, and version target. | Missing config, disabled risky gates, stale alias. | Status called after install/restart on the target alias. |
| Admin session | `interspire_admin_session_probe` | Read | Login succeeds and allowlisted read page loads; Send start page optional. | Bad CSRF/session, Access missing, blocked route. | Probe target admin with `include_send_start=true`; no queue/stat change. |
| Settings posture | `interspire_settings_audit` | Read | Redacted SMTP, bounce, throttle, unsubscribe, and cron fields. | Secret redaction, missing tab, cron omitted when requested. | Audit target settings; no form submit. |
| List ownership | `interspire_list_owner_readback` | Read | Existing list sender/reply/bounce metadata, redacted. | Capped output, HTML enrichment failure, email redaction. | Read target lists before and after list create/update. |
| List creation | `interspire_list_create_preview` / `interspire_list_create_apply` | Preview/apply | Preview finds the Interspire create form and source-derived `AddList` route; apply submits browser-equivalent hidden fields, selected controls, save control when named, Referer, Origin, and current page CSRF context, creates exactly one new list, then proves requested metadata on the new edit page, using a guarded post-create metadata save if Interspire ignored Bounce Email on create. | Missing form, stale plan, missing gates, wrong action route, missing/empty form CSRF with page-level CSRF present, duplicate new ids, field persistence mismatch, webhook/multi-select state loss. | Preview and apply on a disposable target list; reread list owner metadata and confirm local bounce polling was not enabled unless explicitly requested. |
| XML scaffold candidates | deferred XML list/newsletter scaffold tools | Preview/apply | Deployment-specific compatibility evidence may identify XML list/newsletter scaffold candidates, but no XML write tool is operational until request details, permission behavior, response shape, and post-write readback are fixture-proven. | Missing XML auth, method not allowlisted, permission denial, malformed details, ambiguous success, object not created/copied, redaction leak. | Deferred. If implemented, run on a disposable target object only, then prove list/campaign readback and queue/stats unchanged. |
| Campaign inventory | `interspire_campaign_readback` | Read | Returns redacted campaign manage rows plus structured campaign ids/action flags without admin URLs or CSRF tokens. | Linked campaign-name rows, token leakage, email leakage, capped output. | Read target campaign inventory and confirm the intended source campaign id before copy/edit. |
| Campaign copy | `interspire_campaign_copy_preview` / `interspire_campaign_copy_apply` | Preview/apply | Preview finds exact Copy route; apply creates exactly one new draft id. | Wrong campaign id, stale plan, duplicate id detection, route with extra params. | Copy a known disposable/source campaign; reread new campaign row. |
| Campaign template edit | `interspire_campaign_template_update_preview` / `interspire_campaign_template_update_apply` | Preview/apply | Preview resolves body controls; apply persists name/subject/body/tracking fields and rereads them. | Missing Step2 controls, stale plan, hidden field loss, tracking flag drift. | Apply a harmless draft-only change to a disposable draft; audit body after. |
| Campaign body audit | `interspire_campaign_body_audit` | Read/no-send proof | Counts unsubscribe tokens, URL protocols, images, alt text, links, and hashes without raw HTML. | Missing body form, raw HTML leakage, secret leakage. | Audit target draft and record warnings. |
| Render artifact | `interspire_campaign_render_artifact` | Private artifact | Writes private preview files under approved root and returns paths/hashes only. | Path traversal, disallowed root, raw HTML in response. | Render target draft to private artifact root; open separately for visual proof if needed. |
| CSV import preflight | `interspire_contact_import_preflight` | Read/local file proof | Reads only configured private roots; returns headers, aggregate counts, duplicates, invalid-looking count, and hash. | Disallowed root, `..`, non-CSV, raw row/email leakage. | Preflight a synthetic private CSV before any real audience artifact. |
| Queue/stat posture | `interspire_queue_stats_readback` | Read | Schedule and Stats rows redacted and capped. | Raw recipient leakage, capped warning, parse fallback. | Read before and after every no-send proof/apply operation. |
| Send wizard proof | `interspire_send_wizard_readback` / `interspire_seed_readiness_gate` | No-send proof | Renders only the final editable pre-send state, returns campaign/list/count/sender/tracking proof, and proves queue/stats unchanged. | Wrong list/campaign, count mismatch, send boundary attempted, queue/stat changed. | Render target draft/list through no-send proof only; no send, no schedule, no cron. |

Rows may be deferred only when the deferred state is recorded in Ops and the
operator workflow does not depend on that capability.

## Failure Handling

If any live proof fails:

1. Stop operational use of that capability.
2. File or update an Ops friction report with the exact redacted failure.
3. Add a fixture or regression test for the discovered shape.
4. Patch the MCP and rerun the affected row plus adjacent rows that depend on
   it.
5. Rebuild through hosted GitHub Actions, install with checksum verification,
   restart Codex, and repeat the live no-send proof before handoff.

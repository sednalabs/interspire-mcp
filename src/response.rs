//! MCP response contracts and redacted domain report shapes.
//!
//! Reports in this module are intentionally aggregate and redacted. They
//! distinguish source evidence from unproven readiness gates so an agent cannot
//! confuse list/campaign readback or queue cancellation with send
//! authorization.

mod audience;
mod common;
mod forms;
mod oci_ledger;
mod production_send;
mod queue;
mod render;
mod scaffold;
mod seed_send;
mod send_ops;
mod send_outcome;
mod send_wizard;
mod template;
mod test_send;

pub use audience::*;
pub use common::*;
pub use forms::*;
pub use oci_ledger::*;
pub use production_send::*;
pub use queue::*;
pub use render::*;
pub use scaffold::*;
pub use seed_send::*;
pub use send_ops::*;
pub use send_outcome::*;
pub use send_wizard::*;
pub use template::*;
pub use test_send::*;

pub fn sensitive_field_query_metadata() -> SensitiveToolMetadata {
    let meta = mcp_toolkit_core::mcp_apps::with_mcp_apps_sensitive_output_metadata(
        None,
        "unredacted_admin_form_values",
    );
    let security_schemes = meta
        .0
        .get(mcp_toolkit_core::mcp_apps::MCP_APPS_SECURITY_SCHEMES_META_KEY)
        .cloned()
        .unwrap_or_else(|| serde_json::json!([{"type": "noauth"}]));

    SensitiveToolMetadata {
        tool_family: "interspire_sensitive".to_string(),
        sensitivity: "unredacted_admin_form_values".to_string(),
        approval_required: true,
        apps_sdk_metadata: serde_json::json!({
            "name": "interspire_sensitive_field_query",
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            },
            "securitySchemes": security_schemes,
            "_meta": meta.0
        }),
    }
}

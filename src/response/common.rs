use crate::{config::WriteExecutionMode, error::InterspireError, redact};
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct StatusRequest {
    #[serde(default)]
    pub include_html_probe: bool,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListSummaryRequest {
    #[serde(default = "default_true")]
    pub include_html_enrichment: bool,
    /// Maximum list rows to return. Defaults to 25 and is capped at 100.
    #[serde(default = "default_list_read_limit")]
    #[schemars(range(min = 1, max = 100))]
    pub max_lists: usize,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ContactStateRequest {
    pub email: String,
    pub list_id: u64,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListOwnerReadbackRequest {
    #[serde(default)]
    pub max_lists: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SettingsAuditRequest {
    #[serde(default)]
    pub include_cron: bool,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct UserSmtpReadbackRequest {
    #[serde(default)]
    pub max_users: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct QueueStatsReadbackRequest {
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignReadbackRequest {
    #[serde(default)]
    pub campaign_id: Option<u64>,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub source: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub ok: bool,
    pub configured: bool,
    pub xml_configured: bool,
    pub admin_html_configured: bool,
    pub guarded_writes_enabled: bool,
    pub queue_controls_enabled: bool,
    pub form_write_controls_enabled: bool,
    pub contact_write_controls_enabled: bool,
    pub send_controls_enabled: bool,
    pub production_send_controls_enabled: bool,
    pub write_execution_mode: WriteExecutionMode,
    pub safe_mode: bool,
    pub capabilities: Vec<String>,
    pub blocked_operations: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListSummaryReport {
    pub ok: bool,
    pub configured: bool,
    pub lists: Vec<ListSummary>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListSummary {
    pub list_id: u64,
    pub name: String,
    pub subscribed_count: Option<u64>,
    pub unsubscribed_count: Option<u64>,
    pub autoresponder_count: Option<u64>,
    pub owner_name: Option<String>,
    pub owner_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactStateReport {
    pub ok: bool,
    pub configured: bool,
    pub list_id: u64,
    pub email_redacted: String,
    pub email_hash: String,
    pub found_on_list: Option<bool>,
    pub state: String,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListOwnerReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub lists: Vec<ListSummary>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsAuditReport {
    pub ok: bool,
    pub configured: bool,
    pub sections: Vec<SettingsSection>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsSection {
    pub name: String,
    pub fields: Vec<RedactedField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactedField {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSmtpReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub users: Vec<UserSmtpSummary>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSmtpSummary {
    pub user_id: u64,
    pub username: String,
    pub full_name: Option<String>,
    pub email_redacted: Option<String>,
    pub active: Option<bool>,
    pub smtp_type: Option<String>,
    pub smtp_server: Option<String>,
    pub smtp_username_redacted: Option<String>,
    pub smtp_port: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueStatsReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub scheduled_rows: Vec<String>,
    pub stats_rows: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: Option<u64>,
    pub campaign_fields: Vec<RedactedField>,
    pub campaign_rows: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Serialize)]
struct ToolError {
    ok: bool,
    error_code: String,
    message: String,
}

impl StatusReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            xml_configured: true,
            admin_html_configured: false,
            guarded_writes_enabled: false,
            queue_controls_enabled: false,
            form_write_controls_enabled: false,
            contact_write_controls_enabled: false,
            send_controls_enabled: false,
            production_send_controls_enabled: false,
            write_execution_mode: WriteExecutionMode::PreviewApply,
            safe_mode: true,
            capabilities: vec![
                "interspire_status".to_string(),
                "interspire_list_summary".to_string(),
                "interspire_contact_state".to_string(),
                "interspire_list_owner_readback".to_string(),
                "interspire_settings_audit".to_string(),
                "interspire_user_smtp_readback".to_string(),
                "interspire_queue_stats_readback".to_string(),
                "interspire_queue_control_preview".to_string(),
                "interspire_queue_control_apply".to_string(),
                "interspire_campaign_readback".to_string(),
                "interspire_campaign_update_preview".to_string(),
                "interspire_campaign_update_apply".to_string(),
                "interspire_list_update_preview".to_string(),
                "interspire_list_update_apply".to_string(),
                "interspire_user_update_preview".to_string(),
                "interspire_user_update_apply".to_string(),
                "interspire_settings_update_preview".to_string(),
                "interspire_settings_update_apply".to_string(),
                "interspire_warmup_audience_readiness".to_string(),
                "interspire_audience_hygiene_export".to_string(),
                "interspire_audience_hygiene_export_begin".to_string(),
                "interspire_audience_hygiene_export_resume".to_string(),
                "interspire_audience_hygiene_export_status".to_string(),
            ],
            blocked_operations: blocked_operations(),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl ListOwnerReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            lists: ListSummaryReport::fixture().lists,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl SettingsAuditReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            sections: vec![SettingsSection {
                name: "email".to_string(),
                fields: vec![
                    RedactedField {
                        name: "smtp_server".to_string(),
                        value: Some("[redacted-host]".to_string()),
                    },
                    RedactedField {
                        name: "force_unsublink".to_string(),
                        value: Some("1".to_string()),
                    },
                ],
            }],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl UserSmtpReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            users: vec![UserSmtpSummary {
                user_id: 1,
                username: "user-1".to_string(),
                full_name: Some("[redacted-name]".to_string()),
                email_redacted: Some(redact::redact_email("admin@example.com")),
                active: Some(true),
                smtp_type: Some("global".to_string()),
                smtp_server: Some("[redacted-host]".to_string()),
                smtp_username_redacted: Some("[redacted-username]".to_string()),
                smtp_port: Some("587".to_string()),
            }],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl QueueStatsReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            scheduled_rows: vec!["Campaign 7 sending in 5 minutes".to_string()],
            stats_rows: vec!["Campaign 7 sent count 42".to_string()],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl CampaignReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            campaign_id: Some(7),
            campaign_fields: vec![RedactedField {
                name: "subject".to_string(),
                value: Some("Example campaign".to_string()),
            }],
            campaign_rows: Vec::new(),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl ListSummaryReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            lists: vec![ListSummary {
                list_id: 7,
                name: "Editorial updates".to_string(),
                subscribed_count: Some(42),
                unsubscribed_count: Some(3),
                autoresponder_count: Some(0),
                owner_name: Some("[redacted-name]".to_string()),
                owner_email_redacted: Some(redact::redact_email("editor@example.com")),
                reply_to_email_redacted: Some(redact::redact_email("reply@example.com")),
                bounce_email_redacted: Some(redact::redact_email("bounce@example.com")),
                source: "fixture+xml+html".to_string(),
            }],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl ContactStateReport {
    pub fn fixture(email: &str, list_id: u64) -> Self {
        Self {
            ok: true,
            configured: true,
            list_id,
            email_redacted: redact::redact_email(email),
            email_hash: redact::email_hash(email),
            found_on_list: Some(true),
            state: "present_on_list".to_string(),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

pub fn blocked_operations() -> Vec<String> {
    [
        "send",
        "schedule",
        "cron_trigger",
        "queue_cancel_without_guarded_plan",
        "form_write_without_guarded_plan",
        "import",
        "generic_raw_contact_export",
        "recipient_export_without_private_artifact_guard",
        "delete_contacts",
        "unsubscribe",
        "resubscribe",
        "suppression_mutation",
        "dns_or_provider_mutation",
    ]
    .iter()
    .map(|value| (*value).to_string())
    .collect()
}

pub fn tool_json<T: Serialize>(result: Result<T, InterspireError>) -> String {
    let value = match result {
        Ok(report) => serde_json::to_value(report).unwrap_or_else(|err| {
            serde_json::json!({
                "ok": false,
                "error_code": "serialization_error",
                "message": err.to_string(),
            })
        }),
        Err(err) => serde_json::to_value(ToolError {
            ok: false,
            error_code: err.code().to_string(),
            message: redact::redact_sensitive_text(&err.to_string()),
        })
        .unwrap_or_else(|serialize_err| {
            serde_json::json!({
                "ok": false,
                "error_code": "serialization_error",
                "message": serialize_err.to_string(),
            })
        }),
    };

    serde_json::to_string_pretty(&value).unwrap_or_else(|err| {
        format!(
            "{{\"ok\":false,\"error_code\":\"serialization_error\",\"message\":\"{}\"}}",
            err
        )
    })
}

fn default_true() -> bool {
    true
}

pub const DEFAULT_LIST_READ_LIMIT: usize = 25;
pub const HARD_LIST_READ_LIMIT: usize = 100;

pub fn default_list_read_limit() -> usize {
    DEFAULT_LIST_READ_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_json_redacts_error_text_before_serializing() {
        let json = tool_json::<StatusReport>(Err(InterspireError::Http(
            "request failed for reporter@example.com at https://iem.example.net/admin/index.php; dns iem.example.net:443"
                .to_string(),
        )));
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid tool json");
        let message = value["message"].as_str().expect("message string");

        assert_eq!(value["ok"], false);
        assert_eq!(value["error_code"], "http_error");
        assert!(!message.contains("reporter"));
        assert!(!message.contains("example.com"));
        assert!(!message.contains("https://"));
        assert!(!message.contains("iem.example.net"));
        assert!(!message.contains(":443"));
        assert!(message.contains("[redacted-email]"));
        assert!(message.contains("[redacted-url]"));
        assert!(message.contains("[redacted-host]"));
    }

    #[test]
    fn tool_json_redacts_separated_secret_values_in_error_text() {
        let json = tool_json::<StatusReport>(Err(InterspireError::Http(
            r#"auth failed password: hunter2 token abc123 cookie = session-value api_key = key-secret "api_token": "quoted-secret""#
                .to_string(),
        )));
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid tool json");
        let message = value["message"].as_str().expect("message string");

        assert_eq!(value["ok"], false);
        assert_eq!(value["error_code"], "http_error");
        assert!(!message.contains("hunter2"));
        assert!(!message.contains("abc123"));
        assert!(!message.contains("session-value"));
        assert!(!message.contains("key-secret"));
        assert!(!message.contains("quoted-secret"));
    }
}

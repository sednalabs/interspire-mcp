use super::{Evidence, RedactedField};
use crate::config::WriteExecutionMode;
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct FormFieldUpdate {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub checked: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignUpdatePreviewRequest {
    pub campaign_id: u64,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignUpdateApplyRequest {
    pub campaign_id: u64,
    pub plan_id: String,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListUpdatePreviewRequest {
    pub list_id: u64,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListUpdateApplyRequest {
    pub list_id: u64,
    pub plan_id: String,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct UserUpdatePreviewRequest {
    pub user_id: u64,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct UserUpdateApplyRequest {
    pub user_id: u64,
    pub plan_id: String,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, rmcp::schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SettingsSectionName {
    Application,
    Email,
    Bounce,
    Cron,
}

impl SettingsSectionName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Email => "email",
            Self::Bounce => "bounce",
            Self::Cron => "cron",
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SettingsUpdatePreviewRequest {
    pub section: SettingsSectionName,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SettingsUpdateApplyRequest {
    pub section: SettingsSectionName,
    pub plan_id: String,
    #[serde(default)]
    pub updates: Vec<FormFieldUpdate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormFieldDescriptor {
    pub name: String,
    pub control_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormFieldChange {
    pub name: String,
    pub control_kind: String,
    pub current_value: Option<String>,
    pub requested_value: Option<String>,
    pub will_change: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardedWritePreviewReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub form_write_controls_enabled: bool,
    pub write_execution_mode: WriteExecutionMode,
    pub target: String,
    pub target_id: Option<u64>,
    pub section: Option<String>,
    pub plan_id: String,
    pub apply_directly_allowed: bool,
    pub available_fields: Vec<FormFieldDescriptor>,
    pub changes: Vec<FormFieldChange>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardedWriteApplyReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub form_write_controls_enabled: bool,
    pub write_execution_mode: WriteExecutionMode,
    pub target: String,
    pub target_id: Option<u64>,
    pub section: Option<String>,
    pub applied: bool,
    pub plan_id: String,
    pub changes: Vec<FormFieldChange>,
    pub post_apply_fields: Vec<RedactedField>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl GuardedWritePreviewReport {
    pub fn fixture(target: &str, target_id: Option<u64>, section: Option<&str>) -> Self {
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: true,
            form_write_controls_enabled: true,
            write_execution_mode: WriteExecutionMode::PreviewApply,
            target: target.to_string(),
            target_id,
            section: section.map(ToString::to_string),
            plan_id: "ifw_000000000000000000000000".to_string(),
            apply_directly_allowed: false,
            available_fields: vec![FormFieldDescriptor {
                name: "subject".to_string(),
                control_kind: "text".to_string(),
            }],
            changes: vec![FormFieldChange {
                name: "subject".to_string(),
                control_kind: "text".to_string(),
                current_value: Some("Before".to_string()),
                requested_value: Some("After".to_string()),
                will_change: true,
            }],
            warnings: vec!["preview only; apply requires guarded write enablement".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl GuardedWriteApplyReport {
    pub fn fixture(target: &str, target_id: Option<u64>, section: Option<&str>) -> Self {
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: true,
            form_write_controls_enabled: true,
            write_execution_mode: WriteExecutionMode::PreviewApply,
            target: target.to_string(),
            target_id,
            section: section.map(ToString::to_string),
            applied: true,
            plan_id: "ifw_000000000000000000000000".to_string(),
            changes: vec![FormFieldChange {
                name: "subject".to_string(),
                control_kind: "text".to_string(),
                current_value: Some("Before".to_string()),
                requested_value: Some("After".to_string()),
                will_change: true,
            }],
            post_apply_fields: vec![RedactedField {
                name: "subject".to_string(),
                value: Some("After".to_string()),
            }],
            warnings: vec!["fixture response; no live Interspire write occurred".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

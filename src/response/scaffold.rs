use super::{Evidence, FormFieldUpdate};
use crate::config::WriteExecutionMode;
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListCreatePreviewRequest {
    pub name: String,
    pub owner_name: String,
    pub owner_email: String,
    pub reply_to_email: String,
    pub bounce_email: String,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListCreateApplyRequest {
    pub plan_id: String,
    pub name: String,
    pub owner_name: String,
    pub owner_email: String,
    pub reply_to_email: String,
    pub bounce_email: String,
}

impl ListCreatePreviewRequest {
    pub fn updates(&self) -> Vec<FormFieldUpdate> {
        list_create_updates(
            &self.name,
            &self.owner_name,
            &self.owner_email,
            &self.reply_to_email,
            &self.bounce_email,
        )
    }
}

impl ListCreateApplyRequest {
    pub fn updates(&self) -> Vec<FormFieldUpdate> {
        list_create_updates(
            &self.name,
            &self.owner_name,
            &self.owner_email,
            &self.reply_to_email,
            &self.bounce_email,
        )
    }
}

fn list_create_updates(
    name: &str,
    owner_name: &str,
    owner_email: &str,
    reply_to_email: &str,
    bounce_email: &str,
) -> Vec<FormFieldUpdate> {
    [
        ("name", name),
        ("ownername", owner_name),
        ("owneremail", owner_email),
        ("replytoemail", reply_to_email),
        ("bounceemail", bounce_email),
    ]
    .into_iter()
    .map(|(name, value)| FormFieldUpdate {
        name: name.to_string(),
        value: Some(value.to_string()),
        checked: None,
    })
    .collect()
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignCopyPreviewRequest {
    pub source_campaign_id: u64,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignCopyApplyRequest {
    pub source_campaign_id: u64,
    pub plan_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignCopyPreviewReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub form_write_controls_enabled: bool,
    pub write_execution_mode: WriteExecutionMode,
    pub source_campaign_id: u64,
    pub plan_id: String,
    pub copy_candidate_found: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignCopyApplyReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub form_write_controls_enabled: bool,
    pub write_execution_mode: WriteExecutionMode,
    pub source_campaign_id: u64,
    pub plan_id: String,
    pub applied: bool,
    pub new_campaign_id: Option<u64>,
    pub new_campaign_row: Option<String>,
    pub source_campaign_readback: bool,
    pub new_campaign_readback: bool,
    pub copy_content_verified: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ContactImportPreflightRequest {
    pub csv_path: String,
    #[serde(default)]
    pub target_list_id: Option<u64>,
    #[serde(default)]
    pub email_column: Option<String>,
    #[serde(default)]
    pub expected_unique_emails: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactImportPreflightReport {
    pub ok: bool,
    pub configured: bool,
    pub target_list_id: Option<u64>,
    pub csv_path_redacted: String,
    pub csv_sha256: String,
    pub header_columns: Vec<String>,
    pub selected_email_column: Option<String>,
    pub data_row_count: u64,
    pub unique_email_count: u64,
    pub duplicate_email_count: u64,
    pub invalid_email_like_count: u64,
    pub expected_unique_emails: Option<u64>,
    pub expected_unique_match: Option<bool>,
    pub import_apply_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl CampaignCopyPreviewReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: true,
            form_write_controls_enabled: true,
            write_execution_mode: WriteExecutionMode::PreviewApply,
            source_campaign_id: 7,
            plan_id: "icp_000000000000000000000000".to_string(),
            copy_candidate_found: true,
            warnings: vec!["fixture response; no live Interspire write occurred".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl CampaignCopyApplyReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: true,
            form_write_controls_enabled: true,
            write_execution_mode: WriteExecutionMode::PreviewApply,
            source_campaign_id: 7,
            plan_id: "icp_000000000000000000000000".to_string(),
            applied: true,
            new_campaign_id: Some(8),
            new_campaign_row: Some("Copied campaign Active View Send Edit Copy Delete".to_string()),
            source_campaign_readback: true,
            new_campaign_readback: true,
            copy_content_verified: false,
            warnings: vec!["fixture response; no live Interspire write occurred".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl ContactImportPreflightReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            target_list_id: Some(1),
            csv_path_redacted: "[private-artifact]/contacts.csv".to_string(),
            csv_sha256: "0".repeat(64),
            header_columns: vec!["column_1".to_string()],
            selected_email_column: Some("column_1".to_string()),
            data_row_count: 1,
            unique_email_count: 1,
            duplicate_email_count: 0,
            invalid_email_like_count: 0,
            expected_unique_emails: Some(1),
            expected_unique_match: Some(true),
            import_apply_authorized: false,
            warnings: vec!["preflight only; no contacts were imported or mutated".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

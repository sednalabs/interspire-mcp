use super::{
    CampaignBodyAuditReport, Evidence, FormFieldUpdate, GuardedWriteApplyReport,
    GuardedWritePreviewReport,
};
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTemplateUpdatePreviewRequest {
    pub campaign_id: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
    #[serde(default)]
    pub send_multipart: Option<bool>,
    #[serde(default)]
    pub track_opens: Option<bool>,
    #[serde(default)]
    pub track_links: Option<bool>,
    #[serde(default)]
    pub embed_images: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTemplateUpdateApplyRequest {
    pub campaign_id: u64,
    pub plan_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
    #[serde(default)]
    pub send_multipart: Option<bool>,
    #[serde(default)]
    pub track_opens: Option<bool>,
    #[serde(default)]
    pub track_links: Option<bool>,
    #[serde(default)]
    pub embed_images: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTemplateArtifactUpdatePreviewRequest {
    pub campaign_id: u64,
    pub html_artifact_path: String,
    #[serde(default)]
    pub expected_html_sha256: Option<String>,
    #[serde(default)]
    pub expected_html_bytes: Option<u64>,
    #[serde(default)]
    pub text_artifact_path: Option<String>,
    #[serde(default)]
    pub expected_text_sha256: Option<String>,
    #[serde(default)]
    pub expected_text_bytes: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub send_multipart: Option<bool>,
    #[serde(default)]
    pub track_opens: Option<bool>,
    #[serde(default)]
    pub track_links: Option<bool>,
    #[serde(default)]
    pub embed_images: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTemplateArtifactUpdateApplyRequest {
    pub campaign_id: u64,
    pub plan_id: String,
    pub html_artifact_path: String,
    #[serde(default)]
    pub expected_html_sha256: Option<String>,
    #[serde(default)]
    pub expected_html_bytes: Option<u64>,
    #[serde(default)]
    pub text_artifact_path: Option<String>,
    #[serde(default)]
    pub expected_text_sha256: Option<String>,
    #[serde(default)]
    pub expected_text_bytes: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub send_multipart: Option<bool>,
    #[serde(default)]
    pub track_opens: Option<bool>,
    #[serde(default)]
    pub track_links: Option<bool>,
    #[serde(default)]
    pub embed_images: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateArtifactSummary {
    pub kind: String,
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignTemplateArtifactUpdatePreviewReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: u64,
    pub artifacts: Vec<TemplateArtifactSummary>,
    pub guarded_preview: GuardedWritePreviewReport,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignTemplateArtifactUpdateApplyReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: u64,
    pub artifacts: Vec<TemplateArtifactSummary>,
    pub guarded_apply: GuardedWriteApplyReport,
    pub campaign_body: CampaignBodyAuditReport,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl CampaignTemplateUpdatePreviewRequest {
    pub fn updates(&self) -> Vec<FormFieldUpdate> {
        template_updates(
            self.name.as_deref(),
            self.subject.as_deref(),
            self.html_body.as_deref(),
            self.text_body.as_deref(),
            self.send_multipart,
            self.track_opens,
            self.track_links,
            self.embed_images,
        )
    }
}

impl CampaignTemplateUpdateApplyRequest {
    pub fn updates(&self) -> Vec<FormFieldUpdate> {
        template_updates(
            self.name.as_deref(),
            self.subject.as_deref(),
            self.html_body.as_deref(),
            self.text_body.as_deref(),
            self.send_multipart,
            self.track_opens,
            self.track_links,
            self.embed_images,
        )
    }
}

impl CampaignTemplateArtifactUpdatePreviewRequest {
    pub fn updates_with_bodies(
        &self,
        html_body: &str,
        text_body: Option<&str>,
    ) -> Vec<FormFieldUpdate> {
        template_updates(
            self.name.as_deref(),
            self.subject.as_deref(),
            Some(html_body),
            text_body,
            self.send_multipart,
            self.track_opens,
            self.track_links,
            self.embed_images,
        )
    }
}

impl CampaignTemplateArtifactUpdateApplyRequest {
    pub fn updates_with_bodies(
        &self,
        html_body: &str,
        text_body: Option<&str>,
    ) -> Vec<FormFieldUpdate> {
        template_updates(
            self.name.as_deref(),
            self.subject.as_deref(),
            Some(html_body),
            text_body,
            self.send_multipart,
            self.track_opens,
            self.track_links,
            self.embed_images,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn template_updates(
    name: Option<&str>,
    subject: Option<&str>,
    html_body: Option<&str>,
    text_body: Option<&str>,
    send_multipart: Option<bool>,
    track_opens: Option<bool>,
    track_links: Option<bool>,
    embed_images: Option<bool>,
) -> Vec<FormFieldUpdate> {
    let mut updates = Vec::new();
    push_value(&mut updates, "name", name);
    push_value(&mut updates, "subject", subject);
    push_value(&mut updates, "html_body", html_body);
    push_value(&mut updates, "text_body", text_body);
    push_checked(&mut updates, "sendmultipart", send_multipart);
    push_checked(&mut updates, "trackopens", track_opens);
    push_checked(&mut updates, "tracklinks", track_links);
    push_checked(&mut updates, "embedimages", embed_images);
    updates
}

fn push_value(updates: &mut Vec<FormFieldUpdate>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        updates.push(FormFieldUpdate {
            name: name.to_string(),
            value: Some(value.to_string()),
            checked: None,
        });
    }
}

fn push_checked(updates: &mut Vec<FormFieldUpdate>, name: &str, checked: Option<bool>) {
    if let Some(checked) = checked {
        updates.push(FormFieldUpdate {
            name: name.to_string(),
            value: None,
            checked: Some(checked),
        });
    }
}

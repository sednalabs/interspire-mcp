use super::{CampaignBodyAuditReport, Evidence};
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignRenderArtifactRequest {
    pub campaign_id: u64,
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default)]
    pub artifact_prefix: Option<String>,
    #[serde(default)]
    pub include_image_blocked_variant: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderArtifact {
    pub kind: String,
    pub path: String,
    pub private: bool,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignRenderArtifactReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: u64,
    pub subject: Option<String>,
    pub html_sha256: Option<String>,
    pub html_bytes: usize,
    pub artifacts: Vec<RenderArtifact>,
    pub native_browser_next_step: String,
    pub campaign_body: CampaignBodyAuditReport,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl CampaignRenderArtifactReport {
    pub fn fixture() -> Self {
        let campaign_body = CampaignBodyAuditReport::fixture();
        Self {
            ok: true,
            configured: true,
            campaign_id: campaign_body.campaign_id,
            subject: campaign_body.subject.clone(),
            html_sha256: campaign_body.html_sha256.clone(),
            html_bytes: campaign_body.html_bytes,
            artifacts: vec![RenderArtifact {
                kind: "preview_index_html".to_string(),
                path: "/tmp/interspire-render/fixture-preview.html".to_string(),
                private: true,
                bytes: 1024,
                sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            }],
            native_browser_next_step:
                "Open the preview_index_html artifact with native browser and capture desktop/mobile screenshots."
                    .to_string(),
            campaign_body,
            production_send_authorized: false,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

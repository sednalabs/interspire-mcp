use super::Evidence;
use crate::redact;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct AdminSessionProbeRequest {
    /// Also prove the Send wizard start page can be read after login.
    #[serde(default)]
    pub include_send_start: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminSessionProbeReport {
    pub ok: bool,
    pub configured: bool,
    pub cloudflare_access_configured: bool,
    pub login_csrf_present: Option<bool>,
    pub login_established: bool,
    pub lists_page_read: bool,
    pub send_start_page_read: Option<bool>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignBodyAuditRequest {
    pub campaign_id: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignBodyAuditReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: u64,
    pub name: Option<String>,
    pub subject: Option<String>,
    pub preheader_sha256: Option<String>,
    pub html_sha256: Option<String>,
    pub html_bytes: usize,
    pub text_sha256: Option<String>,
    pub text_bytes: usize,
    pub unsubscribe_token_count: usize,
    pub html_unsubscribe_token_count: usize,
    pub text_unsubscribe_token_count: usize,
    pub http_url_count: usize,
    pub https_url_count: usize,
    pub mailto_count: usize,
    pub image_count: usize,
    pub missing_alt_image_count: usize,
    pub link_count: usize,
    pub visible_tracking_copy_detected: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SendWizardReadbackRequest {
    /// Interspire campaign/newsletter id expected on the final editable send form.
    pub campaign_id: u64,
    /// Interspire list ids to select for the no-send wizard proof.
    #[schemars(length(min = 1))]
    pub list_ids: Vec<u64>,
    /// Optional expected recipient count. When provided, a mismatch is reported as a warning.
    #[serde(default)]
    pub expected_recipient_count: Option<u64>,
    /// Maximum queue/stat rows to compare before and after the no-send wizard render.
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_queue_rows: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendWizardReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: u64,
    pub requested_list_ids: Vec<u64>,
    pub selected_list_ids: Vec<u64>,
    pub selected_campaign_id: Option<u64>,
    pub requested_campaign_available: bool,
    pub requested_list_ids_proven_by_recipient_count: bool,
    pub campaign_label: Option<String>,
    pub recipient_count: Option<u64>,
    pub from_name: Option<String>,
    pub from_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
    pub send_immediately_checked: Option<bool>,
    pub notify_owner_checked: Option<bool>,
    pub track_opens_checked: Option<bool>,
    pub track_links_checked: Option<bool>,
    pub multipart_checked: Option<bool>,
    pub embed_images_checked: Option<bool>,
    pub final_form_action_fingerprint: Option<String>,
    pub final_form_posts_to_send_boundary: bool,
    pub queue_rows_before: usize,
    pub queue_rows_after: usize,
    pub stats_rows_before: usize,
    pub stats_rows_after: usize,
    pub queue_unchanged: bool,
    pub stats_unchanged: bool,
    pub send_performed: bool,
    pub scheduled: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SeedReadinessGateRequest {
    pub campaign_id: u64,
    #[schemars(length(min = 1))]
    pub list_ids: Vec<u64>,
    #[serde(default)]
    pub expected_recipient_count: Option<u64>,
    #[serde(default)]
    pub expected_from_email: Option<String>,
    #[serde(default)]
    pub expected_reply_to_email: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeedReadinessGate {
    pub name: String,
    pub passed: bool,
    pub severity: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeedReadinessGateReport {
    pub ok: bool,
    pub configured: bool,
    pub ready_for_seed_approval: bool,
    pub campaign_id: u64,
    pub requested_list_ids: Vec<u64>,
    pub campaign_body: CampaignBodyAuditReport,
    pub send_wizard: SendWizardReadbackReport,
    pub gates: Vec<SeedReadinessGate>,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl AdminSessionProbeReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            cloudflare_access_configured: false,
            login_csrf_present: Some(true),
            login_established: true,
            lists_page_read: true,
            send_start_page_read: Some(true),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl CampaignBodyAuditReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            campaign_id: 7,
            name: Some("Launch campaign".to_string()),
            subject: Some("Launch subject".to_string()),
            preheader_sha256: Some(hex::encode(Sha256::digest(b"fixture preheader"))),
            html_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            html_bytes: 2048,
            text_sha256: Some(
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            ),
            text_bytes: 128,
            unsubscribe_token_count: 2,
            html_unsubscribe_token_count: 1,
            text_unsubscribe_token_count: 1,
            http_url_count: 0,
            https_url_count: 4,
            mailto_count: 1,
            image_count: 3,
            missing_alt_image_count: 0,
            link_count: 6,
            visible_tracking_copy_detected: false,
            production_send_authorized: false,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl SendWizardReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            campaign_id: 7,
            requested_list_ids: vec![3],
            selected_list_ids: vec![3],
            selected_campaign_id: Some(7),
            requested_campaign_available: true,
            requested_list_ids_proven_by_recipient_count: true,
            campaign_label: Some("Launch campaign".to_string()),
            recipient_count: Some(1),
            from_name: Some("Example Update".to_string()),
            from_email_redacted: Some(redact::redact_email("sender@example.invalid")),
            reply_to_email_redacted: Some(redact::redact_email("editor@example.invalid")),
            bounce_email_redacted: Some(redact::redact_email("bounces@example.invalid")),
            send_immediately_checked: Some(true),
            notify_owner_checked: Some(false),
            track_opens_checked: Some(true),
            track_links_checked: Some(true),
            multipart_checked: Some(true),
            embed_images_checked: Some(false),
            final_form_action_fingerprint: Some("route:000000000000".to_string()),
            final_form_posts_to_send_boundary: true,
            queue_rows_before: 0,
            queue_rows_after: 0,
            stats_rows_before: 0,
            stats_rows_after: 0,
            queue_unchanged: true,
            stats_unchanged: true,
            send_performed: false,
            scheduled: false,
            production_send_authorized: false,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl SeedReadinessGateReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            ready_for_seed_approval: true,
            campaign_id: 7,
            requested_list_ids: vec![3],
            campaign_body: CampaignBodyAuditReport::fixture(),
            send_wizard: SendWizardReadbackReport::fixture(),
            gates: vec![SeedReadinessGate {
                name: "queue_unchanged".to_string(),
                passed: true,
                severity: "blocker".to_string(),
                detail: "queue rows unchanged during no-send proof".to_string(),
            }],
            production_send_authorized: false,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

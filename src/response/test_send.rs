use super::{CampaignBodyAuditReport, Evidence};
use crate::redact;
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTestSendPreviewRequest {
    pub campaign_id: u64,
    pub recipient_email: String,
    pub from_preview_email: String,
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_queue_rows: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignTestSendPreviewReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: u64,
    pub recipient_email_redacted: String,
    pub from_preview_email_redacted: String,
    pub preview_digest: Option<String>,
    pub subject: Option<String>,
    pub html_sha256: Option<String>,
    pub html_bytes: usize,
    pub text_bytes: usize,
    pub preheader_present: bool,
    pub route_fingerprint: Option<String>,
    pub campaign_body: CampaignBodyAuditReport,
    pub send_performed: bool,
    pub queue_rows_before: usize,
    pub queue_rows_after: usize,
    pub stats_rows_before: usize,
    pub stats_rows_after: usize,
    pub queue_unchanged: bool,
    pub stats_unchanged: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTestSendApplyRequest {
    pub campaign_id: u64,
    pub recipient_email: String,
    pub from_preview_email: String,
    pub expected_preview_digest: String,
    pub expected_subject: String,
    pub expected_html_sha256: String,
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_queue_rows: Option<usize>,
    pub acknowledge_test_send: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignTestSendApplyReport {
    pub ok: bool,
    pub configured: bool,
    pub sent: bool,
    pub campaign_id: u64,
    pub recipient_email_redacted: String,
    pub from_preview_email_redacted: String,
    pub preview_digest: Option<String>,
    pub subject: Option<String>,
    pub html_sha256: Option<String>,
    pub html_bytes: usize,
    pub text_bytes: usize,
    pub preheader_present: bool,
    pub post_status_code: Option<u16>,
    pub response_message: Option<String>,
    pub campaign_body: CampaignBodyAuditReport,
    pub queue_rows_before: usize,
    pub queue_rows_after: usize,
    pub stats_rows_before: usize,
    pub stats_rows_after: usize,
    pub queue_unchanged: bool,
    pub stats_unchanged: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl CampaignTestSendPreviewReport {
    pub fn fixture() -> Self {
        let campaign_body = CampaignBodyAuditReport::fixture();
        Self {
            ok: true,
            configured: true,
            campaign_id: campaign_body.campaign_id,
            recipient_email_redacted: redact::redact_email("recipient@example.invalid"),
            from_preview_email_redacted: redact::redact_email("sender@example.invalid"),
            preview_digest: Some("0".repeat(64)),
            subject: campaign_body.subject.clone(),
            html_sha256: campaign_body.html_sha256.clone(),
            html_bytes: campaign_body.html_bytes,
            text_bytes: campaign_body.text_bytes,
            preheader_present: true,
            route_fingerprint: Some("route:000000000000".to_string()),
            campaign_body,
            send_performed: false,
            queue_rows_before: 0,
            queue_rows_after: 0,
            stats_rows_before: 0,
            stats_rows_after: 0,
            queue_unchanged: true,
            stats_unchanged: true,
            production_send_authorized: false,
            warnings: vec![
                "Interspire preview sends do not prove list-specific unsubscribe, custom fields, or production audience merge behavior".to_string(),
            ],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl CampaignTestSendApplyReport {
    pub fn denied(request: &CampaignTestSendApplyRequest, warning: impl Into<String>) -> Self {
        Self::denied_with_configured(request, warning, true)
    }

    pub fn denied_with_configured(
        request: &CampaignTestSendApplyRequest,
        warning: impl Into<String>,
        configured: bool,
    ) -> Self {
        Self {
            ok: false,
            configured,
            sent: false,
            campaign_id: request.campaign_id,
            recipient_email_redacted: redact::redact_email(&request.recipient_email),
            from_preview_email_redacted: redact::redact_email(&request.from_preview_email),
            preview_digest: Some(request.expected_preview_digest.clone()),
            subject: Some(redact::redact_sensitive_text(&request.expected_subject)),
            html_sha256: Some(request.expected_html_sha256.clone()),
            html_bytes: 0,
            text_bytes: 0,
            preheader_present: false,
            post_status_code: None,
            response_message: None,
            campaign_body: CampaignBodyAuditReport::fixture(),
            queue_rows_before: 0,
            queue_rows_after: 0,
            stats_rows_before: 0,
            stats_rows_after: 0,
            queue_unchanged: true,
            stats_unchanged: true,
            production_send_authorized: false,
            warnings: vec![redact::redact_sensitive_text(&warning.into())],
            evidence: Evidence {
                source: "interspire_admin_html".to_string(),
                notes: vec!["no preview send request sent".to_string()],
            },
        }
    }

    pub fn fixture() -> Self {
        let preview = CampaignTestSendPreviewReport::fixture();
        Self {
            ok: true,
            configured: true,
            sent: true,
            campaign_id: preview.campaign_id,
            recipient_email_redacted: preview.recipient_email_redacted,
            from_preview_email_redacted: preview.from_preview_email_redacted,
            preview_digest: preview.preview_digest,
            subject: preview.subject,
            html_sha256: preview.html_sha256,
            html_bytes: preview.html_bytes,
            text_bytes: preview.text_bytes,
            preheader_present: preview.preheader_present,
            post_status_code: Some(200),
            response_message: Some("preview email accepted by Interspire".to_string()),
            campaign_body: preview.campaign_body,
            queue_rows_before: 0,
            queue_rows_after: 0,
            stats_rows_before: 0,
            stats_rows_after: 0,
            queue_unchanged: true,
            stats_unchanged: true,
            production_send_authorized: false,
            warnings: preview.warnings,
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

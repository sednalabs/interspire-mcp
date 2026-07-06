use super::{
    CampaignBodyAuditReport, Evidence, OciLedgerPreflightReport, OciLedgerPreflightRequest,
    SeedReadinessGate, SendReconciliationReport, SendWizardReadbackReport,
};
use crate::redact;
use serde::Serialize;

pub const PRODUCTION_SEND_CONFIRMATION_PHRASE: &str = "SEND_PRODUCTION_CAMPAIGN";

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ProductionSendApplyRequest {
    pub campaign_id: u64,
    #[schemars(length(min = 1))]
    pub list_ids: Vec<u64>,
    #[schemars(range(min = 1))]
    pub expected_recipient_count: u64,
    pub expected_from_email: String,
    pub expected_reply_to_email: String,
    pub expected_subject: String,
    pub expected_html_sha256: String,
    #[serde(default)]
    pub ops_work_item_ref: Option<String>,
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_queue_rows: Option<usize>,
    #[serde(default)]
    pub oci_ledger_preflight: Option<OciLedgerPreflightRequest>,
    pub acknowledge_production_send: bool,
    pub confirmation_phrase: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductionSendApplyReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub send_controls_enabled: bool,
    pub production_send_controls_enabled: bool,
    pub sent: bool,
    pub campaign_id: u64,
    pub requested_list_ids: Vec<u64>,
    pub recipient_count: Option<u64>,
    pub from_name: Option<String>,
    pub from_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
    pub subject: Option<String>,
    pub html_sha256: Option<String>,
    pub ops_work_item_ref: Option<String>,
    pub gates: Vec<SeedReadinessGate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_wizard: Option<SendWizardReadbackReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign_body: Option<CampaignBodyAuditReport>,
    pub post_status_code: Option<u16>,
    pub post_redirected: bool,
    pub oci_ledger_preflight: OciLedgerPreflightReport,
    pub reconciliation: SendReconciliationReport,
    pub queue_rows_before: usize,
    pub queue_rows_after: usize,
    pub stats_rows_before: usize,
    pub stats_rows_after: usize,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

impl ProductionSendApplyReport {
    pub fn with_oci_ledger_preflight(mut self, report: OciLedgerPreflightReport) -> Self {
        self.oci_ledger_preflight = report;
        self
    }

    pub fn denied(
        request: &ProductionSendApplyRequest,
        guarded_writes_enabled: bool,
        send_controls_enabled: bool,
        production_send_controls_enabled: bool,
        warning: String,
    ) -> Self {
        Self {
            ok: false,
            configured: true,
            guarded_writes_enabled,
            send_controls_enabled,
            production_send_controls_enabled,
            sent: false,
            campaign_id: request.campaign_id,
            requested_list_ids: request.list_ids.clone(),
            recipient_count: None,
            from_name: None,
            from_email_redacted: Some(redact::redact_email(&request.expected_from_email)),
            reply_to_email_redacted: Some(redact::redact_email(&request.expected_reply_to_email)),
            bounce_email_redacted: None,
            subject: Some(redact::redact_sensitive_text(&request.expected_subject)),
            html_sha256: Some(request.expected_html_sha256.clone()),
            ops_work_item_ref: request.ops_work_item_ref.clone(),
            gates: Vec::new(),
            send_wizard: None,
            campaign_body: None,
            post_status_code: None,
            post_redirected: false,
            oci_ledger_preflight: OciLedgerPreflightReport::skipped(
                false,
                false,
                "send was refused before OCI ledger preflight",
            ),
            reconciliation: SendReconciliationReport::refused(
                0,
                0,
                0,
                0,
                "no production send request sent".to_string(),
            ),
            queue_rows_before: 0,
            queue_rows_after: 0,
            stats_rows_before: 0,
            stats_rows_after: 0,
            production_send_authorized: false,
            warnings: vec![redact::redact_sensitive_text(&warning)],
            evidence: Evidence {
                source: "interspire_admin_html".to_string(),
                notes: vec!["no production send request sent".to_string()],
            },
        }
    }

    pub fn fixture() -> Self {
        let send_wizard = SendWizardReadbackReport::fixture();
        let campaign_body = CampaignBodyAuditReport::fixture();
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: true,
            send_controls_enabled: true,
            production_send_controls_enabled: true,
            sent: true,
            campaign_id: send_wizard.campaign_id,
            requested_list_ids: send_wizard.requested_list_ids.clone(),
            recipient_count: send_wizard.recipient_count,
            from_name: send_wizard.from_name.clone(),
            from_email_redacted: send_wizard.from_email_redacted.clone(),
            reply_to_email_redacted: send_wizard.reply_to_email_redacted.clone(),
            bounce_email_redacted: send_wizard.bounce_email_redacted.clone(),
            subject: campaign_body.subject.clone(),
            html_sha256: campaign_body.html_sha256.clone(),
            ops_work_item_ref: Some("w0000".to_string()),
            gates: vec![SeedReadinessGate {
                name: "production_send_acknowledged".to_string(),
                passed: true,
                severity: "blocker".to_string(),
                detail: "production send was explicitly acknowledged".to_string(),
            }],
            send_wizard: Some(send_wizard),
            campaign_body: Some(campaign_body),
            post_status_code: Some(302),
            post_redirected: true,
            oci_ledger_preflight: OciLedgerPreflightReport::fixture_verified(),
            reconciliation: SendReconciliationReport::fixture_production(),
            queue_rows_before: 0,
            queue_rows_after: 0,
            stats_rows_before: 0,
            stats_rows_after: 1,
            production_send_authorized: true,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

use crate::redact;
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct OciLedgerPreflightRequest {
    #[schemars(length(min = 1, max = 200))]
    pub campaign_id: String,
    #[schemars(length(min = 1, max = 200))]
    pub batch_id: String,
    #[schemars(range(min = 1))]
    pub expected_rows: u64,
    #[serde(default)]
    #[schemars(length(min = 1, max = 253))]
    pub sender_domain: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub expected_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct OciSendLedgerPreparePreviewRequest {
    #[schemars(length(min = 1, max = 200))]
    pub campaign_id: String,
    #[schemars(length(min = 1, max = 200))]
    pub batch_id: String,
    #[schemars(range(min = 1))]
    pub expected_rows: u64,
    #[schemars(length(min = 1, max = 253))]
    pub sender_domain: String,
    #[schemars(length(min = 1, max = 4096))]
    pub manifest_path: String,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub expected_manifest_sha256: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 1, max = 320))]
    pub approved_sender: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub template_sha256: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub subject_sha256: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct OciSendLedgerPrepareApplyRequest {
    #[schemars(length(min = 1, max = 200))]
    pub campaign_id: String,
    #[schemars(length(min = 1, max = 200))]
    pub batch_id: String,
    #[schemars(range(min = 1))]
    pub expected_rows: u64,
    #[schemars(length(min = 1, max = 253))]
    pub sender_domain: String,
    #[schemars(length(min = 1, max = 4096))]
    pub manifest_path: String,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub expected_manifest_sha256: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 1, max = 320))]
    pub approved_sender: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub template_sha256: Option<String>,
    #[serde(default)]
    #[schemars(length(min = 64, max = 64))]
    pub subject_sha256: Option<String>,
    #[schemars(length(min = 1, max = 80))]
    pub expected_plan_id: String,
    #[serde(default)]
    pub acknowledge_ledger_write: bool,
}

impl OciSendLedgerPrepareApplyRequest {
    pub fn preview_request(&self) -> OciSendLedgerPreparePreviewRequest {
        OciSendLedgerPreparePreviewRequest {
            campaign_id: self.campaign_id.clone(),
            batch_id: self.batch_id.clone(),
            expected_rows: self.expected_rows,
            sender_domain: self.sender_domain.clone(),
            manifest_path: self.manifest_path.clone(),
            expected_manifest_sha256: self.expected_manifest_sha256.clone(),
            approved_sender: self.approved_sender.clone(),
            template_sha256: self.template_sha256.clone(),
            subject_sha256: self.subject_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OciLedgerPreflightReport {
    pub required: bool,
    pub configured: bool,
    pub requested: bool,
    pub verified: bool,
    pub campaign_hash: Option<String>,
    pub batch_hash: Option<String>,
    pub sender_domain: Option<String>,
    pub expected_rows: Option<u64>,
    pub matched_rows: u64,
    pub rows_with_recipient_key: u64,
    pub rows_with_trace_key: u64,
    pub invalid_rows: u64,
    pub manifest_sha256: Option<String>,
    pub raw_payload_returned: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OciSendLedgerPrepareReport {
    pub ok: bool,
    pub configured: bool,
    pub apply: bool,
    pub guarded_writes_enabled: bool,
    pub send_controls_enabled: bool,
    pub ledger_written: bool,
    pub already_present: bool,
    pub appended_rows: u64,
    pub validated_manifest_rows: u64,
    pub expected_rows: u64,
    pub duplicate_recipient_key_count: u64,
    pub duplicate_trace_key_count: u64,
    pub campaign_hash: String,
    pub batch_hash: String,
    pub sender_domain: Option<String>,
    pub manifest_sha256: Option<String>,
    pub approved_sender_hash: Option<String>,
    pub template_sha256: Option<String>,
    pub subject_sha256: Option<String>,
    pub plan_id: Option<String>,
    pub expected_plan_match: Option<bool>,
    pub oci_ledger_preflight: OciLedgerPreflightReport,
    pub send_authorized: bool,
    pub production_send_authorized: bool,
    pub raw_payload_returned: bool,
    pub warnings: Vec<String>,
    pub evidence: super::Evidence,
}

impl OciLedgerPreflightReport {
    pub fn skipped(required: bool, configured: bool, note: &str) -> Self {
        Self {
            required,
            configured,
            requested: false,
            verified: !required,
            campaign_hash: None,
            batch_hash: None,
            sender_domain: None,
            expected_rows: None,
            matched_rows: 0,
            rows_with_recipient_key: 0,
            rows_with_trace_key: 0,
            invalid_rows: 0,
            manifest_sha256: None,
            raw_payload_returned: false,
            warnings: vec![note.to_string()],
        }
    }

    pub fn blocked(
        required: bool,
        configured: bool,
        request: Option<&OciLedgerPreflightRequest>,
        warning: String,
    ) -> Self {
        Self {
            required,
            configured,
            requested: request.is_some(),
            verified: false,
            campaign_hash: request.map(|item| short_hash(&item.campaign_id)),
            batch_hash: request.map(|item| short_hash(&item.batch_id)),
            sender_domain: None,
            expected_rows: request.map(|item| item.expected_rows),
            matched_rows: 0,
            rows_with_recipient_key: 0,
            rows_with_trace_key: 0,
            invalid_rows: 0,
            manifest_sha256: None,
            raw_payload_returned: false,
            warnings: vec![redact::redact_sensitive_text(&warning)],
        }
    }

    pub fn fixture_verified() -> Self {
        Self {
            required: true,
            configured: true,
            requested: true,
            verified: true,
            campaign_hash: Some(short_hash("fixture-campaign")),
            batch_hash: Some(short_hash("fixture-batch")),
            sender_domain: Some("example.invalid".to_string()),
            expected_rows: Some(1),
            matched_rows: 1,
            rows_with_recipient_key: 1,
            rows_with_trace_key: 1,
            invalid_rows: 0,
            manifest_sha256: None,
            raw_payload_returned: false,
            warnings: Vec::new(),
        }
    }
}

impl OciSendLedgerPrepareReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            apply: false,
            guarded_writes_enabled: false,
            send_controls_enabled: false,
            ledger_written: false,
            already_present: false,
            appended_rows: 0,
            validated_manifest_rows: 1,
            expected_rows: 1,
            duplicate_recipient_key_count: 0,
            duplicate_trace_key_count: 0,
            campaign_hash: short_hash("fixture-campaign"),
            batch_hash: short_hash("fixture-batch"),
            sender_domain: Some("example.invalid".to_string()),
            manifest_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            approved_sender_hash: Some(short_hash("sender@example.invalid")),
            template_sha256: None,
            subject_sha256: None,
            plan_id: Some("iqc_fixture_oci_ledger".to_string()),
            expected_plan_match: None,
            oci_ledger_preflight: OciLedgerPreflightReport::fixture_verified(),
            send_authorized: false,
            production_send_authorized: false,
            raw_payload_returned: false,
            warnings: Vec::new(),
            evidence: super::Evidence {
                source: "fixture_private_oci_send_ledger_manifest".to_string(),
                notes: vec!["fixture no-send ledger prepare report".to_string()],
            },
        }
    }
}

pub(crate) fn short_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let normalized = value.trim().to_ascii_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    hex::encode(&digest[..10])
}

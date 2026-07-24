use super::Evidence;
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct QueueControlPreviewRequest {
    /// Maximum rows per queue source to inspect. Defaults to 100 and is capped at 100.
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct QueueControlApplyRequest {
    pub plan_id: String,
    pub action: QueueControlAction,
    /// Explicit acknowledgement that this call may mutate one queue job.
    pub acknowledge_queue_mutation: bool,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, rmcp::schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QueueControlAction {
    Cancel,
    Delete,
    Pause,
    Resume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueControlSource {
    Schedule,
    CampaignManage,
}

impl QueueControlSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::CampaignManage => "campaign_manage",
        }
    }
}

impl QueueControlAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Delete => "delete",
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueControlCandidate {
    pub plan_id: String,
    pub action: QueueControlAction,
    pub source: QueueControlSource,
    pub campaign_id: Option<u64>,
    pub action_label: String,
    pub row_summary: String,
    pub route_fingerprint: String,
    pub requires_guarded_write: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueControlPreviewReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub queue_controls_enabled: bool,
    pub candidates: Vec<QueueControlCandidate>,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueControlApplyReport {
    pub ok: bool,
    pub configured: bool,
    pub guarded_writes_enabled: bool,
    pub queue_controls_enabled: bool,
    pub status: QueueControlApplyStatus,
    pub applied: bool,
    pub plan_id: Option<String>,
    pub action: QueueControlAction,
    pub before_candidate_count: usize,
    pub before_row_summary: Option<String>,
    pub after_candidate_count: usize,
    pub after_row_still_present: bool,
    pub after_matching_action_still_available: bool,
    pub after_target_actions: Vec<QueueControlAction>,
    pub legacy_lists_mutated: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueControlApplyStatus {
    AppliedProven,
    Blocked,
}

impl QueueControlPreviewReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: false,
            queue_controls_enabled: false,
            candidates: vec![QueueControlCandidate {
                plan_id: "iqc_000000000000000000000000".to_string(),
                action: QueueControlAction::Cancel,
                source: QueueControlSource::Schedule,
                campaign_id: None,
                action_label: "Cancel".to_string(),
                row_summary: "Campaign 7 scheduled for later".to_string(),
                route_fingerprint: "route:000000000000".to_string(),
                requires_guarded_write: true,
            }],
            production_send_authorized: false,
            warnings: vec!["preview only; apply requires guarded write enablement".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl QueueControlApplyReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            guarded_writes_enabled: true,
            queue_controls_enabled: true,
            status: QueueControlApplyStatus::AppliedProven,
            applied: true,
            plan_id: Some("iqc_000000000000000000000000".to_string()),
            action: QueueControlAction::Cancel,
            before_candidate_count: 1,
            before_row_summary: Some("Campaign 7 scheduled for later".to_string()),
            after_candidate_count: 0,
            after_row_still_present: false,
            after_matching_action_still_available: false,
            after_target_actions: Vec::new(),
            legacy_lists_mutated: false,
            production_send_authorized: false,
            warnings: vec!["fixture response; no live Interspire write occurred".to_string()],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

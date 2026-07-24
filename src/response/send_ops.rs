use super::{
    Evidence, OciLedgerPreflightReport, OciLedgerPreflightRequest, QueueControlAction,
    QueueControlSource,
};
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SendJobStatusReadbackRequest {
    pub expected_job_id: u64,
    #[serde(default)]
    pub expected_campaign_id: Option<u64>,
    #[serde(default)]
    pub expected_list_ids: Vec<u64>,
    #[serde(default)]
    pub expected_queue_total: Option<u64>,
    #[serde(default)]
    pub expected_body_sha256: Option<String>,
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, Serialize, rmcp::schemars::JsonSchema)]
pub struct SendJobFollowUpContract {
    pub job_id: u64,
    pub campaign_id: u64,
    pub list_ids: Vec<u64>,
    pub expected_queue_total: u64,
    pub body_sha256: Option<String>,
    pub status_tool: String,
}

impl SendJobFollowUpContract {
    pub fn new(
        job_id: u64,
        campaign_id: u64,
        list_ids: Vec<u64>,
        expected_queue_total: u64,
        body_sha256: Option<String>,
    ) -> Self {
        Self {
            job_id,
            campaign_id,
            list_ids,
            expected_queue_total,
            body_sha256,
            status_tool: "interspire_send_job_status_readback".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SendJobStatusReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub identity_verified: bool,
    pub job_id: u64,
    pub campaign_id: Option<u64>,
    pub list_ids: Vec<u64>,
    pub expected_queue_total: Option<u64>,
    pub schedule: SendJobScheduleState,
    pub stats: SendJobStatsState,
    pub queue_counters: SendJobQueueCounters,
    pub unsent_reason_aggregates: Vec<UnsentReasonAggregate>,
    pub follow_up_contract: Option<SendJobFollowUpContract>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendJobScheduleState {
    pub matched_rows: usize,
    pub row_summaries: Vec<String>,
    pub available_actions: Vec<QueueControlAction>,
    pub action_plans: Vec<SendJobActionPlan>,
    pub sent_count: Option<u64>,
    pub total_count: Option<u64>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendJobActionPlan {
    pub action: QueueControlAction,
    pub source: QueueControlSource,
    pub plan_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendJobStatsState {
    pub matched_rows: usize,
    pub row_summaries: Vec<String>,
    pub sent_count: Option<u64>,
    pub failed_count: Option<u64>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SendJobQueueCounters {
    pub source: String,
    pub total: Option<u64>,
    pub processed: Option<u64>,
    pub unprocessed: Option<u64>,
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnsentReasonAggregate {
    pub reason_redacted: String,
    pub count: u64,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CronReadinessRequest {
    #[serde(default)]
    pub include_settings_inventory: bool,
    #[serde(default)]
    #[schemars(range(min = 1, max = 500))]
    pub max_fields_per_section: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CronReadinessReport {
    pub ok: bool,
    pub configured: bool,
    pub application_cron_configured: bool,
    pub server_runner_proven: bool,
    pub production_send_ready: bool,
    pub cron_fields: Vec<CronFieldSummary>,
    pub schedule_warnings: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CronFieldSummary {
    pub name: String,
    pub value_redacted: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SendStopGateReadinessRequest {
    pub expected_job_id: u64,
    #[serde(default)]
    pub expected_campaign_id: Option<u64>,
    #[serde(default)]
    pub expected_list_ids: Vec<u64>,
    #[serde(default)]
    pub expected_queue_total: Option<u64>,
    #[serde(default)]
    pub oci_ledger_preflight: Option<OciLedgerPreflightRequest>,
    #[serde(default = "default_hard_bounce_pause_threshold")]
    #[schemars(range(min = 0.0, max = 1.0))]
    pub hard_bounce_pause_threshold: f64,
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendStopGateReadinessReport {
    pub ok: bool,
    pub configured: bool,
    pub recommended_action: StopGateAction,
    pub hard_bounce_rate: Option<f64>,
    pub hard_bounce_pause_threshold: f64,
    pub interspire_status: SendJobStatusReadbackReport,
    pub oci_ledger_preflight: OciLedgerPreflightReport,
    pub pause_plan_id: Option<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopGateAction {
    Continue,
    Hold,
    PauseAvailable,
    PauseUnavailable,
}

fn default_hard_bounce_pause_threshold() -> f64 {
    0.02
}

impl SendJobStatusReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            identity_verified: true,
            job_id: 13,
            campaign_id: Some(2),
            list_ids: vec![12],
            expected_queue_total: Some(100),
            schedule: SendJobScheduleState {
                matched_rows: 1,
                row_summaries: vec!["Campaign 2 In Progress (Sent to 63 / 100)".to_string()],
                available_actions: vec![QueueControlAction::Pause],
                action_plans: vec![SendJobActionPlan {
                    action: QueueControlAction::Pause,
                    source: QueueControlSource::Schedule,
                    plan_id: "iqc_fixture_pause".to_string(),
                }],
                sent_count: Some(63),
                total_count: Some(100),
                state: "active".to_string(),
            },
            stats: SendJobStatsState {
                matched_rows: 0,
                row_summaries: Vec::new(),
                sent_count: None,
                failed_count: None,
                state: "pending".to_string(),
            },
            queue_counters: SendJobQueueCounters {
                source: "admin_html_schedule".to_string(),
                total: Some(100),
                processed: Some(63),
                unprocessed: Some(37),
                unavailable_reason: Some(
                    "direct Interspire queue table counters are not configured for this public MCP"
                        .to_string(),
                ),
            },
            unsent_reason_aggregates: Vec::new(),
            follow_up_contract: Some(SendJobFollowUpContract::new(
                13,
                2,
                vec![12],
                100,
                Some(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                ),
            )),
            warnings: vec![
                "unsent reason aggregates require a reviewed private table source; none was configured"
                    .to_string(),
            ],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic send job status fixture".to_string()],
            },
        }
    }
}

impl CronReadinessReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            application_cron_configured: false,
            server_runner_proven: false,
            production_send_ready: false,
            cron_fields: vec![
                CronFieldSummary {
                    name: "cron_enabled".to_string(),
                    value_redacted: Some("0".to_string()),
                },
                CronFieldSummary {
                    name: "cron_send".to_string(),
                    value_redacted: Some("5".to_string()),
                },
            ],
            schedule_warnings: vec!["Interspire reports cron.php has not run recently".to_string()],
            warnings: vec![
                "Interspire master cron checkbox is not enabled".to_string(),
                "Interspire application cron settings were not proven enabled".to_string(),
                "server cron runner was not proven by this MCP; production sends should hold"
                    .to_string(),
            ],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic cron readiness fixture".to_string()],
            },
        }
    }
}

impl SendStopGateReadinessReport {
    pub fn fixture() -> Self {
        let status = SendJobStatusReadbackReport::fixture();
        Self {
            ok: true,
            configured: true,
            recommended_action: StopGateAction::PauseAvailable,
            hard_bounce_rate: Some(0.04),
            hard_bounce_pause_threshold: 0.02,
            pause_plan_id: status
                .follow_up_contract
                .as_ref()
                .map(|_| "iqc_fixture_pause".to_string()),
            interspire_status: status,
            oci_ledger_preflight: OciLedgerPreflightReport::fixture_verified(),
            warnings: vec![
                "hard bounce rate meets or exceeds the configured pause threshold".to_string(),
            ],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic stop-gate readiness fixture".to_string()],
            },
        }
    }
}

use super::SendJobFollowUpContract;
use crate::redact;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SendApplyStatus {
    Refused,
    Posted,
    Queued,
    Processed,
    TransportFailed,
    DeliveredUnverified,
    SeedProven,
}

impl SendApplyStatus {
    pub fn terminal_success(self) -> bool {
        matches!(
            self,
            Self::Processed | Self::DeliveredUnverified | Self::SeedProven
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SendReconciliationReport {
    pub status: SendApplyStatus,
    pub job_id: Option<u64>,
    pub follow_up_contract: Option<SendJobFollowUpContract>,
    pub queue_id: Option<u64>,
    pub stat_id: Option<u64>,
    pub sent_count: Option<u64>,
    pub failed_count: Option<u64>,
    pub unsent_count: Option<u64>,
    pub smtp_reason_redacted: Option<String>,
    pub popup_steps: usize,
    pub queue_rows_before: usize,
    pub queue_rows_after: usize,
    pub stats_rows_before: usize,
    pub stats_rows_after: usize,
    pub proof_gaps: Vec<String>,
    pub notes: Vec<String>,
}

impl SendReconciliationReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: SendApplyStatus,
        job_id: Option<u64>,
        queue_id: Option<u64>,
        stat_id: Option<u64>,
        sent_count: Option<u64>,
        failed_count: Option<u64>,
        unsent_count: Option<u64>,
        smtp_reason: Option<String>,
        popup_steps: usize,
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
        proof_gaps: Vec<String>,
        notes: Vec<String>,
    ) -> Self {
        Self {
            status,
            job_id,
            follow_up_contract: None,
            queue_id,
            stat_id,
            sent_count,
            failed_count,
            unsent_count,
            smtp_reason_redacted: smtp_reason.map(|reason| redact::redact_sensitive_text(&reason)),
            popup_steps,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            proof_gaps: proof_gaps
                .into_iter()
                .map(|gap| redact::redact_sensitive_text(&gap))
                .collect(),
            notes: notes
                .into_iter()
                .map(|note| redact::redact_sensitive_text(&note))
                .collect(),
        }
    }

    pub fn with_follow_up_contract(mut self, contract: Option<SendJobFollowUpContract>) -> Self {
        self.follow_up_contract = contract;
        self
    }

    pub fn refused(
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
        note: String,
    ) -> Self {
        Self::new(
            SendApplyStatus::Refused,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            vec!["send was refused before the Interspire final send boundary".to_string()],
            vec![note],
        )
    }

    pub fn from_boundary_post(
        posted: bool,
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
    ) -> Self {
        let status = if posted {
            SendApplyStatus::Posted
        } else {
            SendApplyStatus::Refused
        };
        let proof_gaps = if posted {
            vec!["post-send queue/stats processing was not proven".to_string()]
        } else {
            vec!["final send boundary was not posted".to_string()]
        };
        Self::new(
            status,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            proof_gaps,
            Vec::new(),
        )
    }

    pub fn fixture_seed() -> Self {
        Self::new(
            SendApplyStatus::SeedProven,
            Some(2),
            None,
            Some(1),
            Some(1),
            Some(0),
            Some(0),
            None,
            2,
            0,
            0,
            0,
            1,
            vec!["provider inbox delivery still requires external readback".to_string()],
            vec!["synthetic fixture".to_string()],
        )
    }

    pub fn fixture_production() -> Self {
        Self::new(
            SendApplyStatus::Processed,
            Some(2),
            None,
            Some(1),
            Some(1),
            Some(0),
            Some(0),
            None,
            2,
            0,
            0,
            0,
            1,
            vec![
                "provider delivery, bounces, and complaints require external monitoring"
                    .to_string(),
            ],
            vec!["synthetic fixture".to_string()],
        )
    }
}

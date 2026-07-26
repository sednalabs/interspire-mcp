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
    #[serde(skip)]
    terminal_identity_bound: bool,
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
        Self::new_internal(
            status,
            job_id,
            queue_id,
            stat_id,
            sent_count,
            failed_count,
            unsent_count,
            smtp_reason,
            popup_steps,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            proof_gaps,
            notes,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_internal(
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
        terminal_identity_bound: bool,
    ) -> Self {
        let mut proof_gaps = proof_gaps;
        let job_id = job_id.and_then(|id| {
            if id == 0 {
                proof_gaps.push("job identity must be a positive integer".to_string());
                None
            } else {
                Some(id)
            }
        });
        let stat_id = stat_id.and_then(|id| {
            if id == 0 {
                proof_gaps.push("Stats identity must be a positive integer".to_string());
                None
            } else {
                Some(id)
            }
        });
        let terminal_identity_bound =
            terminal_identity_bound && job_id.is_some() && stat_id.is_some();
        let terminal_transport_conflict = status.terminal_success() && smtp_reason.is_some();
        let terminal_claim_downgraded =
            status.terminal_success() && !terminal_identity_bound && !terminal_transport_conflict;
        let status = if terminal_transport_conflict {
            proof_gaps.push(
                "a terminal success claim conflicted with transport-failure evidence".to_string(),
            );
            SendApplyStatus::TransportFailed
        } else if terminal_claim_downgraded {
            if job_id.is_some() {
                SendApplyStatus::Queued
            } else {
                SendApplyStatus::Posted
            }
        } else {
            status
        };
        if terminal_claim_downgraded {
            proof_gaps.push(
                "terminal application proof requires bound positive job and durable Stats identities from verified readback"
                    .to_string(),
            );
        }
        let counts_authorized =
            status.terminal_success() && terminal_identity_bound && smtp_reason.is_none();
        let (sent_count, failed_count, unsent_count) = if counts_authorized {
            (sent_count, failed_count, unsent_count)
        } else {
            (None, None, None)
        };
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
            terminal_identity_bound,
        }
    }

    pub fn terminal_application_proven(&self) -> bool {
        self.status.terminal_success()
            && self.terminal_identity_bound
            && self.job_id.is_some_and(|id| id > 0)
            && self.stat_id.is_some_and(|id| id > 0)
            && self.smtp_reason_redacted.is_none()
    }

    pub fn with_follow_up_contract(mut self, contract: Option<SendJobFollowUpContract>) -> Self {
        self.follow_up_contract = contract;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn processed_with_bound_identity(
        job_id: u64,
        stat_id: u64,
        sent_count: u64,
        popup_steps: usize,
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
        notes: Vec<String>,
    ) -> Self {
        Self::new_internal(
            SendApplyStatus::Processed,
            Some(job_id),
            None,
            Some(stat_id),
            Some(sent_count),
            None,
            None,
            None,
            popup_steps,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            Vec::new(),
            notes,
            true,
        )
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
        Self::new_internal(
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
            true,
        )
    }

    pub fn fixture_production() -> Self {
        Self::new_internal(
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
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{SendApplyStatus, SendReconciliationReport};

    fn reconciliation(
        status: SendApplyStatus,
        job_id: Option<u64>,
        stat_id: Option<u64>,
    ) -> SendReconciliationReport {
        SendReconciliationReport::new(
            status,
            job_id,
            None,
            stat_id,
            Some(25),
            Some(0),
            Some(0),
            None,
            1,
            0,
            0,
            0,
            usize::from(stat_id.is_some()),
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn send_reconciliation_terminal_proof_requires_bound_readback_not_presence_only_ids() {
        let missing_stats_identity = reconciliation(SendApplyStatus::Processed, Some(41), None);

        assert_eq!(missing_stats_identity.status, SendApplyStatus::Queued);
        assert!(!missing_stats_identity.terminal_application_proven());
        assert_eq!(missing_stats_identity.sent_count, None);
        assert_eq!(missing_stats_identity.failed_count, None);
        assert_eq!(missing_stats_identity.unsent_count, None);
        assert!(missing_stats_identity
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("bound positive job")));

        let unbound_ids = reconciliation(SendApplyStatus::Processed, Some(41), Some(73));

        assert_eq!(unbound_ids.status, SendApplyStatus::Queued);
        assert!(!unbound_ids.terminal_application_proven());
        assert_eq!(unbound_ids.sent_count, None);
        assert!(unbound_ids
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("verified readback")));
    }

    #[test]
    fn send_reconciliation_terminal_proof_downgrades_missing_job_to_posted() {
        let missing_job = reconciliation(SendApplyStatus::SeedProven, None, Some(73));

        assert_eq!(missing_job.status, SendApplyStatus::Posted);
        assert!(!missing_job.terminal_application_proven());
        assert_eq!(missing_job.sent_count, None);
    }

    #[test]
    fn send_reconciliation_terminal_controls_preserve_nonterminal_states() {
        let refused = reconciliation(SendApplyStatus::Refused, None, None);
        let posted = reconciliation(SendApplyStatus::Posted, None, None);
        let queued = reconciliation(SendApplyStatus::Queued, Some(41), None);

        assert_eq!(refused.status, SendApplyStatus::Refused);
        assert_eq!(posted.status, SendApplyStatus::Posted);
        assert_eq!(queued.status, SendApplyStatus::Queued);
        assert!(!refused.terminal_application_proven());
        assert!(!posted.terminal_application_proven());
        assert!(!queued.terminal_application_proven());
    }

    #[test]
    fn send_reconciliation_terminal_proof_rejects_zero_identities_and_transport_conflict() {
        let zero_identities =
            reconciliation(SendApplyStatus::DeliveredUnverified, Some(0), Some(0));
        let transport_conflict = SendReconciliationReport::new(
            SendApplyStatus::Processed,
            Some(41),
            None,
            Some(73),
            Some(25),
            Some(0),
            Some(0),
            Some("synthetic transport failure".to_string()),
            1,
            0,
            0,
            0,
            1,
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(zero_identities.status, SendApplyStatus::Posted);
        assert_eq!(zero_identities.job_id, None);
        assert_eq!(zero_identities.stat_id, None);
        assert_eq!(zero_identities.sent_count, None);
        assert!(zero_identities
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("positive integer")));

        assert_eq!(transport_conflict.status, SendApplyStatus::TransportFailed);
        assert!(!transport_conflict.terminal_application_proven());
        assert_eq!(transport_conflict.sent_count, None);
        assert!(transport_conflict
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("transport-failure evidence")));
    }

    #[test]
    fn synthetic_terminal_fixtures_use_the_internal_bound_identity_path() {
        let seed = SendReconciliationReport::fixture_seed();
        let production = SendReconciliationReport::fixture_production();

        assert_eq!(seed.status, SendApplyStatus::SeedProven);
        assert!(seed.terminal_application_proven());
        assert_eq!(production.status, SendApplyStatus::Processed);
        assert!(production.terminal_application_proven());
    }
}

use super::SendJobFollowUpContract;
use crate::redact;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SendApplyStatus {
    Refused,
    ResponseUncertain,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SendUncertaintyDecision {
    HoldDoNotRetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SendUncertaintyIdentityState {
    NoNewJob,
    AmbiguousOrUnbound,
    ReadbackIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SendUncertaintyNextAction {
    HoldForBoundedReadOnlyReconciliation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SendBaselineCaptureStage {
    FinalPreDispatch,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendUncertaintyRecoveryContract {
    pub decision: SendUncertaintyDecision,
    pub retry_authorized: bool,
    pub mutation_authorized: bool,
    pub terminal_success_authorized: bool,
    pub baselines_authenticated: bool,
    pub baselines_captured_before_dispatch: bool,
    pub baseline_capture_stage: SendBaselineCaptureStage,
    pub baseline_context_verified: bool,
    pub baseline_identity_stable: bool,
    pub baseline_inventory_complete: bool,
    pub reconciliation_attempted_in_same_invocation: bool,
    pub baseline_max_rows: usize,
    pub campaign_id: u64,
    pub list_ids: Vec<u64>,
    pub expected_recipient_count: u64,
    pub expected_body_sha256: Option<String>,
    pub schedule_job_ids_before: Vec<u64>,
    pub manage_job_ids_before: Vec<u64>,
    pub campaign_job_ids_before: Vec<u64>,
    pub stats_ids_before: Vec<u64>,
    pub readback_complete: bool,
    pub identity_state: SendUncertaintyIdentityState,
    pub observed_job_id: Option<u64>,
    pub next_action: SendUncertaintyNextAction,
    pub status_follow_up: Option<SendJobFollowUpContract>,
    pub guidance: String,
}

impl SendUncertaintyRecoveryContract {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hold(
        campaign_id: u64,
        list_ids: Vec<u64>,
        expected_recipient_count: u64,
        expected_body_sha256: Option<String>,
        schedule_job_ids_before: Vec<u64>,
        manage_job_ids_before: Vec<u64>,
        campaign_job_ids_before: Vec<u64>,
        stats_ids_before: Vec<u64>,
        baseline_max_rows: usize,
        baseline_capture_stage: SendBaselineCaptureStage,
        baseline_context_verified: bool,
        baseline_identity_stable: bool,
        baseline_inventory_complete: bool,
        readback_complete: bool,
        identity_state: SendUncertaintyIdentityState,
    ) -> Self {
        let identity_state = if !baseline_context_verified
            || !baseline_identity_stable
            || !baseline_inventory_complete
        {
            SendUncertaintyIdentityState::ReadbackIncomplete
        } else {
            identity_state
        };
        let readback_complete = baseline_context_verified
            && baseline_identity_stable
            && baseline_inventory_complete
            && readback_complete
            && !matches!(
                identity_state,
                SendUncertaintyIdentityState::ReadbackIncomplete
            );
        let guidance = match identity_state {
            SendUncertaintyIdentityState::NoNewJob =>
                "Hold and do not retry or resend. Repeat only bounded read-only Schedule, Manage, and Stats reconciliation from the captured baseline; absence of a new identity does not prove non-receipt."
                    .to_string(),
            SendUncertaintyIdentityState::AmbiguousOrUnbound =>
                "Hold and do not retry or resend. Queue-only identities remain unbound to this request even with campaign association; never choose by row order, labels, counts, timing, or singleton difference."
                    .to_string(),
            SendUncertaintyIdentityState::ReadbackIncomplete =>
                "Hold and do not retry or resend. Restore complete authenticated bounded Schedule, Manage, and Stats reads before reconciliation; partial or capped state cannot prove absence or success."
                    .to_string(),
        };
        Self {
            decision: SendUncertaintyDecision::HoldDoNotRetry,
            retry_authorized: false,
            mutation_authorized: false,
            terminal_success_authorized: false,
            baselines_authenticated: true,
            baselines_captured_before_dispatch: true,
            baseline_capture_stage,
            baseline_context_verified,
            baseline_identity_stable,
            baseline_inventory_complete,
            reconciliation_attempted_in_same_invocation: true,
            baseline_max_rows,
            campaign_id,
            list_ids,
            expected_recipient_count,
            expected_body_sha256,
            schedule_job_ids_before,
            manage_job_ids_before,
            campaign_job_ids_before,
            stats_ids_before,
            readback_complete,
            identity_state,
            observed_job_id: None,
            next_action: SendUncertaintyNextAction::HoldForBoundedReadOnlyReconciliation,
            status_follow_up: None,
            guidance,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SendReconciliationReport {
    pub status: SendApplyStatus,
    pub job_id: Option<u64>,
    pub follow_up_contract: Option<SendJobFollowUpContract>,
    pub uncertainty_recovery_contract: Option<SendUncertaintyRecoveryContract>,
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
            uncertainty_recovery_contract: None,
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
        self.follow_up_contract = if matches!(self.status, SendApplyStatus::ResponseUncertain) {
            None
        } else {
            contract
        };
        self
    }

    pub(crate) fn with_uncertainty_recovery_contract(
        mut self,
        contract: Option<SendUncertaintyRecoveryContract>,
    ) -> Self {
        self.uncertainty_recovery_contract =
            if matches!(self.status, SendApplyStatus::ResponseUncertain) {
                contract
            } else {
                None
            };
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
    use super::{
        SendApplyStatus, SendBaselineCaptureStage, SendReconciliationReport,
        SendUncertaintyDecision, SendUncertaintyIdentityState, SendUncertaintyNextAction,
        SendUncertaintyRecoveryContract,
    };
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
        let response_uncertain = reconciliation(SendApplyStatus::ResponseUncertain, None, None);
        let posted = reconciliation(SendApplyStatus::Posted, None, None);
        let queued = reconciliation(SendApplyStatus::Queued, Some(41), None);

        assert_eq!(refused.status, SendApplyStatus::Refused);
        assert_eq!(
            response_uncertain.status,
            SendApplyStatus::ResponseUncertain
        );
        assert_eq!(posted.status, SendApplyStatus::Posted);
        assert_eq!(queued.status, SendApplyStatus::Queued);
        assert!(!refused.terminal_application_proven());
        assert!(!response_uncertain.terminal_application_proven());
        assert!(!posted.terminal_application_proven());
        assert!(!queued.terminal_application_proven());
    }

    #[test]
    fn uncertainty_recovery_contract_is_a_closed_hold_do_not_retry_authority() {
        let recovery = SendUncertaintyRecoveryContract::hold(
            9001,
            vec![8001],
            25,
            Some("synthetic-body-sha256".to_string()),
            vec![41],
            vec![41],
            vec![41],
            vec![70],
            25,
            SendBaselineCaptureStage::FinalPreDispatch,
            true,
            true,
            true,
            true,
            SendUncertaintyIdentityState::AmbiguousOrUnbound,
        );

        assert_eq!(recovery.decision, SendUncertaintyDecision::HoldDoNotRetry);
        assert!(!recovery.retry_authorized);
        assert!(!recovery.mutation_authorized);
        assert!(!recovery.terminal_success_authorized);
        assert!(recovery.baselines_authenticated);
        assert!(recovery.baselines_captured_before_dispatch);
        assert_eq!(
            recovery.baseline_capture_stage,
            SendBaselineCaptureStage::FinalPreDispatch
        );
        assert!(recovery.baseline_context_verified);
        assert!(recovery.baseline_identity_stable);
        assert!(recovery.baseline_inventory_complete);
        assert!(recovery.reconciliation_attempted_in_same_invocation);
        assert_eq!(recovery.schedule_job_ids_before, vec![41]);
        assert_eq!(recovery.manage_job_ids_before, vec![41]);
        assert_eq!(recovery.campaign_job_ids_before, vec![41]);
        assert_eq!(recovery.stats_ids_before, vec![70]);
        assert_eq!(
            recovery.next_action,
            SendUncertaintyNextAction::HoldForBoundedReadOnlyReconciliation
        );
        assert_eq!(recovery.observed_job_id, None);
        assert!(recovery.status_follow_up.is_none());
        assert!(recovery.guidance.contains("do not retry or resend"));
        assert!(recovery.guidance.contains("singleton difference"));

        let unstable = SendUncertaintyRecoveryContract::hold(
            9001,
            vec![8001],
            25,
            Some("synthetic-body-sha256".to_string()),
            vec![41],
            vec![41],
            vec![41],
            vec![70],
            25,
            SendBaselineCaptureStage::FinalPreDispatch,
            true,
            false,
            true,
            true,
            SendUncertaintyIdentityState::NoNewJob,
        );
        assert_eq!(
            unstable.identity_state,
            SendUncertaintyIdentityState::ReadbackIncomplete
        );
        assert!(!unstable.readback_complete);
        assert!(unstable.status_follow_up.is_none());
        assert!(!unstable.retry_authorized);
        assert!(!unstable.mutation_authorized);
        assert!(!unstable.terminal_success_authorized);

        let non_uncertain = reconciliation(SendApplyStatus::Queued, Some(43), None)
            .with_uncertainty_recovery_contract(Some(recovery.clone()));
        assert!(non_uncertain.uncertainty_recovery_contract.is_none());

        let report = reconciliation(SendApplyStatus::ResponseUncertain, Some(43), None)
            .with_follow_up_contract(recovery.status_follow_up.clone())
            .with_uncertainty_recovery_contract(Some(recovery));
        assert!(report.follow_up_contract.is_none());
        assert!(report.uncertainty_recovery_contract.is_some());
        assert!(!report.terminal_application_proven());
        let serialized =
            serde_json::to_value(&report).unwrap_or_else(|err| panic!("serialize: {err}"));
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["decision"],
            "hold_do_not_retry"
        );
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["retry_authorized"],
            false
        );
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["baseline_capture_stage"],
            "final_pre_dispatch"
        );
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["baseline_identity_stable"],
            true
        );
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["manage_job_ids_before"],
            serde_json::json!([41])
        );
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["campaign_job_ids_before"],
            serde_json::json!([41])
        );
        assert_eq!(
            serialized["uncertainty_recovery_contract"]["terminal_success_authorized"],
            false
        );
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

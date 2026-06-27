//! MCP response contracts and redacted domain report shapes.
//!
//! Reports in this module are intentionally aggregate and redacted. They
//! distinguish source evidence from unproven readiness gates so an agent cannot
//! confuse list/campaign readback or queue cancellation with send
//! authorization.

use crate::{error::InterspireError, redact};
use serde::Serialize;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct StatusRequest {
    #[serde(default)]
    pub include_html_probe: bool,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListSummaryRequest {
    #[serde(default = "default_true")]
    pub include_html_enrichment: bool,
    /// Maximum list rows to return. Defaults to 25 and is capped at 100.
    #[serde(default = "default_list_read_limit")]
    #[schemars(range(min = 1, max = 100))]
    pub max_lists: usize,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ContactStateRequest {
    pub email: String,
    pub list_id: u64,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListOwnerReadbackRequest {
    #[serde(default)]
    pub max_lists: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SettingsAuditRequest {
    #[serde(default)]
    pub include_cron: bool,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct UserSmtpReadbackRequest {
    #[serde(default)]
    pub max_users: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct QueueStatsReadbackRequest {
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct QueueControlPreviewRequest {
    /// Maximum scheduled rows to inspect. Defaults to 25 and is capped at 100.
    #[serde(default)]
    #[schemars(range(min = 1, max = 100))]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct QueueControlApplyRequest {
    pub plan_id: String,
    pub action: QueueControlAction,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignReadbackRequest {
    #[serde(default)]
    pub campaign_id: Option<u64>,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct WarmupAudienceReadinessRequest {
    #[serde(default = "default_warmup_source_list_ids")]
    pub source_list_ids: Vec<u64>,
    #[serde(default = "default_warmup_priority_list_ids")]
    pub priority_list_ids: Vec<u64>,
    #[serde(default = "default_warmup_tranche_sizes")]
    pub tranche_sizes: Vec<u64>,
    #[serde(default)]
    pub include_html_enrichment: bool,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct AudienceHygieneExportRequest {
    #[serde(default = "default_warmup_source_list_ids")]
    pub source_list_ids: Vec<u64>,
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default)]
    pub artifact_prefix: Option<String>,
    #[serde(default = "default_true")]
    pub include_sqlite: bool,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct AudienceHygieneExportBeginRequest {
    #[serde(default = "default_warmup_source_list_ids")]
    pub source_list_ids: Vec<u64>,
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default)]
    pub artifact_prefix: Option<String>,
    #[serde(default = "default_true")]
    pub include_sqlite: bool,
    #[serde(default = "default_hygiene_query_budget")]
    #[schemars(range(min = 1, max = 25))]
    pub max_queries_per_call: usize,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct AudienceHygieneExportResumeRequest {
    pub job_id: String,
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default = "default_hygiene_query_budget")]
    #[schemars(range(min = 1, max = 25))]
    pub max_queries_per_call: usize,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct AudienceHygieneExportStatusRequest {
    pub job_id: String,
    #[serde(default)]
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub source: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub ok: bool,
    pub configured: bool,
    pub xml_configured: bool,
    pub admin_html_configured: bool,
    pub guarded_writes_enabled: bool,
    pub queue_controls_enabled: bool,
    pub safe_mode: bool,
    pub capabilities: Vec<String>,
    pub blocked_operations: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListSummaryReport {
    pub ok: bool,
    pub configured: bool,
    pub lists: Vec<ListSummary>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListSummary {
    pub list_id: u64,
    pub name: String,
    pub subscribed_count: Option<u64>,
    pub unsubscribed_count: Option<u64>,
    pub autoresponder_count: Option<u64>,
    pub owner_name: Option<String>,
    pub owner_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactStateReport {
    pub ok: bool,
    pub configured: bool,
    pub list_id: u64,
    pub email_redacted: String,
    pub email_hash: String,
    pub found_on_list: Option<bool>,
    pub state: String,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListOwnerReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub lists: Vec<ListSummary>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsAuditReport {
    pub ok: bool,
    pub configured: bool,
    pub sections: Vec<SettingsSection>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsSection {
    pub name: String,
    pub fields: Vec<RedactedField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactedField {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSmtpReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub users: Vec<UserSmtpSummary>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSmtpSummary {
    pub user_id: u64,
    pub username: String,
    pub full_name: Option<String>,
    pub email_redacted: Option<String>,
    pub active: Option<bool>,
    pub smtp_type: Option<String>,
    pub smtp_server: Option<String>,
    pub smtp_username_redacted: Option<String>,
    pub smtp_port: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueStatsReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub scheduled_rows: Vec<String>,
    pub stats_rows: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, rmcp::schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QueueControlAction {
    Cancel,
    Delete,
}

impl QueueControlAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueControlCandidate {
    pub plan_id: String,
    pub action: QueueControlAction,
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
    pub applied: bool,
    pub plan_id: String,
    pub action: QueueControlAction,
    pub before_candidate_count: usize,
    pub before_row_summary: Option<String>,
    pub after_candidate_count: usize,
    pub after_row_still_present: bool,
    pub legacy_lists_mutated: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CampaignReadbackReport {
    pub ok: bool,
    pub configured: bool,
    pub campaign_id: Option<u64>,
    pub campaign_fields: Vec<RedactedField>,
    pub campaign_rows: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct WarmupAudienceReadinessReport {
    pub ok: bool,
    pub configured: bool,
    pub source_list_ids: Vec<u64>,
    pub matched_lists: Vec<WarmupListReadiness>,
    pub missing_list_ids: Vec<u64>,
    pub gross_subscribed_count: u64,
    pub gross_unsubscribed_count: u64,
    pub gross_autoresponder_count: u64,
    pub eligibility_rules: Vec<String>,
    pub tranche_plan: Vec<WarmupTrancheReadiness>,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct WarmupListReadiness {
    pub list_id: u64,
    pub name: String,
    pub subscribed_count: Option<u64>,
    pub unsubscribed_count: Option<u64>,
    pub priority_tier: String,
    pub owner_name: Option<String>,
    pub owner_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WarmupTrancheReadiness {
    pub target_count: u64,
    pub status: String,
    pub source_preference: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AudienceHygieneExportReport {
    pub ok: bool,
    pub configured: bool,
    pub job_id: Option<String>,
    pub phase: Option<String>,
    pub job_dir: Option<String>,
    pub source_list_ids: Vec<u64>,
    pub processed_list_count: u64,
    pub remaining_list_ids: Vec<u64>,
    pub missing_list_ids: Vec<u64>,
    pub active_list_id: Option<u64>,
    pub active_list_name: Option<String>,
    pub queries_processed_this_call: u64,
    pub completed_query_count: u64,
    pub remaining_query_count: u64,
    pub lists: Vec<AudienceHygieneListSummary>,
    pub gross_api_items: u64,
    pub eligible_items_before_dedupe: u64,
    pub deduped_eligible_count: u64,
    pub duplicate_eligible_items_removed: u64,
    pub excluded_unconfirmed: u64,
    pub excluded_unsubscribed: u64,
    pub excluded_bounced: u64,
    pub invalid_syntax_count: u64,
    pub role_localpart_count: u64,
    pub disposable_domain_hint_count: u64,
    pub checkpoint_artifacts: Vec<AudienceHygieneArtifact>,
    pub artifacts: Vec<AudienceHygieneArtifact>,
    pub legacy_lists_mutated: bool,
    pub production_send_authorized: bool,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AudienceHygieneListSummary {
    pub list_id: u64,
    pub name: String,
    pub api_items: u64,
    pub eligible_items_before_dedupe: u64,
    pub excluded_unconfirmed: u64,
    pub excluded_unsubscribed: u64,
    pub excluded_bounced: u64,
    pub invalid_syntax: u64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AudienceHygieneArtifact {
    pub kind: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub contains_raw_recipient_data: bool,
}

#[derive(Debug, Serialize)]
struct ToolError {
    ok: bool,
    error_code: String,
    message: String,
}

impl StatusReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            xml_configured: true,
            admin_html_configured: false,
            guarded_writes_enabled: false,
            queue_controls_enabled: false,
            safe_mode: true,
            capabilities: vec![
                "interspire_status".to_string(),
                "interspire_list_summary".to_string(),
                "interspire_contact_state".to_string(),
                "interspire_list_owner_readback".to_string(),
                "interspire_settings_audit".to_string(),
                "interspire_user_smtp_readback".to_string(),
                "interspire_queue_stats_readback".to_string(),
                "interspire_queue_control_preview".to_string(),
                "interspire_queue_control_apply".to_string(),
                "interspire_campaign_readback".to_string(),
                "interspire_warmup_audience_readiness".to_string(),
                "interspire_audience_hygiene_export".to_string(),
                "interspire_audience_hygiene_export_begin".to_string(),
                "interspire_audience_hygiene_export_resume".to_string(),
                "interspire_audience_hygiene_export_status".to_string(),
            ],
            blocked_operations: blocked_operations(),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl ListOwnerReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            lists: ListSummaryReport::fixture().lists,
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl SettingsAuditReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            sections: vec![SettingsSection {
                name: "email".to_string(),
                fields: vec![
                    RedactedField {
                        name: "smtp_server".to_string(),
                        value: Some("[redacted-host]".to_string()),
                    },
                    RedactedField {
                        name: "force_unsublink".to_string(),
                        value: Some("1".to_string()),
                    },
                ],
            }],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl UserSmtpReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            users: vec![UserSmtpSummary {
                user_id: 1,
                username: "user-1".to_string(),
                full_name: Some("[redacted-name]".to_string()),
                email_redacted: Some(redact::redact_email("admin@example.com")),
                active: Some(true),
                smtp_type: Some("global".to_string()),
                smtp_server: Some("[redacted-host]".to_string()),
                smtp_username_redacted: Some("[redacted-username]".to_string()),
                smtp_port: Some("587".to_string()),
            }],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl QueueStatsReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            scheduled_rows: vec!["Campaign 7 sending in 5 minutes".to_string()],
            stats_rows: vec!["Campaign 7 sent count 42".to_string()],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
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
            applied: true,
            plan_id: "iqc_000000000000000000000000".to_string(),
            action: QueueControlAction::Cancel,
            before_candidate_count: 1,
            before_row_summary: Some("Campaign 7 scheduled for later".to_string()),
            after_candidate_count: 0,
            after_row_still_present: false,
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

impl CampaignReadbackReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            campaign_id: Some(7),
            campaign_fields: vec![RedactedField {
                name: "subject".to_string(),
                value: Some("Example campaign".to_string()),
            }],
            campaign_rows: Vec::new(),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl WarmupAudienceReadinessReport {
    pub fn from_lists(
        request: &WarmupAudienceReadinessRequest,
        lists: Vec<ListSummary>,
        mut warnings: Vec<String>,
        evidence: Evidence,
    ) -> Self {
        let source_list_ids = approved_warmup_source_list_ids(request);
        let priority_list_ids = approved_warmup_priority_list_ids(request, &source_list_ids);
        let blocked_source_list_ids =
            blocked_warmup_source_list_ids(&normalized_ids(&request.source_list_ids));
        if !blocked_source_list_ids.is_empty() {
            warnings.push(format!(
                "ignored source list ids outside the warm-up request policy: {}",
                join_ids(&blocked_source_list_ids)
            ));
        }
        let requested_priority_list_ids = normalized_ids(&request.priority_list_ids);
        let blocked_priority_list_ids = requested_priority_list_ids
            .iter()
            .copied()
            .filter(|list_id| !priority_list_ids.contains(list_id))
            .collect::<Vec<_>>();
        if !blocked_priority_list_ids.is_empty() {
            warnings.push(format!(
                "ignored priority list ids outside effective warm-up source set: {}",
                join_ids(&blocked_priority_list_ids)
            ));
        }
        let mut matched_lists = Vec::new();
        let mut missing_list_ids = Vec::new();
        let mut gross_subscribed_count = 0;
        let mut gross_unsubscribed_count = 0;
        let mut gross_autoresponder_count = 0;

        for list_id in &source_list_ids {
            let Some(list) = lists.iter().find(|candidate| candidate.list_id == *list_id) else {
                missing_list_ids.push(*list_id);
                continue;
            };

            gross_subscribed_count += list.subscribed_count.unwrap_or(0);
            gross_unsubscribed_count += list.unsubscribed_count.unwrap_or(0);
            gross_autoresponder_count += list.autoresponder_count.unwrap_or(0);

            let mut notes = Vec::new();
            if list.subscribed_count.is_none() {
                notes.push("subscribed count unavailable from XML list readback".to_string());
            }
            if list.owner_email_redacted.is_none()
                || list.reply_to_email_redacted.is_none()
                || list.bounce_email_redacted.is_none()
            {
                notes.push("sender metadata not fully enriched from admin HTML".to_string());
            }

            matched_lists.push(WarmupListReadiness {
                list_id: *list_id,
                name: list.name.clone(),
                subscribed_count: list.subscribed_count,
                unsubscribed_count: list.unsubscribed_count,
                priority_tier: if priority_list_ids.contains(list_id) {
                    "priority_recent".to_string()
                } else {
                    "later_ramp".to_string()
                },
                owner_name: list.owner_name.clone(),
                owner_email_redacted: list.owner_email_redacted.clone(),
                reply_to_email_redacted: list.reply_to_email_redacted.clone(),
                bounce_email_redacted: list.bounce_email_redacted.clone(),
                notes,
            });
        }

        if source_list_ids.is_empty() {
            warnings.push(
                "no explicit warm-up source list ids were provided after safety filtering"
                    .to_string(),
            );
        } else if missing_list_ids.is_empty() {
            warnings.push(
                "Specified source list universe matched Interspire list readback".to_string(),
            );
        } else {
            warnings.push(format!(
                "missing specified source list ids: {}",
                join_ids(&missing_list_ids)
            ));
        }
        warnings.push(
            "Gross counts are not deduped and do not prove confirmed-only, engagement, suppression, bounce, complaint, or provider reconciliation state"
                .to_string(),
        );
        warnings.push(
            "This readback is not send authorization; production tranches still require the Interspire production send gate"
                .to_string(),
        );

        let tranche_plan = defaulted_tranche_sizes(&request.tranche_sizes)
            .into_iter()
            .map(|target_count| WarmupTrancheReadiness {
                target_count,
                status: if gross_subscribed_count >= target_count {
                    "gross_count_available_not_eligible_count".to_string()
                } else {
                    "insufficient_gross_count".to_string()
                },
                source_preference: if priority_list_ids.is_empty() {
                    "specified source list universe only".to_string()
                } else {
                    format!("priority list ids first: {}", join_ids(&priority_list_ids))
                },
            })
            .collect();

        Self {
            ok: true,
            configured: true,
            source_list_ids,
            matched_lists,
            missing_list_ids,
            gross_subscribed_count,
            gross_unsubscribed_count,
            gross_autoresponder_count,
            eligibility_rules: warmup_eligibility_rules(),
            tranche_plan,
            production_send_authorized: false,
            warnings,
            evidence,
        }
    }

    pub fn fixture() -> Self {
        Self::from_lists(
            &WarmupAudienceReadinessRequest::default(),
            ListSummaryReport::fixture().lists,
            Vec::new(),
            Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        )
    }
}

impl AudienceHygieneExportReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            job_id: Some("iah_000000000000000000000000".to_string()),
            phase: Some("complete".to_string()),
            job_dir: Some("/tmp/interspire-audience-hygiene-fixture".to_string()),
            source_list_ids: default_warmup_source_list_ids(),
            processed_list_count: 1,
            remaining_list_ids: Vec::new(),
            missing_list_ids: Vec::new(),
            active_list_id: None,
            active_list_name: None,
            queries_processed_this_call: 1,
            completed_query_count: 1,
            remaining_query_count: 0,
            lists: vec![AudienceHygieneListSummary {
                list_id: 7,
                name: "Fixture list".to_string(),
                api_items: 3,
                eligible_items_before_dedupe: 2,
                excluded_unconfirmed: 1,
                excluded_unsubscribed: 0,
                excluded_bounced: 0,
                invalid_syntax: 0,
            }],
            gross_api_items: 3,
            eligible_items_before_dedupe: 2,
            deduped_eligible_count: 1,
            duplicate_eligible_items_removed: 1,
            excluded_unconfirmed: 1,
            excluded_unsubscribed: 0,
            excluded_bounced: 0,
            invalid_syntax_count: 0,
            role_localpart_count: 0,
            disposable_domain_hint_count: 0,
            checkpoint_artifacts: vec![AudienceHygieneArtifact {
                kind: "checkpoint_state_json".to_string(),
                path: "/tmp/interspire-audience-hygiene-fixture/state.json".to_string(),
                sha256: "1".repeat(64),
                bytes: 512,
                contains_raw_recipient_data: true,
            }],
            artifacts: vec![AudienceHygieneArtifact {
                kind: "aggregate_summary_json".to_string(),
                path: "/tmp/interspire-audience-hygiene-fixture-summary.json".to_string(),
                sha256: "0".repeat(64),
                bytes: 256,
                contains_raw_recipient_data: false,
            }],
            legacy_lists_mutated: false,
            production_send_authorized: false,
            warnings: vec![
                "fixture response contains aggregate evidence only".to_string(),
                "production send not authorized".to_string(),
            ],
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

pub fn approved_warmup_source_list_ids(request: &WarmupAudienceReadinessRequest) -> Vec<u64> {
    let requested = normalized_ids(&request.source_list_ids);
    priority_first_source_list_ids(&requested, &normalized_ids(&request.priority_list_ids))
}

pub fn approved_hygiene_source_list_ids(request: &AudienceHygieneExportRequest) -> Vec<u64> {
    normalized_ids(&request.source_list_ids)
}

pub fn blocked_hygiene_source_list_ids(request: &AudienceHygieneExportRequest) -> Vec<u64> {
    let _ = request;
    Vec::new()
}

fn approved_warmup_priority_list_ids(
    request: &WarmupAudienceReadinessRequest,
    source_list_ids: &[u64],
) -> Vec<u64> {
    normalized_ids(&request.priority_list_ids)
        .into_iter()
        .filter(|list_id| source_list_ids.contains(list_id))
        .collect()
}

fn priority_first_source_list_ids(source_list_ids: &[u64], priority_list_ids: &[u64]) -> Vec<u64> {
    let mut ordered = priority_list_ids
        .iter()
        .copied()
        .filter(|list_id| source_list_ids.contains(list_id))
        .collect::<Vec<_>>();
    for list_id in source_list_ids {
        if !ordered.contains(list_id) {
            ordered.push(*list_id);
        }
    }
    ordered
}

fn blocked_warmup_source_list_ids(requested_source_list_ids: &[u64]) -> Vec<u64> {
    let _ = requested_source_list_ids;
    Vec::new()
}

impl ListSummaryReport {
    pub fn fixture() -> Self {
        Self {
            ok: true,
            configured: true,
            lists: vec![ListSummary {
                list_id: 7,
                name: "Editorial updates".to_string(),
                subscribed_count: Some(42),
                unsubscribed_count: Some(3),
                autoresponder_count: Some(0),
                owner_name: Some("[redacted-name]".to_string()),
                owner_email_redacted: Some(redact::redact_email("editor@example.com")),
                reply_to_email_redacted: Some(redact::redact_email("reply@example.com")),
                bounce_email_redacted: Some(redact::redact_email("bounce@example.com")),
                source: "fixture+xml+html".to_string(),
            }],
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

impl ContactStateReport {
    pub fn fixture(email: &str, list_id: u64) -> Self {
        Self {
            ok: true,
            configured: true,
            list_id,
            email_redacted: redact::redact_email(email),
            email_hash: redact::email_hash(email),
            found_on_list: Some(true),
            state: "present_on_list".to_string(),
            warnings: Vec::new(),
            evidence: Evidence {
                source: "fixture".to_string(),
                notes: vec!["synthetic fixture".to_string()],
            },
        }
    }
}

pub fn blocked_operations() -> Vec<String> {
    [
        "send",
        "schedule",
        "cron_trigger",
        "queue_cancel_without_guarded_plan",
        "import",
        "generic_raw_contact_export",
        "recipient_export_without_private_artifact_guard",
        "delete_contacts",
        "unsubscribe",
        "resubscribe",
        "suppression_mutation",
        "settings_save",
        "smtp_change",
        "bounce_setting_change",
        "dns_or_provider_mutation",
    ]
    .iter()
    .map(|value| (*value).to_string())
    .collect()
}

pub fn tool_json<T: Serialize>(result: Result<T, InterspireError>) -> String {
    let value = match result {
        Ok(report) => serde_json::to_value(report).unwrap_or_else(|err| {
            serde_json::json!({
                "ok": false,
                "error_code": "serialization_error",
                "message": err.to_string(),
            })
        }),
        Err(err) => serde_json::to_value(ToolError {
            ok: false,
            error_code: err.code().to_string(),
            message: redact::redact_sensitive_text(&err.to_string()),
        })
        .unwrap_or_else(|serialize_err| {
            serde_json::json!({
                "ok": false,
                "error_code": "serialization_error",
                "message": serialize_err.to_string(),
            })
        }),
    };

    serde_json::to_string_pretty(&value).unwrap_or_else(|err| {
        format!(
            "{{\"ok\":false,\"error_code\":\"serialization_error\",\"message\":\"{}\"}}",
            err
        )
    })
}

fn default_true() -> bool {
    true
}

pub const DEFAULT_LIST_READ_LIMIT: usize = 25;
pub const HARD_LIST_READ_LIMIT: usize = 100;

pub fn default_list_read_limit() -> usize {
    DEFAULT_LIST_READ_LIMIT
}

pub const DEFAULT_HYGIENE_QUERY_BUDGET: usize = 4;
pub const HARD_HYGIENE_QUERY_BUDGET: usize = 25;

pub fn default_hygiene_query_budget() -> usize {
    DEFAULT_HYGIENE_QUERY_BUDGET
}

impl Default for WarmupAudienceReadinessRequest {
    fn default() -> Self {
        Self {
            source_list_ids: default_warmup_source_list_ids(),
            priority_list_ids: default_warmup_priority_list_ids(),
            tranche_sizes: default_warmup_tranche_sizes(),
            include_html_enrichment: false,
        }
    }
}

impl Default for AudienceHygieneExportRequest {
    fn default() -> Self {
        Self {
            source_list_ids: default_warmup_source_list_ids(),
            output_dir: None,
            artifact_prefix: None,
            include_sqlite: true,
        }
    }
}

pub fn default_warmup_source_list_ids() -> Vec<u64> {
    Vec::new()
}

pub fn default_warmup_priority_list_ids() -> Vec<u64> {
    Vec::new()
}

fn default_warmup_tranche_sizes() -> Vec<u64> {
    vec![100, 400, 500]
}

fn defaulted_tranche_sizes(values: &[u64]) -> Vec<u64> {
    let values = values
        .iter()
        .copied()
        .filter(|value| *value > 0)
        .collect::<Vec<_>>();
    if values.is_empty() {
        default_warmup_tranche_sizes()
    } else {
        values
    }
}

fn normalized_ids(values: &[u64]) -> Vec<u64> {
    let mut values = values
        .iter()
        .copied()
        .filter(|value| *value > 0)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn join_ids(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn warmup_eligibility_rules() -> Vec<String> {
    [
        "specified source lists only",
        "active/subscribed contacts only",
        "confirmed contacts only",
        "exclude unsubscribed, bounced, complained, and suppressed contacts",
        "dedupe by normalized email before tranche selection",
        "prioritize recent open/click engagement before older broad lists",
        "start with a tiny first tranche and stop on complaint, bounce, or suppression signals",
    ]
    .iter()
    .map(|value| (*value).to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_json_redacts_error_text_before_serializing() {
        let json = tool_json::<StatusReport>(Err(InterspireError::Http(
            "request failed for reporter@example.com at https://iem.example.net/admin/index.php; dns iem.example.net:443"
                .to_string(),
        )));
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid tool json");
        let message = value["message"].as_str().expect("message string");

        assert_eq!(value["ok"], false);
        assert_eq!(value["error_code"], "http_error");
        assert!(!message.contains("reporter"));
        assert!(!message.contains("example.com"));
        assert!(!message.contains("https://"));
        assert!(!message.contains("iem.example.net"));
        assert!(!message.contains(":443"));
        assert!(message.contains("[redacted-email]"));
        assert!(message.contains("[redacted-url]"));
        assert!(message.contains("[redacted-host]"));
    }

    #[test]
    fn tool_json_redacts_separated_secret_values_in_error_text() {
        let json = tool_json::<StatusReport>(Err(InterspireError::Http(
            r#"auth failed password: hunter2 token abc123 cookie = session-value api_key = key-secret "api_token": "quoted-secret""#
                .to_string(),
        )));
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid tool json");
        let message = value["message"].as_str().expect("message string");

        assert_eq!(value["ok"], false);
        assert_eq!(value["error_code"], "http_error");
        assert!(!message.contains("hunter2"));
        assert!(!message.contains("abc123"));
        assert!(!message.contains("session-value"));
        assert!(!message.contains("key-secret"));
        assert!(!message.contains("quoted-secret"));
    }

    #[test]
    fn warmup_readiness_uses_explicit_source_ids_without_hidden_universe() {
        let request = WarmupAudienceReadinessRequest {
            source_list_ids: vec![72, 999],
            priority_list_ids: vec![999, 111],
            tranche_sizes: vec![100],
            include_html_enrichment: false,
        };
        let report = WarmupAudienceReadinessReport::from_lists(
            &request,
            vec![
                ListSummary {
                    list_id: 72,
                    name: "Approved".to_string(),
                    subscribed_count: Some(100),
                    unsubscribed_count: Some(1),
                    autoresponder_count: Some(0),
                    owner_name: None,
                    owner_email_redacted: None,
                    reply_to_email_redacted: None,
                    bounce_email_redacted: None,
                    source: "fixture".to_string(),
                },
                ListSummary {
                    list_id: 999,
                    name: "Blocked".to_string(),
                    subscribed_count: Some(10_000),
                    unsubscribed_count: Some(0),
                    autoresponder_count: Some(0),
                    owner_name: None,
                    owner_email_redacted: None,
                    reply_to_email_redacted: None,
                    bounce_email_redacted: None,
                    source: "fixture".to_string(),
                },
            ],
            Vec::new(),
            Evidence {
                source: "fixture".to_string(),
                notes: Vec::new(),
            },
        );

        assert_eq!(report.source_list_ids, vec![999, 72]);
        assert_eq!(
            report
                .matched_lists
                .iter()
                .map(|list| list.list_id)
                .collect::<Vec<_>>(),
            vec![999, 72]
        );
        assert_eq!(report.gross_subscribed_count, 10_100);
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("ignored source list ids")));
        assert!(report.warnings.iter().any(|warning| warning
            .contains("ignored priority list ids")
            && warning.contains("111")));
    }

    #[test]
    fn warmup_readiness_orders_priority_lists_first() {
        let request = WarmupAudienceReadinessRequest {
            source_list_ids: vec![72, 111, 114],
            priority_list_ids: vec![111, 114],
            tranche_sizes: vec![100],
            include_html_enrichment: false,
        };
        let report = WarmupAudienceReadinessReport::from_lists(
            &request,
            vec![
                ListSummary {
                    list_id: 72,
                    name: "Older".to_string(),
                    subscribed_count: Some(500),
                    unsubscribed_count: Some(0),
                    autoresponder_count: Some(0),
                    owner_name: None,
                    owner_email_redacted: None,
                    reply_to_email_redacted: None,
                    bounce_email_redacted: None,
                    source: "fixture".to_string(),
                },
                ListSummary {
                    list_id: 111,
                    name: "Recent".to_string(),
                    subscribed_count: Some(100),
                    unsubscribed_count: Some(0),
                    autoresponder_count: Some(0),
                    owner_name: None,
                    owner_email_redacted: None,
                    reply_to_email_redacted: None,
                    bounce_email_redacted: None,
                    source: "fixture".to_string(),
                },
                ListSummary {
                    list_id: 114,
                    name: "Recent 2".to_string(),
                    subscribed_count: Some(100),
                    unsubscribed_count: Some(0),
                    autoresponder_count: Some(0),
                    owner_name: None,
                    owner_email_redacted: None,
                    reply_to_email_redacted: None,
                    bounce_email_redacted: None,
                    source: "fixture".to_string(),
                },
            ],
            Vec::new(),
            Evidence {
                source: "fixture".to_string(),
                notes: Vec::new(),
            },
        );

        assert_eq!(report.source_list_ids, vec![111, 114, 72]);
        assert_eq!(
            report
                .matched_lists
                .iter()
                .map(|list| list.list_id)
                .collect::<Vec<_>>(),
            vec![111, 114, 72]
        );
        assert_eq!(
            report.tranche_plan[0].source_preference,
            "priority list ids first: 111, 114"
        );
    }

    #[test]
    fn warmup_readiness_requires_explicit_source_ids() {
        let request = WarmupAudienceReadinessRequest {
            source_list_ids: Vec::new(),
            priority_list_ids: Vec::new(),
            tranche_sizes: vec![100],
            include_html_enrichment: false,
        };
        let report = WarmupAudienceReadinessReport::from_lists(
            &request,
            vec![ListSummary {
                list_id: 999,
                name: "Blocked".to_string(),
                subscribed_count: Some(10_000),
                unsubscribed_count: Some(0),
                autoresponder_count: Some(0),
                owner_name: None,
                owner_email_redacted: None,
                reply_to_email_redacted: None,
                bounce_email_redacted: None,
                source: "fixture".to_string(),
            }],
            Vec::new(),
            Evidence {
                source: "fixture".to_string(),
                notes: Vec::new(),
            },
        );

        assert!(report.source_list_ids.is_empty());
        assert!(report.matched_lists.is_empty());
        assert_eq!(report.gross_subscribed_count, 0);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("no explicit warm-up source list ids")));
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("matched Interspire list readback")));
    }
}

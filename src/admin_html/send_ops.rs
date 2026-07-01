use super::{admin_evidence, compact_text, parse_table_rows, AdminHtmlClient, QueueControlLink};
use crate::{
    config::OciSendLedgerConfig,
    error::InterspireError,
    oci_ledger,
    response::{
        CronFieldSummary, CronReadinessReport, Evidence, OciLedgerPreflightReport, RedactedField,
        SendJobActionPlan, SendJobFollowUpContract, SendJobQueueCounters, SendJobScheduleState,
        SendJobStatsState, SendJobStatusReadbackReport, SendJobStatusReadbackRequest,
        SendStopGateReadinessReport, SendStopGateReadinessRequest, SettingsInventorySection,
        StopGateAction,
    },
    safety::AdminReadPage,
};
use std::collections::BTreeSet;

impl AdminHtmlClient {
    pub fn send_job_status_readback(
        &self,
        request: &SendJobStatusReadbackRequest,
    ) -> Result<SendJobStatusReadbackReport, InterspireError> {
        if !self.configured() {
            return Ok(send_job_status_not_configured(request));
        }
        self.login()?;

        let max_rows = request.max_rows.unwrap_or(25).clamp(1, 100);
        let schedule_html = self.get_allowed(&AdminReadPage::Schedule.path())?;
        let stats_html = self.get_allowed(&AdminReadPage::Stats.path())?;
        let schedule_rows = parse_table_rows(&schedule_html, max_rows)?;
        let stats_rows = parse_table_rows(&stats_html, max_rows)?;
        let links = self.load_queue_control_links(max_rows)?;
        build_send_job_status_report(request, schedule_rows, stats_rows, links)
    }

    pub fn cron_readiness(
        &self,
        include_settings_inventory: bool,
        max_fields_per_section: usize,
    ) -> Result<CronReadinessReport, InterspireError> {
        if !self.configured() {
            return Ok(CronReadinessReport {
                ok: true,
                configured: false,
                application_cron_configured: false,
                server_runner_proven: false,
                production_send_ready: false,
                cron_fields: Vec::new(),
                schedule_warnings: Vec::new(),
                warnings: vec![
                    "admin HTML fallback is not configured; no cron readiness read attempted"
                        .to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }
        self.login()?;

        let cron_html = self.get_allowed(&AdminReadPage::Settings { tab: 4 }.path())?;
        let mut cron_fields =
            cron_fields_from_settings_fields(super::parse_settings_fields("cron", &cron_html)?);
        let mut warnings = Vec::new();
        if include_settings_inventory {
            let section = super::parse_settings_inventory_section(
                "cron",
                &cron_html,
                false,
                false,
                max_fields_per_section,
            )?;
            if section.capped {
                warnings.push(format!(
                    "cron settings inventory applied max_fields_per_section cap {max_fields_per_section}"
                ));
            }
            if section.total_control_count == 0 {
                warnings.push("cron settings page returned no form controls".to_string());
            }
            cron_fields.extend(cron_fields_from_inventory_section(&section));
            dedupe_cron_fields(&mut cron_fields);
        }

        let schedule_html = self.get_allowed(&AdminReadPage::Schedule.path())?;
        let schedule_text = compact_text(
            &scraper::Html::parse_document(&schedule_html)
                .root_element()
                .text()
                .collect::<Vec<_>>()
                .join(" "),
        );
        let schedule_warnings = cron_schedule_warnings(&schedule_text);
        let application_cron_configured = cron_fields.iter().any(|field| {
            field
                .value_redacted
                .as_deref()
                .is_some_and(looks_enabled_cron_value)
        });
        let server_runner_proven =
            schedule_warnings.is_empty() && contains_cron_detected_positive(&schedule_text);
        if application_cron_configured && !server_runner_proven {
            warnings.push(
                "Interspire cron settings appear enabled, but a server cron runner was not proven"
                    .to_string(),
            );
        }
        if !application_cron_configured {
            warnings
                .push("Interspire application cron settings were not proven enabled".to_string());
        }
        if !include_settings_inventory {
            warnings.push(
                "settings inventory was not requested; cron readiness used the compact audit surface"
                    .to_string(),
            );
        }

        Ok(CronReadinessReport {
            ok: true,
            configured: true,
            application_cron_configured,
            server_runner_proven,
            production_send_ready: application_cron_configured && server_runner_proven,
            cron_fields,
            schedule_warnings,
            warnings,
            evidence: admin_evidence(vec![
                "allowlisted Settings cron tab GET read".to_string(),
                "allowlisted Schedule GET read for cron detection text".to_string(),
                "no cron route was triggered".to_string(),
            ]),
        })
    }

    pub fn send_stop_gate_readiness(
        &self,
        request: &SendStopGateReadinessRequest,
        oci_config: &OciSendLedgerConfig,
    ) -> Result<SendStopGateReadinessReport, InterspireError> {
        let status_request = SendJobStatusReadbackRequest {
            expected_job_id: request.expected_job_id,
            expected_campaign_id: request.expected_campaign_id,
            expected_list_ids: request.expected_list_ids.clone(),
            expected_queue_total: request.expected_queue_total,
            expected_body_sha256: None,
            max_rows: request.max_rows,
        };
        let interspire_status = self.send_job_status_readback(&status_request)?;
        let expected_rows = request
            .expected_queue_total
            .or(interspire_status.queue_counters.total)
            .unwrap_or(0);
        let oci = oci_ledger::verify_preflight(
            oci_config,
            request.oci_ledger_preflight.as_ref(),
            expected_rows,
            request.expected_campaign_id,
        );

        let hard_bounces = interspire_status.stats.failed_count;
        let delivered_or_attempted = interspire_status
            .queue_counters
            .processed
            .or(interspire_status.schedule.sent_count)
            .or(interspire_status.stats.sent_count);
        let hard_bounce_rate = match (hard_bounces, delivered_or_attempted) {
            (Some(bounces), Some(total)) if total > 0 => Some(bounces as f64 / total as f64),
            _ => None,
        };
        let pause_plan_id = interspire_status
            .schedule
            .action_plans
            .iter()
            .find(|plan| matches!(plan.action, crate::response::QueueControlAction::Pause))
            .map(|plan| plan.plan_id.clone());
        let should_pause = hard_bounce_rate
            .map(|rate| rate >= request.hard_bounce_pause_threshold)
            .unwrap_or(false);
        let bounce_data_unavailable = hard_bounce_rate.is_none();
        let recommended_action = if should_pause {
            if pause_plan_id.is_some() {
                StopGateAction::PauseAvailable
            } else {
                StopGateAction::PauseUnavailable
            }
        } else if !interspire_status.identity_verified
            || bounce_data_unavailable
            || oci_preflight_blocks_send(&oci)
        {
            StopGateAction::Hold
        } else {
            StopGateAction::Continue
        };

        let mut warnings = Vec::new();
        if should_pause {
            warnings.push(
                "hard bounce rate meets or exceeds the configured pause threshold".to_string(),
            );
        }
        if pause_plan_id.is_none() && should_pause {
            warnings.push("pause threshold reached but no pause plan was exposed".to_string());
        }
        if oci_preflight_blocks_send(&oci) {
            warnings
                .push("OCI ledger preflight did not verify for this stop-gate read".to_string());
        }
        if bounce_data_unavailable {
            warnings.push(
                "hard bounce rate was unavailable from Interspire admin readback; stop gate should hold until provider or private bounce evidence is available"
                    .to_string(),
            );
        }

        Ok(SendStopGateReadinessReport {
            ok: interspire_status.ok,
            configured: interspire_status.configured,
            recommended_action,
            hard_bounce_rate,
            hard_bounce_pause_threshold: request.hard_bounce_pause_threshold,
            interspire_status,
            oci_ledger_preflight: oci,
            pause_plan_id,
            warnings,
            evidence: admin_evidence(vec![
                "composed read-only Interspire send-job status".to_string(),
                "computed local stop-gate recommendation without applying queue controls"
                    .to_string(),
            ]),
        })
    }
}

fn build_send_job_status_report(
    request: &SendJobStatusReadbackRequest,
    schedule_rows: Vec<String>,
    stats_rows: Vec<String>,
    links: Vec<QueueControlLink>,
) -> Result<SendJobStatusReadbackReport, InterspireError> {
    let matching_links = links
        .iter()
        .filter(|link| link.route.identifier_value == request.expected_job_id)
        .collect::<Vec<_>>();
    let mut row_summaries = matching_links
        .iter()
        .map(|link| link.candidate.row_summary.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if row_summaries.is_empty() {
        row_summaries = schedule_rows
            .iter()
            .filter(|row| row_mentions_id(row, request.expected_job_id))
            .cloned()
            .collect();
    }
    let mut available_actions = Vec::new();
    let mut action_plans = Vec::new();
    for link in &matching_links {
        if !available_actions.contains(&link.candidate.action) {
            available_actions.push(link.candidate.action);
        }
        action_plans.push(SendJobActionPlan {
            action: link.candidate.action,
            plan_id: link.candidate.plan_id.clone(),
        });
    }
    let (schedule_sent, schedule_total) = row_summaries
        .iter()
        .find_map(|row| parse_sent_total(row))
        .unwrap_or((None, None));
    if let (Some(expected), Some(actual)) = (request.expected_queue_total, schedule_total) {
        if expected != actual {
            return Err(InterspireError::Safety(format!(
                "send job {} expected queue total {expected} but Schedule shows {actual}",
                request.expected_job_id
            )));
        }
    }

    let stats_matches = matching_stats_rows(request, &stats_rows);
    let stats_sent = stats_matches
        .iter()
        .find_map(|row| parse_named_count(row, "sent"));
    let stats_failed = stats_matches.iter().find_map(|row| {
        parse_named_count(row, "failed").or_else(|| parse_named_count(row, "bounce"))
    });

    let total = schedule_total;
    let processed = schedule_sent.or(stats_sent);
    let unprocessed = match (total, processed) {
        (Some(total), Some(processed)) if total >= processed => Some(total - processed),
        _ => None,
    };
    let identity_verified = !matching_links.is_empty();
    let campaign_id = request.expected_campaign_id;
    let mut warnings = Vec::new();
    if !identity_verified {
        warnings.push(format!(
            "Schedule page did not expose a queue-control action proving job {} identity",
            request.expected_job_id
        ));
    }
    if !row_summaries.is_empty() && !identity_verified {
        warnings.push(
            "Schedule page text mentioned the expected job id, but this was treated as weak context rather than identity proof"
                .to_string(),
        );
    }
    if request.expected_queue_total.is_some() && schedule_total.is_none() {
        warnings.push(
            "expected queue total was supplied by caller but not proven by the Schedule page"
                .to_string(),
        );
    }
    if !request.expected_list_ids.is_empty() {
        warnings.push(
            "Schedule/Stats admin pages do not prove exact list scope; list ids are carried as caller-bound context"
                .to_string(),
        );
    }
    if request.expected_body_sha256.is_some() {
        warnings.push(
            "body hash is carried in the follow-up contract; Schedule/Stats pages do not re-prove campaign body hash"
                .to_string(),
        );
    }
    warnings.push(
        "direct Interspire queue, jobs_lists, stats, and unsent table counters are not exposed by this public admin-HTML readback"
            .to_string(),
    );

    let follow_up_contract = match (
        identity_verified,
        request.expected_job_id,
        campaign_id,
        total,
    ) {
        (true, job_id, Some(campaign_id), Some(total)) => Some(SendJobFollowUpContract::new(
            job_id,
            campaign_id,
            request.expected_list_ids.clone(),
            total,
            request.expected_body_sha256.clone(),
        )),
        _ => None,
    };

    Ok(SendJobStatusReadbackReport {
        ok: identity_verified,
        configured: true,
        identity_verified,
        job_id: request.expected_job_id,
        campaign_id,
        list_ids: request.expected_list_ids.clone(),
        expected_queue_total: request.expected_queue_total,
        schedule: SendJobScheduleState {
            matched_rows: row_summaries.len(),
            row_summaries,
            available_actions,
            action_plans,
            sent_count: schedule_sent,
            total_count: schedule_total,
            state: schedule_state(schedule_sent, schedule_total),
        },
        stats: SendJobStatsState {
            matched_rows: stats_matches.len(),
            row_summaries: stats_matches,
            sent_count: stats_sent,
            failed_count: stats_failed,
            state: if stats_sent.is_some() || stats_failed.is_some() {
                "present".to_string()
            } else {
                "pending".to_string()
            },
        },
        queue_counters: SendJobQueueCounters {
            source: "admin_html_schedule".to_string(),
            total,
            processed,
            unprocessed,
            unavailable_reason: Some(
                "authoritative queue-table processed flags require a reviewed private table source"
                    .to_string(),
            ),
        },
        unsent_reason_aggregates: Vec::new(),
        follow_up_contract,
        warnings,
        evidence: admin_evidence(vec![
            "allowlisted Schedule GET read".to_string(),
            "allowlisted Stats GET read".to_string(),
            "queue-control actions were parsed but not applied".to_string(),
        ]),
    })
}

fn send_job_status_not_configured(
    request: &SendJobStatusReadbackRequest,
) -> SendJobStatusReadbackReport {
    SendJobStatusReadbackReport {
        ok: true,
        configured: false,
        identity_verified: false,
        job_id: request.expected_job_id,
        campaign_id: request.expected_campaign_id,
        list_ids: request.expected_list_ids.clone(),
        expected_queue_total: request.expected_queue_total,
        schedule: SendJobScheduleState {
            matched_rows: 0,
            row_summaries: Vec::new(),
            available_actions: Vec::new(),
            action_plans: Vec::new(),
            sent_count: None,
            total_count: None,
            state: "not_configured".to_string(),
        },
        stats: SendJobStatsState {
            matched_rows: 0,
            row_summaries: Vec::new(),
            sent_count: None,
            failed_count: None,
            state: "not_configured".to_string(),
        },
        queue_counters: SendJobQueueCounters {
            source: "unconfigured".to_string(),
            total: None,
            processed: None,
            unprocessed: None,
            unavailable_reason: Some("admin HTML fallback is not configured".to_string()),
        },
        unsent_reason_aggregates: Vec::new(),
        follow_up_contract: None,
        warnings: vec![
            "admin HTML fallback is not configured; no send-job status read attempted".to_string(),
        ],
        evidence: Evidence {
            source: "interspire_admin_html".to_string(),
            notes: vec!["no request sent".to_string()],
        },
    }
}

fn parse_sent_total(row: &str) -> Option<(Option<u64>, Option<u64>)> {
    let normalized = row.replace(',', "");
    let lower = normalized.to_ascii_lowercase();
    if !lower.contains("sent") && !lower.contains('/') {
        return None;
    }
    let bytes = normalized.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'/' {
            continue;
        }
        let left = number_before(&normalized[..index]);
        let right = number_after(&normalized[index + 1..]);
        if left.is_some() || right.is_some() {
            return Some((left, right));
        }
    }
    None
}

fn parse_named_count(row: &str, name: &str) -> Option<u64> {
    let lower = row.to_ascii_lowercase().replace(',', "");
    let offset = lower.find(name)?;
    number_after(&lower[offset + name.len()..])
}

fn number_before(value: &str) -> Option<u64> {
    value
        .trim_end()
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .parse::<u64>()
        .ok()
}

fn number_after(value: &str) -> Option<u64> {
    value
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse::<u64>()
        .ok()
}

fn row_mentions_id(row: &str, id: u64) -> bool {
    let needle = id.to_string();
    row.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == needle)
}

fn matching_stats_rows(
    request: &SendJobStatusReadbackRequest,
    stats_rows: &[String],
) -> Vec<String> {
    stats_rows
        .iter()
        .filter(|row| {
            row_mentions_id(row, request.expected_job_id)
                || request
                    .expected_campaign_id
                    .is_some_and(|campaign_id| row_mentions_id(row, campaign_id))
        })
        .cloned()
        .collect()
}

fn oci_preflight_blocks_send(oci: &OciLedgerPreflightReport) -> bool {
    !oci.verified && (oci.requested || oci.required)
}

fn schedule_state(sent: Option<u64>, total: Option<u64>) -> String {
    match (sent, total) {
        (Some(sent), Some(total)) if sent >= total && total > 0 => "complete".to_string(),
        (Some(sent), Some(total)) if sent > 0 && sent < total => "active".to_string(),
        (Some(0), Some(total)) if total > 0 => "queued".to_string(),
        _ => "unknown".to_string(),
    }
}

fn cron_fields_from_settings_fields(fields: Vec<RedactedField>) -> Vec<CronFieldSummary> {
    fields
        .into_iter()
        .filter(|field| field.name.to_ascii_lowercase().contains("cron"))
        .map(cron_field_summary)
        .collect()
}

fn cron_fields_from_inventory_section(section: &SettingsInventorySection) -> Vec<CronFieldSummary> {
    section
        .fields
        .iter()
        .filter(|field| field.name.to_ascii_lowercase().contains("cron"))
        .cloned()
        .map(cron_field_summary)
        .collect()
}

fn cron_field_summary(field: RedactedField) -> CronFieldSummary {
    CronFieldSummary {
        name: field.name,
        value_redacted: field.value,
    }
}

fn dedupe_cron_fields(fields: &mut Vec<CronFieldSummary>) {
    let mut seen = BTreeSet::new();
    fields.retain(|field| seen.insert((field.name.clone(), field.value_redacted.clone())));
}

fn looks_enabled_cron_value(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    !matches!(
        normalized.as_str(),
        "" | "0" | "false" | "off" | "no" | "disabled"
    )
}

fn cron_schedule_warnings(schedule_text: &str) -> Vec<String> {
    let lower = schedule_text.to_ascii_lowercase();
    let mut warnings = Vec::new();
    if contains_cron_negative_phrase(&lower) {
        warnings.push("Interspire Schedule page indicates cron has not been detected".to_string());
    }
    if lower.contains("cron.php") && lower.contains("manual") {
        warnings.push("Schedule page references manual cron.php execution".to_string());
    }
    warnings
}

fn contains_cron_detected_positive(schedule_text: &str) -> bool {
    let lower = schedule_text.to_ascii_lowercase();
    lower.contains("cron")
        && (lower.contains("last run") || lower.contains("detected"))
        && !contains_cron_negative_phrase(&lower)
}

fn contains_cron_negative_phrase(lower_schedule_text: &str) -> bool {
    [
        "cron has not",
        "cron has never",
        "cron not detected",
        "cron is not",
        "cron was not",
        "cron never run",
        "cron has never run",
        "cron has never been run",
        "never run cron",
        "not detected cron",
    ]
    .iter()
    .any(|phrase| lower_schedule_text.contains(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sent_total_from_interspire_progress_text() {
        assert_eq!(
            parse_sent_total("In Progress (Sent to 63 / 100)"),
            Some((Some(63), Some(100)))
        );
    }

    #[test]
    fn missing_sent_count_does_not_parse_job_id_before_slash() {
        assert_eq!(
            parse_sent_total("Job 13 In Progress (Sent to / 100)"),
            Some((None, Some(100)))
        );
    }

    #[test]
    fn cron_readiness_ignores_unrelated_not_and_never_text() {
        let schedule_text =
            "Cron status: Last Run 2026-07-01. Repeat: Never. Do not close this window.";

        assert!(cron_schedule_warnings(schedule_text).is_empty());
        assert!(contains_cron_detected_positive(schedule_text));
    }

    #[test]
    fn cron_readiness_warns_on_specific_negative_status_text() {
        let schedule_text = "Cron has not been detected by Interspire.";

        assert_eq!(
            cron_schedule_warnings(schedule_text),
            vec!["Interspire Schedule page indicates cron has not been detected".to_string()]
        );
        assert!(!contains_cron_detected_positive(schedule_text));
    }

    #[test]
    fn cron_field_names_remain_distinct_public_keys() {
        let mut fields = vec![
            cron_field_summary(RedactedField {
                name: "cron_enabled".to_string(),
                value: Some("1".to_string()),
            }),
            cron_field_summary(RedactedField {
                name: "cron_send".to_string(),
                value: Some("1".to_string()),
            }),
        ];

        dedupe_cron_fields(&mut fields);

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "cron_enabled");
        assert_eq!(fields[1].name, "cron_send");
    }

    #[test]
    fn schedule_total_mismatch_blocks() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 13,
            expected_campaign_id: Some(2),
            expected_list_ids: vec![12],
            expected_queue_total: Some(100),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let err = build_send_job_status_report(
            &request,
            vec!["Job 13 In Progress (Sent to 1 / 99)".to_string()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected queue total 100"));
    }

    #[test]
    fn weak_schedule_text_does_not_verify_identity_or_follow_up_contract() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 13,
            expected_campaign_id: Some(2),
            expected_list_ids: vec![12],
            expected_queue_total: Some(100),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let report = build_send_job_status_report(
            &request,
            vec!["Campaign 2 Job 13 In Progress (Sent to 63 / 100)".to_string()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.identity_verified);
        assert!(report.follow_up_contract.is_none());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("weak context")));
    }

    #[test]
    fn omitted_campaign_id_does_not_match_unrelated_stats_rows() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 13,
            expected_campaign_id: None,
            expected_list_ids: Vec::new(),
            expected_queue_total: None,
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let rows = vec![
            "Campaign 2 Sent 42 Failed 9".to_string(),
            "Job 13 Sent 3 Failed 1".to_string(),
        ];

        assert_eq!(
            matching_stats_rows(&request, &rows),
            vec!["Job 13 Sent 3 Failed 1".to_string()]
        );
    }

    #[test]
    fn required_unrequested_oci_preflight_blocks_stop_gate() {
        let required = OciLedgerPreflightReport::skipped(
            true,
            true,
            "OCI send ledger preflight was not requested.",
        );
        let optional = OciLedgerPreflightReport::skipped(
            false,
            true,
            "OCI send ledger preflight was not requested.",
        );

        assert!(oci_preflight_blocks_send(&required));
        assert!(!oci_preflight_blocks_send(&optional));
    }
}

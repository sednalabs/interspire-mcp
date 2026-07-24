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
        let links = self.load_queue_control_links(max_rows)?.links;
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
        let cron_master_enabled = cron_master_enabled_from_fields(&cron_fields);
        let application_cron_configured = cron_master_enabled == Some(true);
        let server_runner_proven = schedule_warnings.is_empty()
            && schedule_page_proves_cron_runner(&schedule_text, application_cron_configured);
        if application_cron_configured && !server_runner_proven {
            warnings.push(
                "Interspire cron settings appear enabled, but a server cron runner was not proven"
                    .to_string(),
            );
        }
        match cron_master_enabled {
            Some(false) => {
                warnings.push("Interspire master cron checkbox is not enabled".to_string());
            }
            None => {
                warnings.push(
                    "Interspire master cron checkbox state was not proven; interval settings alone do not enable cron"
                        .to_string(),
                );
            }
            Some(true) => {}
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
    if let Some(expected_campaign_id) = request.expected_campaign_id {
        let manage_campaign_ids = matching_links
            .iter()
            .filter(|link| {
                link.candidate.source == crate::response::QueueControlSource::CampaignManage
            })
            .map(|link| link.candidate.campaign_id)
            .collect::<BTreeSet<_>>();
        if !manage_campaign_ids.is_empty()
            && manage_campaign_ids != BTreeSet::from([Some(expected_campaign_id)])
        {
            return Err(InterspireError::Safety(format!(
                "send job {} campaign Manage row did not prove expected campaign {}",
                request.expected_job_id, expected_campaign_id
            )));
        }
    }
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
            source: link.candidate.source,
            plan_id: link.candidate.plan_id.clone(),
        });
    }
    let (schedule_sent, schedule_total) = row_summaries
        .iter()
        .find_map(|row| parse_sent_total(row))
        .unwrap_or((None, None));
    let matching_sources = matching_links
        .iter()
        .map(|link| link.candidate.source)
        .collect::<BTreeSet<_>>();
    if matching_sources.len() > 1 {
        return Err(InterspireError::Safety(format!(
            "send job {} exposed queue controls on conflicting Schedule and campaign Manage sources",
            request.expected_job_id
        )));
    }
    let queue_source = matching_sources
        .iter()
        .next()
        .map(|source| format!("admin_html_{}", source.as_str()))
        .unwrap_or_else(|| "admin_html_unproven".to_string());
    if let (Some(expected), Some(actual)) = (request.expected_queue_total, schedule_total) {
        if expected != actual {
            return Err(InterspireError::Safety(format!(
                "send job {} expected queue total {expected} but {} shows {actual}",
                request.expected_job_id, queue_source
            )));
        }
    }

    let stats_matches = matching_stats_rows(request, &stats_rows);
    let stats_counts = stats_matches
        .iter()
        .filter_map(|row| parse_stats_row_counts(row))
        .collect::<Vec<_>>();
    let stats_rows_maybe_capped = stats_rows.len() >= request.max_rows.unwrap_or(25);
    let stats_row_has_incidental_job_id = stats_matches
        .iter()
        .any(|row| row_mentions_id(row, request.expected_job_id));
    // Stats rows do not carry the current queue job identity. Keep their
    // redacted rows/count-shape as ambiguity context, but never project their
    // counters onto the current job or stop-gate calculation.
    let stats_sent = None;
    let stats_failed = None;

    let total = schedule_total;
    let processed = schedule_sent;
    let unprocessed = match (total, processed) {
        (Some(total), Some(processed)) if total >= processed => Some(total - processed),
        _ => None,
    };
    let identity_verified = !matching_links.is_empty();
    let campaign_id = request.expected_campaign_id;
    let mut warnings = Vec::new();
    if !identity_verified {
        warnings.push(format!(
            "Schedule and campaign Manage pages did not expose a queue-control action proving job {} identity",
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
            "expected queue total was supplied by caller but not proven by the current queue-control row"
                .to_string(),
        );
    }
    if stats_rows_maybe_capped && !stats_matches.is_empty() && !identity_verified {
        warnings.push(
            "Stats row uniqueness was not proven because the fetched Stats row slice reached the configured cap"
                .to_string(),
        );
    }
    if stats_row_has_incidental_job_id && !matching_links.is_empty() {
        warnings.push(
            "Stats row text contained the expected job id token, but Schedule identity remained authoritative"
                .to_string(),
        );
    } else if stats_row_has_incidental_job_id {
        warnings.push(
            "Stats row text contained the expected job id token; this was treated as incidental text rather than completed-send identity proof"
                .to_string(),
        );
    }
    if !stats_matches.is_empty() {
        warnings.push(
            "Stats rows are historical aggregate context only and were not used to prove current job identity"
                .to_string(),
        );
    }
    if !request.expected_list_ids.is_empty() {
        warnings.push(
            "Schedule/Manage/Stats admin pages do not prove exact list scope; list ids are carried as caller-bound context"
                .to_string(),
        );
    }
    if request.expected_body_sha256.is_some() {
        warnings.push(
            "body hash is carried in the follow-up contract; Schedule/Manage/Stats pages do not re-prove campaign body hash"
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
            state: if stats_sent.is_some() || stats_failed.is_some() || !stats_counts.is_empty() {
                "ambiguous".to_string()
            } else {
                "pending".to_string()
            },
        },
        queue_counters: SendJobQueueCounters {
            source: queue_source,
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
            "allowlisted Schedule and newsletter Manage GET reads".to_string(),
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

#[derive(Debug, Clone, Copy)]
struct StatsRowCounts {
    recipients: u64,
    _unsubscribes: u64,
    _bounces: u64,
}

fn parse_stats_row_counts(row: &str) -> Option<StatsRowCounts> {
    let tokens = row
        .split_whitespace()
        .map(|token| token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != ','))
        .collect::<Vec<_>>();
    let action_index = tokens
        .iter()
        .rposition(|token| token.eq_ignore_ascii_case("view"))?;
    if action_index < 3 {
        return None;
    }
    let recipients = parse_count_token(tokens[action_index - 3])?;
    let unsubscribes = parse_count_token(tokens[action_index - 2])?;
    let bounces = parse_count_token(tokens[action_index - 1])?;
    Some(StatsRowCounts {
        recipients,
        _unsubscribes: unsubscribes,
        _bounces: bounces,
    })
}

fn parse_count_token(token: &str) -> Option<u64> {
    token.replace(',', "").parse::<u64>().ok()
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
            request.expected_queue_total.is_some_and(|expected| {
                parse_stats_row_counts(row).is_some_and(|counts| counts.recipients == expected)
            })
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
    let mut fields = section
        .fields
        .iter()
        .filter(|field| field.name.to_ascii_lowercase().contains("cron"))
        .cloned()
        .map(cron_field_summary)
        .collect::<Vec<_>>();
    fields.extend(
        section
            .omitted_fields
            .iter()
            .filter(|field| {
                field.name.to_ascii_lowercase().contains("cron")
                    && field
                        .reason
                        .to_ascii_lowercase()
                        .contains("unchecked control")
            })
            .map(|field| CronFieldSummary {
                name: field.name.clone(),
                value_redacted: Some("0".to_string()),
            }),
    );
    fields
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

fn cron_master_enabled_from_fields(fields: &[CronFieldSummary]) -> Option<bool> {
    fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("cron_enabled"))
        .and_then(|field| field.value_redacted.as_deref())
        .map(looks_enabled_cron_value)
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
    lower.contains("cron") && lower.contains("detected") && !contains_cron_negative_phrase(&lower)
}

fn schedule_page_proves_cron_runner(
    schedule_text: &str,
    application_cron_configured: bool,
) -> bool {
    if contains_cron_detected_positive(schedule_text) {
        return true;
    }
    if !application_cron_configured {
        return false;
    }

    let lower = schedule_text.to_ascii_lowercase();
    lower.contains("view scheduled email queue")
        && lower.contains("updatecrontimer")
        && !contains_cron_negative_phrase(&lower)
}

fn contains_cron_negative_phrase(lower_schedule_text: &str) -> bool {
    [
        "cron has not",
        "cron has never",
        "cron not detected",
        "cron is not",
        "cron was not",
        "not yet detected",
        "has not yet detected",
        "has not detected",
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
        assert!(!contains_cron_detected_positive(schedule_text));
    }

    #[test]
    fn cron_readiness_requires_explicit_detected_positive_text() {
        let schedule_text = "Cron status: cron has been detected and is running.";

        assert!(cron_schedule_warnings(schedule_text).is_empty());
        assert!(contains_cron_detected_positive(schedule_text));
        assert!(schedule_page_proves_cron_runner(schedule_text, true));
    }

    #[test]
    fn cron_readiness_warns_on_specific_negative_status_text() {
        let schedule_text = "Cron has not been detected by Interspire.";

        assert_eq!(
            cron_schedule_warnings(schedule_text),
            vec!["Interspire Schedule page indicates cron has not been detected".to_string()]
        );
        assert!(!contains_cron_detected_positive(schedule_text));
        assert!(!schedule_page_proves_cron_runner(schedule_text, true));
    }

    #[test]
    fn cron_readiness_warns_on_not_yet_detected_status_text() {
        let schedule_text =
            "You have enabled cron support, but the system has not yet detected a cron job running.";

        assert_eq!(
            cron_schedule_warnings(schedule_text),
            vec!["Interspire Schedule page indicates cron has not been detected".to_string()]
        );
        assert!(!contains_cron_detected_positive(schedule_text));
        assert!(!schedule_page_proves_cron_runner(schedule_text, true));
    }

    #[test]
    fn cron_readiness_accepts_live_schedule_page_after_warning_disappears() {
        let schedule_text = "View Scheduled Email Queue Any emails you have scheduled to be sent out are shown below. UpdateCronTimer('Unknown', 0, false); Results per page: 10";

        assert!(cron_schedule_warnings(schedule_text).is_empty());
        assert!(!contains_cron_detected_positive(schedule_text));
        assert!(schedule_page_proves_cron_runner(schedule_text, true));
        assert!(!schedule_page_proves_cron_runner(schedule_text, false));
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
    fn cron_readiness_requires_master_cron_checkbox_not_only_intervals() {
        let interval_only = vec![cron_field_summary(RedactedField {
            name: "cron_send".to_string(),
            value: Some("5".to_string()),
        })];
        assert_eq!(cron_master_enabled_from_fields(&interval_only), None);

        let disabled_master = vec![
            cron_field_summary(RedactedField {
                name: "cron_enabled".to_string(),
                value: Some("0".to_string()),
            }),
            cron_field_summary(RedactedField {
                name: "cron_send".to_string(),
                value: Some("5".to_string()),
            }),
        ];
        assert_eq!(
            cron_master_enabled_from_fields(&disabled_master),
            Some(false)
        );

        let enabled_master = vec![cron_field_summary(RedactedField {
            name: "cron_enabled".to_string(),
            value: Some("1".to_string()),
        })];
        assert_eq!(cron_master_enabled_from_fields(&enabled_master), Some(true));
    }

    #[test]
    fn unchecked_inventory_cron_checkbox_is_reported_as_disabled_master() {
        let section = SettingsInventorySection {
            name: "cron".to_string(),
            fields: vec![RedactedField {
                name: "cron_send".to_string(),
                value: Some("5".to_string()),
            }],
            omitted_fields: vec![crate::response::SettingsInventoryOmittedField {
                name: "cron_enabled".to_string(),
                reason: "unchecked control omitted".to_string(),
            }],
            total_control_count: 2,
            returned_field_count: 1,
            omitted_field_count: 1,
            capped: false,
        };

        let fields = cron_fields_from_inventory_section(&section);

        assert!(fields.iter().any(|field| {
            field.name == "cron_enabled" && field.value_redacted.as_deref() == Some("0")
        }));
        assert_eq!(cron_master_enabled_from_fields(&fields), Some(false));
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
    fn stats_rows_do_not_match_numeric_id_tokens_without_expected_total() {
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

        assert!(matching_stats_rows(&request, &rows).is_empty());
    }

    #[test]
    fn completed_stats_row_with_expected_total_never_verifies_current_job_identity() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 42,
            expected_campaign_id: Some(16),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: Some(
                "c6777082c91bcfc19f95bccba3a196fd1a25c1b5653b95d4f607930b8ce6fd4c".to_string(),
            ),
            max_rows: Some(25),
        };
        let report = build_send_job_status_report(
            &request,
            Vec::new(),
            vec![
                "Previous Newsletter 'Prior clean cohort ... July 2 2026, 10:16 am July 2 2026, 10:16 am 3,496 18 0 View Export Print Delete".to_string(),
                "Current Newsletter 'Expected probe cohort ... July 6 2026, 1:28 pm July 6 2026, 1:28 pm 500 0 0 View Export Print Delete".to_string(),
            ],
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.identity_verified);
        assert_eq!(report.stats.matched_rows, 1);
        assert_eq!(report.stats.sent_count, None);
        assert_eq!(report.stats.failed_count, None);
        assert_eq!(report.queue_counters.total, None);
        assert_eq!(report.queue_counters.processed, None);
        assert!(report.follow_up_contract.is_none());
        assert!(report.stats.row_summaries[0].contains("Expected probe cohort"));
        assert!(!report.stats.row_summaries[0].contains("Prior clean cohort"));
    }

    #[test]
    fn campaign_id_token_in_stats_time_does_not_match_stale_completed_row() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 42,
            expected_campaign_id: Some(16),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let stale_rows = vec![
            "Previous Newsletter 'Prior clean cohort ... July 2 2026, 10:16 am July 2 2026, 10:16 am 3,496 18 0 View Export Print Delete".to_string(),
        ];

        assert!(matching_stats_rows(&request, &stale_rows).is_empty());
    }

    #[test]
    fn duplicate_completed_stats_totals_do_not_verify_identity() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 42,
            expected_campaign_id: Some(16),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let report = build_send_job_status_report(
            &request,
            Vec::new(),
            vec![
                "Campaign A 'List A' July 6 2026, 1:20 pm July 6 2026, 1:21 pm 500 0 0 View Export Print Delete".to_string(),
                "Campaign B 'List B' July 6 2026, 1:28 pm July 6 2026, 1:28 pm 500 0 0 View Export Print Delete".to_string(),
            ],
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.identity_verified);
        assert_eq!(report.stats.matched_rows, 2);
        assert_eq!(report.queue_counters.total, None);
        assert!(report.follow_up_contract.is_none());
    }

    #[test]
    fn view_token_in_stats_label_does_not_hide_duplicate_completed_total() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 42,
            expected_campaign_id: Some(16),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let report = build_send_job_status_report(
            &request,
            Vec::new(),
            vec![
                "Campaign Customer View 'List A' July 6 2026, 1:20 pm July 6 2026, 1:21 pm 500 0 0 View Export Print Delete".to_string(),
                "Campaign B 'List B' July 6 2026, 1:28 pm July 6 2026, 1:28 pm 500 0 0 View Export Print Delete".to_string(),
            ],
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.identity_verified);
        assert_eq!(report.stats.matched_rows, 2);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("historical aggregate context")));
    }

    #[test]
    fn capped_stats_slice_does_not_verify_completed_identity() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 42,
            expected_campaign_id: Some(16),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: None,
            max_rows: Some(1),
        };
        let report = build_send_job_status_report(
            &request,
            Vec::new(),
            vec![
                "Campaign A 'List A' July 6 2026, 1:28 pm July 6 2026, 1:28 pm 500 0 0 View Export Print Delete".to_string(),
            ],
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.identity_verified);
        assert_eq!(report.stats.matched_rows, 1);
        assert_eq!(report.queue_counters.total, None);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("configured cap")));
    }

    #[test]
    fn incidental_job_id_token_in_stats_text_blocks_completed_identity() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 16,
            expected_campaign_id: Some(2),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let report = build_send_job_status_report(
            &request,
            Vec::new(),
            vec![
                "Campaign A 'List A' July 6 2026, 10:16 am July 6 2026, 10:16 am 500 0 0 View Export Print Delete".to_string(),
            ],
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.identity_verified);
        assert_eq!(report.stats.matched_rows, 1);
        assert_eq!(report.queue_counters.total, None);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("incidental text")));
    }

    #[test]
    fn active_schedule_identity_does_not_inherit_unrelated_completed_stats_counts() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 42,
            expected_campaign_id: Some(16),
            expected_list_ids: vec![27],
            expected_queue_total: Some(500),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let schedule_html = r#"
            <table>
              <tr>
                <td>Campaign A Sending now</td>
                <td><a href="index.php?Page=Schedule&Action=Pause&job=42">Pause</a></td>
              </tr>
            </table>
        "#;
        let links = super::super::parse_queue_control_links(
            "https://example.test/admin/",
            schedule_html,
            25,
            crate::response::QueueControlSource::Schedule,
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let report = build_send_job_status_report(
            &request,
            vec!["Campaign A Sending now Pause".to_string()],
            vec![
                "Older Campaign 'Older List' July 6 2026, 1:20 pm July 6 2026, 1:21 pm 500 0 0 View Export Print Delete".to_string(),
            ],
            links,
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.ok);
        assert!(report.identity_verified);
        assert_eq!(report.schedule.matched_rows, 1);
        assert_eq!(report.queue_counters.total, None);
        assert_eq!(report.queue_counters.processed, None);
        assert_eq!(report.stats.state, "ambiguous");
    }

    #[test]
    fn manage_only_immediate_job_proves_current_identity_without_stats_fallback() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 88,
            expected_campaign_id: Some(44),
            expected_list_ids: vec![3],
            expected_queue_total: Some(70),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let manage_html = r#"
            <table>
              <tr>
                <td>Campaign Alpha</td>
                <td>In Progress (0 of 70)</td>
                <td>
                  <a href="index.php?Page=Newsletters&Action=Edit&id=44">Edit</a>
                  <a href="index.php?Page=Send&Action=PauseSend&Job=88">Pause</a>
                </td>
              </tr>
            </table>
        "#;
        let links = super::super::parse_queue_control_links(
            "https://example.test/admin/",
            manage_html,
            25,
            crate::response::QueueControlSource::CampaignManage,
        )
        .unwrap_or_else(|err| panic!("{err}"));

        let report = build_send_job_status_report(
            &request,
            Vec::new(),
            vec![
                "Older Campaign 'Older List' July 6 2026, 1:20 pm July 6 2026, 1:21 pm 70 0 0 View Export Print Delete".to_string(),
            ],
            links,
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.ok);
        assert!(report.identity_verified);
        assert_eq!(report.schedule.matched_rows, 1);
        assert_eq!(
            report.schedule.action_plans[0].source,
            crate::response::QueueControlSource::CampaignManage
        );
        assert_eq!(report.stats.state, "ambiguous");
        assert_eq!(report.queue_counters.source, "admin_html_campaign_manage");
        assert_eq!(report.queue_counters.processed, None);
    }

    #[test]
    fn manage_only_job_fails_closed_on_campaign_mismatch() {
        let request = SendJobStatusReadbackRequest {
            expected_job_id: 88,
            expected_campaign_id: Some(45),
            expected_list_ids: Vec::new(),
            expected_queue_total: Some(70),
            expected_body_sha256: None,
            max_rows: Some(25),
        };
        let manage_html = r#"
            <table><tr>
              <td><a href="index.php?Page=Newsletters&Action=Edit&id=44">Edit</a></td>
              <td><a href="index.php?Page=Send&Action=PauseSend&Job=88">Pause</a></td>
            </tr></table>
        "#;
        let links = super::super::parse_queue_control_links(
            "https://example.test/admin/",
            manage_html,
            25,
            crate::response::QueueControlSource::CampaignManage,
        )
        .unwrap_or_else(|err| panic!("{err}"));

        let error = build_send_job_status_report(&request, Vec::new(), Vec::new(), links)
            .expect_err("campaign mismatch must fail closed");
        assert!(error
            .to_string()
            .contains("did not prove expected campaign"));
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

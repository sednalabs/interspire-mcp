//! Resumable audience hygiene export jobs.
//!
//! Long-running Interspire subscriber exports can exceed MCP tool timeouts if a
//! single call tries to read every list and shard before checkpointing. This
//! module owns the bounded start/resume/status workflow that persists raw
//! recipient state privately under an approved output root and advances the
//! export a few XML subscriber queries at a time.

use crate::{
    audience_hygiene::{
        append_base_export_warnings, artifact, candidate_rows, ensure_output_dir_still_approved,
        is_disposable_hint, is_role_address, min_optional_text, normalize_email, safe_output_dir,
        safe_prefix, set_private_dir_permissions, unix_timestamp_nanos, write_artifacts, Candidate,
        Totals,
    },
    error::InterspireError,
    response::{
        AudienceHygieneArtifact, AudienceHygieneExportBeginRequest, AudienceHygieneExportReport,
        AudienceHygieneExportRequest, AudienceHygieneExportResumeRequest,
        AudienceHygieneExportStatusRequest, AudienceHygieneListSummary,
    },
    xml_api::{self, SubscriberRecord, XmlApiClient},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const JOB_STATE_VERSION: u8 = 1;
const JOB_STATE_FILE: &str = "state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportJobState {
    version: u8,
    job_id: String,
    job_dir: String,
    artifact_prefix: String,
    include_sqlite: bool,
    source_list_ids: Vec<u64>,
    missing_list_ids: Vec<u64>,
    lists: Vec<JobListState>,
    totals: Totals,
    candidates: BTreeMap<String, Candidate>,
    warnings: Vec<String>,
    evidence_notes: Vec<String>,
    completed_query_count: u64,
    finalized: bool,
    final_artifacts: Vec<AudienceHygieneArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobListState {
    list_id: u64,
    name: String,
    declared_subscribed_count: Option<u64>,
    declared_unsubscribed_count: Option<u64>,
    pending_queries: Vec<String>,
    totals: Totals,
    summary: Option<AudienceHygieneListSummary>,
    split_warning_emitted: bool,
}

pub(crate) fn begin_export(
    xml: &XmlApiClient,
    request: &AudienceHygieneExportBeginRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let source_list_ids = normalized_source_list_ids(&request.source_list_ids);
    let mut warnings = Vec::new();
    if source_list_ids.is_empty() {
        warnings.push(
            "no explicit audience hygiene source list ids were provided after safety filtering"
                .to_string(),
        );
        return Ok(empty_report(false, source_list_ids, warnings));
    }

    let output_dir = safe_output_dir(request.output_dir.as_deref())?;
    fs::create_dir_all(&output_dir).map_err(|err| {
        InterspireError::Io(format!(
            "failed to create private audience export directory: {err}"
        ))
    })?;
    set_private_dir_permissions(&output_dir)?;
    ensure_output_dir_still_approved(&output_dir)?;

    if !xml.configured() {
        warnings
            .push("XML API is not configured; no audience hygiene export attempted".to_string());
        return Ok(empty_report(false, source_list_ids, warnings));
    }

    let lists = filter_requested_lists(xml.get_lists()?, &source_list_ids);
    let matched_list_ids = lists.iter().map(|list| list.list_id).collect::<Vec<_>>();
    let missing_list_ids = source_list_ids
        .iter()
        .copied()
        .filter(|list_id| !matched_list_ids.contains(list_id))
        .collect::<Vec<_>>();
    if !missing_list_ids.is_empty() {
        warnings.push(format!(
            "missing specified audience hygiene source list ids: {}",
            join_ids(&missing_list_ids)
        ));
    }

    let prefix = safe_prefix(request.artifact_prefix.as_deref());
    let job_id = build_job_id(&source_list_ids)?;
    let job_dir = output_dir.join(format!("{prefix}-{job_id}"));
    if job_dir.exists() {
        return Err(InterspireError::Io(format!(
            "checkpoint job directory already exists: {}",
            job_dir.display()
        )));
    }
    fs::create_dir_all(&job_dir).map_err(|err| {
        InterspireError::Io(format!("failed to create checkpoint job directory: {err}"))
    })?;
    set_private_dir_permissions(&job_dir)?;
    ensure_output_dir_still_approved(&job_dir)?;

    let state = ExportJobState {
        version: JOB_STATE_VERSION,
        job_id: job_id.clone(),
        job_dir: job_dir.display().to_string(),
        artifact_prefix: prefix,
        include_sqlite: request.include_sqlite,
        source_list_ids,
        missing_list_ids,
        lists: lists
            .into_iter()
            .map(|list| JobListState {
                list_id: list.list_id,
                name: list.name,
                declared_subscribed_count: list.subscribed_count,
                declared_unsubscribed_count: list.unsubscribed_count,
                pending_queries: xml_api::initial_subscriber_queries(list.subscribed_count),
                totals: Totals::default(),
                summary: None,
                split_warning_emitted: false,
            })
            .collect(),
        totals: Totals::default(),
        candidates: BTreeMap::new(),
        warnings,
        evidence_notes: vec![
            "user/GetLists XML API read".to_string(),
            "checkpointed subscribers/GetSubscribers XML API read with bounded shard/query steps"
                .to_string(),
            "private checkpoint state written outside repository; aggregate MCP response only"
                .to_string(),
        ],
        completed_query_count: 0,
        finalized: false,
        final_artifacts: Vec::new(),
    };
    write_state(&job_dir, &state)?;

    resume_export(
        xml,
        &AudienceHygieneExportResumeRequest {
            job_id,
            output_dir: Some(output_dir.display().to_string()),
            max_queries_per_call: request.max_queries_per_call,
        },
    )
}

pub(crate) fn resume_export(
    xml: &XmlApiClient,
    request: &AudienceHygieneExportResumeRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let output_dir = safe_output_dir(request.output_dir.as_deref())?;
    let mut state = load_state(&output_dir, &request.job_id)?;

    if !xml.configured() {
        let mut report = build_report(&state, 0)?;
        report.configured = false;
        report
            .warnings
            .push("XML API is not configured; checkpoint export did not advance".to_string());
        return Ok(report);
    }

    let budget = request
        .max_queries_per_call
        .clamp(1, crate::response::HARD_HYGIENE_QUERY_BUDGET);
    let mut processed_this_call = 0_u64;

    while processed_this_call < budget as u64 {
        let Some(index) = next_incomplete_list_index(&state) else {
            break;
        };

        if state.lists[index].pending_queries.is_empty() {
            finalize_list(&mut state.lists[index], &mut state.warnings);
            write_state(Path::new(&state.job_dir), &state)?;
            continue;
        }

        let query = state.lists[index]
            .pending_queries
            .pop()
            .unwrap_or_else(|| "@".to_string());
        let list_id = state.lists[index].list_id;
        let list_name = state.lists[index].name.clone();
        match xml.get_subscribers_for_checkpoint_query(list_id, &query) {
            Ok(records) => {
                process_records(
                    &mut state.candidates,
                    &mut state.totals,
                    &mut state.lists[index].totals,
                    &records,
                    list_id,
                    &list_name,
                );
                processed_this_call += 1;
                state.completed_query_count += 1;
                if state.lists[index].pending_queries.is_empty() {
                    finalize_list(&mut state.lists[index], &mut state.warnings);
                }
                write_state(Path::new(&state.job_dir), &state)?;
            }
            Err(err) => {
                if let Some(children) = xml_api::split_subscriber_query(&query, &err) {
                    state.lists[index].pending_queries.extend(children);
                    processed_this_call += 1;
                    state.completed_query_count += 1;
                    if !state.lists[index].split_warning_emitted {
                        state.warnings.push(format!(
                            "List {} query {} exceeded a bounded subscriber response and was split into narrower domain-prefix shards",
                            list_id, query
                        ));
                        state.lists[index].split_warning_emitted = true;
                    }
                    write_state(Path::new(&state.job_dir), &state)?;
                    continue;
                }

                state.lists[index].pending_queries.push(query);
                write_state(Path::new(&state.job_dir), &state)?;
                return Err(err);
            }
        }
    }

    if !state.finalized && next_incomplete_list_index(&state).is_none() {
        finalize_job(&mut state)?;
        write_state(Path::new(&state.job_dir), &state)?;
    }

    build_report(&state, processed_this_call)
}

pub(crate) fn export_status(
    request: &AudienceHygieneExportStatusRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let output_dir = safe_output_dir(request.output_dir.as_deref())?;
    let state = load_state(&output_dir, &request.job_id)?;
    build_report(&state, 0)
}

fn empty_report(
    configured: bool,
    source_list_ids: Vec<u64>,
    warnings: Vec<String>,
) -> AudienceHygieneExportReport {
    AudienceHygieneExportReport {
        ok: true,
        configured,
        job_id: None,
        phase: None,
        job_dir: None,
        source_list_ids,
        processed_list_count: 0,
        remaining_list_ids: Vec::new(),
        missing_list_ids: Vec::new(),
        active_list_id: None,
        active_list_name: None,
        queries_processed_this_call: 0,
        completed_query_count: 0,
        remaining_query_count: 0,
        lists: Vec::new(),
        gross_api_items: 0,
        eligible_items_before_dedupe: 0,
        deduped_eligible_count: 0,
        duplicate_eligible_items_removed: 0,
        excluded_unconfirmed: 0,
        excluded_unsubscribed: 0,
        excluded_bounced: 0,
        invalid_syntax_count: 0,
        role_localpart_count: 0,
        disposable_domain_hint_count: 0,
        checkpoint_artifacts: Vec::new(),
        artifacts: Vec::new(),
        legacy_lists_mutated: false,
        production_send_authorized: false,
        warnings,
        evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
    }
}

fn finalize_job(state: &mut ExportJobState) -> Result<(), InterspireError> {
    let request = AudienceHygieneExportRequest {
        source_list_ids: state.source_list_ids.clone(),
        output_dir: Some(state.job_dir.clone()),
        artifact_prefix: Some(state.artifact_prefix.clone()),
        include_sqlite: state.include_sqlite,
    };
    state.final_artifacts = write_artifacts(
        &request,
        &candidate_rows(&state.candidates),
        &completed_list_summaries(&state.lists),
        &state.totals,
        &state.source_list_ids,
    )?;
    state.finalized = true;
    Ok(())
}

fn build_report(
    state: &ExportJobState,
    queries_processed_this_call: u64,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let job_dir = Path::new(&state.job_dir);
    let checkpoint_artifacts = vec![artifact(
        "checkpoint_state_json",
        &state_path(job_dir),
        true,
    )?];
    let completed_lists = completed_list_summaries(&state.lists);
    let remaining_list_ids = state
        .lists
        .iter()
        .filter(|list| list.summary.is_none())
        .map(|list| list.list_id)
        .collect::<Vec<_>>();
    let active_list = state.lists.iter().find(|list| list.summary.is_none());
    let deduped_eligible_count = state.candidates.len() as u64;
    let role_localpart_count = state
        .candidates
        .values()
        .filter(|candidate| candidate.role_localpart)
        .count() as u64;
    let disposable_domain_hint_count = state
        .candidates
        .values()
        .filter(|candidate| candidate.disposable_domain_hint)
        .count() as u64;
    let remaining_query_count = state
        .lists
        .iter()
        .map(|list| list.pending_queries.len() as u64)
        .sum();
    let mut warnings = state.warnings.clone();
    append_base_export_warnings(&mut warnings);

    Ok(AudienceHygieneExportReport {
        ok: true,
        configured: true,
        job_id: Some(state.job_id.clone()),
        phase: Some(if state.finalized {
            "complete".to_string()
        } else {
            "in_progress".to_string()
        }),
        job_dir: Some(state.job_dir.clone()),
        source_list_ids: state.source_list_ids.clone(),
        processed_list_count: completed_lists.len() as u64,
        remaining_list_ids,
        missing_list_ids: state.missing_list_ids.clone(),
        active_list_id: active_list.map(|list| list.list_id),
        active_list_name: active_list.map(|list| list.name.clone()),
        queries_processed_this_call,
        completed_query_count: state.completed_query_count,
        remaining_query_count,
        lists: completed_lists,
        gross_api_items: state.totals.api_items,
        eligible_items_before_dedupe: state.totals.eligible_items_before_dedupe,
        deduped_eligible_count,
        duplicate_eligible_items_removed: state
            .totals
            .eligible_items_before_dedupe
            .saturating_sub(deduped_eligible_count),
        excluded_unconfirmed: state.totals.excluded_unconfirmed,
        excluded_unsubscribed: state.totals.excluded_unsubscribed,
        excluded_bounced: state.totals.excluded_bounced,
        invalid_syntax_count: state.totals.invalid_syntax,
        role_localpart_count,
        disposable_domain_hint_count,
        checkpoint_artifacts,
        artifacts: state.final_artifacts.clone(),
        legacy_lists_mutated: false,
        production_send_authorized: false,
        warnings,
        evidence: xml_api::xml_evidence(state.evidence_notes.clone()),
    })
}

fn process_records(
    candidates: &mut BTreeMap<String, Candidate>,
    totals: &mut Totals,
    list_totals: &mut Totals,
    records: &[SubscriberRecord],
    list_id: u64,
    list_name: &str,
) {
    for record in records {
        totals.api_items += 1;
        list_totals.api_items += 1;

        let Some(email) = normalize_email(&record.email_address) else {
            totals.invalid_syntax += 1;
            list_totals.invalid_syntax += 1;
            continue;
        };
        if !record.confirmed {
            totals.excluded_unconfirmed += 1;
            list_totals.excluded_unconfirmed += 1;
            continue;
        }
        if record.unsubscribed {
            totals.excluded_unsubscribed += 1;
            list_totals.excluded_unsubscribed += 1;
            continue;
        }
        if record.bounced {
            totals.excluded_bounced += 1;
            list_totals.excluded_bounced += 1;
            continue;
        }

        totals.eligible_items_before_dedupe += 1;
        list_totals.eligible_items_before_dedupe += 1;

        let candidate = candidates.entry(email.clone()).or_default();
        candidate.source_list_ids.insert(list_id);
        candidate.source_list_names.insert(list_name.to_string());
        if let Some(subscriber_id) = record.subscriber_id {
            candidate.subscriber_ids.insert(subscriber_id.to_string());
        }
        if let Some(subscribe_date) = record.subscribe_date {
            candidate.first_subscribe_ts = min_optional_text(
                candidate.first_subscribe_ts.take(),
                Some(subscribe_date.to_string()),
            );
        }
        candidate.role_localpart |= is_role_address(&email);
        candidate.disposable_domain_hint |= is_disposable_hint(&email);
    }
}

fn finalize_list(list: &mut JobListState, warnings: &mut Vec<String>) {
    if list.summary.is_some() {
        return;
    }
    append_list_status_authority_warnings(warnings, list);
    list.summary = Some(AudienceHygieneListSummary {
        list_id: list.list_id,
        name: list.name.clone(),
        api_items: list.totals.api_items,
        eligible_items_before_dedupe: list.totals.eligible_items_before_dedupe,
        excluded_unconfirmed: list.totals.excluded_unconfirmed,
        excluded_unsubscribed: list.totals.excluded_unsubscribed,
        excluded_bounced: list.totals.excluded_bounced,
        invalid_syntax: list.totals.invalid_syntax,
    });
}

fn append_list_status_authority_warnings(warnings: &mut Vec<String>, list: &JobListState) {
    if let Some(subscribed_count) = list.declared_subscribed_count {
        if list.totals.eligible_items_before_dedupe > subscribed_count {
            warnings.push(format!(
                "Subscriber XML export for list {} returned {} eligible-looking rows, exceeding GetLists subscribed_count {}; treat this artifact as candidate discovery, not subscribed/send-ready proof",
                list.list_id, list.totals.eligible_items_before_dedupe, subscribed_count
            ));
        }
    }

    let exceeds_declared_subscribed =
        list.declared_subscribed_count
            .is_some_and(|subscribed_count| {
                list.totals.eligible_items_before_dedupe > subscribed_count
            });
    if exceeds_declared_subscribed
        && list.declared_unsubscribed_count.unwrap_or_default() > 0
        && list.totals.excluded_unsubscribed == 0
    {
        warnings.push(format!(
            "GetLists reports unsubscribed_count {} for list {}, but subscriber XML export excluded zero unsubscribed rows; unsubscribe status is not proven by this export",
            list.declared_unsubscribed_count.unwrap_or_default(),
            list.list_id
        ));
    }
}

fn completed_list_summaries(lists: &[JobListState]) -> Vec<AudienceHygieneListSummary> {
    lists
        .iter()
        .filter_map(|list| list.summary.clone())
        .collect()
}

fn next_incomplete_list_index(state: &ExportJobState) -> Option<usize> {
    state.lists.iter().position(|list| list.summary.is_none())
}

fn build_job_id(source_list_ids: &[u64]) -> Result<String, InterspireError> {
    Ok(format!(
        "iah_{}_{}",
        unix_timestamp_nanos()?,
        source_list_ids.len()
    ))
}

fn load_state(output_dir: &Path, job_id: &str) -> Result<ExportJobState, InterspireError> {
    let job_dir = find_job_dir(output_dir, job_id)?;
    let body = fs::read(state_path(&job_dir))
        .map_err(|err| InterspireError::Io(format!("failed to read checkpoint state: {err}")))?;
    let state: ExportJobState = serde_json::from_slice(&body)
        .map_err(|err| InterspireError::Io(format!("failed to parse checkpoint state: {err}")))?;
    if state.version != JOB_STATE_VERSION {
        return Err(InterspireError::Io(format!(
            "unsupported checkpoint state version {}",
            state.version
        )));
    }
    Ok(state)
}

fn find_job_dir(output_dir: &Path, job_id: &str) -> Result<PathBuf, InterspireError> {
    let job_id = job_id.trim();
    if job_id.is_empty() {
        return Err(InterspireError::Safety(
            "checkpoint job_id must be a non-empty exact identifier".to_string(),
        ));
    }
    let entries = fs::read_dir(output_dir)
        .map_err(|err| InterspireError::Io(format!("failed to read output dir: {err}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| InterspireError::Io(format!("failed to read dir entry: {err}")))?;
        let path = entry.path();
        if path.is_dir() {
            ensure_output_dir_still_approved(&path)?;
            if matches!(stored_job_id(&path).as_deref(), Ok(stored) if stored == job_id) {
                return Ok(path);
            }
        }
    }
    Err(InterspireError::Io(format!(
        "checkpoint job {} was not found under {}",
        job_id,
        output_dir.display()
    )))
}

fn stored_job_id(job_dir: &Path) -> Result<String, InterspireError> {
    #[derive(Deserialize)]
    struct StoredJobIdentity {
        job_id: String,
    }

    let path = state_path(job_dir);
    let body = fs::read(&path).map_err(|err| {
        InterspireError::Io(format!(
            "failed to read checkpoint state {}: {err}",
            path.display()
        ))
    })?;
    let identity: StoredJobIdentity = serde_json::from_slice(&body).map_err(|err| {
        InterspireError::Io(format!(
            "failed to parse checkpoint state {}: {err}",
            path.display()
        ))
    })?;
    Ok(identity.job_id)
}

fn write_state(job_dir: &Path, state: &ExportJobState) -> Result<(), InterspireError> {
    ensure_output_dir_still_approved(job_dir)?;
    let path = state_path(job_dir);
    let temp_path = job_dir.join(format!(".{}.tmp", JOB_STATE_FILE));
    let body = serde_json::to_vec_pretty(state).map_err(|err| {
        InterspireError::Io(format!("failed to serialize checkpoint state: {err}"))
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|err| {
            InterspireError::Io(format!("failed to open checkpoint temp file: {err}"))
        })?;
    file.write_all(&body)
        .map_err(|err| InterspireError::Io(format!("failed to write checkpoint state: {err}")))?;
    file.flush()
        .map_err(|err| InterspireError::Io(format!("failed to flush checkpoint state: {err}")))?;
    let mut perms = file
        .metadata()
        .map_err(|err| InterspireError::Io(format!("failed to stat checkpoint temp file: {err}")))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&temp_path, perms).map_err(|err| {
        InterspireError::Io(format!("failed to set checkpoint temp permissions: {err}"))
    })?;
    fs::rename(&temp_path, &path).map_err(|err| {
        InterspireError::Io(format!("failed to move checkpoint state into place: {err}"))
    })?;
    Ok(())
}

fn state_path(job_dir: &Path) -> PathBuf {
    job_dir.join(JOB_STATE_FILE)
}

fn normalized_source_list_ids(values: &[u64]) -> Vec<u64> {
    let mut normalized = Vec::new();
    for list_id in values.iter().copied().filter(|list_id| *list_id > 0) {
        if !normalized.contains(&list_id) {
            normalized.push(list_id);
        }
    }
    normalized
}

fn filter_requested_lists(
    mut lists: Vec<crate::response::ListSummary>,
    requested_source_list_ids: &[u64],
) -> Vec<crate::response::ListSummary> {
    let mut selected = Vec::new();
    for list_id in requested_source_list_ids {
        if let Some(index) = lists
            .iter()
            .position(|candidate| candidate.list_id == *list_id)
        {
            selected.push(lists.remove(index));
        }
    }
    selected
}

fn join_ids(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "interspire-checkpoint-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn fixture_state(job_dir: &Path, job_id: &str) -> ExportJobState {
        ExportJobState {
            version: JOB_STATE_VERSION,
            job_id: job_id.to_string(),
            job_dir: job_dir.display().to_string(),
            artifact_prefix: "fixture".to_string(),
            include_sqlite: false,
            source_list_ids: vec![7],
            missing_list_ids: Vec::new(),
            lists: Vec::new(),
            totals: Totals::default(),
            candidates: BTreeMap::new(),
            warnings: Vec::new(),
            evidence_notes: vec!["fixture".to_string()],
            completed_query_count: 0,
            finalized: false,
            final_artifacts: Vec::new(),
        }
    }

    #[test]
    fn find_job_dir_requires_exact_job_id_match() {
        let output_dir = unique_dir("lookup");
        let job_one = output_dir.join("fixture-iah_123");
        let job_two = output_dir.join("fixture-iah_999123");
        fs::create_dir_all(&job_one).expect("create first job dir");
        fs::create_dir_all(&job_two).expect("create second job dir");
        write_state(&job_one, &fixture_state(&job_one, "iah_123")).expect("write first state");
        write_state(&job_two, &fixture_state(&job_two, "iah_999123")).expect("write second state");

        let resolved = find_job_dir(&output_dir, "iah_123").expect("exact job id should resolve");
        assert_eq!(resolved, job_one);
        assert!(find_job_dir(&output_dir, "123").is_err());
        assert!(find_job_dir(&output_dir, "").is_err());

        fs::remove_dir_all(&output_dir).unwrap_or_default();
    }

    #[test]
    fn build_report_restores_base_export_warnings() {
        let output_dir = unique_dir("warnings");
        let job_dir = output_dir.join("fixture-iah_456");
        fs::create_dir_all(&job_dir).expect("create job dir");
        let state = fixture_state(&job_dir, "iah_456");
        write_state(&job_dir, &state).expect("write checkpoint state");

        let report = build_report(&state, 0).expect("report should build");
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("raw recipient addresses") && warning.contains("git")
        }));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("does not remove provider suppressions")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("not send authorization")));

        fs::remove_dir_all(&output_dir).unwrap_or_default();
    }
}

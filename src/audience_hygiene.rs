//! Audience hygiene artifact builder for private ESP validation workflows.
//!
//! This module performs local, private processing of Interspire subscriber
//! records after the XML adapter has read them. MCP responses remain aggregate
//! and redacted; raw recipient data is written only to private staging artifacts
//! outside the repository.

use crate::{
    error::InterspireError,
    response::{
        AudienceHygieneArtifact, AudienceHygieneExportReport, AudienceHygieneExportRequest,
        AudienceHygieneListSummary, Evidence,
    },
    xml_api::SubscriberRecord,
};
use csv::Writer;
use rusqlite::{params, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const OUTPUT_DIR_ENV: &str = "INTERSPIRE_AUDIENCE_HYGIENE_OUTPUT_DIR";
const OUTPUT_ROOTS_ENV: &str = "INTERSPIRE_AUDIENCE_HYGIENE_ROOTS";

#[derive(Debug, Clone)]
pub struct HygieneListInput {
    pub list_id: u64,
    pub name: String,
    pub declared_subscribed_count: Option<u64>,
    pub declared_unsubscribed_count: Option<u64>,
    pub records: Vec<SubscriberRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CandidateRow {
    email: String,
    source_list_ids: String,
    source_list_names: String,
    subscriber_ids: String,
    first_subscribe_ts: String,
    role_localpart: bool,
    disposable_domain_hint: bool,
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub(crate) struct Candidate {
    pub(crate) source_list_ids: BTreeSet<u64>,
    pub(crate) source_list_names: BTreeSet<String>,
    pub(crate) subscriber_ids: BTreeSet<String>,
    pub(crate) first_subscribe_ts: Option<String>,
    pub(crate) role_localpart: bool,
    pub(crate) disposable_domain_hint: bool,
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub(crate) struct Totals {
    pub(crate) api_items: u64,
    pub(crate) eligible_items_before_dedupe: u64,
    pub(crate) excluded_unconfirmed: u64,
    pub(crate) excluded_unsubscribed: u64,
    pub(crate) excluded_bounced: u64,
    pub(crate) invalid_syntax: u64,
}

pub(crate) fn append_base_export_warnings(warnings: &mut Vec<String>) {
    for warning in [
        "Private artifacts may contain raw recipient addresses; keep them out of git, issue trackers, tickets, and chat",
        "This export does not remove provider suppressions or hard bounces yet; that is a separate recovery gate",
        "This export is not send authorization and does not mutate legacy Interspire lists",
    ] {
        if !warnings.iter().any(|existing| existing == warning) {
            warnings.push(warning.to_string());
        }
    }
}

pub fn build_audience_hygiene_export(
    request: &AudienceHygieneExportRequest,
    source_list_ids: Vec<u64>,
    missing_list_ids: Vec<u64>,
    inputs: Vec<HygieneListInput>,
    evidence: Evidence,
    mut warnings: Vec<String>,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let mut totals = Totals::default();
    let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut list_summaries = Vec::new();

    for input in inputs {
        let mut list_totals = Totals::default();
        for record in &input.records {
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
            candidate.source_list_ids.insert(input.list_id);
            candidate.source_list_names.insert(input.name.clone());
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

        append_status_authority_warnings(&mut warnings, &input, &list_totals);

        list_summaries.push(AudienceHygieneListSummary {
            list_id: input.list_id,
            name: input.name,
            api_items: list_totals.api_items,
            eligible_items_before_dedupe: list_totals.eligible_items_before_dedupe,
            excluded_unconfirmed: list_totals.excluded_unconfirmed,
            excluded_unsubscribed: list_totals.excluded_unsubscribed,
            excluded_bounced: list_totals.excluded_bounced,
            invalid_syntax: list_totals.invalid_syntax,
        });
    }

    let rows = candidate_rows(&candidates);
    let role_localpart_count = rows.iter().filter(|row| row.role_localpart).count() as u64;
    let disposable_domain_hint_count =
        rows.iter().filter(|row| row.disposable_domain_hint).count() as u64;

    let artifacts = write_artifacts(request, &rows, &list_summaries, &totals, &source_list_ids)?;

    append_base_export_warnings(&mut warnings);

    Ok(AudienceHygieneExportReport {
        ok: true,
        configured: true,
        job_id: None,
        phase: None,
        job_dir: None,
        source_list_ids,
        processed_list_count: list_summaries.len() as u64,
        remaining_list_ids: Vec::new(),
        missing_list_ids,
        active_list_id: None,
        active_list_name: None,
        queries_processed_this_call: 0,
        completed_query_count: 0,
        remaining_query_count: 0,
        lists: list_summaries,
        gross_api_items: totals.api_items,
        eligible_items_before_dedupe: totals.eligible_items_before_dedupe,
        deduped_eligible_count: rows.len() as u64,
        duplicate_eligible_items_removed: totals
            .eligible_items_before_dedupe
            .saturating_sub(rows.len() as u64),
        excluded_unconfirmed: totals.excluded_unconfirmed,
        excluded_unsubscribed: totals.excluded_unsubscribed,
        excluded_bounced: totals.excluded_bounced,
        invalid_syntax_count: totals.invalid_syntax,
        role_localpart_count,
        disposable_domain_hint_count,
        checkpoint_artifacts: Vec::new(),
        artifacts,
        legacy_lists_mutated: false,
        production_send_authorized: false,
        warnings,
        evidence,
    })
}

pub(crate) fn append_status_authority_warnings(
    warnings: &mut Vec<String>,
    input: &HygieneListInput,
    list_totals: &Totals,
) {
    if let Some(subscribed_count) = input.declared_subscribed_count {
        if list_totals.eligible_items_before_dedupe > subscribed_count {
            warnings.push(format!(
                "Subscriber XML export for list {} returned {} eligible-looking rows, exceeding GetLists subscribed_count {}; treat this artifact as candidate discovery, not subscribed/send-ready proof",
                input.list_id, list_totals.eligible_items_before_dedupe, subscribed_count
            ));
        }
    }

    let exceeds_declared_subscribed =
        input
            .declared_subscribed_count
            .is_some_and(|subscribed_count| {
                list_totals.eligible_items_before_dedupe > subscribed_count
            });
    if exceeds_declared_subscribed
        && input.declared_unsubscribed_count.unwrap_or_default() > 0
        && list_totals.excluded_unsubscribed == 0
    {
        warnings.push(format!(
            "GetLists reports unsubscribed_count {} for list {}, but subscriber XML export excluded zero unsubscribed rows; unsubscribe status is not proven by this export",
            input.declared_unsubscribed_count.unwrap_or_default(),
            input.list_id
        ));
    }
}

pub(crate) fn write_artifacts(
    request: &AudienceHygieneExportRequest,
    rows: &[CandidateRow],
    lists: &[AudienceHygieneListSummary],
    totals: &Totals,
    source_list_ids: &[u64],
) -> Result<Vec<AudienceHygieneArtifact>, InterspireError> {
    let output_dir = safe_output_dir(request.output_dir.as_deref())?;
    fs::create_dir_all(&output_dir).map_err(|err| {
        InterspireError::Io(format!(
            "failed to create private audience export directory: {err}"
        ))
    })?;
    set_private_dir_permissions(&output_dir)?;
    ensure_output_dir_still_approved(&output_dir)?;

    let stamp = unix_timestamp_nanos()?;
    let prefix = safe_prefix(request.artifact_prefix.as_deref());
    let mut artifacts = Vec::new();

    let private_csv = output_dir.join(format!("{prefix}-{stamp}-deduped-private.csv"));
    write_private_csv(&private_csv, rows)?;
    artifacts.push(artifact("deduped_private_csv", &private_csv, true)?);

    let mailgun_csv = output_dir.join(format!("{prefix}-{stamp}-mailgun-validation.csv"));
    write_mailgun_csv(&mailgun_csv, rows)?;
    artifacts.push(artifact("mailgun_validation_csv", &mailgun_csv, true)?);

    if request.include_sqlite {
        let sqlite_path = output_dir.join(format!("{prefix}-{stamp}.sqlite3"));
        write_sqlite(&sqlite_path, rows, lists, totals, source_list_ids)?;
        artifacts.push(artifact("sqlite3", &sqlite_path, true)?);
    }

    let summary_path = output_dir.join(format!("{prefix}-{stamp}-summary.json"));
    write_summary_json(
        &summary_path,
        lists,
        totals,
        source_list_ids,
        rows.len() as u64,
    )?;
    artifacts.push(artifact("aggregate_summary_json", &summary_path, false)?);

    Ok(artifacts)
}

pub(crate) fn candidate_rows(candidates: &BTreeMap<String, Candidate>) -> Vec<CandidateRow> {
    candidates
        .iter()
        .map(|(email, candidate)| CandidateRow {
            email: email.clone(),
            source_list_ids: candidate
                .source_list_ids
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(";"),
            source_list_names: candidate
                .source_list_names
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(";"),
            subscriber_ids: candidate
                .subscriber_ids
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(";"),
            first_subscribe_ts: candidate.first_subscribe_ts.clone().unwrap_or_default(),
            role_localpart: candidate.role_localpart,
            disposable_domain_hint: candidate.disposable_domain_hint,
        })
        .collect()
}

fn write_private_csv(path: &Path, rows: &[CandidateRow]) -> Result<(), InterspireError> {
    let file = create_private_file(path, "private CSV")?;
    let mut writer = Writer::from_writer(file);
    for row in rows {
        writer
            .serialize(row)
            .map_err(|err| InterspireError::Io(format!("failed to write private CSV: {err}")))?;
    }
    writer
        .flush()
        .map_err(|err| InterspireError::Io(format!("failed to flush private CSV: {err}")))?;
    set_private_file_permissions(path)
}

fn write_mailgun_csv(path: &Path, rows: &[CandidateRow]) -> Result<(), InterspireError> {
    let file = create_private_file(path, "Mailgun validation CSV")?;
    let mut writer = Writer::from_writer(file);
    writer
        .write_record(["email"])
        .map_err(|err| InterspireError::Io(format!("failed to write CSV header: {err}")))?;
    for row in rows {
        writer
            .write_record([row.email.as_str()])
            .map_err(|err| InterspireError::Io(format!("failed to write CSV row: {err}")))?;
    }
    writer.flush().map_err(|err| {
        InterspireError::Io(format!("failed to flush Mailgun validation CSV: {err}"))
    })?;
    set_private_file_permissions(path)
}

fn write_sqlite(
    path: &Path,
    rows: &[CandidateRow],
    lists: &[AudienceHygieneListSummary],
    totals: &Totals,
    source_list_ids: &[u64],
) -> Result<(), InterspireError> {
    if path.exists() {
        fs::remove_file(path)
            .map_err(|err| InterspireError::Io(format!("failed to replace sqlite file: {err}")))?;
    }
    drop(create_private_file(path, "sqlite artifact")?);
    let mut conn = Connection::open(path)
        .map_err(|err| InterspireError::Io(format!("failed to open sqlite artifact: {err}")))?;
    conn.execute_batch(
        "
        CREATE TABLE candidates (
          email TEXT PRIMARY KEY,
          source_list_ids TEXT NOT NULL,
          source_list_names TEXT NOT NULL,
          subscriber_ids TEXT NOT NULL,
          first_subscribe_ts TEXT NOT NULL,
          role_localpart INTEGER NOT NULL,
          disposable_domain_hint INTEGER NOT NULL
        );
        CREATE TABLE source_lists (
          list_id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          api_items INTEGER NOT NULL,
          eligible_items_before_dedupe INTEGER NOT NULL,
          excluded_unconfirmed INTEGER NOT NULL,
          excluded_unsubscribed INTEGER NOT NULL,
          excluded_bounced INTEGER NOT NULL,
          invalid_syntax INTEGER NOT NULL
        );
        CREATE TABLE export_summary (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        ",
    )
    .map_err(|err| InterspireError::Io(format!("failed to initialize sqlite artifact: {err}")))?;

    let tx = conn
        .transaction()
        .map_err(|err| InterspireError::Io(format!("failed to start sqlite transaction: {err}")))?;
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO candidates
                (email, source_list_ids, source_list_names, subscriber_ids, first_subscribe_ts, role_localpart, disposable_domain_hint)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .map_err(|err| InterspireError::Io(format!("failed to prepare sqlite insert: {err}")))?;
        for row in rows {
            stmt.execute(params![
                row.email,
                row.source_list_ids,
                row.source_list_names,
                row.subscriber_ids,
                row.first_subscribe_ts,
                row.role_localpart as i64,
                row.disposable_domain_hint as i64,
            ])
            .map_err(|err| {
                InterspireError::Io(format!("failed to insert sqlite candidate: {err}"))
            })?;
        }
    }
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO source_lists
                (list_id, name, api_items, eligible_items_before_dedupe, excluded_unconfirmed, excluded_unsubscribed, excluded_bounced, invalid_syntax)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(|err| InterspireError::Io(format!("failed to prepare list insert: {err}")))?;
        for list in lists {
            stmt.execute(params![
                list.list_id,
                list.name,
                list.api_items,
                list.eligible_items_before_dedupe,
                list.excluded_unconfirmed,
                list.excluded_unsubscribed,
                list.excluded_bounced,
                list.invalid_syntax,
            ])
            .map_err(|err| {
                InterspireError::Io(format!("failed to insert sqlite list summary: {err}"))
            })?;
        }
    }
    tx.execute(
        "INSERT INTO export_summary (key, value) VALUES (?1, ?2)",
        params!["source_list_ids", join_u64(source_list_ids)],
    )
    .map_err(|err| InterspireError::Io(format!("failed to insert sqlite summary: {err}")))?;
    tx.execute(
        "INSERT INTO export_summary (key, value) VALUES (?1, ?2)",
        params!["gross_api_items", totals.api_items.to_string()],
    )
    .map_err(|err| InterspireError::Io(format!("failed to insert sqlite summary: {err}")))?;
    tx.execute(
        "INSERT INTO export_summary (key, value) VALUES (?1, ?2)",
        params![
            "eligible_items_before_dedupe",
            totals.eligible_items_before_dedupe.to_string()
        ],
    )
    .map_err(|err| InterspireError::Io(format!("failed to insert sqlite summary: {err}")))?;
    tx.commit()
        .map_err(|err| InterspireError::Io(format!("failed to commit sqlite artifact: {err}")))?;
    set_private_file_permissions(path)
}

fn write_summary_json(
    path: &Path,
    lists: &[AudienceHygieneListSummary],
    totals: &Totals,
    source_list_ids: &[u64],
    deduped_eligible_count: u64,
) -> Result<(), InterspireError> {
    let value = serde_json::json!({
        "source_list_ids": source_list_ids,
        "gross_api_items": totals.api_items,
        "eligible_items_before_dedupe": totals.eligible_items_before_dedupe,
        "deduped_eligible_count": deduped_eligible_count,
        "duplicate_eligible_items_removed": totals.eligible_items_before_dedupe.saturating_sub(deduped_eligible_count),
        "excluded_unconfirmed": totals.excluded_unconfirmed,
        "excluded_unsubscribed": totals.excluded_unsubscribed,
        "excluded_bounced": totals.excluded_bounced,
        "invalid_syntax_count": totals.invalid_syntax,
        "lists": lists,
        "contains_raw_recipient_data": false,
    });
    let body = serde_json::to_vec_pretty(&value)
        .map_err(|err| InterspireError::Io(format!("failed to serialize summary json: {err}")))?;
    let mut file = create_private_file(path, "summary json")?;
    file.write_all(&body)
        .map_err(|err| InterspireError::Io(format!("failed to write summary json: {err}")))?;
    file.flush()
        .map_err(|err| InterspireError::Io(format!("failed to flush summary json: {err}")))?;
    set_private_file_permissions(path)
}

pub(crate) fn artifact(
    kind: &str,
    path: &Path,
    contains_raw_recipient_data: bool,
) -> Result<AudienceHygieneArtifact, InterspireError> {
    let bytes = fs::read(path)
        .map_err(|err| InterspireError::Io(format!("failed to hash audience artifact: {err}")))?;
    let digest = Sha256::digest(&bytes);
    Ok(AudienceHygieneArtifact {
        kind: kind.to_string(),
        path: path.display().to_string(),
        sha256: hex::encode(digest),
        bytes: bytes.len() as u64,
        contains_raw_recipient_data,
    })
}

pub(crate) fn safe_output_dir(raw: Option<&str>) -> Result<PathBuf, InterspireError> {
    let raw_path = raw
        .map(ToString::to_string)
        .or_else(|| env::var(OUTPUT_DIR_ENV).ok())
        .ok_or_else(|| {
            InterspireError::Safety(format!(
                "audience hygiene output_dir must be supplied or {OUTPUT_DIR_ENV} must be set"
            ))
        })?;
    let path = PathBuf::from(&raw_path);
    if !path.is_absolute() {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir must be absolute".to_string(),
        ));
    }
    if raw_path_has_dot_component(&raw_path)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir must not contain dot path components".to_string(),
        ));
    }
    let repo_root = artifact_guard_repo_root()?;
    let allowed_roots = approved_output_roots()?;
    if allowed_roots.contains(&path) {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir must be a subdirectory, not an allowed root".to_string(),
        ));
    }
    if !allowed_roots.iter().any(|root| path.starts_with(root)) {
        return Err(InterspireError::Safety(format!(
            "audience hygiene output_dir must be under one of the private roots listed in {OUTPUT_ROOTS_ENV}"
        )));
    }

    if let Ok(canonical_target) = path.canonicalize() {
        if allowed_roots.contains(&canonical_target) {
            return Err(InterspireError::Safety(
                "audience hygiene output_dir must be a subdirectory, not an allowed root"
                    .to_string(),
            ));
        }
        if repo_root
            .as_ref()
            .is_some_and(|root| canonical_target.starts_with(root))
        {
            return Err(InterspireError::Safety(
                "audience hygiene artifacts must be outside the repository".to_string(),
            ));
        }
        if !allowed_roots
            .iter()
            .any(|root| canonical_target.starts_with(root))
        {
            return Err(InterspireError::Safety(
                "audience hygiene output_dir resolved outside the approved private artifact roots"
                    .to_string(),
            ));
        }
    }

    let existing_ancestor = nearest_existing_ancestor(&path)?;
    let canonical_ancestor = canonical_path(&existing_ancestor)?;
    if repo_root
        .as_ref()
        .is_some_and(|root| canonical_ancestor.starts_with(root))
    {
        return Err(InterspireError::Safety(
            "audience hygiene artifacts must be outside the repository".to_string(),
        ));
    }
    if !allowed_roots
        .iter()
        .any(|root| canonical_ancestor.starts_with(root))
    {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir resolved outside the approved private artifact roots"
                .to_string(),
        ));
    }

    Ok(path)
}

fn approved_output_roots() -> Result<Vec<PathBuf>, InterspireError> {
    #[cfg(test)]
    {
        let mut roots = env_output_roots()?;
        roots.push(canonical_path(Path::new("/tmp"))?);
        roots.push(canonical_path(&std::env::temp_dir())?);
        Ok(roots)
    }
    #[cfg(not(test))]
    {
        let roots = env_output_roots()?;
        if roots.is_empty() {
            return Err(InterspireError::Safety(format!(
                "{OUTPUT_ROOTS_ENV} must list at least one existing private absolute artifact root"
            )));
        }
        Ok(roots)
    }
}

fn env_output_roots() -> Result<Vec<PathBuf>, InterspireError> {
    let Some(raw) = env::var(OUTPUT_ROOTS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(Vec::new());
    };

    raw.split(':')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(InterspireError::Safety(format!(
                    "{OUTPUT_ROOTS_ENV} entries must be absolute paths"
                )));
            }
            if raw_path_has_dot_component(value)
                || path
                    .components()
                    .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            {
                return Err(InterspireError::Safety(format!(
                    "{OUTPUT_ROOTS_ENV} entries must not contain dot path components"
                )));
            }
            canonical_path(&path)
        })
        .collect()
}

pub(crate) fn ensure_output_dir_still_approved(path: &Path) -> Result<(), InterspireError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        InterspireError::Io(format!(
            "failed to stat private audience export directory: {err}"
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir must not be a symlink".to_string(),
        ));
    }

    let repo_root = artifact_guard_repo_root()?;
    let allowed_roots = approved_output_roots()?;
    let canonical_target = canonical_path(path)?;
    if allowed_roots.contains(&canonical_target) {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir must be a subdirectory, not an allowed root".to_string(),
        ));
    }
    if repo_root
        .as_ref()
        .is_some_and(|root| canonical_target.starts_with(root))
    {
        return Err(InterspireError::Safety(
            "audience hygiene artifacts must be outside the repository".to_string(),
        ));
    }
    if !allowed_roots
        .iter()
        .any(|root| canonical_target.starts_with(root))
    {
        return Err(InterspireError::Safety(
            "audience hygiene output_dir resolved outside the approved private artifact roots"
                .to_string(),
        ));
    }
    Ok(())
}

fn nearest_existing_ancestor(path: &Path) -> Result<PathBuf, InterspireError> {
    let mut current = path;
    while !current.exists() {
        current = current.parent().ok_or_else(|| {
            InterspireError::Safety(
                "audience hygiene output_dir has no existing parent directory".to_string(),
            )
        })?;
    }
    Ok(current.to_path_buf())
}

fn raw_path_has_dot_component(raw: &str) -> bool {
    raw.split('/')
        .any(|component| matches!(component, "." | ".."))
}

fn canonical_path(path: &Path) -> Result<PathBuf, InterspireError> {
    path.canonicalize().map_err(|err| {
        InterspireError::Safety(format!(
            "failed to canonicalize audience hygiene path: {err}"
        ))
    })
}

fn artifact_guard_repo_root() -> Result<Option<PathBuf>, InterspireError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !path.exists() {
        return Ok(None);
    }
    canonical_path(path).map(Some)
}

pub(crate) fn set_private_dir_permissions(path: &Path) -> Result<(), InterspireError> {
    let mut perms = fs::metadata(path)
        .map_err(|err| InterspireError::Io(format!("failed to stat private directory: {err}")))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
        .map_err(|err| InterspireError::Io(format!("failed to set directory permissions: {err}")))
}

fn set_private_file_permissions(path: &Path) -> Result<(), InterspireError> {
    let mut perms = fs::metadata(path)
        .map_err(|err| InterspireError::Io(format!("failed to stat private artifact: {err}")))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .map_err(|err| InterspireError::Io(format!("failed to set artifact permissions: {err}")))
}

fn create_private_file(path: &Path, label: &str) -> Result<fs::File, InterspireError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| {
            InterspireError::Io(format!(
                "failed to create private {} artifact: {}",
                label, err
            ))
        })
}

pub(crate) fn unix_timestamp_nanos() -> Result<u128, InterspireError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|err| InterspireError::Io(format!("system time before unix epoch: {err}")))
}

pub(crate) fn safe_prefix(raw: Option<&str>) -> String {
    let raw = raw.unwrap_or("interspire-audience-hygiene");
    let mut out = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "interspire-audience-hygiene".to_string()
    } else {
        out.chars().take(80).collect()
    }
}

pub(crate) fn normalize_email(raw: &str) -> Option<String> {
    let email = raw
        .trim()
        .trim_matches(['<', '>', '"', '\''])
        .to_ascii_lowercase();
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    if local.chars().any(|ch| ch.is_whitespace()) {
        return None;
    }
    let labels = domain.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return None;
    }
    if labels.iter().any(|label| {
        label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) {
        return None;
    }
    Some(email)
}

pub(crate) fn is_role_address(email: &str) -> bool {
    let Some((local, _domain)) = email.split_once('@') else {
        return false;
    };
    matches!(
        local,
        "abuse"
            | "admin"
            | "administrator"
            | "billing"
            | "bounce"
            | "bounces"
            | "compliance"
            | "contact"
            | "devnull"
            | "dns"
            | "enquiries"
            | "enquiry"
            | "feedback"
            | "help"
            | "helpdesk"
            | "hostmaster"
            | "info"
            | "inquiries"
            | "inquiry"
            | "list"
            | "listserv"
            | "mailer-daemon"
            | "marketing"
            | "media"
            | "news"
            | "newsletter"
            | "newsletters"
            | "no-reply"
            | "noreply"
            | "null"
            | "office"
            | "operations"
            | "postmaster"
            | "press"
            | "privacy"
            | "reception"
            | "reply"
            | "root"
            | "sales"
            | "security"
            | "spam"
            | "support"
            | "team"
            | "unsubscribe"
            | "webmaster"
    )
}

pub(crate) fn is_disposable_hint(email: &str) -> bool {
    let Some((_local, domain)) = email.split_once('@') else {
        return false;
    };
    matches!(
        domain,
        "10minutemail.com"
            | "guerrillamail.com"
            | "mailinator.com"
            | "tempmail.com"
            | "throwawaymail.com"
            | "yopmail.com"
    )
}

pub(crate) fn min_optional_text(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn join_u64(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(email: &str, confirmed: bool, unsubscribed: bool, bounced: bool) -> SubscriberRecord {
        SubscriberRecord {
            subscriber_id: Some(1),
            email_address: email.to_string(),
            subscribe_date: Some(100),
            confirmed,
            unsubscribed,
            bounced,
        }
    }

    #[test]
    fn hygiene_export_dedupes_and_filters_without_mutation_claims() {
        let dir = std::env::temp_dir().join(format!(
            "interspire-hygiene-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let request = AudienceHygieneExportRequest {
            source_list_ids: vec![7],
            output_dir: Some(dir.display().to_string()),
            artifact_prefix: Some("contract".to_string()),
            include_sqlite: true,
        };
        let report = build_audience_hygiene_export(
            &request,
            vec![7],
            Vec::new(),
            vec![HygieneListInput {
                list_id: 7,
                name: "Test list".to_string(),
                declared_subscribed_count: Some(1),
                declared_unsubscribed_count: Some(1),
                records: vec![
                    record("Person@Example.com", true, false, false),
                    record("person@example.com", true, false, false),
                    record("old@example.net", false, false, false),
                    record("gone@example.net", true, true, false),
                    record("bad@example.net", true, false, true),
                    record("not-an-email", true, false, false),
                    record("info@example.org", true, false, false),
                ],
            }],
            Evidence {
                source: "fixture".to_string(),
                notes: Vec::new(),
            },
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(report.gross_api_items, 7);
        assert_eq!(report.eligible_items_before_dedupe, 3);
        assert_eq!(report.deduped_eligible_count, 2);
        assert_eq!(report.duplicate_eligible_items_removed, 1);
        assert_eq!(report.excluded_unconfirmed, 1);
        assert_eq!(report.excluded_unsubscribed, 1);
        assert_eq!(report.excluded_bounced, 1);
        assert_eq!(report.invalid_syntax_count, 1);
        assert_eq!(report.role_localpart_count, 1);
        assert!(!report.legacy_lists_mutated);
        assert!(!report.production_send_authorized);
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == "sqlite3"));
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("exceeding GetLists subscribed_count")
                && warning.contains("candidate discovery")
        }));
        assert!(report
            .artifacts
            .iter()
            .filter(|artifact| artifact.contains_raw_recipient_data)
            .all(|artifact| artifact.bytes > 0 && artifact.sha256.len() == 64));

        fs::remove_dir_all(&dir).unwrap_or_default();
    }

    #[test]
    fn hygiene_export_warns_when_xml_status_counts_conflict_with_list_summary() {
        let dir = std::env::temp_dir().join(format!(
            "interspire-hygiene-status-warning-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let request = AudienceHygieneExportRequest {
            source_list_ids: vec![7],
            output_dir: Some(dir.display().to_string()),
            artifact_prefix: Some("contract".to_string()),
            include_sqlite: false,
        };
        let report = build_audience_hygiene_export(
            &request,
            vec![7],
            Vec::new(),
            vec![HygieneListInput {
                list_id: 7,
                name: "Test list".to_string(),
                declared_subscribed_count: Some(1),
                declared_unsubscribed_count: Some(9),
                records: vec![
                    record("one@example.com", true, false, false),
                    record("two@example.com", true, false, false),
                ],
            }],
            Evidence {
                source: "fixture".to_string(),
                notes: Vec::new(),
            },
            Vec::new(),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.warnings.iter().any(|warning| {
            warning.contains("exceeding GetLists subscribed_count")
                && warning.contains("candidate discovery")
        }));
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("GetLists reports unsubscribed_count")
                && warning.contains("unsubscribe status is not proven")
        }));

        fs::remove_dir_all(&dir).unwrap_or_default();
    }

    #[test]
    fn rejects_relative_or_repo_artifact_paths() {
        let err = safe_output_dir(Some("relative/path")).unwrap_err();
        assert_eq!(err.code(), "safety_policy_blocked");

        let repo_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("private-output");
        let err = safe_output_dir(Some(&repo_path.display().to_string())).unwrap_err();
        assert_eq!(err.code(), "safety_policy_blocked");
    }

    #[test]
    fn compile_time_manifest_root_guard_is_non_fatal() {
        let _ = artifact_guard_repo_root().expect("manifest root guard should not fail");
    }

    #[test]
    fn rejects_allowed_roots_and_symlink_escape_paths() {
        let temp_dir = std::env::temp_dir();
        let err = safe_output_dir(Some(&temp_dir.display().to_string())).unwrap_err();
        assert_eq!(err.code(), "safety_policy_blocked");

        let dotdot_path = temp_dir.join("interspire-hygiene-new").join("..");
        let err = safe_output_dir(Some(&dotdot_path.display().to_string())).unwrap_err();
        assert_eq!(err.code(), "safety_policy_blocked");

        let dot_path = format!("{}/interspire-hygiene-new/./child", temp_dir.display());
        let err = safe_output_dir(Some(&dot_path)).unwrap_err();
        assert_eq!(err.code(), "safety_policy_blocked");

        let link_path = temp_dir.join(format!(
            "interspire-hygiene-link-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::os::unix::fs::symlink(env!("CARGO_MANIFEST_DIR"), &link_path)
            .expect("create temp symlink");
        let err = safe_output_dir(Some(&link_path.display().to_string())).unwrap_err();
        fs::remove_file(&link_path).unwrap_or_default();

        assert_eq!(err.code(), "safety_policy_blocked");
    }

    #[test]
    fn private_csv_creation_rejects_preexisting_symlink_file() {
        let temp_dir = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let link_path = temp_dir.join(format!("interspire-hygiene-file-link-{unique}.csv"));
        let target_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("blocked-hygiene-{unique}.csv"));
        std::os::unix::fs::symlink(&target_path, &link_path).expect("create temp symlink");

        let err = write_private_csv(
            &link_path,
            &[CandidateRow {
                email: "person@example.com".to_string(),
                source_list_ids: "7".to_string(),
                source_list_names: "Test".to_string(),
                subscriber_ids: "1".to_string(),
                first_subscribe_ts: "100".to_string(),
                role_localpart: false,
                disposable_domain_hint: false,
            }],
        )
        .unwrap_err();
        fs::remove_file(&link_path).unwrap_or_default();
        fs::remove_file(&target_path).unwrap_or_default();

        assert_eq!(err.code(), "io_error");
        assert!(!target_path.exists());
    }
}

use crate::{
    config::{GuardedWriteConfig, OciSendLedgerConfig},
    error::InterspireError,
    guarded_write, redact,
    response::{
        short_hash as ledger_hash, Evidence, OciLedgerPreflightReport, OciLedgerPreflightRequest,
        OciSendLedgerPrepareApplyRequest, OciSendLedgerPreparePreviewRequest,
        OciSendLedgerPrepareReport,
    },
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const LEDGER_PREPARE_VERSION: &str = "interspire-oci-send-ledger-prepare-v1";
const MAX_LEDGER_MANIFEST_BYTES: u64 = 50_000_000;
const MAX_LEDGER_MANIFEST_ROWS: u64 = 250_000;
const LEDGER_PREPARE_MAX_AGE_SECONDS: u64 = 15 * 60;
const LEDGER_PREPARE_CLOCK_SKEW_SECONDS: u64 = 5 * 60;

pub fn verify_preflight(
    config: &OciSendLedgerConfig,
    request: Option<&OciLedgerPreflightRequest>,
    expected_recipient_count: u64,
    interspire_campaign_id: Option<u64>,
) -> OciLedgerPreflightReport {
    let configured = config
        .path
        .as_deref()
        .is_some_and(|path| !path.trim().is_empty());
    let required = config.required_for_sends;
    let Some(request) = request else {
        return OciLedgerPreflightReport::skipped(
            required,
            configured,
            "OCI send ledger preflight was not requested.",
        );
    };

    if request.expected_rows != expected_recipient_count {
        return OciLedgerPreflightReport::blocked(
            required,
            configured,
            Some(request),
            "OCI send ledger expected row count does not match the Interspire send recipient count"
                .to_string(),
        );
    }
    if !valid_identifier(&request.campaign_id) || !valid_identifier(&request.batch_id) {
        return OciLedgerPreflightReport::blocked(
            required,
            configured,
            Some(request),
            "OCI send ledger campaign_id and batch_id must be non-empty printable identifiers"
                .to_string(),
        );
    }
    if let Some(expected_campaign_id) = interspire_campaign_id {
        if request.campaign_id.trim() != expected_campaign_id.to_string() {
            return OciLedgerPreflightReport::blocked(
                required,
                configured,
                Some(request),
                "OCI send ledger campaign_id must match the Interspire campaign being sent"
                    .to_string(),
            );
        }
    }
    if let Some(domain) = request.sender_domain.as_deref() {
        if !valid_domain(domain) {
            return OciLedgerPreflightReport::blocked(
                required,
                configured,
                Some(request),
                "OCI send ledger sender_domain must be a valid domain token".to_string(),
            );
        }
    }
    if let Some(manifest) = request.expected_manifest_sha256.as_deref() {
        if !valid_sha256(manifest) {
            return OciLedgerPreflightReport::blocked(
                required,
                configured,
                Some(request),
                "OCI send ledger expected_manifest_sha256 must be a 64-character hex SHA-256"
                    .to_string(),
            );
        }
    }

    if !configured {
        return OciLedgerPreflightReport::blocked(
            required,
            false,
            Some(request),
            "INTERSPIRE_OCI_SEND_LEDGER_PATH is not configured; guarded send refused before the Interspire final send boundary"
                .to_string(),
        );
    }
    let path = match private_ledger_path(config) {
        Ok(path) => path,
        Err(err) => {
            return OciLedgerPreflightReport::blocked(
                required,
                true,
                Some(request),
                format!(
                    "configured OCI send ledger did not satisfy private path policy; guarded send refused before the Interspire final send boundary: {err}"
                ),
            );
        }
    };
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    else {
        return OciLedgerPreflightReport::blocked(
            required,
            true,
            Some(request),
            "configured OCI send ledger could not be opened; guarded send refused before the Interspire final send boundary"
                .to_string(),
        );
    };

    let mut matched_rows = 0u64;
    let mut rows_with_recipient_key = 0u64;
    let mut rows_with_trace_key = 0u64;
    let mut rows_with_provider_visible_trace_key = 0u64;
    let mut rows_with_submitted_at = 0u64;
    let mut stale_rows_ignored = 0u64;
    let mut invalid_rows = 0u64;
    let now_unix = current_unix_seconds().unwrap_or(0);
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            invalid_rows += 1;
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            invalid_rows += 1;
            continue;
        };
        if !value.is_object() {
            invalid_rows += 1;
            continue;
        }
        if !row_matches(request, &value) {
            continue;
        }
        if !has_fresh_submitted_at(&value, now_unix) {
            stale_rows_ignored += 1;
            continue;
        }
        matched_rows += 1;
        if has_any_string(
            &value,
            &[
                "recipient_id",
                "recipientId",
                "recipient_id_hash",
                "recipientIdHash",
                "recipient",
                "recipient_email",
                "recipientEmail",
                "recipient_address_hash",
                "recipientAddressHash",
                "recipient_hash",
                "recipientHash",
            ],
        ) {
            rows_with_recipient_key += 1;
        }
        if has_any_string(
            &value,
            &[
                "message_id",
                "messageId",
                "provider_message_id",
                "providerMessageId",
                "message_id_hash",
                "messageIdHash",
                "correlation_id",
                "correlationId",
                "correlation_id_hash",
                "correlationIdHash",
                "header_value",
                "headerValue",
                "header_value_hash",
                "headerValueHash",
            ],
        ) {
            rows_with_trace_key += 1;
        }
        if has_provider_visible_trace_key(&value) {
            rows_with_provider_visible_trace_key += 1;
        }
        if has_valid_submitted_at(&value) {
            rows_with_submitted_at += 1;
        }
    }

    let mut warnings = Vec::new();
    if matched_rows != request.expected_rows {
        warnings.push(format!(
            "OCI send ledger matched {matched_rows} rows but expected {} rows",
            request.expected_rows
        ));
    }
    if rows_with_recipient_key != matched_rows {
        warnings.push(
            "one or more matched OCI send ledger rows lack a recipient key or recipient hash"
                .to_string(),
        );
    }
    if rows_with_trace_key != matched_rows {
        warnings.push(
            "one or more matched OCI send ledger rows lack a message, correlation, or header key"
                .to_string(),
        );
    }
    if rows_with_submitted_at != matched_rows {
        warnings.push(
            "one or more matched OCI send ledger rows lack a valid UTC submitted_at/timestamp"
                .to_string(),
        );
    }
    if stale_rows_ignored > 0 && matched_rows != request.expected_rows {
        warnings.push(format!(
            "{stale_rows_ignored} otherwise matching OCI send ledger row(s) were ignored because submitted_at was missing, invalid, older than 15 minutes, or too far in the future"
        ));
    }
    if invalid_rows > 0 {
        warnings.push("one or more OCI send ledger rows were invalid JSON objects".to_string());
    }

    OciLedgerPreflightReport {
        required,
        configured: true,
        requested: true,
        verified: warnings.is_empty(),
        campaign_hash: Some(ledger_hash(request.campaign_id.trim())),
        batch_hash: Some(ledger_hash(request.batch_id.trim())),
        sender_domain: request
            .sender_domain
            .as_ref()
            .map(|value| value.trim().to_ascii_lowercase()),
        expected_rows: Some(request.expected_rows),
        matched_rows,
        rows_with_recipient_key,
        rows_with_trace_key,
        rows_with_provider_visible_trace_key,
        rows_with_submitted_at,
        stale_rows_ignored,
        invalid_rows,
        manifest_sha256: request
            .expected_manifest_sha256
            .as_ref()
            .map(|value| value.trim().to_ascii_lowercase()),
        raw_payload_returned: false,
        warnings: warnings
            .into_iter()
            .map(|warning| redact::redact_sensitive_text(&warning))
            .collect(),
    }
}

pub fn prepare_preview(
    config: &OciSendLedgerConfig,
    request: &OciSendLedgerPreparePreviewRequest,
) -> Result<OciSendLedgerPrepareReport, InterspireError> {
    let context = LedgerPrepareContext::build(config, request)?;
    let preflight = verify_preflight(
        config,
        Some(&context.preflight_request),
        request.expected_rows,
        None,
    );
    Ok(context.report(PrepareReportOptions {
        apply: false,
        guarded_writes_enabled: false,
        send_controls_enabled: false,
        ledger_written: false,
        already_present: false,
        appended_rows: 0,
        expected_plan_match: None,
        ok: context.warnings.is_empty(),
        preflight,
        extra_warnings: Vec::new(),
        notes: vec![
            "preview only; no private ledger file was written".to_string(),
            "no Interspire send, schedule, queue, contact, or provider request was sent"
                .to_string(),
            "raw manifest rows and recipient values were not returned".to_string(),
        ],
    }))
}

pub fn prepare_apply(
    guarded_config: &GuardedWriteConfig,
    config: &OciSendLedgerConfig,
    request: &OciSendLedgerPrepareApplyRequest,
) -> Result<OciSendLedgerPrepareReport, InterspireError> {
    guarded_write::require_send_controls_enabled(guarded_config)?;
    let preview_request = request.preview_request();
    let context = LedgerPrepareContext::build(config, &preview_request)?;
    let plan_matches = context.plan_id == request.expected_plan_id.trim();

    if !request.acknowledge_ledger_write {
        let preflight = verify_context_preflight(config, &context);
        return Ok(context.report(PrepareReportOptions {
            apply: true,
            guarded_writes_enabled: guarded_config.enabled,
            send_controls_enabled: guarded_config.send_controls_enabled,
            ledger_written: false,
            already_present: preflight.verified,
            appended_rows: 0,
            expected_plan_match: Some(plan_matches),
            ok: false,
            preflight,
            extra_warnings: vec![
                "acknowledge_ledger_write=true is required before writing private OCI ledger rows"
                    .to_string(),
            ],
            notes: vec![
                "apply denied before writing the private ledger".to_string(),
                "no Interspire send, schedule, queue, contact, or provider request was sent"
                    .to_string(),
            ],
        }));
    }

    if !plan_matches {
        let preflight = verify_context_preflight(config, &context);
        return Ok(context.report(PrepareReportOptions {
            apply: true,
            guarded_writes_enabled: guarded_config.enabled,
            send_controls_enabled: guarded_config.send_controls_enabled,
            ledger_written: false,
            already_present: preflight.verified,
            appended_rows: 0,
            expected_plan_match: Some(false),
            ok: false,
            preflight,
            extra_warnings: vec![
                "expected_plan_id did not match the current private OCI ledger prepare plan"
                    .to_string(),
            ],
            notes: vec![
                "apply denied before writing the private ledger".to_string(),
                "no Interspire send, schedule, queue, contact, or provider request was sent"
                    .to_string(),
            ],
        }));
    }

    if !context.warnings.is_empty() {
        let preflight = verify_context_preflight(config, &context);
        return Ok(context.report(PrepareReportOptions {
            apply: true,
            guarded_writes_enabled: guarded_config.enabled,
            send_controls_enabled: guarded_config.send_controls_enabled,
            ledger_written: false,
            already_present: preflight.verified,
            appended_rows: 0,
            expected_plan_match: Some(true),
            ok: false,
            preflight,
            extra_warnings: vec![
                "private OCI ledger prepare plan has validation warnings; refusing to write"
                    .to_string(),
            ],
            notes: vec![
                "apply denied before writing the private ledger".to_string(),
                "no Interspire send, schedule, queue, contact, or provider request was sent"
                    .to_string(),
            ],
        }));
    }

    let _lock = LedgerPrepareLock::acquire(&context.ledger_path)?;
    let before = verify_context_preflight(config, &context);
    if before.verified {
        if !prepared_rows_already_present(&context.ledger_path, &context.ledger_rows)? {
            return Ok(context.report(PrepareReportOptions {
                apply: true,
                guarded_writes_enabled: guarded_config.enabled,
                send_controls_enabled: guarded_config.send_controls_enabled,
                ledger_written: false,
                already_present: false,
                appended_rows: 0,
                expected_plan_match: Some(true),
                ok: false,
                preflight: before,
                extra_warnings: vec![
                    "existing OCI ledger rows satisfy preflight but do not match the current prepared row set; refusing to claim idempotence or append"
                        .to_string(),
                ],
                notes: vec![
                    "apply denied before writing the private ledger".to_string(),
                    "no Interspire send, schedule, queue, contact, or provider request was sent"
                        .to_string(),
                ],
            }));
        }
        return Ok(context.report(PrepareReportOptions {
            apply: true,
            guarded_writes_enabled: guarded_config.enabled,
            send_controls_enabled: guarded_config.send_controls_enabled,
            ledger_written: false,
            already_present: true,
            appended_rows: 0,
            expected_plan_match: Some(true),
            ok: true,
            preflight: before,
            extra_warnings: Vec::new(),
            notes: vec![
                "matching private OCI ledger rows were already present".to_string(),
                "no Interspire send, schedule, queue, contact, or provider request was sent"
                    .to_string(),
            ],
        }));
    }

    if before.matched_rows > 0 {
        return Ok(context.report(PrepareReportOptions {
            apply: true,
            guarded_writes_enabled: guarded_config.enabled,
            send_controls_enabled: guarded_config.send_controls_enabled,
            ledger_written: false,
            already_present: false,
            appended_rows: 0,
            expected_plan_match: Some(true),
            ok: false,
            preflight: before,
            extra_warnings: vec![
                "existing partial OCI ledger rows matched this campaign and batch; refusing to append duplicate prepare rows"
                    .to_string(),
            ],
            notes: vec![
                "apply denied before writing the private ledger".to_string(),
                "no Interspire send, schedule, queue, contact, or provider request was sent"
                    .to_string(),
            ],
        }));
    }

    let submitted_at = utc_now_rfc3339_seconds()?;
    append_private_ledger_rows(&context.ledger_path, &context.ledger_rows, &submitted_at)?;
    let after = verify_context_preflight(config, &context);
    let ok = after.verified;
    let mut extra_warnings = Vec::new();
    if !ok {
        extra_warnings.push(
            "private OCI ledger rows were written but the post-write preflight did not verify"
                .to_string(),
        );
    }
    Ok(context.report(PrepareReportOptions {
        apply: true,
        guarded_writes_enabled: guarded_config.enabled,
        send_controls_enabled: guarded_config.send_controls_enabled,
        ledger_written: true,
        already_present: false,
        appended_rows: context.ledger_rows.len() as u64,
        expected_plan_match: Some(true),
        ok,
        preflight: after,
        extra_warnings,
        notes: vec![
            "sanitized private OCI ledger rows were appended".to_string(),
            "OCI ledger preflight was rerun after the write".to_string(),
            "no Interspire send, schedule, queue, contact, or provider request was sent"
                .to_string(),
        ],
    }))
}

struct LedgerPrepareContext {
    ledger_path: PathBuf,
    ledger_rows: Vec<String>,
    preflight_request: OciLedgerPreflightRequest,
    campaign_hash: String,
    batch_hash: String,
    sender_domain: String,
    manifest_sha256: String,
    approved_sender_hash: Option<String>,
    template_sha256: Option<String>,
    subject_sha256: Option<String>,
    plan_id: String,
    validated_manifest_rows: u64,
    expected_rows: u64,
    duplicate_recipient_key_count: u64,
    duplicate_trace_key_count: u64,
    message_id_trace_rows: u64,
    correlation_id_trace_rows: u64,
    header_value_trace_rows: u64,
    provider_visible_trace_candidate_rows: u64,
    local_correlation_only_rows: u64,
    warnings: Vec<String>,
}

impl LedgerPrepareContext {
    fn build(
        config: &OciSendLedgerConfig,
        request: &OciSendLedgerPreparePreviewRequest,
    ) -> Result<Self, InterspireError> {
        let campaign_id = request.campaign_id.trim();
        let batch_id = request.batch_id.trim();
        let sender_domain = request.sender_domain.trim().to_ascii_lowercase();
        validate_prepare_request(request, campaign_id, batch_id, &sender_domain)?;
        let ledger_path = private_ledger_path(config)?;
        let manifest_path = private_manifest_path(&ledger_path, &request.manifest_path)?;
        let manifest =
            read_private_manifest(&manifest_path, request.expected_manifest_sha256.as_deref())?;
        let prepared = prepare_manifest_rows(request, &sender_domain, &manifest)?;
        let expected_rows_string = request.expected_rows.to_string();
        let campaign_hash = ledger_hash(campaign_id);
        let batch_hash = ledger_hash(batch_id);
        let approved_sender_hash = request
            .approved_sender
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ledger_hash);
        let template_sha256 = normalized_optional_sha256(request.template_sha256.as_deref())?;
        let subject_sha256 = normalized_optional_sha256(request.subject_sha256.as_deref())?;
        let plan_id = guarded_write::stable_plan_id(&[
            LEDGER_PREPARE_VERSION,
            campaign_id,
            &batch_hash,
            &sender_domain,
            &expected_rows_string,
            &manifest.sha256,
            approved_sender_hash.as_deref().unwrap_or(""),
            template_sha256.as_deref().unwrap_or(""),
            subject_sha256.as_deref().unwrap_or(""),
        ]);
        let mut warnings = prepared.warnings;
        if prepared.rows.len() as u64 != request.expected_rows {
            warnings.push(format!(
                "private OCI send ledger manifest contained {} usable rows but expected {} rows",
                prepared.rows.len(),
                request.expected_rows
            ));
        }

        Ok(Self {
            ledger_path,
            ledger_rows: prepared.rows,
            preflight_request: OciLedgerPreflightRequest {
                campaign_id: campaign_id.to_string(),
                batch_id: batch_id.to_string(),
                expected_rows: request.expected_rows,
                sender_domain: Some(sender_domain.clone()),
                expected_manifest_sha256: Some(manifest.sha256.clone()),
            },
            campaign_hash,
            batch_hash,
            sender_domain,
            manifest_sha256: manifest.sha256,
            approved_sender_hash,
            template_sha256,
            subject_sha256,
            plan_id,
            validated_manifest_rows: prepared.validated_rows,
            expected_rows: request.expected_rows,
            duplicate_recipient_key_count: prepared.duplicate_recipient_key_count,
            duplicate_trace_key_count: prepared.duplicate_trace_key_count,
            message_id_trace_rows: prepared.message_id_trace_rows,
            correlation_id_trace_rows: prepared.correlation_id_trace_rows,
            header_value_trace_rows: prepared.header_value_trace_rows,
            provider_visible_trace_candidate_rows: prepared.provider_visible_trace_candidate_rows,
            local_correlation_only_rows: prepared.local_correlation_only_rows,
            warnings,
        })
    }

    fn report(&self, options: PrepareReportOptions) -> OciSendLedgerPrepareReport {
        let mut warnings = self.warnings.clone();
        warnings.extend(options.extra_warnings);
        OciSendLedgerPrepareReport {
            ok: options.ok && warnings.is_empty(),
            configured: true,
            apply: options.apply,
            guarded_writes_enabled: options.guarded_writes_enabled,
            send_controls_enabled: options.send_controls_enabled,
            ledger_written: options.ledger_written,
            already_present: options.already_present,
            appended_rows: options.appended_rows,
            validated_manifest_rows: self.validated_manifest_rows,
            expected_rows: self.expected_rows,
            duplicate_recipient_key_count: self.duplicate_recipient_key_count,
            duplicate_trace_key_count: self.duplicate_trace_key_count,
            message_id_trace_rows: self.message_id_trace_rows,
            correlation_id_trace_rows: self.correlation_id_trace_rows,
            header_value_trace_rows: self.header_value_trace_rows,
            provider_visible_trace_candidate_rows: self.provider_visible_trace_candidate_rows,
            local_correlation_only_rows: self.local_correlation_only_rows,
            campaign_hash: self.campaign_hash.clone(),
            batch_hash: self.batch_hash.clone(),
            sender_domain: Some(self.sender_domain.clone()),
            manifest_sha256: Some(self.manifest_sha256.clone()),
            approved_sender_hash: self.approved_sender_hash.clone(),
            template_sha256: self.template_sha256.clone(),
            subject_sha256: self.subject_sha256.clone(),
            plan_id: Some(self.plan_id.clone()),
            expected_plan_match: options.expected_plan_match,
            oci_ledger_preflight: options.preflight,
            send_authorized: false,
            production_send_authorized: false,
            raw_payload_returned: false,
            warnings: warnings
                .into_iter()
                .map(|warning| redact::redact_sensitive_text(&warning))
                .collect(),
            evidence: Evidence {
                source: "private_oci_send_ledger_manifest".to_string(),
                notes: options.notes,
            },
        }
    }
}

struct PrepareReportOptions {
    apply: bool,
    guarded_writes_enabled: bool,
    send_controls_enabled: bool,
    ledger_written: bool,
    already_present: bool,
    appended_rows: u64,
    expected_plan_match: Option<bool>,
    ok: bool,
    preflight: OciLedgerPreflightReport,
    extra_warnings: Vec<String>,
    notes: Vec<String>,
}

struct PrivateManifest {
    sha256: String,
    text: String,
}

struct PreparedManifestRows {
    rows: Vec<String>,
    validated_rows: u64,
    duplicate_recipient_key_count: u64,
    duplicate_trace_key_count: u64,
    message_id_trace_rows: u64,
    correlation_id_trace_rows: u64,
    header_value_trace_rows: u64,
    provider_visible_trace_candidate_rows: u64,
    local_correlation_only_rows: u64,
    warnings: Vec<String>,
}

struct LedgerPrepareLock {
    path: PathBuf,
    _file: File,
}

impl LedgerPrepareLock {
    fn acquire(ledger_path: &Path) -> Result<Self, InterspireError> {
        let parent = ledger_path.parent().ok_or_else(|| {
            InterspireError::Safety(
                "OCI send ledger path must have a private parent directory".to_string(),
            )
        })?;
        let file_name = ledger_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                InterspireError::Safety("OCI send ledger filename is invalid".to_string())
            })?;
        let lock_path = parent.join(format!(".{file_name}.lock"));
        ensure_private_direct_child_path(&lock_path, "OCI send ledger lock")?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    InterspireError::Safety(
                        "another OCI send ledger prepare apply is already in progress".to_string(),
                    )
                } else {
                    InterspireError::Io(format!(
                        "failed to acquire private OCI send ledger apply lock: {err}"
                    ))
                }
            })?;
        Ok(Self {
            path: lock_path,
            _file: file,
        })
    }
}

impl Drop for LedgerPrepareLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn row_matches(request: &OciLedgerPreflightRequest, value: &Value) -> bool {
    if !matches_identifier(
        &request.campaign_id,
        string_any(value, &["campaign_id", "campaignId"]),
        string_any(
            value,
            &[
                "campaign_hash",
                "campaignHash",
                "campaign_id_hash",
                "campaignIdHash",
            ],
        ),
    ) {
        return false;
    }
    if !matches_identifier(
        &request.batch_id,
        string_any(value, &["batch_id", "batchId"]),
        string_any(
            value,
            &["batch_hash", "batchHash", "batch_id_hash", "batchIdHash"],
        ),
    ) {
        return false;
    }
    if let Some(sender_domain) = request.sender_domain.as_deref() {
        let expected = sender_domain.trim().to_ascii_lowercase();
        let actual = string_any(value, &["sender_domain", "senderDomain"])
            .and_then(domain_from_address_or_domain)
            .or_else(|| {
                string_any(value, &["sender", "approved_sender", "approvedSender"])
                    .and_then(email_domain)
            });
        if actual.as_deref() != Some(expected.as_str()) {
            return false;
        }
    }
    if let Some(expected_manifest) = request.expected_manifest_sha256.as_deref() {
        if !matches_sha256(
            expected_manifest,
            string_any(value, &["manifest_sha256", "manifestSha256"]),
        ) {
            return false;
        }
    }
    true
}

fn verify_context_preflight(
    config: &OciSendLedgerConfig,
    context: &LedgerPrepareContext,
) -> OciLedgerPreflightReport {
    verify_preflight(
        config,
        Some(&context.preflight_request),
        context.expected_rows,
        None,
    )
}

fn prepared_rows_already_present(path: &Path, rows: &[String]) -> Result<bool, InterspireError> {
    let mut expected = row_fingerprints_from_serialized_rows(rows)?;
    if expected.is_empty() {
        return Ok(false);
    }
    let now_unix = current_unix_seconds()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            InterspireError::Io(format!(
                "failed to open private OCI send ledger for read: {err}"
            ))
        })?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|err| {
            InterspireError::Io(format!("failed to read private OCI send ledger: {err}"))
        })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if !has_fresh_submitted_at(&value, now_unix) {
            continue;
        }
        if let Some(fingerprint) = ledger_row_fingerprint(&value) {
            expected.remove(&fingerprint);
            if expected.is_empty() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn row_fingerprints_from_serialized_rows(
    rows: &[String],
) -> Result<BTreeSet<String>, InterspireError> {
    let mut fingerprints = BTreeSet::new();
    for row in rows {
        let value = serde_json::from_str::<Value>(row).map_err(|err| {
            InterspireError::Io(format!(
                "failed to parse prepared private OCI ledger row for fingerprint: {err}"
            ))
        })?;
        let Some(fingerprint) = ledger_row_fingerprint(&value) else {
            return Err(InterspireError::Io(
                "prepared private OCI ledger row did not contain a complete fingerprint"
                    .to_string(),
            ));
        };
        fingerprints.insert(fingerprint);
    }
    Ok(fingerprints)
}

fn ledger_row_fingerprint(value: &Value) -> Option<String> {
    if !value.is_object() {
        return None;
    }
    let campaign_hash = string_any(
        value,
        &[
            "campaign_hash",
            "campaignHash",
            "campaign_id_hash",
            "campaignIdHash",
        ],
    )
    .map(normalized_hash)
    .or_else(|| string_any(value, &["campaign_id", "campaignId"]).map(ledger_hash))?;
    let batch_hash = string_any(
        value,
        &["batch_hash", "batchHash", "batch_id_hash", "batchIdHash"],
    )
    .map(normalized_hash)
    .or_else(|| string_any(value, &["batch_id", "batchId"]).map(ledger_hash))?;
    let sender_domain = string_any(value, &["sender_domain", "senderDomain"])
        .and_then(domain_from_address_or_domain)?;
    let manifest_sha256 = string_any(value, &["manifest_sha256", "manifestSha256"])?
        .trim()
        .to_ascii_lowercase();
    let recipient_hash = string_any(
        value,
        &[
            "recipient_hash",
            "recipientHash",
            "recipient_id_hash",
            "recipientIdHash",
            "recipient_address_hash",
            "recipientAddressHash",
        ],
    )?
    .trim()
    .to_ascii_lowercase();
    let (trace_kind, trace_hash) = if let Some(hash) =
        string_any(value, &["message_id_hash", "messageIdHash"])
    {
        ("message", hash.trim().to_ascii_lowercase())
    } else if let Some(hash) = string_any(value, &["correlation_id_hash", "correlationIdHash"]) {
        ("correlation", hash.trim().to_ascii_lowercase())
    } else if let Some(hash) = string_any(value, &["header_value_hash", "headerValueHash"]) {
        ("header", hash.trim().to_ascii_lowercase())
    } else {
        return None;
    };
    Some(format!(
        "{campaign_hash}\0{batch_hash}\0{sender_domain}\0{manifest_sha256}\0{recipient_hash}\0{trace_kind}\0{trace_hash}"
    ))
}

fn validate_prepare_request(
    request: &OciSendLedgerPreparePreviewRequest,
    campaign_id: &str,
    batch_id: &str,
    sender_domain: &str,
) -> Result<(), InterspireError> {
    if !valid_identifier(campaign_id) || !valid_identifier(batch_id) {
        return Err(InterspireError::Safety(
            "OCI send ledger prepare campaign_id and batch_id must be non-empty printable identifiers"
                .to_string(),
        ));
    }
    if !valid_domain(sender_domain) {
        return Err(InterspireError::Safety(
            "OCI send ledger prepare sender_domain must be a valid domain token".to_string(),
        ));
    }
    if let Some(manifest) = request.expected_manifest_sha256.as_deref() {
        if !valid_sha256(manifest) {
            return Err(InterspireError::Safety(
                "OCI send ledger prepare expected_manifest_sha256 must be a 64-character hex SHA-256"
                    .to_string(),
            ));
        }
    }
    let _ = normalized_optional_sha256(request.template_sha256.as_deref())?;
    let _ = normalized_optional_sha256(request.subject_sha256.as_deref())?;
    Ok(())
}

fn private_ledger_path(config: &OciSendLedgerConfig) -> Result<PathBuf, InterspireError> {
    let Some(raw_path) = config
        .path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Err(InterspireError::Safety(
            "INTERSPIRE_OCI_SEND_LEDGER_PATH is required before preparing private OCI ledger rows"
                .to_string(),
        ));
    };
    let path = PathBuf::from(raw_path);
    ensure_private_direct_child_path(&path, "OCI send ledger")?;
    let parent = path.parent().ok_or_else(|| {
        InterspireError::Safety(
            "OCI send ledger path must have a private parent directory".to_string(),
        )
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|err| {
        InterspireError::Io(format!(
            "failed to stat private OCI ledger directory: {err}"
        ))
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(InterspireError::Safety(
            "OCI send ledger parent must be a real private directory".to_string(),
        ));
    }
    ensure_private_unix_permissions(&parent_metadata, "OCI send ledger parent")?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(InterspireError::Safety(
                "OCI send ledger path must be a regular file when it already exists".to_string(),
            ));
        }
        ensure_private_unix_permissions(&metadata, "OCI send ledger")?;
    }
    Ok(path)
}

fn private_manifest_path(ledger_path: &Path, raw_path: &str) -> Result<PathBuf, InterspireError> {
    let path = PathBuf::from(raw_path.trim());
    ensure_private_direct_child_path(&path, "OCI send ledger manifest")?;
    if path.parent() != ledger_path.parent() {
        return Err(InterspireError::Safety(
            "OCI send ledger manifest must be a direct child of the configured ledger directory"
                .to_string(),
        ));
    }
    if path == ledger_path {
        return Err(InterspireError::Safety(
            "OCI send ledger manifest must not be the ledger output file".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(&path).map_err(|err| {
        InterspireError::Io(format!("failed to stat private OCI ledger manifest: {err}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InterspireError::Safety(
            "OCI send ledger manifest must be a regular private file".to_string(),
        ));
    }
    ensure_private_unix_permissions(&metadata, "OCI send ledger manifest")?;
    if metadata.len() == 0 || metadata.len() > MAX_LEDGER_MANIFEST_BYTES {
        return Err(InterspireError::Safety(format!(
            "OCI send ledger manifest size must be between 1 and {MAX_LEDGER_MANIFEST_BYTES} bytes"
        )));
    }
    Ok(path)
}

fn ensure_private_unix_permissions(
    metadata: &fs::Metadata,
    label: &str,
) -> Result<(), InterspireError> {
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(InterspireError::Safety(format!(
            "{label} must not be readable, writable, or executable by group or others"
        )));
    }
    Ok(())
}

fn ensure_private_direct_child_path(path: &Path, label: &str) -> Result<(), InterspireError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(InterspireError::Safety(format!(
            "{label} path must be an absolute direct-child file path without dot components"
        )));
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(InterspireError::Safety(format!(
            "{label} filename is invalid"
        )));
    };
    if file_name.is_empty()
        || file_name.len() > 160
        || file_name.contains("..")
        || !file_name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(InterspireError::Safety(format!(
            "{label} filename is outside the private filename policy"
        )));
    }
    Ok(())
}

fn read_private_manifest(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<PrivateManifest, InterspireError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            InterspireError::Io(format!("failed to open private OCI ledger manifest: {err}"))
        })?;
    let metadata = file.metadata().map_err(|err| {
        InterspireError::Io(format!("failed to stat private OCI ledger manifest: {err}"))
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_LEDGER_MANIFEST_BYTES {
        return Err(InterspireError::Safety(format!(
            "OCI send ledger manifest size must be between 1 and {MAX_LEDGER_MANIFEST_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|err| {
        InterspireError::Io(format!("failed to read private OCI ledger manifest: {err}"))
    })?;
    let sha256 = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    if let Some(expected) = expected_sha256 {
        if expected.trim().to_ascii_lowercase() != sha256 {
            return Err(InterspireError::Safety(
                "private OCI send ledger manifest SHA-256 did not match expected value".to_string(),
            ));
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        InterspireError::Safety(
            "private OCI send ledger manifest must be valid UTF-8 JSONL".to_string(),
        )
    })?;
    Ok(PrivateManifest { sha256, text })
}

fn prepare_manifest_rows(
    request: &OciSendLedgerPreparePreviewRequest,
    sender_domain: &str,
    manifest: &PrivateManifest,
) -> Result<PreparedManifestRows, InterspireError> {
    let campaign_id = request.campaign_id.trim();
    let campaign_hash = ledger_hash(campaign_id);
    let batch_hash = ledger_hash(request.batch_id.trim());
    let approved_sender_hash = request
        .approved_sender
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ledger_hash);
    let template_sha256 = normalized_optional_sha256(request.template_sha256.as_deref())?;
    let subject_sha256 = normalized_optional_sha256(request.subject_sha256.as_deref())?;
    let mut rows = Vec::new();
    let mut recipient_keys = BTreeSet::new();
    let mut trace_keys = BTreeSet::new();
    let mut duplicate_recipient_key_count = 0u64;
    let mut duplicate_trace_key_count = 0u64;
    let mut message_id_trace_rows = 0u64;
    let mut correlation_id_trace_rows = 0u64;
    let mut header_value_trace_rows = 0u64;
    let mut warnings = Vec::new();

    for (index, line) in manifest.text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if rows.len() as u64 >= MAX_LEDGER_MANIFEST_ROWS {
            return Err(InterspireError::Safety(format!(
                "OCI send ledger manifest must contain at most {MAX_LEDGER_MANIFEST_ROWS} rows"
            )));
        }
        let value = serde_json::from_str::<Value>(line).map_err(|_| {
            InterspireError::Safety(format!(
                "OCI send ledger manifest row {} is not a valid JSON object",
                index + 1
            ))
        })?;
        if !value.is_object() {
            return Err(InterspireError::Safety(format!(
                "OCI send ledger manifest row {} is not a valid JSON object",
                index + 1
            )));
        }
        let Some(recipient_hash) = recipient_hash_from_manifest(&value)? else {
            return Err(InterspireError::Safety(format!(
                "OCI send ledger manifest row {} lacks a recipient identifier or recipient hash",
                index + 1
            )));
        };
        let Some((trace_field, trace_hash)) = trace_hash_from_manifest(&value)? else {
            return Err(InterspireError::Safety(format!(
                "OCI send ledger manifest row {} lacks a provider message, correlation, or header identifier",
                index + 1
            )));
        };
        if !recipient_keys.insert(recipient_hash.clone()) {
            duplicate_recipient_key_count += 1;
        }
        if !trace_keys.insert(trace_hash.clone()) {
            duplicate_trace_key_count += 1;
        }
        match trace_field {
            "message_id_hash" => message_id_trace_rows += 1,
            "correlation_id_hash" => correlation_id_trace_rows += 1,
            "header_value_hash" => header_value_trace_rows += 1,
            _ => {}
        }

        let mut row = Map::new();
        row.insert("provider".to_string(), Value::String("oci".to_string()));
        row.insert(
            "ledger_prepare_version".to_string(),
            Value::String(LEDGER_PREPARE_VERSION.to_string()),
        );
        row.insert(
            "campaign_id".to_string(),
            Value::String(campaign_id.to_string()),
        );
        row.insert(
            "campaign_hash".to_string(),
            Value::String(campaign_hash.clone()),
        );
        row.insert("batch_hash".to_string(), Value::String(batch_hash.clone()));
        row.insert(
            "sender_domain".to_string(),
            Value::String(sender_domain.to_string()),
        );
        row.insert(
            "manifest_sha256".to_string(),
            Value::String(manifest.sha256.clone()),
        );
        row.insert("recipient_hash".to_string(), Value::String(recipient_hash));
        row.insert(trace_field.to_string(), Value::String(trace_hash));
        if let Some(hash) = approved_sender_hash.as_ref() {
            row.insert(
                "approved_sender_hash".to_string(),
                Value::String(hash.clone()),
            );
        }
        if let Some(sha256) = template_sha256.as_ref() {
            row.insert("template_sha256".to_string(), Value::String(sha256.clone()));
        }
        if let Some(sha256) = subject_sha256.as_ref() {
            row.insert("subject_sha256".to_string(), Value::String(sha256.clone()));
        }
        rows.push(serde_json::to_string(&Value::Object(row)).map_err(|err| {
            InterspireError::Io(format!("failed to serialize private OCI ledger row: {err}"))
        })?);
    }

    if duplicate_recipient_key_count > 0 {
        warnings
            .push("private OCI send ledger manifest contains duplicate recipient keys".to_string());
    }
    if duplicate_trace_key_count > 0 {
        warnings.push("private OCI send ledger manifest contains duplicate trace keys".to_string());
    }

    Ok(PreparedManifestRows {
        validated_rows: rows.len() as u64,
        rows,
        duplicate_recipient_key_count,
        duplicate_trace_key_count,
        message_id_trace_rows,
        correlation_id_trace_rows,
        header_value_trace_rows,
        provider_visible_trace_candidate_rows: message_id_trace_rows + header_value_trace_rows,
        local_correlation_only_rows: correlation_id_trace_rows,
        warnings,
    })
}

fn recipient_hash_from_manifest(value: &Value) -> Result<Option<String>, InterspireError> {
    hash_or_raw_from_manifest(
        value,
        &[
            "recipient_hash",
            "recipientHash",
            "recipient_id_hash",
            "recipientIdHash",
            "recipient_address_hash",
            "recipientAddressHash",
        ],
        &[
            "recipient_id",
            "recipientId",
            "subscriber_id",
            "subscriberId",
            "contact_id",
            "contactId",
            "recipient",
            "recipient_email",
            "recipientEmail",
            "email",
        ],
    )
}

fn trace_hash_from_manifest(
    value: &Value,
) -> Result<Option<(&'static str, String)>, InterspireError> {
    if let Some(hash) = hash_or_raw_from_manifest(
        value,
        &["message_id_hash", "messageIdHash"],
        &[
            "message_id",
            "messageId",
            "provider_message_id",
            "providerMessageId",
        ],
    )? {
        return Ok(Some(("message_id_hash", hash)));
    }
    if let Some(hash) = hash_or_raw_from_manifest(
        value,
        &["correlation_id_hash", "correlationIdHash"],
        &["correlation_id", "correlationId"],
    )? {
        return Ok(Some(("correlation_id_hash", hash)));
    }
    Ok(hash_or_raw_from_manifest(
        value,
        &["header_value_hash", "headerValueHash"],
        &["header_value", "headerValue"],
    )?
    .map(|hash| ("header_value_hash", hash)))
}

fn hash_or_raw_from_manifest(
    value: &Value,
    hash_keys: &[&str],
    raw_keys: &[&str],
) -> Result<Option<String>, InterspireError> {
    if let Some(hash) = manifest_hash_any(value, hash_keys)? {
        return Ok(Some(hash));
    }
    Ok(non_empty_string_any(value, raw_keys).map(ledger_hash))
}

fn manifest_hash_any(value: &Value, keys: &[&str]) -> Result<Option<String>, InterspireError> {
    for key in keys {
        let Some(raw) = value.get(*key).and_then(Value::as_str) else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !valid_manifest_hash_token(trimmed) {
            return Err(InterspireError::Safety(
                "OCI send ledger manifest *_hash fields must contain 20- or 64-character hex digests"
                    .to_string(),
            ));
        }
        return Ok(Some(trimmed.to_ascii_lowercase()));
    }
    Ok(None)
}

fn non_empty_string_any<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(Value::as_str))
        .find(|item| !item.trim().is_empty())
}

fn valid_manifest_hash_token(value: &str) -> bool {
    matches!(value.len(), 20 | 64) && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn has_valid_submitted_at(value: &Value) -> bool {
    string_any(value, &["submitted_at", "submittedAt", "time", "timestamp"])
        .is_some_and(valid_utc_timestamp)
}

fn has_fresh_submitted_at(value: &Value, now_unix: u64) -> bool {
    let Some(submitted_at) =
        string_any(value, &["submitted_at", "submittedAt", "time", "timestamp"])
    else {
        return false;
    };
    let Some(submitted_unix) = utc_timestamp_seconds(submitted_at) else {
        return false;
    };
    submitted_unix <= now_unix.saturating_add(LEDGER_PREPARE_CLOCK_SKEW_SECONDS)
        && submitted_unix.saturating_add(LEDGER_PREPARE_MAX_AGE_SECONDS) >= now_unix
}

fn valid_utc_timestamp(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(core) = trimmed.strip_suffix('Z') else {
        return false;
    };
    let bytes = core.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    for range in [0..4, 5..7, 8..10, 11..13, 14..16, 17..19] {
        if !bytes[range].iter().all(u8::is_ascii_digit) {
            return false;
        }
    }
    let month = parse_two_digits(bytes, 5);
    let day = parse_two_digits(bytes, 8);
    let hour = parse_two_digits(bytes, 11);
    let minute = parse_two_digits(bytes, 14);
    let second = parse_two_digits(bytes, 17);
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(parse_year(bytes), month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }
    match bytes.get(19) {
        None => true,
        Some(b'.') => {
            let digits = &core[20..];
            !digits.is_empty()
                && digits.len() <= 9
                && digits.as_bytes().iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

fn utc_timestamp_seconds(value: &str) -> Option<u64> {
    if !valid_utc_timestamp(value) {
        return None;
    }
    let core = value.trim().strip_suffix('Z')?;
    let bytes = core.as_bytes();
    let year = parse_year(bytes);
    let month = parse_two_digits(bytes, 5);
    let day = parse_two_digits(bytes, 8);
    let hour = parse_two_digits(bytes, 11) as u64;
    let minute = parse_two_digits(bytes, 14) as u64;
    let second = parse_two_digits(bytes, 17) as u64;
    let days = unix_days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    Some((days as u64 * 86_400) + (hour * 3_600) + (minute * 60) + second)
}

fn parse_two_digits(bytes: &[u8], start: usize) -> u32 {
    ((bytes[start] - b'0') as u32 * 10) + (bytes[start + 1] - b'0') as u32
}

fn parse_year(bytes: &[u8]) -> i64 {
    bytes[0..4]
        .iter()
        .fold(0i64, |year, digit| (year * 10) + (digit - b'0') as i64)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn unix_days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month = month as i64;
    let day = day as i64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn append_private_ledger_rows(
    path: &Path,
    rows: &[String],
    submitted_at: &str,
) -> Result<(), InterspireError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(InterspireError::Safety(
                "OCI send ledger path must be a regular file before append".to_string(),
            ));
        }
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            InterspireError::Io(format!(
                "failed to open private OCI send ledger for append: {err}"
            ))
        })?;
    for row in rows {
        let row = timestamped_private_ledger_row(row, submitted_at)?;
        file.write_all(row.as_bytes()).map_err(|err| {
            InterspireError::Io(format!(
                "failed to write private OCI send ledger row: {err}"
            ))
        })?;
        file.write_all(b"\n").map_err(|err| {
            InterspireError::Io(format!(
                "failed to write private OCI send ledger row: {err}"
            ))
        })?;
    }
    file.flush().map_err(|err| {
        InterspireError::Io(format!("failed to flush private OCI send ledger: {err}"))
    })
}

fn timestamped_private_ledger_row(
    row: &str,
    submitted_at: &str,
) -> Result<String, InterspireError> {
    let mut value = serde_json::from_str::<Value>(row).map_err(|err| {
        InterspireError::Io(format!(
            "failed to parse prepared private OCI ledger row before append: {err}"
        ))
    })?;
    let Some(object) = value.as_object_mut() else {
        return Err(InterspireError::Io(
            "prepared private OCI ledger row was not a JSON object".to_string(),
        ));
    };
    object.insert(
        "submitted_at".to_string(),
        Value::String(submitted_at.to_string()),
    );
    serde_json::to_string(&value).map_err(|err| {
        InterspireError::Io(format!(
            "failed to serialize timestamped private OCI ledger row: {err}"
        ))
    })
}

fn utc_now_rfc3339_seconds() -> Result<String, InterspireError> {
    let seconds = current_unix_seconds()?;
    Ok(format_unix_timestamp_utc(seconds))
}

fn current_unix_seconds() -> Result<u64, InterspireError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| InterspireError::Io(format!("system clock is before Unix epoch: {err}")))?
        .as_secs())
}

fn format_unix_timestamp_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_unix_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

fn normalized_optional_sha256(value: Option<&str>) -> Result<Option<String>, InterspireError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if !valid_sha256(value) {
        return Err(InterspireError::Safety(
            "optional OCI send ledger SHA-256 fields must be 64-character hex digests".to_string(),
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn matches_identifier(filter: &str, raw_value: Option<&str>, hash_value: Option<&str>) -> bool {
    let normalized_filter = filter.trim();
    raw_value.is_some_and(|value| value.trim() == normalized_filter)
        || hash_value
            .map(normalized_hash)
            .is_some_and(|value| value == ledger_hash(normalized_filter))
}

fn matches_sha256(filter: &str, raw_value: Option<&str>) -> bool {
    let normalized_filter = filter.trim();
    raw_value.is_some_and(|value| value.trim().eq_ignore_ascii_case(normalized_filter))
}

fn normalized_hash(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() == 20 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        trimmed.to_ascii_lowercase()
    } else {
        ledger_hash(trimmed)
    }
}

fn string_any<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn has_any_string(value: &Value, keys: &[&str]) -> bool {
    string_any(value, keys).is_some_and(|item| !item.trim().is_empty())
}

fn has_provider_visible_trace_key(value: &Value) -> bool {
    has_any_string(
        value,
        &[
            "message_id",
            "messageId",
            "provider_message_id",
            "providerMessageId",
            "message_id_hash",
            "messageIdHash",
            "header_value",
            "headerValue",
            "header_value_hash",
            "headerValueHash",
        ],
    )
}

fn domain_from_address_or_domain(value: &str) -> Option<String> {
    if value.contains('@') {
        return email_domain(value);
    }
    valid_domain(value).then(|| value.trim().to_ascii_lowercase())
}

fn email_domain(value: &str) -> Option<String> {
    let (_local, domain) = value.trim().split_once('@')?;
    valid_domain(domain).then(|| domain.trim().to_ascii_lowercase())
}

fn valid_identifier(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 200
        && !trimmed.chars().any(char::is_control)
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
}

fn valid_domain(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
        && trimmed.contains('.')
        && !trimmed.starts_with('.')
        && !trimmed.ends_with('.')
}

fn valid_sha256(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn preflight_verifies_matching_private_ledger_rows_without_raw_output() {
        let path = fixture_path("valid");
        let submitted_at = fresh_submitted_at();
        write_private_fixture(
            &path,
            format!(
                "{{\"submitted_at\":\"{}\",\"campaign_hash\":\"{}\",\"batch_hash\":\"{}\",\"sender\":\"news@example.invalid\",\"recipient_hash\":\"{}\",\"message_id_hash\":\"{}\"}}\n\
                 {{\"campaign_id\":\"other\",\"batch_id\":\"batch-private\",\"sender\":\"news@example.invalid\",\"recipient\":\"person@example.invalid\",\"message_id\":\"msg-2\"}}\n",
                submitted_at,
                ledger_hash("campaign-private"),
                ledger_hash("batch-private"),
                ledger_hash("person@example.invalid"),
                ledger_hash("msg-1")
            ),
        );
        let report = verify_preflight(
            &OciSendLedgerConfig {
                path: Some(path.to_string_lossy().to_string()),
                required_for_sends: true,
            },
            Some(&OciLedgerPreflightRequest {
                campaign_id: "campaign-private".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: Some("example.invalid".to_string()),
                expected_manifest_sha256: None,
            }),
            1,
            None,
        );
        let body = serde_json::to_string(&report).expect("serialize report");

        assert!(report.verified);
        assert_eq!(report.matched_rows, 1);
        assert_eq!(report.rows_with_recipient_key, 1);
        assert_eq!(report.rows_with_trace_key, 1);
        assert_eq!(report.rows_with_provider_visible_trace_key, 1);
        assert_eq!(report.rows_with_submitted_at, 1);
        assert_eq!(report.stale_rows_ignored, 0);
        assert!(!report.raw_payload_returned);
        assert!(!body.contains("person@example.invalid"));
        assert!(!body.contains("campaign-private"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn preflight_classifies_provider_visible_trace_keys_without_raw_output() {
        let path = fixture_path("provider-visible-trace");
        let submitted_at = fresh_submitted_at();
        write_private_fixture(
            &path,
            format!(
                "{{\"submitted_at\":\"{}\",\"campaign_hash\":\"{}\",\"batch_hash\":\"{}\",\"sender_domain\":\"example.invalid\",\"recipient_hash\":\"{}\",\"correlation_id_hash\":\"{}\"}}\n\
                 {{\"submitted_at\":\"{}\",\"campaign_hash\":\"{}\",\"batch_hash\":\"{}\",\"sender_domain\":\"example.invalid\",\"recipient_hash\":\"{}\",\"header_value_hash\":\"{}\"}}\n",
                submitted_at,
                ledger_hash("campaign-private"),
                ledger_hash("batch-private"),
                ledger_hash("person-one@example.invalid"),
                ledger_hash("trace-one"),
                submitted_at,
                ledger_hash("campaign-private"),
                ledger_hash("batch-private"),
                ledger_hash("person-two@example.invalid"),
                ledger_hash("trace-two")
            ),
        );
        let report = verify_preflight(
            &OciSendLedgerConfig {
                path: Some(path.to_string_lossy().to_string()),
                required_for_sends: true,
            },
            Some(&OciLedgerPreflightRequest {
                campaign_id: "campaign-private".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 2,
                sender_domain: Some("example.invalid".to_string()),
                expected_manifest_sha256: None,
            }),
            2,
            None,
        );
        let body = serde_json::to_string(&report).expect("serialize report");

        assert!(report.verified);
        assert_eq!(report.rows_with_trace_key, 2);
        assert_eq!(report.rows_with_provider_visible_trace_key, 1);
        assert!(!body.contains("person-one@example.invalid"));
        assert!(!body.contains("person-two@example.invalid"));
        assert!(!body.contains("trace-one"));
        assert!(!body.contains("trace-two"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn preflight_blocks_missing_rows_when_required() {
        let path = fixture_path("missing");
        write_private_fixture(&path, "");
        let report = verify_preflight(
            &OciSendLedgerConfig {
                path: Some(path.to_string_lossy().to_string()),
                required_for_sends: true,
            },
            Some(&OciLedgerPreflightRequest {
                campaign_id: "campaign-private".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: Some("example.invalid".to_string()),
                expected_manifest_sha256: None,
            }),
            1,
            None,
        );

        assert!(!report.verified);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("expected 1 rows")));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn preflight_blocks_invalid_manifest_without_echoing_raw_input() {
        let report = verify_preflight(
            &OciSendLedgerConfig {
                path: Some("/unused/private-ledger.jsonl".to_string()),
                required_for_sends: true,
            },
            Some(&OciLedgerPreflightRequest {
                campaign_id: "7".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: Some("example.invalid".to_string()),
                expected_manifest_sha256: Some("private-manifest-token".to_string()),
            }),
            1,
            Some(7),
        );
        let body = serde_json::to_string(&report).expect("serialize report");

        assert!(!report.verified);
        assert!(report.sender_domain.is_none());
        assert!(report.manifest_sha256.is_none());
        assert!(!body.contains("private-manifest-token"));
    }

    #[test]
    fn preflight_rejects_world_readable_existing_ledger() {
        let path = fixture_path("world-readable-ledger");
        fs::write(
            &path,
            format!(
                "{{\"campaign_hash\":\"{}\",\"batch_hash\":\"{}\",\"sender_domain\":\"example.invalid\",\"recipient_hash\":\"{}\",\"message_id_hash\":\"{}\"}}\n",
                ledger_hash("campaign-private"),
                ledger_hash("batch-private"),
                ledger_hash("person@example.invalid"),
                ledger_hash("msg-1")
            ),
        )
        .expect("write fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("chmod fixture ledger");

        let report = verify_preflight(
            &OciSendLedgerConfig {
                path: Some(path.to_string_lossy().to_string()),
                required_for_sends: true,
            },
            Some(&OciLedgerPreflightRequest {
                campaign_id: "campaign-private".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: Some("example.invalid".to_string()),
                expected_manifest_sha256: None,
            }),
            1,
            None,
        );

        assert!(!report.verified);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("private path policy")));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn prepare_preview_builds_private_plan_without_writing_or_exposing_manifest_values() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-prepare-preview-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-prepare-preview-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n\
             {\"recipient_id\":\"subscriber-two\",\"header_value\":\"trace-two\"}\n",
        );

        let report = prepare_preview(
            &OciSendLedgerConfig {
                path: Some(LEDGER.to_string()),
                required_for_sends: true,
            },
            &OciSendLedgerPreparePreviewRequest {
                campaign_id: "7".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 2,
                sender_domain: "example.invalid".to_string(),
                manifest_path: MANIFEST.to_string(),
                expected_manifest_sha256: None,
                approved_sender: Some("sender@example.invalid".to_string()),
                template_sha256: None,
                subject_sha256: None,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let body = serde_json::to_string(&report).expect("serialize report");

        assert!(report.ok);
        assert!(!report.apply);
        assert!(!report.ledger_written);
        assert_eq!(report.validated_manifest_rows, 2);
        assert_eq!(report.message_id_trace_rows, 0);
        assert_eq!(report.correlation_id_trace_rows, 1);
        assert_eq!(report.header_value_trace_rows, 1);
        assert_eq!(report.provider_visible_trace_candidate_rows, 1);
        assert_eq!(report.local_correlation_only_rows, 1);
        assert!(!report.oci_ledger_preflight.verified);
        assert!(!Path::new(LEDGER).exists());
        assert!(!body.contains("person-one@example.invalid"));
        assert!(!body.contains("subscriber-two"));
        assert!(!body.contains("trace-one"));
        assert!(!body.contains("trace-two"));
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_preview_rejects_world_readable_manifest() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-readable-manifest-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-readable-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        fs::write(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"message_id\":\"provider-message-one\"}\n",
        )
        .expect("write manifest");
        fs::set_permissions(MANIFEST, fs::Permissions::from_mode(0o644)).expect("chmod manifest");

        let err = prepare_preview(
            &OciSendLedgerConfig {
                path: Some(LEDGER.to_string()),
                required_for_sends: true,
            },
            &OciSendLedgerPreparePreviewRequest {
                campaign_id: "7".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: "example.invalid".to_string(),
                manifest_path: MANIFEST.to_string(),
                expected_manifest_sha256: None,
                approved_sender: None,
                template_sha256: None,
                subject_sha256: None,
            },
        )
        .expect_err("world-readable manifest should be rejected");

        assert!(matches!(err, InterspireError::Safety(_)));
        assert!(err.to_string().contains("group or others"));
        assert!(!Path::new(LEDGER).exists());
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_writes_sanitized_rows_and_verifies_preflight() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-prepare-apply-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-prepare-apply-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"message_id\":\"provider-message-one\"}\n\
             {\"recipient_id\":\"subscriber-two\",\"correlation_id\":\"trace-two\"}\n",
        );
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: " batch-private ".to_string(),
            expected_rows: 2,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: Some("sender@example.invalid".to_string()),
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        let report = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: preview_request.campaign_id,
                batch_id: preview_request.batch_id,
                expected_rows: preview_request.expected_rows,
                sender_domain: preview_request.sender_domain,
                manifest_path: preview_request.manifest_path,
                expected_manifest_sha256: preview_request.expected_manifest_sha256,
                approved_sender: preview_request.approved_sender,
                template_sha256: preview_request.template_sha256,
                subject_sha256: preview_request.subject_sha256,
                expected_plan_id: preview.plan_id.expect("plan id"),
                acknowledge_ledger_write: true,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let body = serde_json::to_string(&report).expect("serialize report");
        let ledger_body = fs::read_to_string(LEDGER).expect("read ledger");

        assert!(report.ok);
        assert!(report.apply);
        assert!(report.ledger_written);
        assert_eq!(report.appended_rows, 2);
        assert!(report.oci_ledger_preflight.verified);
        assert_eq!(report.oci_ledger_preflight.matched_rows, 2);
        assert_eq!(
            report
                .oci_ledger_preflight
                .rows_with_provider_visible_trace_key,
            1
        );
        assert_eq!(report.oci_ledger_preflight.rows_with_submitted_at, 2);
        assert_eq!(report.message_id_trace_rows, 1);
        assert_eq!(report.correlation_id_trace_rows, 1);
        assert_eq!(report.header_value_trace_rows, 0);
        assert_eq!(report.provider_visible_trace_candidate_rows, 1);
        assert_eq!(report.local_correlation_only_rows, 1);
        assert_eq!(report.batch_hash, ledger_hash("batch-private"));
        assert!(!report.send_authorized);
        assert!(!report.production_send_authorized);
        assert!(!body.contains("person-one@example.invalid"));
        assert!(!body.contains("provider-message-one"));
        assert!(!ledger_body.contains("person-one@example.invalid"));
        assert!(!ledger_body.contains("subscriber-two"));
        assert!(!ledger_body.contains("provider-message-one"));
        assert!(ledger_body.contains("\"recipient_hash\""));
        let ledger_rows = ledger_body
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("ledger row JSON"))
            .collect::<Vec<_>>();
        assert_eq!(ledger_rows.len(), 2);
        for row in &ledger_rows {
            let submitted_at = row
                .get("submitted_at")
                .and_then(Value::as_str)
                .expect("submitted_at");
            assert_eq!(submitted_at.len(), "2026-07-01T03:45:00Z".len());
            assert!(submitted_at.ends_with('Z'));
            assert_eq!(submitted_at.as_bytes()[4], b'-');
            assert_eq!(submitted_at.as_bytes()[7], b'-');
            assert_eq!(submitted_at.as_bytes()[10], b'T');
            assert_eq!(submitted_at.as_bytes()[13], b':');
            assert_eq!(submitted_at.as_bytes()[16], b':');
        }
        assert!(
            ledger_body.contains("\"message_id_hash\"")
                || ledger_body.contains("\"correlation_id_hash\"")
        );
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_refuses_preflight_valid_but_different_existing_rows() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-existing-mismatch-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-existing-mismatch-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"message_id\":\"provider-message-one\"}\n",
        );
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 1,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        let manifest_sha256 = preview.manifest_sha256.clone().expect("manifest sha");
        let submitted_at = fresh_submitted_at();
        write_private_fixture(
            LEDGER,
            format!(
                "{{\"submitted_at\":\"{}\",\"campaign_id\":\"7\",\"batch_hash\":\"{}\",\"sender_domain\":\"example.invalid\",\"manifest_sha256\":\"{}\",\"recipient_hash\":\"{}\",\"message_id_hash\":\"{}\"}}\n",
                submitted_at,
                ledger_hash("batch-private"),
                manifest_sha256,
                ledger_hash("different-recipient"),
                ledger_hash("different-message")
            ),
        );

        let report = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: preview_request.campaign_id,
                batch_id: preview_request.batch_id,
                expected_rows: preview_request.expected_rows,
                sender_domain: preview_request.sender_domain,
                manifest_path: preview_request.manifest_path,
                expected_manifest_sha256: preview_request.expected_manifest_sha256,
                approved_sender: preview_request.approved_sender,
                template_sha256: preview_request.template_sha256,
                subject_sha256: preview_request.subject_sha256,
                expected_plan_id: preview.plan_id.expect("plan id"),
                acknowledge_ledger_write: true,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let ledger_body = fs::read_to_string(LEDGER).expect("read ledger");

        assert!(!report.ok);
        assert!(report.oci_ledger_preflight.verified);
        assert!(!report.already_present);
        assert!(!report.ledger_written);
        assert_eq!(ledger_body.lines().count(), 1);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("do not match the current prepared row set")));
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_appends_fresh_rows_for_timestampless_existing_rows() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-timestampless-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-timestampless-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"message_id\":\"provider-message-one\"}\n",
        );
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 1,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        let manifest_sha256 = preview.manifest_sha256.clone().expect("manifest sha");
        write_private_fixture(
            LEDGER,
            format!(
                "{{\"campaign_id\":\"7\",\"batch_hash\":\"{}\",\"sender_domain\":\"example.invalid\",\"manifest_sha256\":\"{}\",\"recipient_hash\":\"{}\",\"message_id_hash\":\"{}\"}}\n",
                ledger_hash("batch-private"),
                manifest_sha256,
                ledger_hash("person-one@example.invalid"),
                ledger_hash("provider-message-one")
            ),
        );

        let report = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: preview_request.campaign_id,
                batch_id: preview_request.batch_id,
                expected_rows: preview_request.expected_rows,
                sender_domain: preview_request.sender_domain,
                manifest_path: preview_request.manifest_path,
                expected_manifest_sha256: preview_request.expected_manifest_sha256,
                approved_sender: preview_request.approved_sender,
                template_sha256: preview_request.template_sha256,
                subject_sha256: preview_request.subject_sha256,
                expected_plan_id: preview.plan_id.expect("plan id"),
                acknowledge_ledger_write: true,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let ledger_body = fs::read_to_string(LEDGER).expect("read ledger");

        assert!(report.ok);
        assert!(report.oci_ledger_preflight.verified);
        assert_eq!(report.oci_ledger_preflight.matched_rows, 1);
        assert_eq!(report.oci_ledger_preflight.rows_with_submitted_at, 1);
        assert_eq!(report.oci_ledger_preflight.stale_rows_ignored, 1);
        assert!(!report.already_present);
        assert!(report.ledger_written);
        assert_eq!(ledger_body.lines().count(), 2);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_appends_fresh_rows_when_exact_existing_rows_are_stale() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-stale-existing-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-stale-existing-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n",
        );
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 1,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        let manifest_sha256 = preview.manifest_sha256.clone().expect("manifest sha");
        write_private_fixture(
            LEDGER,
            format!(
                "{{\"submitted_at\":\"2000-01-01T00:00:00Z\",\"campaign_id\":\"7\",\"batch_hash\":\"{}\",\"sender_domain\":\"example.invalid\",\"manifest_sha256\":\"{}\",\"recipient_hash\":\"{}\",\"correlation_id_hash\":\"{}\"}}\n",
                ledger_hash("batch-private"),
                manifest_sha256,
                ledger_hash("person-one@example.invalid"),
                ledger_hash("trace-one")
            ),
        );

        let report = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: preview_request.campaign_id,
                batch_id: preview_request.batch_id,
                expected_rows: preview_request.expected_rows,
                sender_domain: preview_request.sender_domain,
                manifest_path: preview_request.manifest_path,
                expected_manifest_sha256: preview_request.expected_manifest_sha256,
                approved_sender: preview_request.approved_sender,
                template_sha256: preview_request.template_sha256,
                subject_sha256: preview_request.subject_sha256,
                expected_plan_id: preview.plan_id.expect("plan id"),
                acknowledge_ledger_write: true,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let ledger_body = fs::read_to_string(LEDGER).expect("read ledger");

        assert!(report.ok);
        assert!(report.ledger_written);
        assert!(!report.already_present);
        assert_eq!(report.appended_rows, 1);
        assert_eq!(report.oci_ledger_preflight.matched_rows, 1);
        assert_eq!(report.oci_ledger_preflight.stale_rows_ignored, 1);
        assert_eq!(ledger_body.lines().count(), 2);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_is_idempotent_for_exact_prepared_rows() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-idempotent-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-idempotent-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n",
        );
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 1,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        let apply_request = OciSendLedgerPrepareApplyRequest {
            campaign_id: preview_request.campaign_id,
            batch_id: preview_request.batch_id,
            expected_rows: preview_request.expected_rows,
            sender_domain: preview_request.sender_domain,
            manifest_path: preview_request.manifest_path,
            expected_manifest_sha256: preview_request.expected_manifest_sha256,
            approved_sender: preview_request.approved_sender,
            template_sha256: preview_request.template_sha256,
            subject_sha256: preview_request.subject_sha256,
            expected_plan_id: preview.plan_id.expect("plan id"),
            acknowledge_ledger_write: true,
        };
        let first = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &apply_request,
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let second = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &apply_request,
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let ledger_body = fs::read_to_string(LEDGER).expect("read ledger");

        assert!(first.ok);
        assert!(first.ledger_written);
        assert!(second.ok);
        assert!(second.already_present);
        assert!(!second.ledger_written);
        assert_eq!(ledger_body.lines().count(), 1);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_refuses_stale_plan_without_writing() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-stale-plan-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-stale-plan-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n",
        );
        let report = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &OciSendLedgerConfig {
                path: Some(LEDGER.to_string()),
                required_for_sends: true,
            },
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: "7".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: "example.invalid".to_string(),
                manifest_path: MANIFEST.to_string(),
                expected_manifest_sha256: None,
                approved_sender: None,
                template_sha256: None,
                subject_sha256: None,
                expected_plan_id: "iqc_wrong_plan".to_string(),
                acknowledge_ledger_write: true,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert_eq!(report.expected_plan_match, Some(false));
        assert!(!report.ledger_written);
        assert!(!Path::new(LEDGER).exists());
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_refuses_when_lock_exists() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-locked-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-locked-manifest.jsonl";
        const LOCK: &str =
            "/tmp/interspire-mcp-oci-private/.interspire-mcp-oci-locked-ledger.jsonl.lock";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        let _ = fs::remove_file(LOCK);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n",
        );
        fs::write(LOCK, "").expect("write lock");
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 1,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        let err = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: preview_request.campaign_id,
                batch_id: preview_request.batch_id,
                expected_rows: preview_request.expected_rows,
                sender_domain: preview_request.sender_domain,
                manifest_path: preview_request.manifest_path,
                expected_manifest_sha256: preview_request.expected_manifest_sha256,
                approved_sender: preview_request.approved_sender,
                template_sha256: preview_request.template_sha256,
                subject_sha256: preview_request.subject_sha256,
                expected_plan_id: preview.plan_id.expect("plan id"),
                acknowledge_ledger_write: true,
            },
        )
        .expect_err("lock should deny apply");

        assert!(matches!(err, InterspireError::Safety(_)));
        assert!(!Path::new(LEDGER).exists());
        let _ = fs::remove_file(LOCK);
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_apply_refuses_warning_plan_without_writing() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-warning-plan-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-warning-plan-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_email\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n",
        );
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };
        let preview_request = OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 2,
            sender_domain: "example.invalid".to_string(),
            manifest_path: MANIFEST.to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let preview =
            prepare_preview(&ledger_config, &preview_request).unwrap_or_else(|err| panic!("{err}"));
        assert!(!preview.ok);
        assert!(preview
            .warnings
            .iter()
            .any(|warning| warning.contains("usable rows")));

        let report = prepare_apply(
            &GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            &ledger_config,
            &OciSendLedgerPrepareApplyRequest {
                campaign_id: preview_request.campaign_id,
                batch_id: preview_request.batch_id,
                expected_rows: preview_request.expected_rows,
                sender_domain: preview_request.sender_domain,
                manifest_path: preview_request.manifest_path,
                expected_manifest_sha256: preview_request.expected_manifest_sha256,
                approved_sender: preview_request.approved_sender,
                template_sha256: preview_request.template_sha256,
                subject_sha256: preview_request.subject_sha256,
                expected_plan_id: preview.plan_id.expect("plan id"),
                acknowledge_ledger_write: true,
            },
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert_eq!(report.expected_plan_match, Some(true));
        assert!(!report.ledger_written);
        assert!(!Path::new(LEDGER).exists());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("validation warnings")));
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_preview_rejects_malformed_manifest_hash_fields() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-bad-hash-ledger.jsonl";
        const MANIFEST: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-bad-hash-manifest.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(MANIFEST);
        write_private_fixture(
            MANIFEST,
            "{\"recipient_hash\":\"person-one@example.invalid\",\"correlation_id\":\"trace-one\"}\n",
        );
        let err = prepare_preview(
            &OciSendLedgerConfig {
                path: Some(LEDGER.to_string()),
                required_for_sends: true,
            },
            &OciSendLedgerPreparePreviewRequest {
                campaign_id: "7".to_string(),
                batch_id: "batch-private".to_string(),
                expected_rows: 1,
                sender_domain: "example.invalid".to_string(),
                manifest_path: MANIFEST.to_string(),
                expected_manifest_sha256: None,
                approved_sender: None,
                template_sha256: None,
                subject_sha256: None,
            },
        )
        .expect_err("malformed hash field should be rejected");

        assert!(matches!(err, InterspireError::Safety(_)));
        assert!(!Path::new(LEDGER).exists());
        let _ = fs::remove_file(MANIFEST);
    }

    #[test]
    fn prepare_preview_rejects_blank_raw_manifest_identifiers() {
        const LEDGER: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-blank-raw-ledger.jsonl";
        const BLANK_RECIPIENT: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-blank-recipient.jsonl";
        const BLANK_TRACE: &str =
            "/tmp/interspire-mcp-oci-private/interspire-mcp-oci-blank-trace.jsonl";
        prepare_private_fixture_parent(LEDGER);
        let _ = fs::remove_file(LEDGER);
        let _ = fs::remove_file(BLANK_RECIPIENT);
        let _ = fs::remove_file(BLANK_TRACE);
        write_private_fixture(
            BLANK_RECIPIENT,
            "{\"recipient_email\":\"\",\"correlation_id\":\"trace-one\"}\n",
        );
        write_private_fixture(
            BLANK_TRACE,
            "{\"recipient_email\":\"person-one@example.invalid\",\"message_id\":\"\"}\n",
        );

        let request = |manifest_path: &Path| OciSendLedgerPreparePreviewRequest {
            campaign_id: "7".to_string(),
            batch_id: "batch-private".to_string(),
            expected_rows: 1,
            sender_domain: "example.invalid".to_string(),
            manifest_path: manifest_path.to_string_lossy().to_string(),
            expected_manifest_sha256: None,
            approved_sender: None,
            template_sha256: None,
            subject_sha256: None,
        };
        let ledger_config = OciSendLedgerConfig {
            path: Some(LEDGER.to_string()),
            required_for_sends: true,
        };

        let blank_recipient = prepare_preview(&ledger_config, &request(Path::new(BLANK_RECIPIENT)))
            .expect_err("blank recipient should be rejected");
        let blank_trace = prepare_preview(&ledger_config, &request(Path::new(BLANK_TRACE)))
            .expect_err("blank trace should be rejected");

        assert!(matches!(blank_recipient, InterspireError::Safety(_)));
        assert!(matches!(blank_trace, InterspireError::Safety(_)));
        assert!(!Path::new(LEDGER).exists());
        let _ = fs::remove_file(BLANK_RECIPIENT);
        let _ = fs::remove_file(BLANK_TRACE);
    }

    #[test]
    fn unix_timestamp_formatter_returns_rfc3339_utc_seconds() {
        assert_eq!(format_unix_timestamp_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_unix_timestamp_utc(1_782_877_500),
            "2026-07-01T03:45:00Z"
        );
    }

    #[test]
    fn utc_timestamp_parser_round_trips_formatter() {
        let seconds = 1_782_877_500;
        let formatted = format_unix_timestamp_utc(seconds);
        assert_eq!(utc_timestamp_seconds(&formatted), Some(seconds));
        assert!(has_fresh_submitted_at(
            &serde_json::json!({ "submitted_at": formatted }),
            seconds + 60
        ));
        assert!(!has_fresh_submitted_at(
            &serde_json::json!({ "submitted_at": "2000-01-01T00:00:00Z" }),
            seconds
        ));
    }

    fn fixture_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/interspire-mcp-oci-private/interspire-oci-ledger-tests-{label}-{unique}.jsonl"
        ));
        prepare_private_fixture_parent(path.to_str().expect("utf8 fixture path"));
        path
    }

    fn prepare_private_fixture_parent(path: &str) {
        let parent = Path::new(path).parent().expect("fixture parent");
        fs::create_dir_all(parent).expect("create fixture parent");
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .expect("chmod fixture parent");
    }

    fn write_private_fixture(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
        let path = path.as_ref();
        prepare_private_fixture_parent(path.to_str().expect("utf8 fixture path"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .expect("open private fixture");
        file.write_all(contents.as_ref())
            .expect("write private fixture");
    }

    fn fresh_submitted_at() -> String {
        utc_now_rfc3339_seconds().expect("fresh timestamp")
    }
}

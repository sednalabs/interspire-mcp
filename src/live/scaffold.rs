use super::LiveInterspireBackend;
use crate::{
    error::InterspireError,
    guarded_write, redact,
    response::{
        CampaignCopyApplyReport, CampaignCopyApplyRequest, CampaignCopyPreviewReport,
        CampaignCopyPreviewRequest, ContactImportPreflightReport, ContactImportPreflightRequest,
        Evidence, GuardedWriteApplyReport, GuardedWritePreviewReport, ListCreateApplyRequest,
        ListCreatePreviewRequest,
    },
};
use csv::StringRecord;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

const IMPORT_PREFLIGHT_MAX_BYTES: u64 = 25 * 1024 * 1024;
const IMPORT_PREFLIGHT_MAX_DATA_ROWS: u64 = 250_000;
const IMPORT_PREFLIGHT_MAX_UNIQUE_EMAILS: usize = 250_000;

impl LiveInterspireBackend {
    pub(super) fn list_create_preview_impl(
        &self,
        request: &ListCreatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(GuardedWritePreviewReport {
                ok: true,
                configured: false,
                guarded_writes_enabled: self.config.guarded_writes.enabled,
                form_write_controls_enabled: self.config.guarded_writes.form_write_controls_enabled,
                write_execution_mode: self.config.guarded_writes.execution_mode,
                target: "list_create".to_string(),
                target_id: None,
                section: None,
                plan_id: String::new(),
                apply_directly_allowed: false,
                available_fields: Vec::new(),
                changes: Vec::new(),
                warnings: vec![
                    "admin HTML fallback is not configured; no list create preview attempted"
                        .to_string(),
                ],
                evidence: Evidence {
                    source: "configuration".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }
        let mut report = html.list_create_preview(&request.updates())?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        report.write_execution_mode = self.config.guarded_writes.execution_mode;
        report.apply_directly_allowed = false;
        Ok(report)
    }

    pub(super) fn list_create_apply_impl(
        &self,
        request: &ListCreateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        let mut report = html.list_create_apply(
            &request.plan_id,
            &request.updates(),
            self.config.guarded_writes.execution_mode,
        )?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        Ok(report)
    }

    pub(super) fn campaign_copy_preview_impl(
        &self,
        request: &CampaignCopyPreviewRequest,
    ) -> Result<CampaignCopyPreviewReport, InterspireError> {
        let html = self.html_client()?;
        html.campaign_copy_preview(
            request.source_campaign_id,
            self.config.guarded_writes.enabled,
            self.config.guarded_writes.form_write_controls_enabled,
            self.config.guarded_writes.execution_mode,
        )
    }

    pub(super) fn campaign_copy_apply_impl(
        &self,
        request: &CampaignCopyApplyRequest,
    ) -> Result<CampaignCopyApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        html.campaign_copy_apply(
            request.source_campaign_id,
            &request.plan_id,
            self.config.guarded_writes.enabled,
            self.config.guarded_writes.form_write_controls_enabled,
            self.config.guarded_writes.execution_mode,
        )
    }

    pub(super) fn contact_import_preflight_impl(
        &self,
        request: &ContactImportPreflightRequest,
    ) -> Result<ContactImportPreflightReport, InterspireError> {
        preflight_contact_import(request, &self.config.import_preflight.allowed_roots)
    }
}

fn preflight_contact_import(
    request: &ContactImportPreflightRequest,
    allowed_roots: &[String],
) -> Result<ContactImportPreflightReport, InterspireError> {
    let csv_path = canonical_allowed_csv_path(&request.csv_path, allowed_roots)?;
    let metadata = fs::metadata(&csv_path)
        .map_err(|err| InterspireError::Io(format!("failed to stat import CSV: {err}")))?;
    if metadata.len() > IMPORT_PREFLIGHT_MAX_BYTES {
        return Err(InterspireError::Safety(format!(
            "import CSV exceeds preflight byte cap of {IMPORT_PREFLIGHT_MAX_BYTES} bytes"
        )));
    }
    let bytes = fs::read(&csv_path)
        .map_err(|err| InterspireError::Io(format!("failed to read import CSV: {err}")))?;
    let csv_sha256 = hex::encode(Sha256::digest(&bytes));
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(bytes.as_slice());
    let headers = reader
        .headers()
        .map_err(|err| InterspireError::HtmlParse(format!("failed to parse CSV headers: {err}")))?
        .clone();
    let email_index = select_email_column(&headers, request.email_column.as_deref())?;
    let header_columns = (0..headers.len())
        .map(generic_column_label)
        .collect::<Vec<_>>();
    let selected_email_column = Some(generic_column_label(email_index));

    let mut data_row_count = 0u64;
    let mut invalid_email_like_count = 0u64;
    let mut unique_emails = BTreeSet::new();
    for result in reader.records() {
        let record = result.map_err(|err| {
            InterspireError::HtmlParse(format!("failed to parse CSV record: {err}"))
        })?;
        data_row_count += 1;
        if data_row_count > IMPORT_PREFLIGHT_MAX_DATA_ROWS {
            return Err(InterspireError::Safety(format!(
                "import CSV exceeds preflight data-row cap of {IMPORT_PREFLIGHT_MAX_DATA_ROWS}"
            )));
        }
        let email = record
            .get(email_index)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if !looks_like_email(&email) {
            invalid_email_like_count += 1;
            continue;
        }
        if !unique_emails.contains(&email)
            && unique_emails.len() >= IMPORT_PREFLIGHT_MAX_UNIQUE_EMAILS
        {
            return Err(InterspireError::Safety(format!(
                "import CSV exceeds preflight unique-email cap of {IMPORT_PREFLIGHT_MAX_UNIQUE_EMAILS}"
            )));
        }
        unique_emails.insert(email);
    }

    let unique_email_count = unique_emails.len() as u64;
    let duplicate_email_count = data_row_count
        .saturating_sub(invalid_email_like_count)
        .saturating_sub(unique_email_count);
    let expected_unique_match = request
        .expected_unique_emails
        .map(|expected| expected == unique_email_count);
    let mut warnings = vec![
        "preflight only; no contacts were imported or mutated".to_string(),
        "raw rows and email addresses are intentionally not returned".to_string(),
    ];
    if invalid_email_like_count > 0 {
        warnings.push(format!(
            "{invalid_email_like_count} rows did not contain a valid-looking email in the selected column"
        ));
    }
    if duplicate_email_count > 0 {
        warnings.push(format!(
            "{duplicate_email_count} duplicate valid-looking email rows detected"
        ));
    }
    if let Some(false) = expected_unique_match {
        let expected = request.expected_unique_emails.unwrap_or_default();
        return Err(InterspireError::Safety(format!(
            "expected unique email count {expected} does not match CSV preflight count {unique_email_count}"
        )));
    }

    Ok(ContactImportPreflightReport {
        ok: true,
        configured: true,
        target_list_id: request.target_list_id,
        csv_path_redacted: redact_path(&csv_path),
        csv_sha256,
        header_columns,
        selected_email_column,
        data_row_count,
        unique_email_count,
        duplicate_email_count,
        invalid_email_like_count,
        expected_unique_emails: request.expected_unique_emails,
        expected_unique_match,
        import_apply_authorized: false,
        warnings,
        evidence: Evidence {
            source: "local_csv_preflight".to_string(),
            notes: vec![
                "CSV path was constrained to configured import-preflight allowed roots".to_string(),
                "preflight computed aggregate counts and file hash only".to_string(),
            ],
        },
    })
}

fn canonical_allowed_csv_path(
    raw_path: &str,
    allowed_roots: &[String],
) -> Result<PathBuf, InterspireError> {
    let path = PathBuf::from(raw_path);
    if allowed_roots.is_empty() {
        return Err(InterspireError::Safety(
            "import preflight requires INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS to be configured"
                .to_string(),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(InterspireError::Safety(
            "CSV path must not contain parent directory components".to_string(),
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|err| InterspireError::Io(format!("failed to canonicalize CSV path: {err}")))?;
    if canonical
        .extension()
        .and_then(|ext| ext.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("csv"))
    {
        return Err(InterspireError::Safety(
            "import preflight only accepts .csv files".to_string(),
        ));
    }

    for root in allowed_roots {
        let root_path = Path::new(root);
        let Ok(canonical_root) = root_path.canonicalize() else {
            continue;
        };
        if canonical.starts_with(&canonical_root) {
            return Ok(canonical);
        }
    }
    Err(InterspireError::Safety(
        "CSV path is outside configured import-preflight allowed roots".to_string(),
    ))
}

fn select_email_column(
    headers: &StringRecord,
    requested: Option<&str>,
) -> Result<usize, InterspireError> {
    if let Some(requested) = requested.filter(|value| !value.trim().is_empty()) {
        return headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(requested.trim()))
            .ok_or_else(|| {
                InterspireError::Safety(
                    "requested email column was not found in CSV headers".to_string(),
                )
            });
    }

    for candidate in [
        "email",
        "emailaddress",
        "email_address",
        "email address",
        "e-mail",
    ] {
        if let Some(index) = headers
            .iter()
            .position(|header| header.trim().eq_ignore_ascii_case(candidate))
        {
            return Ok(index);
        }
    }
    Err(InterspireError::Safety(
        "could not infer email column; provide email_column explicitly".to_string(),
    ))
}

fn looks_like_email(value: &str) -> bool {
    if value.is_empty() || value.contains(char::is_whitespace) || value.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.split('.').all(|part| !part.is_empty())
}

fn redact_path(path: &Path) -> String {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .filter(|ext| !ext.trim().is_empty())
        .map(|ext| format!(".{}", redact::redact_sensitive_text(ext)))
        .unwrap_or_default();
    format!("[allowed-import-root]/candidate{extension}")
}

fn generic_column_label(index: usize) -> String {
    format!("column_{}", index + 1)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_allowed_csv_path, generic_column_label, preflight_contact_import, redact_path,
    };
    use crate::response::ContactImportPreflightRequest;
    use std::{fs, path::Path};

    #[test]
    fn import_preflight_requires_explicit_allowed_roots() {
        let err = canonical_allowed_csv_path("/tmp/example.csv", &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS"));
    }

    #[test]
    fn import_preflight_redacts_filename_and_header_labels() {
        assert_eq!(
            redact_path(Path::new("/private/client-grant@example.invalid-list.csv")),
            "[allowed-import-root]/candidate.csv"
        );
        assert_eq!(generic_column_label(0), "column_1");
        assert_eq!(generic_column_label(2), "column_3");
    }

    #[test]
    fn import_preflight_expected_unique_mismatch_is_blocking() {
        let dir = Path::new("target/interspire-import-preflight-expected-unique-mismatch");
        let _ = fs::remove_file(dir.join("candidate.csv"));
        let _ = fs::remove_dir(dir);
        fs::create_dir_all(dir).expect("create temp import dir");
        let csv_path = dir.join("candidate.csv");
        fs::write(&csv_path, "Email\nfirst@example.invalid\n").expect("write temp csv");

        let err = preflight_contact_import(
            &ContactImportPreflightRequest {
                csv_path: csv_path.display().to_string(),
                target_list_id: None,
                email_column: Some("Email".to_string()),
                expected_unique_emails: Some(2),
            },
            &[dir.display().to_string()],
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("expected unique email count 2"));
        let _ = fs::remove_file(&csv_path);
        let _ = fs::remove_dir(dir);
    }
}

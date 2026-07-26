use super::{
    admin_evidence, compact_text, ensure_authenticated_html, extract_login_csrf_token, forms,
    parse_table_rows, redact_field_value, route_fingerprint,
    stats_identity::{
        parse_stats_identity_inventory, unique_added_stats_identity, StatsIdentityInventory,
    },
    AdminHtmlClient,
};
use crate::{
    error::InterspireError,
    private_artifacts, redact,
    response::{
        AdminSessionProbeReport, CampaignBodyAuditReport, CampaignRenderArtifactReport,
        CampaignRenderArtifactRequest, CampaignTestSendApplyReport, CampaignTestSendApplyRequest,
        CampaignTestSendPreviewReport, CampaignTestSendPreviewRequest, OciLedgerPreflightReport,
        ProductionSendApplyReport, ProductionSendApplyRequest, RenderArtifact, SeedReadinessGate,
        SeedReadinessGateReport, SeedReadinessGateRequest, SeedSendApplyReport,
        SeedSendApplyRequest, SendApplyStatus, SendBaselineCaptureStage, SendJobFollowUpContract,
        SendReconciliationReport, SendUncertaintyIdentityState, SendUncertaintyRecoveryContract,
        SendWizardReadbackReport, SendWizardReadbackRequest, MAX_SEED_SEND_RECIPIENTS,
        PRODUCTION_SEND_CONFIRMATION_PHRASE,
    },
    safety::{self, AdminReadPage},
};
use mcp_toolkit_observability::redaction::truncate;
use reqwest::blocking::RequestBuilder;
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io::Write,
    path::Path,
};
use url::Url;

const MAX_SEND_POPUP_STEPS: usize = 25;

#[derive(Debug, Clone)]
struct GuardedSendEvidence {
    status_code: Option<u16>,
    redirected: bool,
    reconciliation: SendReconciliationReport,
}

struct GuardedSendRequestInput<'a> {
    send_form: (Url, Vec<(String, String)>),
    atomic_authority_binding: GuardedSendAtomicAuthorityBinding,
    campaign_id: u64,
    list_ids: &'a [u64],
    expected_body_sha256: Option<String>,
    expected_recipient_count: u64,
    max_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardedSendBaselineContext {
    campaign_id: u64,
    list_ids: Vec<u64>,
    expected_body_sha256: Option<String>,
    expected_recipient_count: u64,
    max_rows: usize,
    authority_submission_sha256: String,
    authority_state_version: String,
    capture_stage: SendBaselineCaptureStage,
}

struct GuardedSendReconcileInput<'a> {
    send_form: (Url, Vec<(String, String)>),
    atomic_authority_binding: GuardedSendAtomicAuthorityBinding,
    campaign_id: u64,
    list_ids: &'a [u64],
    expected_body_sha256: Option<String>,
    expected_recipient_count: u64,
    max_rows: usize,
    baseline_context: GuardedSendBaselineContext,
    queue_before: Vec<String>,
    schedule_job_ids_before: BTreeSet<u64>,
    manage_job_ids_before: BTreeSet<u64>,
    campaign_job_ids_before: BTreeSet<u64>,
    queue_job_ids_before: BTreeSet<u64>,
    stats_before: Vec<String>,
    stats_identity_before: StatsIdentityInventory,
    baseline_identity_stable: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct GuardedSendAtomicAuthorityBinding {
    submission_sha256: String,
    state_version: String,
}

impl GuardedSendAtomicAuthorityBinding {
    fn validates(&self, send_form: &(Url, Vec<(String, String)>)) -> bool {
        !self.state_version.trim().is_empty()
            && self.submission_sha256 == guarded_send_submission_sha256(send_form)
    }

    #[cfg(test)]
    fn synthetic(send_form: &(Url, Vec<(String, String)>)) -> Self {
        Self {
            submission_sha256: guarded_send_submission_sha256(send_form),
            state_version: "synthetic-atomic-state-version".to_string(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct GuardedSendAuthorityIdentity {
    campaign_id: u64,
    subject_sha256: Option<String>,
    html_sha256: Option<String>,
    text_sha256: Option<String>,
    from_name_sha256: Option<String>,
    from_email_sha256: Option<String>,
    reply_to_email_sha256: Option<String>,
    bounce_email_sha256: Option<String>,
    selected_list_ids: Vec<u64>,
    recipient_count: Option<u64>,
    send_immediately_checked: Option<bool>,
    notify_owner_checked: Option<bool>,
    track_opens_checked: Option<bool>,
    track_links_checked: Option<bool>,
    multipart_checked: Option<bool>,
    embed_images_checked: Option<bool>,
    final_form_action_fingerprint: Option<String>,
    final_form_token_sha256: String,
    submission_sha256: String,
}

struct GuardedSendAuthoritySnapshot {
    campaign_body: CampaignBodyAuditReport,
    send_wizard: SendWizardReadbackReport,
    send_form: (Url, Vec<(String, String)>),
    identity: GuardedSendAuthorityIdentity,
    atomic_binding: Option<GuardedSendAtomicAuthorityBinding>,
}

struct GuardedSendAuthorityExpectation<'a> {
    campaign_id: u64,
    list_ids: &'a [u64],
    expected_recipient_count: u64,
    expected_subject: Option<&'a str>,
    expected_html_sha256: Option<&'a str>,
    expected_from_email: Option<&'a str>,
    expected_reply_to_email: Option<&'a str>,
}

struct GuardedSendAuthorityReview {
    confirmed: GuardedSendAuthoritySnapshot,
    atomic_binding: Option<GuardedSendAtomicAuthorityBinding>,
    refusal_reason: Option<String>,
}

struct GuardedSendBaselineSnapshot {
    queue_before: Vec<String>,
    schedule_job_ids: BTreeSet<u64>,
    manage_job_ids: BTreeSet<u64>,
    campaign_job_ids: BTreeSet<u64>,
    queue_job_ids: BTreeSet<u64>,
    stats_before: Vec<String>,
    stats_identity: StatsIdentityInventory,
}

struct GuardedSendTerminalInput<'a> {
    campaign_id: u64,
    list_ids: &'a [u64],
    expected_body_sha256: Option<String>,
    queue_before: &'a [String],
    queue_after: &'a [String],
    stats_before: &'a [String],
    stats_after: &'a [String],
    schedule_job_ids_before: &'a BTreeSet<u64>,
    manage_job_ids_before: &'a BTreeSet<u64>,
    campaign_job_ids_before: &'a BTreeSet<u64>,
    stats_identity_before: &'a StatsIdentityInventory,
    stats_identity_after: &'a StatsIdentityInventory,
    expected_recipient_count: u64,
    baseline_max_rows: usize,
    baseline_context_verified: bool,
    baseline_identity_stable: bool,
    baseline_capture_stage: SendBaselineCaptureStage,
    job_id: Option<u64>,
    job_active_after: Option<bool>,
    smtp_reason: Option<String>,
    popup_steps: usize,
    approved_cron_schedule: bool,
    response_uncertain: bool,
    reconciliation_readback_complete: bool,
    job_identity_ambiguous: bool,
    proof_gaps: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Default)]
struct GuardedSendJobEvidence {
    job_id: Option<u64>,
    conflicted: bool,
    proof_gaps: Vec<String>,
}

impl GuardedSendJobEvidence {
    fn observe(&mut self, candidate: Option<u64>, source: &str) {
        let Some(candidate) = candidate else {
            return;
        };
        if candidate == 0 {
            self.job_id = None;
            self.conflicted = true;
            self.proof_gaps
                .push(format!("{source} exposed an invalid zero job identity"));
            return;
        }
        if self.conflicted {
            return;
        }
        match self.job_id {
            None => self.job_id = Some(candidate),
            Some(current) if current == candidate => {}
            Some(_) => {
                self.job_id = None;
                self.conflicted = true;
                self.proof_gaps.push(format!(
                    "{source} conflicted with another observed job identity"
                ));
            }
        }
    }

    fn add_gap(&mut self, gap: impl Into<String>) {
        self.proof_gaps.push(gap.into());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueJobIdentityDelta {
    None,
    Unique(u64),
    Ambiguous { added: usize, removed: usize },
}

#[derive(Debug, Default)]
struct GuardedSendProgress {
    status_code: Option<u16>,
    redirected: bool,
    job_evidence: GuardedSendJobEvidence,
    smtp_reason: Option<String>,
    popup_steps: usize,
    approved_cron_schedule: bool,
    response_uncertain: bool,
    notes: Vec<String>,
    queue_after: Option<Vec<String>>,
    stats_after: Option<Vec<String>>,
    stats_identity_after: Option<StatsIdentityInventory>,
    active_job_ids_after: Option<BTreeSet<u64>>,
    reconciliation_readback_complete: bool,
    job_identity_ambiguous: bool,
}

impl AdminHtmlClient {
    pub fn admin_session_probe(
        &self,
        include_send_start: bool,
    ) -> Result<AdminSessionProbeReport, InterspireError> {
        if !self.config.is_configured() {
            return Ok(AdminSessionProbeReport {
                ok: true,
                configured: false,
                cloudflare_access_configured: self.config.cloudflare_access.is_configured(),
                login_csrf_present: None,
                login_established: false,
                lists_page_read: false,
                send_start_page_read: None,
                warnings: vec![
                    "admin HTML fallback is not configured; no login attempted".to_string()
                ],
                evidence: admin_evidence(vec!["no request sent".to_string()]),
            });
        }

        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let login_url = safety::login_url(base_url)?;
        let csrf_present = self.login_csrf_token(&login_url)?.is_some();
        self.login()?;
        let lists_page_read = self.get_allowed(&AdminReadPage::Lists.path()).is_ok();
        let send_start_page_read = if include_send_start {
            Some(self.get_allowed(&AdminReadPage::SendStart.path()).is_ok())
        } else {
            None
        };
        let mut warnings = Vec::new();
        if !lists_page_read {
            warnings.push("login returned but Lists readback did not succeed".to_string());
        }
        if matches!(send_start_page_read, Some(false)) {
            warnings.push("Send start page readback did not succeed after login".to_string());
        }

        Ok(AdminSessionProbeReport {
            ok: lists_page_read && send_start_page_read.unwrap_or(true),
            configured: true,
            cloudflare_access_configured: self.config.cloudflare_access.is_configured(),
            login_csrf_present: Some(csrf_present),
            login_established: lists_page_read,
            lists_page_read,
            send_start_page_read,
            warnings,
            evidence: admin_evidence(vec![
                "admin login attempted through configured client".to_string(),
                "allowlisted Lists GET read used as login proof".to_string(),
            ]),
        })
    }

    pub fn campaign_body_audit(
        &self,
        campaign_id: u64,
    ) -> Result<CampaignBodyAuditReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;
        self.campaign_body_audit_authenticated(campaign_id)
    }

    fn campaign_body_audit_authenticated(
        &self,
        campaign_id: u64,
    ) -> Result<CampaignBodyAuditReport, InterspireError> {
        self.campaign_body_authority_authenticated(campaign_id)
            .map(|(report, _)| report)
    }

    fn campaign_body_authority_authenticated(
        &self,
        campaign_id: u64,
    ) -> Result<(CampaignBodyAuditReport, Option<String>), InterspireError> {
        let resolved = self.resolve_campaign_body_html(campaign_id)?;
        let parts = campaign_body_parts_from_html(&resolved.html)?;
        let subject_sha256 = parts
            .subject
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(sha256_hex);
        let mut report = campaign_body_audit_from_parts(campaign_id, parts)?;
        if report.name.is_none() {
            report.name = resolved
                .step1_name
                .map(|value| redact::redact_sensitive_text(&value));
        }
        if resolved.missing_step2 && report.html_bytes == 0 && report.text_bytes == 0 {
            report.warnings.push(
                "campaign edit page did not expose Interspire 8 Step2 body form; body audit is incomplete"
                    .to_string(),
            );
        }
        if !resolved.used_step2 {
            return Ok((report, subject_sha256));
        }
        report.evidence.notes.push(
            "allowlisted Newsletter edit Step1 POST rendered Interspire 8 Step2 body page; Complete/save form was not posted"
                .to_string(),
        );
        Ok((report, subject_sha256))
    }

    pub fn campaign_render_artifact(
        &self,
        request: &CampaignRenderArtifactRequest,
    ) -> Result<CampaignRenderArtifactReport, InterspireError> {
        if !self.config.is_configured() {
            return Ok(CampaignRenderArtifactReport {
                ok: true,
                configured: false,
                campaign_id: request.campaign_id,
                subject: None,
                html_sha256: None,
                html_bytes: 0,
                artifacts: Vec::new(),
                native_browser_next_step:
                    "Admin HTML is not configured; no render artifact was written.".to_string(),
                campaign_body: CampaignBodyAuditReport::fixture(),
                production_send_authorized: false,
                warnings: vec![
                    "admin HTML fallback is not configured; no campaign render artifact attempted"
                        .to_string(),
                ],
                evidence: admin_evidence(vec!["no request sent".to_string()]),
            });
        }

        self.login()?;
        let resolved = self.resolve_campaign_body_html(request.campaign_id)?;
        let parts = campaign_body_parts_from_html(&resolved.html)?;
        let body_audit = campaign_body_audit_from_parts(request.campaign_id, parts.clone())?;
        if parts.html_body.trim().is_empty() {
            return Err(InterspireError::HtmlParse(
                "campaign body resolver did not expose a non-empty HTML body".to_string(),
            ));
        }

        let output_dir =
            private_artifacts::prepare_private_render_output_dir(request.output_dir.as_deref())?;
        let stamp = private_artifacts::unix_timestamp_nanos()?;
        let prefix = private_artifacts::fixed_render_prefix(request.artifact_prefix.as_deref())?;

        let source_path = output_dir.join(format!("{prefix}-{stamp}-source.html"));
        let mut artifacts = vec![write_private_text_artifact(
            "campaign_source_html",
            &source_path,
            &parts.html_body,
            "campaign source HTML",
        )?];

        let image_blocked_path = if request.include_image_blocked_variant {
            let path = output_dir.join(format!("{prefix}-{stamp}-image-blocked.html"));
            artifacts.push(write_private_text_artifact(
                "image_blocked_html",
                &path,
                &format!(
                    "<style>img{{visibility:hidden!important;outline:1px dashed #999!important;background:#f3f3f3!important;}}</style>\n{}",
                    parts.html_body
                ),
                "image-blocked campaign HTML",
            )?);
            Some(path)
        } else {
            None
        };

        let preview_path = output_dir.join(format!("{prefix}-{stamp}-preview.html"));
        let preview_html =
            render_preview_index(&parts, &source_path, image_blocked_path.as_deref())?;
        artifacts.insert(
            0,
            write_private_text_artifact(
                "preview_index_html",
                &preview_path,
                &preview_html,
                "campaign render preview",
            )?,
        );

        Ok(CampaignRenderArtifactReport {
            ok: true,
            configured: true,
            campaign_id: request.campaign_id,
            subject: body_audit.subject.clone(),
            html_sha256: body_audit.html_sha256.clone(),
            html_bytes: body_audit.html_bytes,
            artifacts,
            native_browser_next_step:
                "Open the preview_index_html artifact with native browser and capture desktop/mobile screenshots; inspect rendered images before making visual claims."
                    .to_string(),
            campaign_body: body_audit,
            production_send_authorized: false,
            warnings: vec![
                "render artifacts are private local files; this tool does not send, schedule, or mutate the campaign".to_string(),
                "open the preview_index_html artifact rather than treating artifact paths or hashes as visual signoff".to_string(),
            ],
            evidence: admin_evidence({
                let mut notes = vec![format!(
                    "allowlisted Newsletter edit GET read for campaign {}",
                    request.campaign_id
                )];
                if resolved.used_step2 {
                    notes.push(
                        "allowlisted Newsletter edit Step1 POST rendered Interspire 8 Step2 body page; Complete/save form was not posted"
                            .to_string(),
                    );
                }
                notes.push("persisted campaign HTML was written to private render artifacts".to_string());
                notes
            }),
        })
    }

    pub fn campaign_test_send_preview(
        &self,
        request: &CampaignTestSendPreviewRequest,
    ) -> Result<CampaignTestSendPreviewReport, InterspireError> {
        validate_single_preview_email(&request.recipient_email, "recipient_email")?;
        validate_single_preview_email(&request.from_preview_email, "from_preview_email")?;
        if !self.config.is_configured() {
            return Ok(CampaignTestSendPreviewReport {
                ok: false,
                configured: false,
                campaign_id: request.campaign_id,
                recipient_email_redacted: redact::redact_email(&request.recipient_email),
                from_preview_email_redacted: redact::redact_email(&request.from_preview_email),
                preview_digest: None,
                subject: None,
                html_sha256: None,
                html_bytes: 0,
                text_bytes: 0,
                preheader_present: false,
                route_fingerprint: None,
                campaign_body: CampaignBodyAuditReport::fixture(),
                send_performed: false,
                queue_rows_before: 0,
                queue_rows_after: 0,
                stats_rows_before: 0,
                stats_rows_after: 0,
                queue_unchanged: true,
                stats_unchanged: true,
                production_send_authorized: false,
                warnings: vec![
                    "admin HTML fallback is not configured; no campaign test-send preview attempted"
                        .to_string(),
                ],
                evidence: admin_evidence(vec!["no request sent".to_string()]),
            });
        }

        self.login()?;
        let max_rows = request.max_queue_rows.unwrap_or(25).clamp(1, 100);
        let queue_before = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_before_html = self.get_allowed(&AdminReadPage::Stats.path())?;
        let stats_before = parse_table_rows(&stats_before_html, max_rows)?;
        let resolved = self.resolve_campaign_body_html(request.campaign_id)?;
        let parts = campaign_body_parts_from_html(&resolved.html)?;
        let campaign_body = campaign_body_audit_from_parts(request.campaign_id, parts.clone())?;
        let has_applyable_html = campaign_test_send_has_applyable_html(&parts, &campaign_body);
        let preview_digest = has_applyable_html.then(|| {
            let preheader_sha256 = optional_nonempty_sha256(parts.preheader.as_deref());
            campaign_test_send_digest(
                request.campaign_id,
                &request.recipient_email,
                &request.from_preview_email,
                parts.subject.as_deref().unwrap_or_default(),
                campaign_body.html_sha256.as_deref().unwrap_or_default(),
                campaign_body.text_sha256.as_deref(),
                preheader_sha256.as_deref(),
            )
        });
        let queue_after = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_after =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
        let route = safety::ensure_allowed_campaign_test_send_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            "index.php?Page=Newsletters&Action=SendPreview",
        )?;
        let queue_unchanged = queue_before == queue_after;
        let stats_unchanged = stats_before == stats_after;
        let mut warnings = campaign_test_send_limitations();
        if parts.html_body.trim().is_empty() && parts.text_body.trim().is_empty() {
            warnings.push("campaign test-send preview found no HTML or text body".to_string());
        }
        if !has_applyable_html {
            warnings.push(
                "campaign test-send apply requires a non-empty HTML body and HTML SHA-256; text-only campaigns are not applyable by this tool"
                    .to_string(),
            );
        }
        if !queue_unchanged {
            warnings.push(
                "Schedule queue rows changed during campaign test-send preview proof".to_string(),
            );
        }
        if !stats_unchanged {
            warnings.push("Stats rows changed during campaign test-send preview proof".to_string());
        }

        Ok(CampaignTestSendPreviewReport {
            ok: campaign_body.ok && has_applyable_html && queue_unchanged && stats_unchanged,
            configured: true,
            campaign_id: request.campaign_id,
            recipient_email_redacted: redact::redact_email(&request.recipient_email),
            from_preview_email_redacted: redact::redact_email(&request.from_preview_email),
            preview_digest,
            subject: campaign_body.subject.clone(),
            html_sha256: campaign_body.html_sha256.clone(),
            html_bytes: campaign_body.html_bytes,
            text_bytes: campaign_body.text_bytes,
            preheader_present: parts
                .preheader
                .as_deref()
                .is_some_and(|value| !value.is_empty()),
            route_fingerprint: Some(route_fingerprint(route.as_str())),
            campaign_body,
            send_performed: false,
            queue_rows_before: queue_before.len(),
            queue_rows_after: queue_after.len(),
            stats_rows_before: stats_before.len(),
            stats_rows_after: stats_after.len(),
            queue_unchanged,
            stats_unchanged,
            production_send_authorized: false,
            warnings,
            evidence: admin_evidence(vec![
                "persisted campaign body was read privately for Interspire SendPreview parameters"
                    .to_string(),
                "native Interspire Newsletters SendPreview route was classified but not posted"
                    .to_string(),
                "Schedule and Stats rows were compared before/after preview proof".to_string(),
            ]),
        })
    }

    pub fn campaign_test_send_apply(
        &self,
        request: &CampaignTestSendApplyRequest,
    ) -> Result<CampaignTestSendApplyReport, InterspireError> {
        validate_single_preview_email(&request.recipient_email, "recipient_email")?;
        validate_single_preview_email(&request.from_preview_email, "from_preview_email")?;
        if !self.config.is_configured() {
            return Ok(CampaignTestSendApplyReport::denied_with_configured(
                request,
                "admin HTML fallback is not configured; no campaign test-send attempted",
                false,
            ));
        }
        if !request.acknowledge_test_send {
            return Ok(CampaignTestSendApplyReport::denied(
                request,
                "campaign test send refused because acknowledge_test_send was not true",
            ));
        }

        self.login()?;
        let max_rows = request.max_queue_rows.unwrap_or(25).clamp(1, 100);
        let queue_before = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_before =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
        let step1_path = AdminReadPage::NewsletterEdit {
            id: request.campaign_id,
        }
        .path();
        let resolved = self.resolve_campaign_body_html(request.campaign_id)?;
        let parts = campaign_body_parts_from_html(&resolved.html)?;
        let campaign_body = campaign_body_audit_from_parts(request.campaign_id, parts.clone())?;
        let raw_subject = parts.subject.clone().unwrap_or_default();
        let html_sha256 = campaign_body.html_sha256.clone().unwrap_or_default();
        let preheader_sha256 = optional_nonempty_sha256(parts.preheader.as_deref());
        let preview_digest = (!html_sha256.is_empty()).then(|| {
            campaign_test_send_digest(
                request.campaign_id,
                &request.recipient_email,
                &request.from_preview_email,
                &raw_subject,
                &html_sha256,
                campaign_body.text_sha256.as_deref(),
                preheader_sha256.as_deref(),
            )
        });
        let mut warnings = campaign_test_send_limitations();
        if !expected_public_subject_matches(
            campaign_body.subject.as_deref(),
            &request.expected_subject,
        ) {
            warnings.push(
                "campaign test send refused because subject did not match expected_subject"
                    .to_string(),
            );
        }
        if campaign_body.html_sha256.as_deref() != Some(request.expected_html_sha256.as_str()) {
            warnings.push(
                "campaign test send refused because HTML SHA-256 did not match expected_html_sha256"
                    .to_string(),
            );
        }
        if preview_digest.as_deref() != Some(request.expected_preview_digest.as_str()) {
            warnings.push(
                "campaign test send refused because preview digest did not match expected_preview_digest"
                    .to_string(),
            );
        }
        if !campaign_test_send_has_applyable_html(&parts, &campaign_body) {
            warnings.push(
                "campaign test send refused because campaign HTML body or HTML SHA-256 was missing"
                    .to_string(),
            );
        }
        if warnings
            .iter()
            .any(|warning| warning.contains("refused because"))
        {
            let queue_after = parse_table_rows(
                &self.get_allowed(&AdminReadPage::Schedule.path())?,
                max_rows,
            )?;
            let stats_after =
                parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
            let queue_unchanged = queue_before == queue_after;
            let stats_unchanged = stats_before == stats_after;
            if !queue_unchanged {
                warnings.push(
                    "Schedule queue rows changed during campaign test-send refusal proof"
                        .to_string(),
                );
            }
            if !stats_unchanged {
                warnings
                    .push("Stats rows changed during campaign test-send refusal proof".to_string());
            }
            return Ok(campaign_test_send_report(
                request,
                false,
                None,
                None,
                campaign_body,
                preview_digest,
                parts
                    .preheader
                    .as_deref()
                    .is_some_and(|value| !value.is_empty()),
                queue_before.len(),
                queue_after.len(),
                stats_before.len(),
                stats_after.len(),
                queue_unchanged,
                stats_unchanged,
                warnings,
                false,
            ));
        }

        let mut post_pairs = vec![
            ("subject".to_string(), raw_subject),
            ("myDevEditControl_html".to_string(), parts.html_body.clone()),
            ("TextContent".to_string(), parts.text_body.clone()),
            ("PreviewEmail".to_string(), request.recipient_email.clone()),
            (
                "FromPreviewEmail".to_string(),
                request.from_preview_email.clone(),
            ),
            (
                "PreHeader".to_string(),
                parts.preheader.clone().unwrap_or_default(),
            ),
            ("id".to_string(), request.campaign_id.to_string()),
        ];
        append_csrf_pair_if_missing(&mut post_pairs, &resolved.html);
        let post_url = safety::ensure_allowed_campaign_test_send_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            "index.php?Page=Newsletters&Action=SendPreview",
        )?;
        let response = self
            .proof_post_with_page_context(post_url, &post_pairs, &step1_path)?
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        let status_code = response.status().as_u16();
        if !response.status().is_success() {
            return Err(InterspireError::Http(format!(
                "campaign test-send route returned HTTP {status_code}"
            )));
        }
        let response_html = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        ensure_authenticated_html(&response_html)?;

        let queue_after = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_after =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
        let queue_unchanged = queue_before == queue_after;
        let stats_unchanged = stats_before == stats_after;
        if !queue_unchanged {
            warnings.push("Schedule queue rows changed during campaign test send".to_string());
        }
        if !stats_unchanged {
            warnings.push("Stats rows changed during campaign test send".to_string());
        }
        let message = preview_send_response_message(&response_html);
        let sent =
            preview_send_response_success(&response_html) && queue_unchanged && stats_unchanged;
        if !sent {
            warnings
                .push("Interspire did not return a successful preview-send response".to_string());
        }

        Ok(campaign_test_send_report(
            request,
            sent,
            Some(status_code),
            message,
            campaign_body,
            preview_digest,
            parts
                .preheader
                .as_deref()
                .is_some_and(|value| !value.is_empty()),
            queue_before.len(),
            queue_after.len(),
            stats_before.len(),
            stats_after.len(),
            queue_unchanged,
            stats_unchanged,
            warnings,
            true,
        ))
    }

    pub(super) fn resolve_campaign_body_html(
        &self,
        campaign_id: u64,
    ) -> Result<ResolvedCampaignBodyHtml, InterspireError> {
        self.resolve_campaign_body_html_with_format(campaign_id, None)
    }

    pub(super) fn resolve_campaign_body_html_with_format(
        &self,
        campaign_id: u64,
        step1_format_override: Option<&str>,
    ) -> Result<ResolvedCampaignBodyHtml, InterspireError> {
        let step1_path = AdminReadPage::NewsletterEdit { id: campaign_id }.path();
        let step1_html = self.get_allowed(&step1_path)?;
        let step1_parts = campaign_body_parts_from_html(&step1_html)?;
        if step1_format_override.is_none()
            && (!step1_parts.html_body.trim().is_empty()
                || !step1_parts.text_body.trim().is_empty())
        {
            return Ok(ResolvedCampaignBodyHtml {
                html: step1_html,
                used_step2: false,
                step1_name: step1_parts.name,
                missing_step2: false,
            });
        }

        let Some(step2_path) = campaign_body_step2_action_path(campaign_id, &step1_html)? else {
            return Ok(ResolvedCampaignBodyHtml {
                html: step1_html,
                used_step2: false,
                step1_name: step1_parts.name,
                missing_step2: true,
            });
        };
        let step2_url = safety::ensure_allowed_campaign_body_step2_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            &step2_path,
            campaign_id,
        )?;
        let mut post_pairs = campaign_body_step1_pairs(campaign_id, &step1_html)?;
        if let Some(format) = step1_format_override {
            upsert_post_pair(&mut post_pairs, "Format", format);
        }
        append_csrf_pair_if_missing(&mut post_pairs, &step1_html);
        let response = self
            .proof_post_with_page_context(step2_url, &post_pairs, &step1_path)?
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !response.status().is_success() {
            return Err(InterspireError::Http(format!(
                "campaign body no-save Step2 render returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let step2_html = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        ensure_authenticated_html(&step2_html)?;

        Ok(ResolvedCampaignBodyHtml {
            html: step2_html,
            used_step2: true,
            step1_name: step1_parts.name,
            missing_step2: false,
        })
    }

    pub fn send_wizard_readback(
        &self,
        request: &SendWizardReadbackRequest,
    ) -> Result<SendWizardReadbackReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        if request.list_ids.is_empty() {
            return Err(InterspireError::Safety(
                "send wizard readback requires at least one explicit list id".to_string(),
            ));
        }
        self.login()?;

        let max_rows = request.max_queue_rows.unwrap_or(25).clamp(1, 100);
        let queue_before = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_before =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;

        let start_html = self.get_allowed(&AdminReadPage::SendStart.path())?;
        let step2_path = send_step2_action_path(&start_html).ok_or_else(|| {
            InterspireError::Safety(
                "Send start page did not expose an allowlisted no-send Step2 form".to_string(),
            )
        })?;
        let step2_url = safety::ensure_allowed_send_wizard_step2_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            &step2_path,
        )?;
        let mut post_pairs = send_start_hidden_pairs(&start_html)?;
        upsert_post_pair(
            &mut post_pairs,
            "newsletter",
            &request.campaign_id.to_string(),
        );
        upsert_post_pair(&mut post_pairs, "ShowFilteringOptions", "2");
        for list_id in &request.list_ids {
            post_pairs.push(("lists[]".to_string(), list_id.to_string()));
        }

        append_csrf_pair_if_missing(&mut post_pairs, &start_html);

        let response = self
            .proof_post_with_page_context(step2_url, &post_pairs, &AdminReadPage::SendStart.path())?
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !response.status().is_success() {
            return Err(InterspireError::Http(format!(
                "send wizard no-send Step2 render returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let final_html = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        ensure_authenticated_html(&final_html)?;

        let queue_after = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_after =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;

        let mut report =
            parse_send_wizard_final_page(request.campaign_id, &request.list_ids, &final_html)?;
        report.queue_rows_before = queue_before.len();
        report.queue_rows_after = queue_after.len();
        report.stats_rows_before = stats_before.len();
        report.stats_rows_after = stats_after.len();
        report.queue_unchanged = rows_unchanged_for_send_proof(&queue_before, &queue_after);
        let stats_content_unchanged = rows_unchanged_for_send_proof(&stats_before, &stats_after);
        report.stats_unchanged = stats_rows_stable_for_no_send_proof(&stats_before, &stats_after);

        if !report.queue_unchanged {
            report
                .warnings
                .push("Schedule queue rows changed during no-send wizard proof".to_string());
        }
        if !report.stats_unchanged {
            report
                .warnings
                .push("Stats rows changed during no-send wizard proof".to_string());
        } else if !stats_content_unchanged {
            report.warnings.push(
                "Stats row content changed during no-send wizard proof, but stable row identity shows no new or removed Stats rows"
                    .to_string(),
            );
        }
        if report.selected_campaign_id != Some(request.campaign_id)
            && !report.requested_campaign_available
        {
            report.warnings.push(format!(
                "requested campaign {} was not selected and was not found in the campaign dropdown",
                request.campaign_id
            ));
        }
        report.requested_list_ids_proven_by_recipient_count = report.selected_list_ids.is_empty()
            && request.expected_recipient_count.is_some()
            && report.recipient_count == request.expected_recipient_count;
        if report.requested_list_ids_proven_by_recipient_count {
            report.warnings.retain(|warning| {
                warning != "final send wizard page did not expose selected list ids"
            });
        }
        if let Some(warning) = list_ids_warning(
            &report.selected_list_ids,
            &request.list_ids,
            report.requested_list_ids_proven_by_recipient_count,
        ) {
            report.warnings.push(warning);
        }
        if let Some(expected) = request.expected_recipient_count {
            if report.recipient_count != Some(expected) {
                report.warnings.push(format!(
                    "recipient count did not match expected count {expected}"
                ));
            }
        }
        report.evidence.notes.push(
            "allowlisted Send Step2 POST rendered final editable page; final form was not posted"
                .to_string(),
        );
        if report.requested_campaign_available
            && report.selected_campaign_id != Some(request.campaign_id)
        {
            report.evidence.notes.push(
                "requested campaign was present as a selectable campaign option on Interspire Step2"
                    .to_string(),
            );
        }
        if report.requested_list_ids_proven_by_recipient_count {
            report.evidence.notes.push(
                "Interspire Step2 did not echo list ids; requested list ids were accepted as session proof because the rendered recipient count matched the expected count"
                    .to_string(),
            );
        }
        let campaign_proven = report.selected_campaign_id == Some(request.campaign_id)
            || report.requested_campaign_available;
        let lists_proven = ids_match(&report.selected_list_ids, &request.list_ids)
            || report.requested_list_ids_proven_by_recipient_count;
        report.ok = report.final_form_posts_to_send_boundary
            && report.queue_unchanged
            && report.stats_unchanged
            && campaign_proven
            && lists_proven
            && match request.expected_recipient_count {
                Some(expected) => report.recipient_count == Some(expected),
                None => true,
            };
        Ok(report)
    }

    pub fn seed_readiness_gate(
        &self,
        request: &SeedReadinessGateRequest,
    ) -> Result<SeedReadinessGateReport, InterspireError> {
        let campaign_body = self.campaign_body_audit(request.campaign_id)?;
        let send_wizard = self.send_wizard_readback(&SendWizardReadbackRequest {
            campaign_id: request.campaign_id,
            list_ids: request.list_ids.clone(),
            expected_recipient_count: request.expected_recipient_count,
            max_queue_rows: Some(25),
        })?;
        let mut gates = Vec::new();
        gates.push(gate(
            "campaign_has_expected_unsubscribe_tokens",
            campaign_unsubscribe_token_shape_ok(&campaign_body),
            "blocker",
            format!(
                "HTML unsubscribe token count is {}; text unsubscribe token count is {}; aggregate count is {}",
                campaign_body.html_unsubscribe_token_count,
                campaign_body.text_unsubscribe_token_count,
                campaign_body.unsubscribe_token_count
            ),
        ));
        gates.push(gate(
            "campaign_has_no_http_urls",
            campaign_body.http_url_count == 0,
            "blocker",
            format!("http:// URL count is {}", campaign_body.http_url_count),
        ));
        gates.push(gate(
            "campaign_has_no_visible_tracking_copy",
            !campaign_body.visible_tracking_copy_detected,
            "blocker",
            "visible tracking copy was not detected".to_string(),
        ));
        gates.push(gate(
            "send_wizard_campaign_matches",
            send_wizard.selected_campaign_id == Some(request.campaign_id)
                || send_wizard.requested_campaign_available,
            "blocker",
            format!(
                "selected campaign id is {:?}; requested campaign available is {}",
                send_wizard.selected_campaign_id, send_wizard.requested_campaign_available
            ),
        ));
        gates.push(gate(
            "send_wizard_lists_match",
            ids_match(&send_wizard.selected_list_ids, &request.list_ids)
                || send_wizard.requested_list_ids_proven_by_recipient_count,
            "blocker",
            format!(
                "selected list ids are {:?}; recipient-count list proof is {}",
                send_wizard.selected_list_ids,
                send_wizard.requested_list_ids_proven_by_recipient_count
            ),
        ));
        gates.push(gate(
            "send_wizard_queue_unchanged",
            send_wizard.queue_unchanged,
            "blocker",
            "queue rows unchanged during no-send proof".to_string(),
        ));
        gates.push(gate(
            "send_wizard_stats_unchanged",
            send_wizard.stats_unchanged,
            "blocker",
            "stats rows kept stable no-send identities, proving no new or removed Stats rows during no-send proof".to_string(),
        ));
        gates.push(gate(
            "final_form_is_send_boundary",
            send_wizard.final_form_posts_to_send_boundary,
            "blocker",
            "next final-form POST is classified as send-boundary and was not posted".to_string(),
        ));
        if let Some(expected) = request.expected_recipient_count {
            gates.push(gate(
                "recipient_count_matches",
                send_wizard.recipient_count == Some(expected),
                "blocker",
                format!("recipient count is {:?}", send_wizard.recipient_count),
            ));
        }
        if let Some(expected) = request.expected_from_email.as_deref() {
            gates.push(gate(
                "from_email_matches",
                send_wizard.from_email_redacted.as_deref() == Some(&redact::redact_email(expected)),
                "blocker",
                "From email matches expected redacted value".to_string(),
            ));
        }
        if let Some(expected) = request.expected_reply_to_email.as_deref() {
            gates.push(gate(
                "reply_to_email_matches",
                send_wizard.reply_to_email_redacted.as_deref()
                    == Some(&redact::redact_email(expected)),
                "blocker",
                "Reply-To email matches expected redacted value".to_string(),
            ));
        }

        let ready_for_seed_approval = gates
            .iter()
            .filter(|check| check.severity == "blocker")
            .all(|check| check.passed);
        let mut warnings = Vec::new();
        warnings.extend(campaign_body.warnings.clone());
        warnings.extend(send_wizard.warnings.clone());
        if !ready_for_seed_approval {
            warnings.push(
                "one or more blocker gates failed; do not ask for seed-send approval".to_string(),
            );
        }

        Ok(SeedReadinessGateReport {
            ok: true,
            configured: true,
            ready_for_seed_approval,
            campaign_id: request.campaign_id,
            requested_list_ids: request.list_ids.clone(),
            campaign_body,
            send_wizard,
            gates,
            production_send_authorized: false,
            warnings,
            evidence: admin_evidence(vec![
                "campaign body audit plus no-send send-wizard proof".to_string(),
                "production_send_authorized remains false".to_string(),
            ]),
        })
    }

    pub fn seed_send_apply(
        &self,
        request: &SeedSendApplyRequest,
        guarded_writes_enabled: bool,
        send_controls_enabled: bool,
    ) -> Result<SeedSendApplyReport, InterspireError> {
        if !self.config.is_configured() {
            return Ok(SeedSendApplyReport::denied(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                "admin HTML fallback is not configured; no seed send attempted".to_string(),
            ));
        }
        if !request.acknowledge_seed_send {
            return Ok(SeedSendApplyReport::denied(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                "seed send refused because acknowledge_seed_send was not true".to_string(),
            ));
        }
        if request.list_ids.is_empty() {
            return Err(InterspireError::Safety(
                "seed send requires at least one explicit list id".to_string(),
            ));
        }
        if request.expected_recipient_count == 0
            || request.expected_recipient_count > MAX_SEED_SEND_RECIPIENTS
        {
            return Err(InterspireError::Safety(format!(
                "seed send expected_recipient_count must be between 1 and {MAX_SEED_SEND_RECIPIENTS}"
            )));
        }

        let readiness_request = SeedReadinessGateRequest {
            campaign_id: request.campaign_id,
            list_ids: request.list_ids.clone(),
            expected_recipient_count: Some(request.expected_recipient_count),
            expected_from_email: request.expected_from_email.clone(),
            expected_reply_to_email: request.expected_reply_to_email.clone(),
        };
        let readiness = self.seed_readiness_gate(&readiness_request)?;
        let refusal_warnings = send_apply_preflight_refusal_warnings(
            "seed",
            readiness.ready_for_seed_approval,
            readiness.campaign_body.subject.as_deref(),
            request.expected_subject.as_deref(),
            readiness.campaign_body.html_sha256.as_deref(),
            request.expected_html_sha256.as_deref(),
        );
        if !refusal_warnings.is_empty() {
            let mut warnings = readiness.warnings.clone();
            warnings.extend(refusal_warnings);
            return Ok(self.seed_send_report_from_readiness(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                readiness,
                false,
                None,
                false,
                0,
                0,
                0,
                0,
                warnings,
            ));
        }

        self.login()?;
        let max_rows = request.max_queue_rows.unwrap_or(25).clamp(1, 100);
        let authority = self.review_guarded_send_live_authority(
            &GuardedSendAuthorityExpectation {
                campaign_id: request.campaign_id,
                list_ids: &request.list_ids,
                expected_recipient_count: request.expected_recipient_count,
                expected_subject: request.expected_subject.as_deref(),
                expected_html_sha256: request.expected_html_sha256.as_deref(),
                expected_from_email: request.expected_from_email.as_deref(),
                expected_reply_to_email: request.expected_reply_to_email.as_deref(),
            },
            max_rows,
        )?;
        let GuardedSendAuthorityReview {
            confirmed,
            atomic_binding,
            refusal_reason,
        } = authority;
        let GuardedSendAuthoritySnapshot {
            campaign_body,
            send_wizard,
            send_form,
            identity,
            ..
        } = confirmed;
        let mut gates = readiness.gates;
        let mut warnings = readiness.warnings;
        warnings.extend(send_wizard.warnings.clone());
        if let Some(reason) = refusal_reason {
            let queue_rows_before = send_wizard.queue_rows_before;
            let queue_rows_after = send_wizard.queue_rows_after;
            let stats_rows_before = send_wizard.stats_rows_before;
            let stats_rows_after = send_wizard.stats_rows_after;
            gates.push(gate(
                "final_atomic_send_authority",
                false,
                "blocker",
                "the current admin HTML surface did not prove one atomic live authority product through dispatch"
                    .to_string(),
            ));
            warnings.push(reason);
            return Ok(self.seed_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                campaign_body,
                send_wizard,
                gates,
                false,
                None,
                false,
                queue_rows_before,
                queue_rows_after,
                stats_rows_before,
                stats_rows_after,
                None,
                warnings,
            ));
        }
        let atomic_authority_binding = atomic_binding.ok_or_else(|| {
            InterspireError::Safety(
                "guarded seed send reached no atomic live authority binding; no final request was constructed or dispatched"
                    .to_string(),
            )
        })?;
        gates.push(gate(
            "final_atomic_send_authority",
            true,
            "blocker",
            "one application-native atomic live authority binding covered the exact final submission"
                .to_string(),
        ));
        let live_campaign_id = identity.campaign_id;
        let live_list_ids = identity.selected_list_ids;
        let live_recipient_count = identity.recipient_count.ok_or_else(|| {
            InterspireError::Safety(
                "guarded seed send lost live recipient-count authority before dispatch".to_string(),
            )
        })?;

        let send_evidence = self.post_guarded_send_and_reconcile(GuardedSendRequestInput {
            send_form,
            atomic_authority_binding,
            campaign_id: live_campaign_id,
            list_ids: &live_list_ids,
            expected_body_sha256: identity.html_sha256,
            expected_recipient_count: live_recipient_count,
            max_rows,
        })?;
        let sent = send_evidence.reconciliation.terminal_application_proven();
        let queue_rows_before = send_evidence.reconciliation.queue_rows_before;
        let queue_rows_after = send_evidence.reconciliation.queue_rows_after;
        let stats_rows_before = send_evidence.reconciliation.stats_rows_before;
        let stats_rows_after = send_evidence.reconciliation.stats_rows_after;
        warnings.extend(seed_send_apply_warnings(&send_evidence.reconciliation));

        Ok(self.seed_send_report_from_parts(
            request,
            guarded_writes_enabled,
            send_controls_enabled,
            campaign_body,
            send_wizard,
            gates,
            sent,
            send_evidence.status_code,
            send_evidence.redirected,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            Some(send_evidence.reconciliation),
            warnings,
        ))
    }

    pub fn production_send_apply(
        &self,
        request: &ProductionSendApplyRequest,
        guarded_writes_enabled: bool,
        send_controls_enabled: bool,
        production_send_controls_enabled: bool,
    ) -> Result<ProductionSendApplyReport, InterspireError> {
        if !self.config.is_configured() {
            return Ok(ProductionSendApplyReport::denied(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                "admin HTML fallback is not configured; no production send attempted".to_string(),
            ));
        }
        if !request.acknowledge_production_send {
            return Ok(ProductionSendApplyReport::denied(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                "production send refused because acknowledge_production_send was not true"
                    .to_string(),
            ));
        }
        if request.confirmation_phrase != PRODUCTION_SEND_CONFIRMATION_PHRASE {
            return Ok(ProductionSendApplyReport::denied(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                "production send refused because confirmation_phrase did not match the required phrase"
                    .to_string(),
            ));
        }
        if request.list_ids.is_empty() {
            return Err(InterspireError::Safety(
                "production send requires at least one explicit list id".to_string(),
            ));
        }
        if request.expected_recipient_count == 0 {
            return Err(InterspireError::Safety(
                "production send expected_recipient_count must be positive".to_string(),
            ));
        }
        if request.expected_from_email.trim().is_empty()
            || request.expected_reply_to_email.trim().is_empty()
            || request.expected_subject.trim().is_empty()
            || request.expected_html_sha256.trim().is_empty()
        {
            return Err(InterspireError::Safety(
                "production send requires expected From, Reply-To, subject, and HTML SHA-256"
                    .to_string(),
            ));
        }

        let readiness_request = SeedReadinessGateRequest {
            campaign_id: request.campaign_id,
            list_ids: request.list_ids.clone(),
            expected_recipient_count: Some(request.expected_recipient_count),
            expected_from_email: Some(request.expected_from_email.clone()),
            expected_reply_to_email: Some(request.expected_reply_to_email.clone()),
        };
        let readiness = self.seed_readiness_gate(&readiness_request)?;
        let refusal_warnings = send_apply_preflight_refusal_warnings(
            "production",
            readiness.ready_for_seed_approval,
            readiness.campaign_body.subject.as_deref(),
            Some(request.expected_subject.as_str()),
            readiness.campaign_body.html_sha256.as_deref(),
            Some(request.expected_html_sha256.as_str()),
        );
        if !refusal_warnings.is_empty() {
            let mut warnings = readiness.warnings.clone();
            warnings.extend(refusal_warnings);
            return Ok(self.production_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                readiness.campaign_body,
                readiness.send_wizard,
                readiness.gates,
                false,
                None,
                false,
                0,
                0,
                0,
                0,
                None,
                warnings,
            ));
        }

        self.login()?;
        let max_rows = request.max_queue_rows.unwrap_or(25).clamp(1, 100);
        let authority = self.review_guarded_send_live_authority(
            &GuardedSendAuthorityExpectation {
                campaign_id: request.campaign_id,
                list_ids: &request.list_ids,
                expected_recipient_count: request.expected_recipient_count,
                expected_subject: Some(request.expected_subject.as_str()),
                expected_html_sha256: Some(request.expected_html_sha256.as_str()),
                expected_from_email: Some(request.expected_from_email.as_str()),
                expected_reply_to_email: Some(request.expected_reply_to_email.as_str()),
            },
            max_rows,
        )?;
        let GuardedSendAuthorityReview {
            confirmed,
            atomic_binding,
            refusal_reason,
        } = authority;
        let GuardedSendAuthoritySnapshot {
            campaign_body,
            send_wizard,
            send_form,
            identity,
            ..
        } = confirmed;
        let mut gates = readiness.gates;
        let mut warnings = readiness.warnings;
        warnings.extend(send_wizard.warnings.clone());
        if let Some(reason) = refusal_reason {
            let queue_rows_before = send_wizard.queue_rows_before;
            let queue_rows_after = send_wizard.queue_rows_after;
            let stats_rows_before = send_wizard.stats_rows_before;
            let stats_rows_after = send_wizard.stats_rows_after;
            gates.push(gate(
                "final_atomic_send_authority",
                false,
                "blocker",
                "the current admin HTML surface did not prove one atomic live authority product through dispatch"
                    .to_string(),
            ));
            warnings.push(reason);
            return Ok(self.production_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                campaign_body,
                send_wizard,
                gates,
                false,
                None,
                false,
                queue_rows_before,
                queue_rows_after,
                stats_rows_before,
                stats_rows_after,
                None,
                warnings,
            ));
        }
        let atomic_authority_binding = atomic_binding.ok_or_else(|| {
            InterspireError::Safety(
                "guarded production send reached no atomic live authority binding; no final request was constructed or dispatched"
                    .to_string(),
            )
        })?;
        gates.push(gate(
            "final_atomic_send_authority",
            true,
            "blocker",
            "one application-native atomic live authority binding covered the exact final submission"
                .to_string(),
        ));
        let live_campaign_id = identity.campaign_id;
        let live_list_ids = identity.selected_list_ids;
        let live_recipient_count = identity.recipient_count.ok_or_else(|| {
            InterspireError::Safety(
                "guarded production send lost live recipient-count authority before dispatch"
                    .to_string(),
            )
        })?;

        let send_evidence = self.post_guarded_send_and_reconcile(GuardedSendRequestInput {
            send_form,
            atomic_authority_binding,
            campaign_id: live_campaign_id,
            list_ids: &live_list_ids,
            expected_body_sha256: identity.html_sha256,
            expected_recipient_count: live_recipient_count,
            max_rows,
        })?;
        let sent = send_evidence.reconciliation.terminal_application_proven();
        let queue_rows_before = send_evidence.reconciliation.queue_rows_before;
        let queue_rows_after = send_evidence.reconciliation.queue_rows_after;
        let stats_rows_before = send_evidence.reconciliation.stats_rows_before;
        let stats_rows_after = send_evidence.reconciliation.stats_rows_after;
        warnings.extend(production_send_apply_warnings(
            &send_evidence.reconciliation,
        ));

        Ok(self.production_send_report_from_parts(
            request,
            guarded_writes_enabled,
            send_controls_enabled,
            production_send_controls_enabled,
            campaign_body,
            send_wizard,
            gates,
            sent,
            send_evidence.status_code,
            send_evidence.redirected,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            Some(send_evidence.reconciliation),
            warnings,
        ))
    }

    fn post_guarded_send_and_reconcile(
        &self,
        input: GuardedSendRequestInput<'_>,
    ) -> Result<GuardedSendEvidence, InterspireError> {
        self.post_guarded_send_and_reconcile_with_dispatch(input, |request| {
            request.send().map_err(|_| ())
        })
    }

    fn post_guarded_send_and_reconcile_with_dispatch<F, E>(
        &self,
        request_input: GuardedSendRequestInput<'_>,
        dispatch: F,
    ) -> Result<GuardedSendEvidence, InterspireError>
    where
        F: FnOnce(RequestBuilder) -> Result<reqwest::blocking::Response, E>,
    {
        let input = self.capture_guarded_send_baseline(request_input)?;
        self.post_guarded_send_from_baseline_with_dispatch(input, dispatch)
    }

    fn capture_guarded_send_baseline<'a>(
        &self,
        request: GuardedSendRequestInput<'a>,
    ) -> Result<GuardedSendReconcileInput<'a>, InterspireError> {
        if !request
            .atomic_authority_binding
            .validates(&request.send_form)
        {
            return Err(InterspireError::Safety(
                "guarded send atomic live authority did not bind the exact final submission; no final request was constructed or dispatched"
                    .to_string(),
            ));
        }
        let candidate = self.capture_guarded_send_baseline_snapshot(
            request.campaign_id,
            request.max_rows,
            "guarded send final pre-dispatch candidate baseline",
            false,
        )?;
        let confirmed = self.capture_guarded_send_baseline_snapshot(
            request.campaign_id,
            request.max_rows,
            "guarded send final pre-dispatch confirmation baseline",
            true,
        )?;
        if candidate.schedule_job_ids != confirmed.schedule_job_ids
            || candidate.manage_job_ids != confirmed.manage_job_ids
            || candidate.campaign_job_ids != confirmed.campaign_job_ids
            || candidate.stats_identity.ids() != confirmed.stats_identity.ids()
        {
            return Err(InterspireError::Safety(
                "guarded send final pre-dispatch baseline identities changed during bounded capture; no final request was dispatched"
                    .to_string(),
            ));
        }
        let baseline_context = GuardedSendBaselineContext {
            campaign_id: request.campaign_id,
            list_ids: request.list_ids.to_vec(),
            expected_body_sha256: request.expected_body_sha256.clone(),
            expected_recipient_count: request.expected_recipient_count,
            max_rows: request.max_rows,
            authority_submission_sha256: request.atomic_authority_binding.submission_sha256.clone(),
            authority_state_version: request.atomic_authority_binding.state_version.clone(),
            capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
        };
        let GuardedSendRequestInput {
            send_form,
            atomic_authority_binding,
            campaign_id,
            list_ids,
            expected_body_sha256,
            expected_recipient_count,
            max_rows,
        } = request;
        let input = GuardedSendReconcileInput {
            send_form,
            atomic_authority_binding,
            campaign_id,
            list_ids,
            expected_body_sha256,
            expected_recipient_count,
            max_rows,
            baseline_context,
            queue_before: confirmed.queue_before,
            schedule_job_ids_before: confirmed.schedule_job_ids,
            manage_job_ids_before: confirmed.manage_job_ids,
            campaign_job_ids_before: confirmed.campaign_job_ids,
            queue_job_ids_before: confirmed.queue_job_ids,
            stats_before: confirmed.stats_before,
            stats_identity_before: confirmed.stats_identity,
            baseline_identity_stable: true,
        };
        validate_guarded_send_baseline_context(&input)?;
        Ok(input)
    }

    fn capture_guarded_send_baseline_snapshot(
        &self,
        campaign_id: u64,
        max_rows: usize,
        operation: &str,
        stats_first: bool,
    ) -> Result<GuardedSendBaselineSnapshot, InterspireError> {
        let (queue_inventory, stats_html) = if stats_first {
            let stats_html = self.get_allowed(&AdminReadPage::Stats.path())?;
            let queue_inventory = self.complete_queue_control_inventory(max_rows, operation)?;
            (queue_inventory, stats_html)
        } else {
            let queue_inventory = self.complete_queue_control_inventory(max_rows, operation)?;
            let stats_html = self.get_allowed(&AdminReadPage::Stats.path())?;
            (queue_inventory, stats_html)
        };
        let queue_before = parse_table_rows(&queue_inventory.schedule_html, max_rows)?;
        let schedule_job_ids = queue_job_ids_for_source(
            &queue_inventory.links,
            crate::response::QueueControlSource::Schedule,
        );
        let manage_job_ids = queue_job_ids_for_source(
            &queue_inventory.links,
            crate::response::QueueControlSource::CampaignManage,
        );
        let campaign_job_ids =
            queue_manage_job_ids_for_campaign(&queue_inventory.links, campaign_id);
        let queue_job_ids = schedule_job_ids.union(&manage_job_ids).copied().collect();
        let stats_identity = parse_stats_identity_inventory(
            self.config.base_url.as_deref().unwrap_or_default(),
            &stats_html,
            max_rows,
        )?;
        let stats_before = parse_table_rows(&stats_html, max_rows)?;
        Ok(GuardedSendBaselineSnapshot {
            queue_before,
            schedule_job_ids,
            manage_job_ids,
            campaign_job_ids,
            queue_job_ids,
            stats_before,
            stats_identity,
        })
    }

    fn post_guarded_send_from_baseline_with_dispatch<F, E>(
        &self,
        input: GuardedSendReconcileInput<'_>,
        dispatch: F,
    ) -> Result<GuardedSendEvidence, InterspireError>
    where
        F: FnOnce(RequestBuilder) -> Result<reqwest::blocking::Response, E>,
    {
        validate_guarded_send_baseline_context(&input)?;
        let (send_url, send_pairs) = input.send_form.clone();
        let request = self.proof_post_with_page_context(
            send_url,
            &send_pairs,
            &AdminReadPage::SendStart.path(),
        )?;
        let mut progress = GuardedSendProgress::default();
        progress.notes.push(
            "complete authenticated Schedule, Manage, and Stats baselines were stable across two bounded captures at the final pre-dispatch stage"
                .to_string(),
        );
        let response = match dispatch(request) {
            Ok(response) => response,
            Err(_) => {
                progress.response_uncertain = true;
                progress.job_evidence.add_gap(
                    "the final request was attempted but no HTTP response was available; whether it reached the application remains uncertain",
                );
                progress.notes.push(
                    "request-response uncertainty was retained as a nonterminal reconciliation receipt"
                        .to_string(),
                );
                return Ok(self.complete_guarded_send_readback(&input, progress, None));
            }
        };
        let status = response.status();
        progress.status_code = Some(status.as_u16());
        progress.redirected = status.is_redirection();
        let mut final_response_summary = None;
        let mut seen_popup_urls = HashSet::new();
        let mut next_popup_url = match guarded_send_location_from_headers(
            self.config.base_url.as_deref().unwrap_or_default(),
            response.headers(),
        ) {
            Ok(url) => url,
            Err(_) => {
                return Ok(guarded_send_evidence_from_progress(
                    &input,
                    progress,
                    Some("the final response exposed a malformed or disallowed continuation route"),
                ));
            }
        };

        if status.is_success() {
            let html = match response.text() {
                Ok(html) => html,
                Err(_) => {
                    return Ok(guarded_send_evidence_from_progress(
                        &input,
                        progress,
                        Some("the final response body was unavailable after request dispatch"),
                    ));
                }
            };
            if !html.trim().is_empty() {
                if ensure_authenticated_html(&html).is_err() {
                    return Ok(guarded_send_evidence_from_progress(
                        &input,
                        progress,
                        Some(
                            "the final response could not be authenticated after request dispatch",
                        ),
                    ));
                }
                progress.smtp_reason = transport_failure_reason(&html);
                final_response_summary = step4_response_summary(&html);
                // Cron-enabled Interspire sends stop at Step4 until the same
                // session follows the exact Schedule approval continuation.
                let approval_url = match guarded_schedule_approval_url(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &html,
                ) {
                    Ok(url) => url,
                    Err(_) => {
                        return Ok(guarded_send_evidence_from_progress(
                            &input,
                            progress,
                            Some(
                                "the final response exposed a malformed or disallowed schedule continuation",
                            ),
                        ));
                    }
                };
                if let Some(approval_url) = approval_url {
                    let approval_response = match self
                        .with_access_headers(self.http.get(approval_url))
                        .send()
                    {
                        Ok(response) => response,
                        Err(_) => {
                            return Ok(guarded_send_evidence_from_progress(
                                    &input,
                                    progress,
                                    Some(
                                        "the schedule continuation response was unavailable after request dispatch",
                                    ),
                                ));
                        }
                    };
                    if !approval_response.status().is_success()
                        && !approval_response.status().is_redirection()
                    {
                        return Ok(guarded_send_evidence_from_progress(
                            &input,
                            progress,
                            Some(
                                "the schedule continuation returned a non-success response after request dispatch",
                            ),
                        ));
                    }
                    progress.approved_cron_schedule = true;
                    progress.notes.push(
                        "Cron send confirmation approved through the guarded Schedule&A=1 route"
                            .to_string(),
                    );
                    if approval_response.status().is_success() {
                        let approval_html = match approval_response.text() {
                            Ok(html) => html,
                            Err(_) => {
                                return Ok(guarded_send_evidence_from_progress(
                                    &input,
                                    progress,
                                    Some(
                                        "the schedule continuation body was unavailable after request dispatch",
                                    ),
                                ));
                            }
                        };
                        if !approval_html.trim().is_empty()
                            && ensure_authenticated_html(&approval_html).is_err()
                        {
                            return Ok(guarded_send_evidence_from_progress(
                                &input,
                                progress,
                                Some(
                                    "the schedule continuation could not be authenticated after request dispatch",
                                ),
                            ));
                        }
                    }
                }
                let body_popup_url = match guarded_send_popup_url(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &html,
                ) {
                    Ok(url) => url,
                    Err(_) => {
                        return Ok(guarded_send_evidence_from_progress(
                            &input,
                            progress,
                            Some(
                                "the final response exposed a malformed or disallowed popup continuation",
                            ),
                        ));
                    }
                };
                next_popup_url = next_popup_url.or(body_popup_url);
            }
        } else if !progress.redirected {
            return Ok(guarded_send_evidence_from_progress(
                &input,
                progress,
                Some(
                    "the final request returned a non-success response; application outcome remains unproven",
                ),
            ));
        }

        while let Some(url) = next_popup_url.take() {
            if progress.popup_steps >= MAX_SEND_POPUP_STEPS {
                progress
                    .notes
                    .push("send popup loop stopped at the maximum step guard".to_string());
                break;
            }
            let url_key = url.as_str().to_string();
            if !seen_popup_urls.insert(url_key) {
                progress
                    .notes
                    .push("send popup loop stopped after a repeated route".to_string());
                break;
            }
            progress
                .job_evidence
                .observe(send_popup_job_id(&url), "popup continuation");
            let response = match self.with_access_headers(self.http.get(url)).send() {
                Ok(response) => response,
                Err(_) => {
                    return Ok(guarded_send_evidence_from_progress(
                        &input,
                        progress,
                        Some(
                            "a popup continuation response was unavailable after request dispatch",
                        ),
                    ));
                }
            };
            let popup_status = response.status();
            let popup_location = match guarded_send_location_from_headers(
                self.config.base_url.as_deref().unwrap_or_default(),
                response.headers(),
            ) {
                Ok(url) => url,
                Err(_) => {
                    return Ok(guarded_send_evidence_from_progress(
                        &input,
                        progress,
                        Some(
                            "a popup response exposed a malformed or disallowed continuation route",
                        ),
                    ));
                }
            };
            if !popup_status.is_success() && !popup_status.is_redirection() {
                return Ok(guarded_send_evidence_from_progress(
                    &input,
                    progress,
                    Some(
                        "a popup continuation returned a non-success response after request dispatch",
                    ),
                ));
            }
            progress.popup_steps += 1;
            if popup_status.is_redirection() {
                next_popup_url = popup_location;
                continue;
            }
            let html = match response.text() {
                Ok(html) => html,
                Err(_) => {
                    return Ok(guarded_send_evidence_from_progress(
                        &input,
                        progress,
                        Some("a popup continuation body was unavailable after request dispatch"),
                    ));
                }
            };
            if !html.trim().is_empty() {
                if ensure_authenticated_html(&html).is_err() {
                    return Ok(guarded_send_evidence_from_progress(
                        &input,
                        progress,
                        Some(
                            "a popup continuation could not be authenticated after request dispatch",
                        ),
                    ));
                }
                progress.smtp_reason = progress
                    .smtp_reason
                    .or_else(|| transport_failure_reason(&html));
                let body_popup_url = match guarded_send_popup_url(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &html,
                ) {
                    Ok(url) => url,
                    Err(_) => {
                        return Ok(guarded_send_evidence_from_progress(
                            &input,
                            progress,
                            Some(
                                "a popup body exposed a malformed or disallowed continuation route",
                            ),
                        ));
                    }
                };
                next_popup_url = popup_location.or(body_popup_url);
            }
        }

        Ok(self.complete_guarded_send_readback(&input, progress, final_response_summary))
    }

    fn complete_guarded_send_readback(
        &self,
        input: &GuardedSendReconcileInput<'_>,
        mut progress: GuardedSendProgress,
        final_response_summary: Option<String>,
    ) -> GuardedSendEvidence {
        let queue_inventory = match self
            .complete_queue_control_inventory(input.max_rows, "guarded send readback")
        {
            Ok(inventory) => inventory,
            Err(_) => {
                return guarded_send_evidence_from_progress(
                    input,
                    progress,
                    Some(
                        "Schedule and campaign Manage identity readback was incomplete after request dispatch",
                    ),
                );
            }
        };
        progress.queue_after =
            match parse_table_rows(&queue_inventory.schedule_html, input.max_rows) {
                Ok(rows) => Some(rows),
                Err(_) => {
                    return guarded_send_evidence_from_progress(
                        input,
                        progress,
                        Some("Schedule readback could not be parsed after request dispatch"),
                    );
                }
            };
        let schedule_job_ids_after = queue_job_ids_for_source(
            &queue_inventory.links,
            crate::response::QueueControlSource::Schedule,
        );
        let manage_job_ids_after = queue_job_ids_for_source(
            &queue_inventory.links,
            crate::response::QueueControlSource::CampaignManage,
        );
        let queue_job_ids_after = schedule_job_ids_after
            .union(&manage_job_ids_after)
            .copied()
            .collect::<BTreeSet<_>>();
        match queue_job_identity_delta(&input.queue_job_ids_before, &queue_job_ids_after) {
            QueueJobIdentityDelta::None if progress.job_evidence.job_id.is_none() => progress
                .job_evidence
                .add_gap("bounded Schedule/Manage readback exposed no new diagnostic job identity"),
            QueueJobIdentityDelta::None => progress.notes.push(
                "bounded Schedule/Manage readback added no queue-only job identity".to_string(),
            ),
            QueueJobIdentityDelta::Unique(job_id) => {
                if progress.job_evidence.job_id == Some(job_id) && !progress.job_evidence.conflicted
                {
                    progress.notes.push(
                        "one Schedule/Manage delta matched the native response-bound job; queue movement remains diagnostic only"
                            .to_string(),
                    );
                } else {
                    progress.job_identity_ambiguous = true;
                    progress.job_evidence.add_gap(
                        "one Schedule/Manage job appeared after the baseline, but queue movement and campaign association do not bind that concurrent job to this request"
                            .to_string(),
                    );
                }
            }
            QueueJobIdentityDelta::Ambiguous { added, removed } => {
                progress.job_identity_ambiguous = true;
                progress.job_evidence.add_gap(format!(
                    "bounded Schedule/Manage identity reconciliation was ambiguous: {added} added and {removed} removed"
                ));
            }
        }
        progress.active_job_ids_after = Some(queue_job_ids_after);

        let stats_after_html = match self.get_allowed(&AdminReadPage::Stats.path()) {
            Ok(html) => html,
            Err(_) => {
                return guarded_send_evidence_from_progress(
                    input,
                    progress,
                    Some("Stats readback was unavailable after request dispatch"),
                );
            }
        };
        progress.stats_after = match parse_table_rows(&stats_after_html, input.max_rows) {
            Ok(rows) => Some(rows),
            Err(_) => {
                return guarded_send_evidence_from_progress(
                    input,
                    progress,
                    Some("Stats readback could not be parsed after request dispatch"),
                );
            }
        };
        progress.stats_identity_after = match parse_stats_identity_inventory(
            self.config.base_url.as_deref().unwrap_or_default(),
            &stats_after_html,
            input.max_rows,
        ) {
            Ok(inventory) => Some(inventory),
            Err(_) => {
                return guarded_send_evidence_from_progress(
                    input,
                    progress,
                    Some("Stats identity readback was incomplete after request dispatch"),
                );
            }
        };
        if progress.job_evidence.job_id.is_none()
            && stable_stats_identity_delta(
                &input.stats_before,
                progress
                    .stats_after
                    .as_deref()
                    .unwrap_or(input.stats_before.as_slice()),
            )
            .added
                == 0
        {
            if let Some(summary) = final_response_summary {
                progress
                    .notes
                    .push(format!("Final Step4 response summary: {summary}"));
            }
        }
        progress.reconciliation_readback_complete = true;
        guarded_send_evidence_from_progress(input, progress, None)
    }

    fn proof_post_with_page_context(
        &self,
        url: Url,
        post_pairs: &[(String, String)],
        referer_path: &str,
    ) -> Result<RequestBuilder, InterspireError> {
        let mut request = self
            .with_access_headers(self.http.post(url))
            .form(post_pairs)
            .header("referer", self.admin_url_for_path(referer_path)?.as_str())
            .header(
                "origin",
                admin_origin(self.config.base_url.as_deref().unwrap_or_default())?,
            );
        if let Some((_, token)) = csrf_pair(post_pairs) {
            request = request.header("x-csrf-token", token.as_str());
        }
        Ok(request)
    }

    fn admin_url_for_path(&self, path: &str) -> Result<Url, InterspireError> {
        safety::ensure_allowed_admin_get(self.config.base_url.as_deref().unwrap_or_default(), path)
    }

    fn render_send_wizard_final_page(
        &self,
        request: &SendWizardReadbackRequest,
        max_rows: usize,
    ) -> Result<(SendWizardReadbackReport, String), InterspireError> {
        let queue_before = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_before =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;

        let start_html = self.get_allowed(&AdminReadPage::SendStart.path())?;
        let step2_path = send_step2_action_path(&start_html).ok_or_else(|| {
            InterspireError::Safety(
                "Send start page did not expose an allowlisted no-send Step2 form".to_string(),
            )
        })?;
        let step2_url = safety::ensure_allowed_send_wizard_step2_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            &step2_path,
        )?;
        let mut post_pairs = send_start_hidden_pairs(&start_html)?;
        upsert_post_pair(
            &mut post_pairs,
            "newsletter",
            &request.campaign_id.to_string(),
        );
        upsert_post_pair(&mut post_pairs, "ShowFilteringOptions", "2");
        for list_id in &request.list_ids {
            post_pairs.push(("lists[]".to_string(), list_id.to_string()));
        }

        append_csrf_pair_if_missing(&mut post_pairs, &start_html);

        let response = self
            .proof_post_with_page_context(step2_url, &post_pairs, &AdminReadPage::SendStart.path())?
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !response.status().is_success() {
            return Err(InterspireError::Http(format!(
                "send wizard no-send Step2 render returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let final_html = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        ensure_authenticated_html(&final_html)?;

        let queue_after = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_after =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;

        let mut report =
            parse_send_wizard_final_page(request.campaign_id, &request.list_ids, &final_html)?;
        report.queue_rows_before = queue_before.len();
        report.queue_rows_after = queue_after.len();
        report.stats_rows_before = stats_before.len();
        report.stats_rows_after = stats_after.len();
        report.queue_unchanged = rows_unchanged_for_send_proof(&queue_before, &queue_after);
        let stats_content_unchanged = rows_unchanged_for_send_proof(&stats_before, &stats_after);
        report.stats_unchanged = stats_rows_stable_for_no_send_proof(&stats_before, &stats_after);

        if !report.queue_unchanged {
            report
                .warnings
                .push("Schedule queue rows changed during no-send wizard proof".to_string());
        }
        if !report.stats_unchanged {
            report
                .warnings
                .push("Stats rows changed during no-send wizard proof".to_string());
        } else if !stats_content_unchanged {
            report.warnings.push(
                "Stats row content changed during no-send wizard proof, but stable row identity shows no new or removed Stats rows"
                    .to_string(),
            );
        }
        if report.selected_campaign_id != Some(request.campaign_id)
            && !report.requested_campaign_available
        {
            report.warnings.push(format!(
                "requested campaign {} was not selected and was not found in the campaign dropdown",
                request.campaign_id
            ));
        }
        report.requested_list_ids_proven_by_recipient_count = report.selected_list_ids.is_empty()
            && request.expected_recipient_count.is_some()
            && report.recipient_count == request.expected_recipient_count;
        if report.requested_list_ids_proven_by_recipient_count {
            report.warnings.retain(|warning| {
                warning != "final send wizard page did not expose selected list ids"
            });
        }
        if let Some(warning) = list_ids_warning(
            &report.selected_list_ids,
            &request.list_ids,
            report.requested_list_ids_proven_by_recipient_count,
        ) {
            report.warnings.push(warning);
        }
        if let Some(expected) = request.expected_recipient_count {
            if report.recipient_count != Some(expected) {
                report.warnings.push(format!(
                    "recipient count did not match expected count {expected}"
                ));
            }
        }
        report.evidence.notes.push(
            "allowlisted Send Step2 POST rendered final editable page; final form was not posted"
                .to_string(),
        );
        if report.requested_campaign_available
            && report.selected_campaign_id != Some(request.campaign_id)
        {
            report.evidence.notes.push(
                "requested campaign was present as a selectable campaign option on Interspire Step2"
                    .to_string(),
            );
        }
        if report.requested_list_ids_proven_by_recipient_count {
            report.evidence.notes.push(
                "Interspire Step2 did not echo list ids; requested list ids were accepted as session proof because the rendered recipient count matched the expected count"
                    .to_string(),
            );
        }
        let campaign_proven = report.selected_campaign_id == Some(request.campaign_id)
            || report.requested_campaign_available;
        let lists_proven = ids_match(&report.selected_list_ids, &request.list_ids)
            || report.requested_list_ids_proven_by_recipient_count;
        report.ok = report.final_form_posts_to_send_boundary
            && report.queue_unchanged
            && report.stats_unchanged
            && campaign_proven
            && lists_proven
            && match request.expected_recipient_count {
                Some(expected) => report.recipient_count == Some(expected),
                None => true,
            };
        Ok((report, final_html))
    }

    fn review_guarded_send_live_authority(
        &self,
        expectation: &GuardedSendAuthorityExpectation<'_>,
        max_rows: usize,
    ) -> Result<GuardedSendAuthorityReview, InterspireError> {
        let prepared = self.capture_guarded_send_live_authority(expectation, max_rows)?;
        let candidate = self.capture_guarded_send_live_authority(expectation, max_rows)?;
        let confirmed = self.capture_guarded_send_live_authority(expectation, max_rows)?;

        let mut refusal_reason = guarded_send_authority_snapshot_refusal(&prepared, expectation)
            .or_else(|| guarded_send_authority_snapshot_refusal(&candidate, expectation))
            .or_else(|| guarded_send_authority_snapshot_refusal(&confirmed, expectation));
        if refusal_reason.is_none() && prepared.identity != candidate.identity {
            refusal_reason = Some(
                "guarded send live campaign, audience, or final-form authority changed between the prepared and candidate authority captures; no final request was constructed or dispatched"
                    .to_string(),
            );
        }
        if refusal_reason.is_none() && candidate.identity != confirmed.identity {
            refusal_reason = Some(
                "guarded send live campaign, audience, or final-form authority changed between the candidate and confirmed authority captures; no final request was constructed or dispatched"
                    .to_string(),
            );
        }

        let atomic_binding = match (
            prepared.atomic_binding.as_ref(),
            candidate.atomic_binding.as_ref(),
            confirmed.atomic_binding.as_ref(),
        ) {
            (Some(prepared_binding), Some(candidate_binding), Some(confirmed_binding))
                if prepared_binding == candidate_binding
                    && candidate_binding == confirmed_binding
                    && confirmed_binding.validates(&confirmed.send_form) =>
            {
                Some(confirmed_binding.clone())
            }
            _ => None,
        };
        if refusal_reason.is_none() && atomic_binding.is_none() {
            refusal_reason = Some(
                "guarded send refused because the admin HTML surface exposed no authenticated atomic state version or lock binding the exact live campaign, body, audience, final-form token, and submitted pairs through the POST boundary; no final request was constructed or dispatched"
                    .to_string(),
            );
        }

        Ok(GuardedSendAuthorityReview {
            confirmed,
            atomic_binding,
            refusal_reason,
        })
    }

    fn capture_guarded_send_live_authority(
        &self,
        expectation: &GuardedSendAuthorityExpectation<'_>,
        max_rows: usize,
    ) -> Result<GuardedSendAuthoritySnapshot, InterspireError> {
        let (campaign_body, subject_sha256) =
            self.campaign_body_authority_authenticated(expectation.campaign_id)?;
        let (send_wizard, final_html) = self.render_send_wizard_final_page(
            &SendWizardReadbackRequest {
                campaign_id: expectation.campaign_id,
                list_ids: expectation.list_ids.to_vec(),
                expected_recipient_count: Some(expectation.expected_recipient_count),
                max_queue_rows: Some(max_rows),
            },
            max_rows,
        )?;
        let send_form = guarded_send_final_form_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            &final_html,
        )?;
        let (_, token) = guarded_send_form_token(&send_form.1)?;
        let mut selected_list_ids = send_wizard.selected_list_ids.clone();
        selected_list_ids.sort_unstable();
        let identity = GuardedSendAuthorityIdentity {
            campaign_id: send_wizard.selected_campaign_id.unwrap_or_default(),
            subject_sha256,
            html_sha256: campaign_body.html_sha256.clone(),
            text_sha256: campaign_body.text_sha256.clone(),
            from_name_sha256: guarded_send_exact_form_value_sha256(
                &send_form.1,
                &["sendfromname", "fromname"],
                false,
            ),
            from_email_sha256: guarded_send_exact_form_value_sha256(
                &send_form.1,
                &["sendfromemail", "fromemail"],
                true,
            ),
            reply_to_email_sha256: guarded_send_exact_form_value_sha256(
                &send_form.1,
                &["replytoemail"],
                true,
            ),
            bounce_email_sha256: guarded_send_exact_form_value_sha256(
                &send_form.1,
                &["bounceemail"],
                true,
            ),
            selected_list_ids,
            recipient_count: send_wizard.recipient_count,
            send_immediately_checked: send_wizard.send_immediately_checked,
            notify_owner_checked: send_wizard.notify_owner_checked,
            track_opens_checked: send_wizard.track_opens_checked,
            track_links_checked: send_wizard.track_links_checked,
            multipart_checked: send_wizard.multipart_checked,
            embed_images_checked: send_wizard.embed_images_checked,
            final_form_action_fingerprint: send_wizard.final_form_action_fingerprint.clone(),
            final_form_token_sha256: sha256_hex(&token),
            submission_sha256: guarded_send_submission_sha256(&send_form),
        };

        Ok(GuardedSendAuthoritySnapshot {
            campaign_body,
            send_wizard,
            send_form,
            identity,
            // The current admin HTML form exposes CSRF protection, not an
            // application-native state version or lock over campaign and
            // audience state. Keep dispatch authority absent until such a
            // binding is implemented and independently proven.
            atomic_binding: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_send_report_from_readiness(
        &self,
        request: &SeedSendApplyRequest,
        guarded_writes_enabled: bool,
        send_controls_enabled: bool,
        readiness: SeedReadinessGateReport,
        sent: bool,
        post_status_code: Option<u16>,
        post_redirected: bool,
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
        warnings: Vec<String>,
    ) -> SeedSendApplyReport {
        self.seed_send_report_from_parts(
            request,
            guarded_writes_enabled,
            send_controls_enabled,
            readiness.campaign_body,
            readiness.send_wizard,
            readiness.gates,
            sent,
            post_status_code,
            post_redirected,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            None,
            warnings,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_send_report_from_parts(
        &self,
        request: &SeedSendApplyRequest,
        guarded_writes_enabled: bool,
        send_controls_enabled: bool,
        campaign_body: CampaignBodyAuditReport,
        mut send_wizard: SendWizardReadbackReport,
        gates: Vec<SeedReadinessGate>,
        sent: bool,
        post_status_code: Option<u16>,
        post_redirected: bool,
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
        reconciliation: Option<SendReconciliationReport>,
        warnings: Vec<String>,
    ) -> SeedSendApplyReport {
        if sent {
            send_wizard.send_performed = true;
        }
        let reconciliation = reconciliation.unwrap_or_else(|| {
            if post_status_code.is_some() {
                SendReconciliationReport::from_boundary_post(
                    true,
                    queue_rows_before,
                    queue_rows_after,
                    stats_rows_before,
                    stats_rows_after,
                )
            } else {
                SendReconciliationReport::refused(
                    queue_rows_before,
                    queue_rows_after,
                    stats_rows_before,
                    stats_rows_after,
                    "no seed send request sent".to_string(),
                )
            }
        });
        let boundary_evidence_note =
            guarded_send_boundary_evidence_note(reconciliation.status, "seed-send");
        SeedSendApplyReport {
            ok: sent,
            configured: true,
            guarded_writes_enabled,
            send_controls_enabled,
            sent,
            campaign_id: request.campaign_id,
            requested_list_ids: request.list_ids.clone(),
            recipient_count: send_wizard.recipient_count,
            from_name: send_wizard.from_name.clone(),
            from_email_redacted: send_wizard.from_email_redacted.clone(),
            reply_to_email_redacted: send_wizard.reply_to_email_redacted.clone(),
            bounce_email_redacted: send_wizard.bounce_email_redacted.clone(),
            subject: campaign_body.subject.clone(),
            html_sha256: campaign_body.html_sha256.clone(),
            gates,
            send_wizard: Some(send_wizard),
            campaign_body: Some(campaign_body),
            post_status_code,
            post_redirected,
            oci_ledger_preflight: OciLedgerPreflightReport::skipped(
                false,
                false,
                "OCI ledger preflight is attached by the live backend send wrapper",
            ),
            reconciliation,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            production_send_authorized: false,
            warnings: warnings
                .into_iter()
                .map(|warning| redact::redact_sensitive_text(&warning))
                .collect(),
            evidence: admin_evidence(vec![
                "seed send apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_SEND_CONTROLS=1".to_string(),
                "fresh campaign body, audience, and final-form authority was evaluated before any final send request".to_string(),
                boundary_evidence_note,
            ]),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn production_send_report_from_parts(
        &self,
        request: &ProductionSendApplyRequest,
        guarded_writes_enabled: bool,
        send_controls_enabled: bool,
        production_send_controls_enabled: bool,
        campaign_body: CampaignBodyAuditReport,
        mut send_wizard: SendWizardReadbackReport,
        gates: Vec<SeedReadinessGate>,
        sent: bool,
        post_status_code: Option<u16>,
        post_redirected: bool,
        queue_rows_before: usize,
        queue_rows_after: usize,
        stats_rows_before: usize,
        stats_rows_after: usize,
        reconciliation: Option<SendReconciliationReport>,
        warnings: Vec<String>,
    ) -> ProductionSendApplyReport {
        if sent {
            send_wizard.send_performed = true;
        }
        let reconciliation = reconciliation.unwrap_or_else(|| {
            if post_status_code.is_some() {
                SendReconciliationReport::from_boundary_post(
                    true,
                    queue_rows_before,
                    queue_rows_after,
                    stats_rows_before,
                    stats_rows_after,
                )
            } else {
                SendReconciliationReport::refused(
                    queue_rows_before,
                    queue_rows_after,
                    stats_rows_before,
                    stats_rows_after,
                    "no production send request sent".to_string(),
                )
            }
        });
        let boundary_evidence_note =
            guarded_send_boundary_evidence_note(reconciliation.status, "production-send");
        ProductionSendApplyReport {
            ok: sent,
            configured: true,
            guarded_writes_enabled,
            send_controls_enabled,
            production_send_controls_enabled,
            sent,
            campaign_id: request.campaign_id,
            requested_list_ids: request.list_ids.clone(),
            recipient_count: send_wizard.recipient_count,
            from_name: send_wizard.from_name.clone(),
            from_email_redacted: send_wizard.from_email_redacted.clone(),
            reply_to_email_redacted: send_wizard.reply_to_email_redacted.clone(),
            bounce_email_redacted: send_wizard.bounce_email_redacted.clone(),
            subject: campaign_body.subject.clone(),
            html_sha256: campaign_body.html_sha256.clone(),
            ops_work_item_ref: request.ops_work_item_ref.clone(),
            gates,
            send_wizard: Some(send_wizard),
            campaign_body: Some(campaign_body),
            post_status_code,
            post_redirected,
            oci_ledger_preflight: OciLedgerPreflightReport::skipped(
                false,
                false,
                "OCI ledger preflight is attached by the live backend send wrapper",
            ),
            reconciliation,
            queue_rows_before,
            queue_rows_after,
            stats_rows_before,
            stats_rows_after,
            production_send_authorized: sent,
            warnings: warnings
                .into_iter()
                .map(|warning| redact::redact_sensitive_text(&warning))
                .collect(),
            evidence: admin_evidence(vec![
                "production send apply requires INTERSPIRE_GUARDED_WRITES=1, INTERSPIRE_SEND_CONTROLS=1, and INTERSPIRE_PRODUCTION_SEND_CONTROLS=1".to_string(),
                "fresh campaign body, audience, and final-form authority was evaluated before any final send request".to_string(),
                boundary_evidence_note,
            ]),
        }
    }
}

fn gate(name: &str, passed: bool, severity: &str, detail: String) -> SeedReadinessGate {
    SeedReadinessGate {
        name: name.to_string(),
        passed,
        severity: severity.to_string(),
        detail: redact::redact_sensitive_text(&detail),
    }
}

fn list_ids_warning(
    selected_list_ids: &[u64],
    requested_list_ids: &[u64],
    recipient_count_proof: bool,
) -> Option<String> {
    if ids_match(selected_list_ids, requested_list_ids) || recipient_count_proof {
        return None;
    }
    if selected_list_ids.is_empty() {
        return Some(
            "selected list ids could not be proven from final wizard page or recipient-count echo"
                .to_string(),
        );
    }
    Some(format!(
        "selected list ids {:?} did not match requested list ids {:?}",
        selected_list_ids, requested_list_ids
    ))
}

fn validate_single_preview_email(value: &str, field_name: &str) -> Result<(), InterspireError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || !trimmed.contains('@')
        || trimmed.contains(',')
        || trimmed.contains(';')
        || trimmed.split_whitespace().count() != 1
    {
        return Err(InterspireError::Safety(format!(
            "{field_name} must be exactly one email address"
        )));
    }
    Ok(())
}

fn expected_public_subject_matches(
    current_public_subject: Option<&str>,
    expected_subject: &str,
) -> bool {
    current_public_subject.unwrap_or_default() == expected_subject
}

fn campaign_test_send_limitations() -> Vec<String> {
    vec![
        "Interspire preview sends do not prove list-specific unsubscribe, custom fields, contact merge fields, or production audience behavior".to_string(),
        "Use a seed-list send when the required proof is production-path unsubscribe/tracking/list metadata behavior".to_string(),
    ]
}

fn campaign_test_send_has_applyable_html(
    parts: &CampaignBodyParts,
    campaign_body: &CampaignBodyAuditReport,
) -> bool {
    !parts.html_body.trim().is_empty() && campaign_body.html_sha256.is_some()
}

#[allow(clippy::too_many_arguments)]
fn campaign_test_send_report(
    request: &CampaignTestSendApplyRequest,
    sent: bool,
    post_status_code: Option<u16>,
    response_message: Option<String>,
    campaign_body: CampaignBodyAuditReport,
    preview_digest: Option<String>,
    preheader_present: bool,
    queue_rows_before: usize,
    queue_rows_after: usize,
    stats_rows_before: usize,
    stats_rows_after: usize,
    queue_unchanged: bool,
    stats_unchanged: bool,
    warnings: Vec<String>,
    route_posted: bool,
) -> CampaignTestSendApplyReport {
    let evidence_notes = if route_posted {
        vec![
            "campaign test-send apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_SEND_CONTROLS=1".to_string(),
            "current persisted campaign subject/body hashes, exact recipient, and caller-supplied preview sender matched apply expectations before posting Interspire SendPreview".to_string(),
            "native Interspire Newsletters SendPreview route was posted for one explicit recipient".to_string(),
            "Schedule and Stats rows were compared before/after the preview send".to_string(),
        ]
    } else {
        vec![
            "campaign test-send apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_SEND_CONTROLS=1".to_string(),
            "current persisted campaign subject/body hashes, exact recipient, and caller-supplied preview sender were checked before apply refusal".to_string(),
            "no Interspire SendPreview route was posted".to_string(),
            "Schedule and Stats rows were compared after campaign-body proof before apply refusal".to_string(),
        ]
    };
    CampaignTestSendApplyReport {
        ok: sent,
        configured: true,
        sent,
        campaign_id: request.campaign_id,
        recipient_email_redacted: redact::redact_email(&request.recipient_email),
        from_preview_email_redacted: redact::redact_email(&request.from_preview_email),
        preview_digest,
        subject: campaign_body.subject.clone(),
        html_sha256: campaign_body.html_sha256.clone(),
        html_bytes: campaign_body.html_bytes,
        text_bytes: campaign_body.text_bytes,
        preheader_present,
        post_status_code,
        response_message: response_message.map(|message| redact::redact_sensitive_text(&message)),
        campaign_body: sent.then_some(campaign_body),
        queue_rows_before,
        queue_rows_after,
        stats_rows_before,
        stats_rows_after,
        queue_unchanged,
        stats_unchanged,
        production_send_authorized: false,
        warnings: warnings
            .into_iter()
            .map(|warning| redact::redact_sensitive_text(&warning))
            .collect(),
        evidence: admin_evidence(evidence_notes),
    }
}

fn preview_send_response_message(html: &str) -> Option<String> {
    let text = compact_text(
        &Html::parse_document(html)
            .root_element()
            .text()
            .collect::<Vec<_>>()
            .join(" "),
    );
    let lower = text.to_ascii_lowercase();
    if lower.contains("a preview has been sent to the email address") && text.len() <= 500 {
        return Some("Interspire reported that the preview email was sent.".to_string());
    }
    if lower.contains("a preview couldn't be sent")
        || lower.contains("no preview email has been sent")
        || lower.contains("no email address was supplied")
    {
        return Some("Interspire reported that the preview email was not sent.".to_string());
    }
    (!text.is_empty()).then(|| truncate("[unrecognized Interspire preview response]", 400))
}

fn preview_send_response_success(html: &str) -> bool {
    let text = compact_text(
        &Html::parse_document(html)
            .root_element()
            .text()
            .collect::<Vec<_>>()
            .join(" "),
    );
    let lower = text.to_ascii_lowercase();
    lower.contains("a preview has been sent to the email address") && text.len() <= 500
}

fn campaign_test_send_digest(
    campaign_id: u64,
    recipient_email: &str,
    from_preview_email: &str,
    subject: &str,
    html_sha256: &str,
    text_sha256: Option<&str>,
    preheader_sha256: Option<&str>,
) -> String {
    let normalized = format!(
        "campaign_id={campaign_id}\nrecipient={}\nfrom={}\nsubject={subject}\nhtml_sha256={html_sha256}\ntext_sha256={}\npreheader_sha256={}\n",
        recipient_email.trim().to_ascii_lowercase(),
        from_preview_email.trim().to_ascii_lowercase(),
        text_sha256.unwrap_or("<empty>"),
        preheader_sha256.unwrap_or("<empty>"),
    );
    sha256_hex(&normalized)
}

fn optional_nonempty_sha256(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(sha256_hex)
}

#[cfg(test)]
fn campaign_body_audit_from_html(
    campaign_id: u64,
    html: &str,
) -> Result<CampaignBodyAuditReport, InterspireError> {
    campaign_body_audit_from_parts(campaign_id, campaign_body_parts_from_html(html)?)
}

#[derive(Debug, Clone, Default)]
struct CampaignBodyParts {
    name: Option<String>,
    subject: Option<String>,
    preheader: Option<String>,
    html_body: String,
    text_body: String,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedCampaignBodyHtml {
    pub(super) html: String,
    pub(super) used_step2: bool,
    pub(super) step1_name: Option<String>,
    pub(super) missing_step2: bool,
}

fn campaign_body_parts_from_html(html: &str) -> Result<CampaignBodyParts, InterspireError> {
    let fields = parse_form_values_exact(html)?;
    let html_body = first_present(
        &fields,
        &[
            "htmlbody",
            "htmlcontents",
            "mydeveditcontrol_html",
            "mydeveditcontrolhtml",
            "html_content",
            "htmlcontent",
        ],
    )
    .unwrap_or_default();
    let text_body = first_present(
        &fields,
        &[
            "textbody",
            "textcontents",
            "mydeveditcontrol_text",
            "mydeveditcontroltext",
            "text_content",
            "textcontent",
        ],
    )
    .unwrap_or_default();
    let name = first_present(&fields, &["name"]);
    let subject = first_present(&fields, &["subject"]);
    let preheader = first_present(&fields, &["preheader"]);
    Ok(CampaignBodyParts {
        name,
        subject,
        preheader,
        html_body,
        text_body,
    })
}

fn campaign_body_audit_from_parts(
    campaign_id: u64,
    parts: CampaignBodyParts,
) -> Result<CampaignBodyAuditReport, InterspireError> {
    let html_body = parts.html_body;
    let text_body = parts.text_body;
    let image_count = count_case_insensitive(&html_body, "<img");
    let missing_alt_image_count = count_missing_alt_images(&html_body)?;
    let html_unsubscribe_token_count = count_unsubscribe_tokens(&html_body);
    let text_unsubscribe_token_count = count_unsubscribe_tokens(&text_body);
    let unsubscribe_token_count = html_unsubscribe_token_count + text_unsubscribe_token_count;
    let mut warnings = Vec::new();
    if !unsubscribe_token_shape_ok(
        html_unsubscribe_token_count,
        text_unsubscribe_token_count,
        text_body.trim().is_empty(),
    ) {
        if text_body.trim().is_empty() {
            warnings.push(format!(
                "expected exactly one HTML unsubscribe token for HTML-only campaign, found {html_unsubscribe_token_count}"
            ));
        } else {
            warnings.push(format!(
                "expected exactly one unsubscribe token in each multipart alternative, found html={html_unsubscribe_token_count} text={text_unsubscribe_token_count}"
            ));
        }
    }
    let http_url_count = count_case_insensitive(&html_body, "http://");
    if http_url_count > 0 {
        warnings.push(format!(
            "campaign body contains {http_url_count} http:// URL(s)"
        ));
    }
    let visible_tracking_copy_detected = html_body.to_ascii_lowercase().contains("track the open");
    if visible_tracking_copy_detected {
        warnings.push("campaign body appears to contain visible tracking-copy text".to_string());
    }

    Ok(CampaignBodyAuditReport {
        ok: true,
        configured: true,
        campaign_id,
        name: parts
            .name
            .map(|value| redact::redact_sensitive_text(&value)),
        subject: parts
            .subject
            .map(|value| redact::redact_sensitive_text(&value)),
        preheader_sha256: parts
            .preheader
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(sha256_hex),
        html_sha256: (!html_body.is_empty()).then(|| sha256_hex(&html_body)),
        html_bytes: html_body.len(),
        text_sha256: (!text_body.is_empty()).then(|| sha256_hex(&text_body)),
        text_bytes: text_body.len(),
        unsubscribe_token_count,
        html_unsubscribe_token_count,
        text_unsubscribe_token_count,
        http_url_count,
        https_url_count: count_case_insensitive(&html_body, "https://"),
        mailto_count: count_case_insensitive(&html_body, "mailto:"),
        image_count,
        missing_alt_image_count,
        link_count: count_case_insensitive(&html_body, "<a "),
        visible_tracking_copy_detected,
        production_send_authorized: false,
        warnings,
        evidence: admin_evidence(vec![format!(
            "allowlisted Newsletter edit GET body audit for campaign {campaign_id}"
        )]),
    })
}

fn campaign_unsubscribe_token_shape_ok(report: &CampaignBodyAuditReport) -> bool {
    unsubscribe_token_shape_ok(
        report.html_unsubscribe_token_count,
        report.text_unsubscribe_token_count,
        report.text_bytes == 0,
    )
}

fn unsubscribe_token_shape_ok(html_count: usize, text_count: usize, text_is_empty: bool) -> bool {
    if text_is_empty {
        html_count == 1 && text_count == 0
    } else {
        html_count == 1 && text_count == 1
    }
}

fn write_private_text_artifact(
    kind: &str,
    path: &Path,
    contents: &str,
    label: &str,
) -> Result<RenderArtifact, InterspireError> {
    let mut file = private_artifacts::create_private_file(path, label)?;
    file.write_all(contents.as_bytes())
        .map_err(|err| InterspireError::Io(format!("failed to write private {label}: {err}")))?;
    file.flush()
        .map_err(|err| InterspireError::Io(format!("failed to flush private {label}: {err}")))?;
    private_artifacts::set_private_file_permissions(path)?;
    let bytes = contents.as_bytes();
    Ok(RenderArtifact {
        kind: kind.to_string(),
        path: path.display().to_string(),
        private: true,
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn render_preview_index(
    parts: &CampaignBodyParts,
    source_path: &Path,
    image_blocked_path: Option<&Path>,
) -> Result<String, InterspireError> {
    let source_file = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            InterspireError::Safety("source artifact filename is invalid".to_string())
        })?;
    let image_blocked_file = image_blocked_path
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str());
    let mut frames = String::new();
    for (label, width, file_name) in [
        ("Desktop 640", 640, source_file),
        ("Mobile 390", 390, source_file),
        ("Narrow 320", 320, source_file),
    ] {
        frames.push_str(&render_iframe(label, width, file_name));
    }
    if let Some(file_name) = image_blocked_file {
        frames.push_str(&render_iframe("Image blocked 390", 390, file_name));
    }
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <style>
    body {{ margin: 0; padding: 24px; background: #e6e8eb; color: #202124; font: 14px/1.45 Arial, Helvetica, sans-serif; }}
    h1 {{ font-size: 18px; margin: 0 0 4px; }}
    .meta {{ margin: 0 0 18px; color: #5f6368; }}
    .frame {{ margin: 0 0 28px; }}
    .frame h2 {{ font-size: 13px; font-weight: 700; margin: 0 0 8px; }}
    iframe {{ display: block; border: 1px solid #b8bec5; background: white; min-height: 900px; box-shadow: 0 1px 3px rgba(0,0,0,.12); }}
  </style>
</head>
<body>
  <h1>{}</h1>
  <p class="meta">Private Interspire render artifact. Use native browser screenshots for visual signoff.</p>
  {}
</body>
</html>
"#,
        html_escape(&redact::redact_sensitive_text(
            parts
                .subject
                .as_deref()
                .unwrap_or("Interspire campaign preview"),
        )),
        html_escape(&redact::redact_sensitive_text(
            parts
                .subject
                .as_deref()
                .unwrap_or("Interspire campaign preview"),
        )),
        frames
    ))
}

fn render_iframe(label: &str, width: u16, file_name: &str) -> String {
    format!(
        r#"<section class="frame">
  <h2>{}</h2>
  <iframe sandbox src="{}" style="width:{}px"></iframe>
</section>
"#,
        html_escape(label),
        html_escape(file_name),
        width
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn campaign_body_step2_action_path(
    campaign_id: u64,
    html: &str,
) -> Result<Option<String>, InterspireError> {
    let document = Html::parse_document(html);
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for form in document.select(&form_selector) {
        let Some(action) = form.value().attr("action") else {
            continue;
        };
        if safety::classify_allowed_campaign_body_step2_post(
            &form_action_url_for_parse(action)?,
            campaign_id,
        )
        .is_ok()
        {
            return Ok(Some(action.to_string()));
        }
    }
    Ok(None)
}

fn campaign_body_step1_pairs(
    campaign_id: u64,
    html: &str,
) -> Result<Vec<(String, String)>, InterspireError> {
    let document = Html::parse_document(html);
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for form in document.select(&form_selector) {
        let Some(action) = form.value().attr("action") else {
            continue;
        };
        if safety::classify_allowed_campaign_body_step2_post(
            &form_action_url_for_parse(action)?,
            campaign_id,
        )
        .is_err()
        {
            continue;
        }
        let pairs = controls_to_proof_post_pairs(&form);
        if pairs
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("name"))
            && pairs
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("format"))
        {
            return Ok(pairs);
        }
        return Err(InterspireError::HtmlParse(
            "campaign Step1 proof form did not include required Name and Format controls"
                .to_string(),
        ));
    }
    Err(InterspireError::HtmlParse(
        "campaign Step1 proof form was not found".to_string(),
    ))
}

fn controls_to_proof_post_pairs(form: &ElementRef<'_>) -> Vec<(String, String)> {
    forms::parse_form_controls(form)
        .into_iter()
        .filter_map(|control| match control.kind {
            forms::FormControlKind::Hidden => {
                Some((control.original_name.clone(), control.value.clone()))
            }
            forms::FormControlKind::Text
            | forms::FormControlKind::Textarea
            | forms::FormControlKind::Select => {
                Some((control.original_name.clone(), control.value.clone()))
            }
            forms::FormControlKind::Checkbox | forms::FormControlKind::Radio => control
                .checked
                .then(|| (control.original_name.clone(), control.value.clone())),
            forms::FormControlKind::Submit => {
                let lower_value = control.value.to_ascii_lowercase();
                let lower_name = control.lower_name.to_ascii_lowercase();
                (lower_name.contains("next") || lower_value.contains("next"))
                    .then(|| (control.original_name.clone(), control.value.clone()))
            }
            forms::FormControlKind::Password => None,
        })
        .collect()
}

fn guarded_send_final_form_post(
    base_url: &str,
    html: &str,
) -> Result<(Url, Vec<(String, String)>), InterspireError> {
    let document = Html::parse_document(html);
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for form in document.select(&form_selector) {
        let Some(action) = form.value().attr("action") else {
            continue;
        };
        let Ok(action_url) = safety::ensure_allowed_guarded_send_final_post(base_url, action)
        else {
            continue;
        };
        let mut pairs = controls_to_guarded_send_final_post_pairs(&form);
        append_csrf_pair_if_missing(&mut pairs, html);
        if pairs.is_empty() {
            return Err(InterspireError::HtmlParse(
                "guarded final send form did not expose postable controls".to_string(),
            ));
        }
        return Ok((action_url, pairs));
    }
    Err(InterspireError::HtmlParse(
        "guarded final send form was not found".to_string(),
    ))
}

fn guarded_send_form_token(
    pairs: &[(String, String)],
) -> Result<(String, String), InterspireError> {
    let tokens = pairs
        .iter()
        .filter(|(name, _)| is_csrf_field_name(name))
        .collect::<Vec<_>>();
    match tokens.as_slice() {
        [(name, value)] if !value.trim().is_empty() => Ok(((*name).clone(), (*value).clone())),
        [] | [_] => Err(InterspireError::Safety(
            "guarded final send form did not expose one authenticated form token; no final request was constructed or dispatched"
                .to_string(),
        )),
        _ => Err(InterspireError::Safety(
            "guarded final send form exposed duplicate form-token authority; no final request was constructed or dispatched"
                .to_string(),
        )),
    }
}

fn guarded_send_submission_sha256(send_form: &(Url, Vec<(String, String)>)) -> String {
    let mut digest = Sha256::new();
    digest.update(b"interspire-mcp:guarded-send-submission:v1\0");
    update_guarded_send_digest_field(&mut digest, send_form.0.as_str().as_bytes());
    update_guarded_send_digest_field(&mut digest, &(send_form.1.len() as u64).to_be_bytes());
    for (name, value) in &send_form.1 {
        update_guarded_send_digest_field(&mut digest, name.as_bytes());
        update_guarded_send_digest_field(&mut digest, value.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn guarded_send_exact_form_value_sha256(
    pairs: &[(String, String)],
    names: &[&str],
    normalize_email: bool,
) -> Option<String> {
    let mut matches = pairs.iter().filter(|(name, _)| {
        names
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected))
    });
    let value = matches.next()?.1.trim();
    if value.is_empty() || matches.next().is_some() {
        return None;
    }
    let value = if normalize_email {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    };
    Some(sha256_hex(&value))
}

fn update_guarded_send_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn guarded_send_authority_snapshot_refusal(
    snapshot: &GuardedSendAuthoritySnapshot,
    expectation: &GuardedSendAuthorityExpectation<'_>,
) -> Option<String> {
    let refuse = |field: &str| {
        Some(format!(
            "guarded send live {field} authority was absent, malformed, or did not match the exact approved request; no final request was constructed or dispatched"
        ))
    };
    if snapshot.send_wizard.selected_campaign_id != Some(expectation.campaign_id) {
        return refuse("campaign");
    }

    let mut expected_list_ids = expectation.list_ids.to_vec();
    expected_list_ids.sort_unstable();
    expected_list_ids.dedup();
    if expected_list_ids.len() != expectation.list_ids.len()
        || snapshot.identity.selected_list_ids.len() != snapshot.send_wizard.selected_list_ids.len()
        || snapshot.identity.selected_list_ids != expected_list_ids
    {
        return refuse("selected-list");
    }
    if snapshot.send_wizard.recipient_count != Some(expectation.expected_recipient_count) {
        return refuse("recipient-count");
    }
    if snapshot.identity.subject_sha256.is_none()
        || expectation.expected_subject.is_some_and(|expected| {
            snapshot.identity.subject_sha256.as_deref() != Some(sha256_hex(expected).as_str())
        })
    {
        return refuse("campaign-subject");
    }
    if snapshot.campaign_body.html_sha256.is_none()
        || expectation
            .expected_html_sha256
            .is_some_and(|expected| snapshot.campaign_body.html_sha256.as_deref() != Some(expected))
    {
        return refuse("campaign-body");
    }
    if snapshot.campaign_body.text_bytes > 0 && snapshot.campaign_body.text_sha256.is_none() {
        return refuse("campaign-text-body");
    }
    if snapshot.identity.from_name_sha256.is_none()
        || snapshot.identity.from_email_sha256.is_none()
        || snapshot.identity.reply_to_email_sha256.is_none()
        || snapshot.identity.bounce_email_sha256.is_none()
        || snapshot.send_wizard.from_name.is_none()
        || snapshot.send_wizard.from_email_redacted.is_none()
        || snapshot.send_wizard.reply_to_email_redacted.is_none()
        || snapshot.send_wizard.bounce_email_redacted.is_none()
    {
        return refuse("sender, reply-to, or bounce");
    }
    if expectation.expected_from_email.is_some_and(|expected| {
        snapshot.identity.from_email_sha256.as_deref()
            != Some(sha256_hex(&expected.trim().to_ascii_lowercase()).as_str())
    }) {
        return refuse("sender");
    }
    if expectation.expected_reply_to_email.is_some_and(|expected| {
        snapshot.identity.reply_to_email_sha256.as_deref()
            != Some(sha256_hex(&expected.trim().to_ascii_lowercase()).as_str())
    }) {
        return refuse("reply-to");
    }
    if snapshot.send_wizard.send_immediately_checked != Some(true)
        || snapshot.send_wizard.notify_owner_checked.is_none()
        || snapshot.send_wizard.track_opens_checked.is_none()
        || snapshot.send_wizard.track_links_checked.is_none()
        || snapshot.send_wizard.multipart_checked.is_none()
        || snapshot.send_wizard.embed_images_checked.is_none()
    {
        return refuse("final-wizard");
    }
    if !snapshot.send_wizard.ok
        || !snapshot.send_wizard.queue_unchanged
        || !snapshot.send_wizard.stats_unchanged
        || !snapshot.send_wizard.final_form_posts_to_send_boundary
        || snapshot.send_wizard.final_form_action_fingerprint.is_none()
    {
        return refuse("final-form action");
    }

    let campaign_values = snapshot
        .send_form
        .1
        .iter()
        .filter(|(name, _)| is_guarded_send_campaign_selection_name(name))
        .map(|(_, value)| value.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if campaign_values.as_slice() != [Some(expectation.campaign_id)] {
        return refuse("submitted campaign pair");
    }
    let mut list_values = snapshot
        .send_form
        .1
        .iter()
        .filter(|(name, _)| is_guarded_send_list_selection_name(name))
        .map(|(_, value)| value.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if list_values.iter().any(Option::is_none) {
        return refuse("submitted list pair");
    }
    let list_value_count = list_values.len();
    let mut list_values = list_values.drain(..).flatten().collect::<Vec<_>>();
    list_values.sort_unstable();
    list_values.dedup();
    if list_values.len() != list_value_count || list_values != expected_list_ids {
        return refuse("submitted list pair");
    }
    if guarded_send_form_token(&snapshot.send_form.1).is_err()
        || snapshot.identity.submission_sha256
            != guarded_send_submission_sha256(&snapshot.send_form)
    {
        return refuse("form-token or submitted-pair");
    }
    None
}

fn is_guarded_send_campaign_selection_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "newsletter"
            | "newsletterid"
            | "newsletter_id"
            | "newsletterchosen"
            | "campaign"
            | "campaignid"
            | "campaign_id"
    )
}

fn is_guarded_send_list_selection_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "lists[]"
            | "list[]"
            | "lists"
            | "list"
            | "listid"
            | "listids"
            | "mailinglist"
            | "mailinglistid"
    )
}

fn rows_changed_for_send_proof(before: &[String], after: &[String]) -> bool {
    !rows_unchanged_for_send_proof(before, after)
}

fn guarded_send_location_from_headers(
    base_url: &str,
    headers: &reqwest::header::HeaderMap,
) -> Result<Option<Url>, InterspireError> {
    let Some(value) = headers.get(reqwest::header::LOCATION) else {
        return Ok(None);
    };
    let location = value.to_str().map_err(|_| {
        InterspireError::Safety("guarded continuation was not valid text".to_string())
    })?;
    safety::ensure_allowed_guarded_send_popup(base_url, location).map(Some)
}

fn guarded_send_evidence_from_progress(
    input: &GuardedSendReconcileInput<'_>,
    mut progress: GuardedSendProgress,
    uncertainty_gap: Option<&str>,
) -> GuardedSendEvidence {
    if let Some(gap) = uncertainty_gap {
        progress.job_evidence.add_gap(gap);
        let note = if progress.response_uncertain {
            "request-response uncertainty was retained as a nonterminal reconciliation receipt"
                .to_string()
        } else {
            "post-boundary uncertainty was retained as a nonterminal reconciliation receipt"
                .to_string()
        };
        if !progress.notes.contains(&note) {
            progress.notes.push(note);
        }
    }
    let queue_after = progress
        .queue_after
        .as_deref()
        .unwrap_or(input.queue_before.as_slice());
    let stats_after = progress
        .stats_after
        .as_deref()
        .unwrap_or(input.stats_before.as_slice());
    let stats_identity_after = progress
        .stats_identity_after
        .as_ref()
        .unwrap_or(&input.stats_identity_before);
    let job_active_after = progress.job_evidence.job_id.map(|job_id| {
        progress
            .active_job_ids_after
            .as_ref()
            .is_none_or(|job_ids| job_ids.contains(&job_id))
    });
    let job_identity_ambiguous =
        progress.job_evidence.conflicted || progress.job_identity_ambiguous;
    let reconciliation = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
        campaign_id: input.campaign_id,
        list_ids: input.list_ids,
        expected_body_sha256: input.expected_body_sha256.clone(),
        queue_before: &input.queue_before,
        queue_after,
        stats_before: &input.stats_before,
        stats_after,
        schedule_job_ids_before: &input.schedule_job_ids_before,
        manage_job_ids_before: &input.manage_job_ids_before,
        campaign_job_ids_before: &input.campaign_job_ids_before,
        stats_identity_before: &input.stats_identity_before,
        stats_identity_after,
        expected_recipient_count: input.expected_recipient_count,
        baseline_max_rows: input.max_rows,
        baseline_context_verified: validate_guarded_send_baseline_context(input).is_ok(),
        baseline_identity_stable: input.baseline_identity_stable,
        baseline_capture_stage: input.baseline_context.capture_stage,
        job_id: progress.job_evidence.job_id,
        job_active_after,
        smtp_reason: progress.smtp_reason,
        popup_steps: progress.popup_steps,
        approved_cron_schedule: progress.approved_cron_schedule,
        response_uncertain: progress.response_uncertain,
        reconciliation_readback_complete: progress.reconciliation_readback_complete,
        job_identity_ambiguous,
        proof_gaps: progress.job_evidence.proof_gaps,
        notes: progress.notes,
    });

    GuardedSendEvidence {
        status_code: progress.status_code,
        redirected: progress.redirected,
        reconciliation,
    }
}

fn rows_unchanged_for_send_proof(before: &[String], after: &[String]) -> bool {
    stable_table_rows_for_send_proof(before) == stable_table_rows_for_send_proof(after)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableStatsIdentityDelta {
    added: usize,
    removed: usize,
}

fn stable_stats_identity_delta(before: &[String], after: &[String]) -> StableStatsIdentityDelta {
    let before_counts = stable_stats_identity_counts(before);
    let after_counts = stable_stats_identity_counts(after);
    let mut added = 0usize;
    let mut removed = 0usize;

    for (identity, before_count) in &before_counts {
        let after_count = after_counts.get(identity).copied().unwrap_or_default();
        removed += before_count.saturating_sub(after_count);
    }
    for (identity, after_count) in &after_counts {
        let before_count = before_counts.get(identity).copied().unwrap_or_default();
        added += after_count.saturating_sub(before_count);
    }

    StableStatsIdentityDelta { added, removed }
}

fn stable_stats_identity_counts(rows: &[String]) -> BTreeMap<String, usize> {
    stable_stats_row_identities_for_no_send_proof(&stable_table_rows_for_send_proof(rows))
        .into_iter()
        .fold(BTreeMap::new(), |mut counts, identity| {
            *counts.entry(identity).or_default() += 1;
            counts
        })
}

fn guarded_send_terminal_reconciliation(
    input: GuardedSendTerminalInput<'_>,
) -> SendReconciliationReport {
    let queue_changed = rows_changed_for_send_proof(input.queue_before, input.queue_after);
    let stats_content_changed = rows_changed_for_send_proof(input.stats_before, input.stats_after);
    let stats_identity_delta = stable_stats_identity_delta(input.stats_before, input.stats_after);
    let mut proof_gaps = input.proof_gaps;
    let mut notes = input.notes;
    match unique_added_stats_identity(input.stats_identity_before, input.stats_identity_after) {
        Ok(Some(row)) => {
            if row.recipients != input.expected_recipient_count {
                proof_gaps.push(format!(
                    "new Stats identity {} reported {} recipients instead of the expected {}",
                    row.stat_id, row.recipients, input.expected_recipient_count
                ));
            } else {
                notes.push(format!(
                    "new Stats identity {} matched the expected aggregate recipient count",
                    row.stat_id
                ));
            }
            proof_gaps.push(format!(
                "new Stats identity {} has no application-native association to the bound job; aggregate labels, counts, timing, and baseline position are nonterminal context only",
                row.stat_id
            ));
        }
        Ok(None) => {
            proof_gaps.push("no new durable Stats identity was observed".to_string());
        }
        Err((added, removed)) => {
            proof_gaps.push(format!(
                "durable Stats identity reconciliation was ambiguous: {added} added and {removed} removed"
            ));
        }
    }

    match stats_identity_delta {
        StableStatsIdentityDelta {
            added: 0,
            removed: 0,
        } if stats_content_changed => {
            proof_gaps.push(
                "existing Stats row text changed, but stable Stats identities were unchanged"
                    .to_string(),
            );
            notes.push(
                "mutable Stats labels, encoding, and counters are not terminal send proof"
                    .to_string(),
            );
        }
        StableStatsIdentityDelta {
            added: 0,
            removed: 0,
        } => {}
        StableStatsIdentityDelta {
            added: 1,
            removed: 0,
        } => {
            notes.push("one new stable Stats row shape was observed".to_string());
        }
        StableStatsIdentityDelta { added, removed } => {
            notes.push(format!(
                "Stats row-shape reconciliation changed: {added} added and {removed} removed"
            ));
        }
    }

    if input.job_id.is_none() {
        proof_gaps
            .push("Interspire job id was not found in redacted send-loop evidence".to_string());
    }
    if queue_changed {
        notes.push("Schedule rows changed after guarded send loop".to_string());
        if input.job_id.is_none() {
            proof_gaps
                .push("Schedule movement was observed without a durable job identity".to_string());
        }
    }
    if input.popup_steps > 0 {
        notes.push(
            "popup progress is execution evidence only and does not prove terminal processing"
                .to_string(),
        );
    }
    if input.approved_cron_schedule {
        notes.push(
            "Cron schedule approval was followed; terminal job and Stats proof remains separate"
                .to_string(),
        );
        if input.job_id.is_none() {
            proof_gaps.push(
                "Cron schedule approval was followed but the approved job id was not extracted"
                    .to_string(),
            );
        }
    }
    match input.job_active_after {
        Some(true) => proof_gaps.push(
            "the bound job still exposed an active Schedule or campaign Manage action".to_string(),
        ),
        None if input.job_id.is_some() => proof_gaps
            .push("post-send Schedule and campaign Manage absence was not proven".to_string()),
        Some(false) | None => {}
    }

    let status = if input.response_uncertain {
        SendApplyStatus::ResponseUncertain
    } else if input.smtp_reason.is_some() {
        SendApplyStatus::TransportFailed
    } else if input.job_id.is_some() {
        SendApplyStatus::Queued
    } else {
        SendApplyStatus::Posted
    };
    match status {
        SendApplyStatus::ResponseUncertain => {
            proof_gaps.push(
                "the final request was attempted, but no HTTP response proved whether the application received it"
                    .to_string(),
            );
            proof_gaps.push(
                "retry or resend is not authorized while request-response uncertainty remains"
                    .to_string(),
            );
        }
        SendApplyStatus::Posted => proof_gaps.push(
            "final send boundary was posted without complete durable application proof".to_string(),
        ),
        _ => {}
    }

    let status_follow_up = input.job_id.map(|job_id| {
        SendJobFollowUpContract::new(
            job_id,
            input.campaign_id,
            input.list_ids.to_vec(),
            input.expected_recipient_count,
            input.expected_body_sha256.clone(),
        )
        .with_stats_baseline(input.stats_identity_before.ids().into_iter().collect())
    });
    let follow_up_contract = if matches!(status, SendApplyStatus::Queued) {
        status_follow_up.clone()
    } else {
        None
    };
    let uncertainty_recovery_contract = if matches!(status, SendApplyStatus::ResponseUncertain) {
        let identity_state = if !input.reconciliation_readback_complete {
            SendUncertaintyIdentityState::ReadbackIncomplete
        } else if input.job_identity_ambiguous || input.job_id.is_some() {
            SendUncertaintyIdentityState::AmbiguousOrUnbound
        } else {
            SendUncertaintyIdentityState::NoNewJob
        };
        Some(SendUncertaintyRecoveryContract::hold(
            input.campaign_id,
            input.list_ids.to_vec(),
            input.expected_recipient_count,
            input.expected_body_sha256.clone(),
            input.schedule_job_ids_before.iter().copied().collect(),
            input.manage_job_ids_before.iter().copied().collect(),
            input.campaign_job_ids_before.iter().copied().collect(),
            input.stats_identity_before.ids().into_iter().collect(),
            input.baseline_max_rows,
            input.baseline_capture_stage,
            input.baseline_context_verified,
            input.baseline_identity_stable,
            true,
            input.reconciliation_readback_complete,
            identity_state,
        ))
    } else {
        None
    };

    SendReconciliationReport::new(
        status,
        if matches!(status, SendApplyStatus::ResponseUncertain) {
            None
        } else {
            input.job_id
        },
        None,
        None,
        None,
        None,
        None,
        input.smtp_reason,
        input.popup_steps,
        input.queue_before.len(),
        input.queue_after.len(),
        input.stats_before.len(),
        input.stats_after.len(),
        proof_gaps,
        notes,
    )
    .with_follow_up_contract(follow_up_contract)
    .with_uncertainty_recovery_contract(uncertainty_recovery_contract)
}

fn stats_rows_stable_for_no_send_proof(before: &[String], after: &[String]) -> bool {
    let before_stable = stable_table_rows_for_send_proof(before);
    let after_stable = stable_table_rows_for_send_proof(after);
    before_stable == after_stable
        || stable_stats_row_identities_for_no_send_proof(&before_stable)
            == stable_stats_row_identities_for_no_send_proof(&after_stable)
}

fn stable_stats_row_identities_for_no_send_proof(rows: &[String]) -> Vec<String> {
    rows.iter()
        .map(|row| stable_stats_row_identity_for_no_send_proof(row))
        .collect()
}

fn stable_stats_row_identity_for_no_send_proof(row: &str) -> String {
    let compact = compact_text(row);
    stats_row_datetime_recipient_identity(&compact).unwrap_or_else(|| {
        compact
            .find('\'')
            .map(|idx| compact_text(&compact[idx..]))
            .unwrap_or(compact)
    })
}

fn stats_row_datetime_recipient_identity(row: &str) -> Option<String> {
    let tokens: Vec<&str> = row.split_whitespace().collect();
    let date_starts: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(idx, _)| stats_date_token_span(&tokens, idx).map(|_| idx))
        .collect();
    if date_starts.len() < 2 {
        return None;
    }
    // Campaign and list labels may contain human-readable dates. The Stats
    // table's stable row identity is anchored at the final Started/Finished
    // timestamp pair, followed by the recipient count.
    let first = date_starts[date_starts.len() - 2];
    let second = date_starts[date_starts.len() - 1];
    let recipient_idx = second.checked_add(5)?;
    let recipients = tokens.get(recipient_idx)?.trim_matches(',');
    if !is_stat_count_token(recipients) {
        return None;
    }
    Some(format!(
        "stat:{}|{}|{}",
        tokens[first..first + 5].join(" "),
        tokens[second..second + 5].join(" "),
        recipients
    ))
}

fn stats_date_token_span(tokens: &[&str], start: usize) -> Option<()> {
    let month = tokens.get(start)?;
    let day = tokens.get(start + 1)?.trim_end_matches(',');
    let year = tokens.get(start + 2)?.trim_end_matches(',');
    let time = tokens.get(start + 3)?;
    let meridiem = tokens.get(start + 4)?.to_ascii_lowercase();
    if !is_month_name(month)
        || !day.chars().all(|ch| ch.is_ascii_digit())
        || day.is_empty()
        || year.len() != 4
        || !year.chars().all(|ch| ch.is_ascii_digit())
        || !time.contains(':')
        || !(meridiem == "am" || meridiem == "pm")
    {
        return None;
    }
    Some(())
}

fn is_month_name(value: &str) -> bool {
    matches!(
        value,
        "January"
            | "February"
            | "March"
            | "April"
            | "May"
            | "June"
            | "July"
            | "August"
            | "September"
            | "October"
            | "November"
            | "December"
    )
}

fn is_stat_count_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|ch| ch.is_ascii_digit() || ch == ',')
        && value.chars().any(|ch| ch.is_ascii_digit())
}

fn stable_table_rows_for_send_proof(rows: &[String]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| stable_table_row_for_send_proof(row))
        .collect()
}

fn stable_table_row_for_send_proof(row: &str) -> Option<String> {
    let compact = compact_text(row);
    let lower = compact.to_ascii_lowercase();
    if lower.contains("updatecrontimer(")
        || lower.starts_with("view scheduled email queue")
        || lower.starts_with("any emails you have scheduled")
        || lower.starts_with("email campaign statistics")
        || lower.starts_with("email campaign name chevron")
        || lower.starts_with("choose an action delete export print results per page")
        || lower.starts_with("results per page:")
    {
        return None;
    }
    Some(compact)
}

fn guarded_send_popup_url(base_url: &str, html: &str) -> Result<Option<Url>, InterspireError> {
    for candidate in send_popup_path_candidates(html) {
        if let Ok(url) = safety::ensure_allowed_guarded_send_popup(base_url, &candidate) {
            return Ok(Some(url));
        }
    }
    Ok(None)
}

fn guarded_schedule_approval_url(
    base_url: &str,
    html: &str,
) -> Result<Option<Url>, InterspireError> {
    for candidate in schedule_approval_path_candidates(html) {
        if let Ok(url) = safety::ensure_allowed_guarded_schedule_approval(base_url, &candidate) {
            return Ok(Some(url));
        }
    }
    Ok(None)
}

fn schedule_approval_path_candidates(html: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let lower = html.to_ascii_lowercase();
    let needles = [
        "index.php?page=schedule&a=1",
        "index.php?page=schedule&amp;a=1",
    ];
    for needle in needles {
        let mut offset = 0usize;
        while let Some(relative) = lower[offset..].find(needle) {
            let start = offset + relative;
            let raw_tail = &html[start..];
            let end = raw_tail
                .find(|ch: char| matches!(ch, '"' | '\'' | '<' | '>' | ')') || ch.is_whitespace())
                .unwrap_or(raw_tail.len());
            candidates.push(raw_tail[..end].replace("&amp;", "&"));
            offset = start + end.max(1);
        }
    }
    candidates
}

fn send_popup_path_candidates(html: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let document = Html::parse_document(html);
    if let Ok(link_selector) = Selector::parse("a") {
        for link in document.select(&link_selector) {
            if let Some(href) = link.value().attr("href") {
                if href.to_ascii_lowercase().contains("page=send")
                    && href.to_ascii_lowercase().contains("action=send")
                {
                    candidates.push(href.to_string());
                }
            }
        }
    }
    if let Ok(form_selector) = Selector::parse("form") {
        for form in document.select(&form_selector) {
            if let Some(action) = form.value().attr("action") {
                if action.to_ascii_lowercase().contains("page=send")
                    && action.to_ascii_lowercase().contains("action=send")
                {
                    candidates.push(action.to_string());
                }
            }
        }
    }

    let lower = html.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(relative) = lower[offset..].find("index.php?page=send&action=send") {
        let start = offset + relative;
        let raw_tail = &html[start..];
        let end = raw_tail
            .find(|ch: char| matches!(ch, '"' | '\'' | '<' | '>' | ')' | ';') || ch.is_whitespace())
            .unwrap_or(raw_tail.len());
        candidates.push(raw_tail[..end].replace("&amp;", "&"));
        offset = start + end.max(1);
    }

    candidates
}

fn queue_job_identity_delta(
    before: &BTreeSet<u64>,
    after: &BTreeSet<u64>,
) -> QueueJobIdentityDelta {
    let added = after.difference(before).copied().collect::<Vec<_>>();
    let removed = before.difference(after).count();
    match (added.as_slice(), removed) {
        ([], 0) => QueueJobIdentityDelta::None,
        ([job_id], 0) => QueueJobIdentityDelta::Unique(*job_id),
        _ => QueueJobIdentityDelta::Ambiguous {
            added: added.len(),
            removed,
        },
    }
}

fn queue_job_ids_for_source(
    links: &[super::QueueControlLink],
    source: crate::response::QueueControlSource,
) -> BTreeSet<u64> {
    links
        .iter()
        .filter(|link| link.candidate.source == source)
        .map(|link| link.route.identifier_value)
        .collect()
}

fn queue_manage_job_ids_for_campaign(
    links: &[super::QueueControlLink],
    campaign_id: u64,
) -> BTreeSet<u64> {
    links
        .iter()
        .filter(|link| {
            link.candidate.source == crate::response::QueueControlSource::CampaignManage
                && link.candidate.campaign_id == Some(campaign_id)
        })
        .map(|link| link.route.identifier_value)
        .collect()
}

fn validate_guarded_send_baseline_context(
    input: &GuardedSendReconcileInput<'_>,
) -> Result<(), InterspireError> {
    if !input.atomic_authority_binding.validates(&input.send_form) {
        return Err(InterspireError::Safety(
            "guarded send atomic live authority no longer bound the exact final submission; no final request was constructed or dispatched"
                .to_string(),
        ));
    }
    let expected = GuardedSendBaselineContext {
        campaign_id: input.campaign_id,
        list_ids: input.list_ids.to_vec(),
        expected_body_sha256: input.expected_body_sha256.clone(),
        expected_recipient_count: input.expected_recipient_count,
        max_rows: input.max_rows,
        authority_submission_sha256: input.atomic_authority_binding.submission_sha256.clone(),
        authority_state_version: input.atomic_authority_binding.state_version.clone(),
        capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
    };
    if input.baseline_context != expected || !input.baseline_identity_stable {
        return Err(InterspireError::Safety(
            "guarded send final pre-dispatch baseline context or freshness did not match the exact request; no final request was dispatched"
                .to_string(),
        ));
    }
    Ok(())
}

fn send_popup_job_id(url: &Url) -> Option<u64> {
    safety::guarded_send_popup_job_id(url).ok()
}

fn seed_send_apply_warnings(reconciliation: &SendReconciliationReport) -> Vec<String> {
    send_apply_warnings(
        reconciliation,
        "seed send",
        "provider delivery and recipient render still require external readback",
    )
}

fn production_send_apply_warnings(reconciliation: &SendReconciliationReport) -> Vec<String> {
    send_apply_warnings(
        reconciliation,
        "production send",
        "provider delivery, bounce rate, and recipient engagement require external monitoring",
    )
}

fn send_apply_preflight_refusal_warnings(
    label: &str,
    ready_for_seed_approval: bool,
    actual_subject: Option<&str>,
    expected_subject: Option<&str>,
    actual_html_sha256: Option<&str>,
    expected_html_sha256: Option<&str>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !ready_for_seed_approval {
        warnings.push(format!(
            "{label} send refused because readiness gates did not pass"
        ));
    }
    if let Some(expected_subject) = expected_subject {
        if actual_subject != Some(expected_subject) {
            warnings.push(format!(
                "{label} send refused because campaign subject did not match expected_subject"
            ));
        }
    }
    if let Some(expected_html_sha256) = expected_html_sha256 {
        if actual_html_sha256 != Some(expected_html_sha256) {
            warnings.push(format!(
                "{label} send refused because campaign HTML SHA-256 did not match expected_html_sha256"
            ));
        }
    }
    warnings
}

fn send_apply_warnings(
    reconciliation: &SendReconciliationReport,
    label: &str,
    external_monitoring_warning: &str,
) -> Vec<String> {
    let mut warnings = match reconciliation.status {
        SendApplyStatus::ResponseUncertain => vec![format!(
            "{label} final request was attempted, but no HTTP response proved whether the application received it; reconciliation remains response-uncertain, so HOLD and do not retry or resend, and use only the returned bounded read-only uncertainty recovery contract"
        )],
        SendApplyStatus::Posted => vec![format!(
            "{label} final boundary was posted, but durable application identity and terminal state were not proven; observed execution or readback signals remain nonterminal"
        )],
        SendApplyStatus::Queued => vec![format!(
            "{label} has a durable job identity, but the bounded admin surface exposes no application-native job-to-Stats association; the returned follow-up contract remains nonterminal readback context"
        )],
        SendApplyStatus::TransportFailed => vec![format!(
            "{label} reached the guarded Interspire send loop but Interspire reported a transport failure"
        )],
        SendApplyStatus::Processed
        | SendApplyStatus::DeliveredUnverified
        | SendApplyStatus::SeedProven => {
            vec![
                format!("{label} final form was posted after immediate readiness proof and reconciled through the Interspire send loop"),
                external_monitoring_warning.to_string(),
            ]
        }
        SendApplyStatus::Refused => vec![format!(
            "{label} was refused before the Interspire final send boundary"
        )],
    };
    if reconciliation.status.terminal_success() && !reconciliation.terminal_application_proven() {
        warnings.push(format!(
            "{label} is not marked sent because durable job and Stats identities were not both proven"
        ));
    }
    warnings
}

fn guarded_send_boundary_evidence_note(status: SendApplyStatus, route_label: &str) -> String {
    match status {
        SendApplyStatus::Refused => {
            format!("no final send form request was attempted on the guarded {route_label} route")
        }
        SendApplyStatus::ResponseUncertain => format!(
            "the final send form request was attempted on the guarded {route_label} route, but no HTTP response proved whether the application received it; hold and do not retry or resend"
        ),
        _ => format!(
            "final send form controls were captured from the live Interspire page and posted to the guarded {route_label} route"
        ),
    }
}

fn transport_failure_reason(html: &str) -> Option<String> {
    let text = compact_text(
        &Html::parse_document(html)
            .root_element()
            .text()
            .collect::<Vec<_>>()
            .join(" "),
    );
    let lower = text.to_ascii_lowercase();
    let markers = [
        "smtp error",
        "smtp failed",
        "authentication failed",
        "unable to send",
        "could not send",
        "send failed",
        "failed to send",
        "transport failed",
        "error sending",
    ];
    if markers.iter().any(|marker| lower.contains(marker)) {
        return Some(truncate(&redact::redact_sensitive_text(&text), 240));
    }
    None
}

fn step4_response_summary(html: &str) -> Option<String> {
    let text = compact_text(
        &Html::parse_document(html)
            .root_element()
            .text()
            .collect::<Vec<_>>()
            .join(" "),
    );
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let branch = if lower.contains("access denied") || lower.contains("permission denied") {
        "access_denied"
    } else if lower.contains("choose") && lower.contains("campaign") {
        "choose_campaign"
    } else if lower.contains("cannot send") && lower.contains("past") {
        "cannot_send_in_past"
    } else if lower.contains("not allowed to send")
        || lower.contains("send limit")
        || lower.contains("sending limit")
        || lower.contains("maximum")
    {
        "send_limit_or_validation"
    } else if lower.contains("scheduled") || lower.contains("total recipients") {
        "cron_confirmation_or_send_summary"
    } else {
        "unclassified"
    };
    let excerpt = truncate(&redact::redact_sensitive_text(&text), 240);
    Some(format!("{branch}; excerpt={excerpt}"))
}

fn controls_to_guarded_send_final_post_pairs(form: &ElementRef<'_>) -> Vec<(String, String)> {
    let mut submit_pair = None;
    let mut pairs = Vec::new();
    for control in forms::parse_form_controls(form) {
        match control.kind {
            forms::FormControlKind::Hidden
            | forms::FormControlKind::Text
            | forms::FormControlKind::Textarea
            | forms::FormControlKind::Select => {
                pairs.push((control.original_name.clone(), control.value.clone()));
            }
            forms::FormControlKind::Checkbox | forms::FormControlKind::Radio => {
                if control.checked {
                    pairs.push((control.original_name.clone(), control.value.clone()));
                }
            }
            forms::FormControlKind::Submit => {
                let lower_name = control.lower_name.to_ascii_lowercase();
                let lower_value = control.value.to_ascii_lowercase();
                let looks_like_send = (lower_name.contains("send")
                    || lower_value.contains("send")
                    || lower_value.contains("finish"))
                    && !lower_name.contains("schedule")
                    && !lower_value.contains("schedule");
                if looks_like_send && submit_pair.is_none() {
                    submit_pair = Some((control.original_name.clone(), control.value.clone()));
                }
            }
            forms::FormControlKind::Password => {}
        }
    }
    if let Some(pair) = submit_pair {
        pairs.push(pair);
    }
    pairs
}

fn form_action_url_for_parse(action: &str) -> Result<Url, InterspireError> {
    Url::parse("https://example.test/admin/")
        .unwrap_or_else(|err| panic!("static URL should parse: {err}"))
        .join(action)
        .map_err(|err| InterspireError::HtmlParse(format!("invalid form action: {err}")))
}

fn send_step2_action_path(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form").ok()?;
    for form in document.select(&form_selector) {
        let action = form.value().attr("action")?;
        if action.contains("Page=Send") && action.contains("Action=Step2") {
            return Some(action.to_string());
        }
    }
    None
}

fn send_start_hidden_pairs(html: &str) -> Result<Vec<(String, String)>, InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let pairs = document
        .select(&input_selector)
        .filter(|input| {
            input
                .value()
                .attr("type")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("hidden"))
        })
        .filter_map(|input| {
            let name = input.value().attr("name")?;
            if !is_safe_send_start_hidden(name) {
                return None;
            }
            Some((
                name.to_string(),
                input.value().attr("value").unwrap_or_default().to_string(),
            ))
        })
        .collect();
    Ok(pairs)
}

fn append_csrf_pair_if_missing(pairs: &mut Vec<(String, String)>, html: &str) {
    if csrf_pair(pairs).is_some() {
        return;
    }
    if let Some(token) = extract_login_csrf_token(html) {
        pairs.push((token.field_name, token.value));
    }
}

fn csrf_pair(pairs: &[(String, String)]) -> Option<(String, String)> {
    pairs
        .iter()
        .find(|(name, value)| is_csrf_field_name(name) && !value.trim().is_empty())
        .map(|(name, value)| (name.clone(), value.clone()))
}

fn is_csrf_field_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "csrf" | "csrftoken" | "csrf_token" | "token" | "_token" | "form_token" | "iem_csrf_token"
    )
}

fn admin_origin(base_url: &str) -> Result<String, InterspireError> {
    let url = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| InterspireError::Safety("admin base url has no host".to_string()))?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn upsert_post_pair(pairs: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, existing)) = pairs
        .iter_mut()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
    {
        *existing = value.to_string();
    } else {
        pairs.push((name.to_string(), value.to_string()));
    }
}

fn is_safe_send_start_hidden(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "csrf"
            | "csrftoken"
            | "csrf_token"
            | "token"
            | "_token"
            | "iem_csrf_token"
            | "showfilteringoptions"
    )
}

fn parse_send_wizard_final_page(
    campaign_id: u64,
    requested_list_ids: &[u64],
    html: &str,
) -> Result<SendWizardReadbackReport, InterspireError> {
    let fields = parse_form_values_exact(html)?;
    let selected_campaign = selected_option(html, "newsletter")?;
    let requested_campaign = option_by_value(html, "newsletter", campaign_id)?;
    let requested_campaign_available = requested_campaign.is_some()
        || selected_campaign
            .as_ref()
            .and_then(|option| option.value.parse::<u64>().ok())
            == Some(campaign_id);
    let campaign_label = selected_campaign
        .as_ref()
        .filter(|option| option.value.parse::<u64>().ok() == Some(campaign_id))
        .or(requested_campaign.as_ref())
        .map(|option| redact::redact_sensitive_text(&option.label));
    let final_form_action = match first_form_action(html, "frmSend")? {
        Some(action) => Some(action),
        None => first_send_form_action(html)?,
    };
    let final_form_posts_to_send_boundary = final_form_action
        .as_deref()
        .is_some_and(is_send_boundary_action);
    let selected_list_ids = selected_or_hidden_list_ids(html)?.unwrap_or_default();
    let recipient_count = recipient_count_marker(html);
    let mut warnings = Vec::new();
    if !final_form_posts_to_send_boundary {
        warnings.push(
            "final send wizard form action was not classified as a send boundary".to_string(),
        );
    }
    if selected_list_ids.is_empty() {
        warnings.push("final send wizard page did not expose selected list ids".to_string());
    }

    Ok(SendWizardReadbackReport {
        ok: false,
        configured: true,
        campaign_id,
        requested_list_ids: requested_list_ids.to_vec(),
        selected_list_ids,
        selected_campaign_id: selected_campaign
            .as_ref()
            .and_then(|option| option.value.parse().ok()),
        requested_campaign_available,
        requested_list_ids_proven_by_recipient_count: false,
        campaign_label,
        recipient_count,
        from_name: value_for(&fields, &["sendfromname", "fromname"])
            .map(|value| redact::redact_sensitive_text(&value)),
        from_email_redacted: value_for(&fields, &["sendfromemail", "fromemail"])
            .and_then(|value| redact_field_value("sendfromemail", &value)),
        reply_to_email_redacted: value_for(&fields, &["replytoemail"])
            .and_then(|value| redact_field_value("replytoemail", &value)),
        bounce_email_redacted: value_for(&fields, &["bounceemail"])
            .and_then(|value| redact_field_value("bounceemail", &value)),
        send_immediately_checked: checkbox_checked(html, "sendimmediately")?,
        notify_owner_checked: checkbox_checked(html, "notifyowner")?,
        track_opens_checked: checkbox_checked(html, "trackopens")?,
        track_links_checked: checkbox_checked(html, "tracklinks")?,
        multipart_checked: checkbox_checked(html, "sendmultipart")?,
        embed_images_checked: checkbox_checked(html, "embedimages")?,
        final_form_action_fingerprint: final_form_action
            .as_deref()
            .map(|action| route_fingerprint(&route_key_for_action(action))),
        final_form_posts_to_send_boundary,
        queue_rows_before: 0,
        queue_rows_after: 0,
        stats_rows_before: 0,
        stats_rows_after: 0,
        queue_unchanged: false,
        stats_unchanged: false,
        send_performed: false,
        scheduled: false,
        production_send_authorized: false,
        warnings,
        evidence: admin_evidence(vec![
            "allowlisted Send start GET read".to_string(),
            "final editable send wizard form parsed without posting".to_string(),
        ]),
    })
}

#[derive(Debug, Clone)]
struct SelectOption {
    value: String,
    label: String,
}

fn selected_option(html: &str, select_name: &str) -> Result<Option<SelectOption>, InterspireError> {
    let document = Html::parse_document(html);
    let select_selector =
        Selector::parse("select").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let option_selector =
        Selector::parse("option").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for select in document.select(&select_selector) {
        if !select
            .value()
            .attr("name")
            .is_some_and(|name| name.eq_ignore_ascii_case(select_name))
        {
            continue;
        }
        let selected = select
            .select(&option_selector)
            .find(|option| option.value().attr("selected").is_some());
        return Ok(selected.map(|option| SelectOption {
            value: option.value().attr("value").unwrap_or_default().to_string(),
            label: compact_text(&option.text().collect::<Vec<_>>().join(" ")),
        }));
    }
    Ok(None)
}

fn option_by_value(
    html: &str,
    select_name: &str,
    expected_value: u64,
) -> Result<Option<SelectOption>, InterspireError> {
    let document = Html::parse_document(html);
    let select_selector =
        Selector::parse("select").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let option_selector =
        Selector::parse("option").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let expected = expected_value.to_string();
    for select in document.select(&select_selector) {
        if !select
            .value()
            .attr("name")
            .is_some_and(|name| name.eq_ignore_ascii_case(select_name))
        {
            continue;
        }
        let matching = select
            .select(&option_selector)
            .find(|option| option.value().attr("value") == Some(expected.as_str()));
        return Ok(matching.map(|option| SelectOption {
            value: option.value().attr("value").unwrap_or_default().to_string(),
            label: compact_text(&option.text().collect::<Vec<_>>().join(" ")),
        }));
    }
    Ok(None)
}

fn parse_form_values_exact(html: &str) -> Result<Vec<(String, String)>, InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let textarea_selector =
        Selector::parse("textarea").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut fields = Vec::new();
    for input in document.select(&input_selector) {
        let Some(name) = input.value().attr("name") else {
            continue;
        };
        let kind = input.value().attr("type").unwrap_or("text");
        if matches!(kind, "password" | "submit" | "button" | "image" | "reset") {
            continue;
        }
        if matches!(kind, "checkbox" | "radio") && input.value().attr("checked").is_none() {
            continue;
        }
        fields.push((
            name.to_ascii_lowercase(),
            input.value().attr("value").unwrap_or_default().to_string(),
        ));
    }
    for textarea in document.select(&textarea_selector) {
        let Some(name) = textarea.value().attr("name") else {
            continue;
        };
        fields.push((
            name.to_ascii_lowercase(),
            textarea.text().collect::<String>(),
        ));
    }
    Ok(fields)
}

fn value_for(fields: &[(String, String)], names: &[&str]) -> Option<String> {
    let names = names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    fields
        .iter()
        .find(|(name, _)| names.iter().any(|wanted| wanted == name))
        .map(|(_, value)| value.clone())
        .filter(|value| !value.trim().is_empty())
}

fn first_present(fields: &[(String, String)], names: &[&str]) -> Option<String> {
    value_for(fields, names)
}

fn checkbox_checked(html: &str, name: &str) -> Result<Option<bool>, InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for input in document.select(&input_selector) {
        if input
            .value()
            .attr("name")
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        {
            return Ok(Some(input.value().attr("checked").is_some()));
        }
    }
    Ok(None)
}

fn selected_or_hidden_list_ids(html: &str) -> Result<Option<Vec<u64>>, InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut ids = Vec::new();
    for input in document.select(&input_selector) {
        let Some(name) = input.value().attr("name") else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !matches!(lower.as_str(), "lists[]" | "list[]" | "lists" | "listid") {
            continue;
        }
        let kind = input.value().attr("type").unwrap_or("text");
        if matches!(kind, "checkbox" | "radio") && input.value().attr("checked").is_none() {
            continue;
        }
        if let Some(id) = input
            .value()
            .attr("value")
            .and_then(|value| value.trim().parse::<u64>().ok())
        {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    if ids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ids))
    }
}

fn ids_match(left: &[u64], right: &[u64]) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    left.dedup();
    right.sort_unstable();
    right.dedup();
    left == right
}

fn first_form_action(html: &str, form_name: &str) -> Result<Option<String>, InterspireError> {
    let document = Html::parse_document(html);
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for form in document.select(&form_selector) {
        if form
            .value()
            .attr("name")
            .is_some_and(|name| name.eq_ignore_ascii_case(form_name))
        {
            return Ok(form.value().attr("action").map(ToString::to_string));
        }
    }
    Ok(None)
}

fn first_send_form_action(html: &str) -> Result<Option<String>, InterspireError> {
    let document = Html::parse_document(html);
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for form in document.select(&form_selector) {
        let Some(action) = form.value().attr("action") else {
            continue;
        };
        if is_send_boundary_action(action) {
            return Ok(Some(action.to_string()));
        }
    }
    Ok(None)
}

fn is_send_boundary_action(action: &str) -> bool {
    let lower = action.to_ascii_lowercase();
    lower.contains("page=send")
        && !lower.contains("action=step2")
        && (lower.contains("action=step3")
            || lower.contains("action=step4")
            || lower.contains("action=send")
            || lower.contains("action=schedule"))
}

fn route_key_for_action(action: &str) -> String {
    action.split('#').next().unwrap_or(action).to_string()
}

fn recipient_count_marker(html: &str) -> Option<u64> {
    let text = compact_text(
        &Html::parse_document(html)
            .root_element()
            .text()
            .collect::<Vec<_>>()
            .join(" "),
    );
    let lower = text.to_ascii_lowercase();
    for marker in ["contact", "recipient", "subscriber"] {
        for (pos, _) in lower.match_indices(marker) {
            let before = &text[..pos];
            let digits = before
                .chars()
                .rev()
                .skip_while(|ch| ch.is_whitespace())
                .take_while(|ch| ch.is_ascii_digit() || *ch == ',')
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
                .replace(',', "");
            if let Ok(value) = digits.parse::<u64>() {
                return Some(value);
            }
        }
    }
    None
}

fn count_unsubscribe_tokens(input: &str) -> usize {
    let lower = input.to_ascii_lowercase();
    ["%%unsubscribelink%%", "%basic:unsublink%"]
        .iter()
        .map(|token| lower.matches(token).count())
        .sum()
}

fn count_case_insensitive(input: &str, needle: &str) -> usize {
    input
        .to_ascii_lowercase()
        .matches(&needle.to_ascii_lowercase())
        .count()
}

fn count_missing_alt_images(html: &str) -> Result<usize, InterspireError> {
    let document = Html::parse_fragment(html);
    let img_selector =
        Selector::parse("img").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    Ok(document
        .select(&img_selector)
        .filter(|image| {
            image
                .value()
                .attr("alt")
                .is_none_or(|alt| alt.trim().is_empty())
        })
        .count())
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::super::stats_identity::{StatsIdentityInventory, StatsRowIdentity};
    use super::{
        append_csrf_pair_if_missing, campaign_body_audit_from_html, campaign_body_parts_from_html,
        campaign_body_step1_pairs, campaign_body_step2_action_path, campaign_test_send_digest,
        campaign_test_send_has_applyable_html, campaign_test_send_report, csrf_pair,
        expected_public_subject_matches, guarded_schedule_approval_url,
        guarded_send_boundary_evidence_note, guarded_send_evidence_from_progress,
        guarded_send_exact_form_value_sha256, guarded_send_final_form_post,
        guarded_send_form_token, guarded_send_popup_url, guarded_send_terminal_reconciliation,
        is_guarded_send_list_selection_name, list_ids_warning, optional_nonempty_sha256,
        parse_send_wizard_final_page, preview_send_response_success, queue_job_identity_delta,
        recipient_count_marker, rows_changed_for_send_proof, rows_unchanged_for_send_proof,
        seed_send_apply_warnings, selected_or_hidden_list_ids,
        send_apply_preflight_refusal_warnings, send_step2_action_path, sha256_hex,
        stable_stats_identity_delta, stats_rows_stable_for_no_send_proof, step4_response_summary,
        transport_failure_reason, validate_single_preview_email, GuardedSendAtomicAuthorityBinding,
        GuardedSendAuthorityExpectation, GuardedSendBaselineContext, GuardedSendJobEvidence,
        GuardedSendProgress, GuardedSendReconcileInput, GuardedSendRequestInput,
        GuardedSendTerminalInput, QueueJobIdentityDelta, StableStatsIdentityDelta,
    };
    use crate::{
        config::{AdminHtmlConfig, InterspireVersion},
        redact,
        response::{
            CampaignBodyAuditReport, CampaignTestSendApplyRequest, ProductionSendApplyRequest,
            SeedSendApplyRequest, SendApplyStatus, SendBaselineCaptureStage,
            SendReconciliationReport, SendUncertaintyDecision, SendUncertaintyIdentityState,
            SendUncertaintyNextAction,
        },
    };
    use std::{
        collections::BTreeSet,
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };
    use url::Url;

    const RESPONSE_LOSS_LIST_IDS: &[u64] = &[8001];
    const AUTHORITY_CAMPAIGN_ID: u64 = 9001;
    const AUTHORITY_LIST_ID: u64 = 8001;
    const AUTHORITY_RECIPIENT_COUNT: u64 = 5;
    const AUTHORITY_HTML_BODY: &str =
        "<html><body><a href=\"https://example.invalid\">Read</a>%%UNSUBSCRIBELINK%%</body></html>";
    const AUTHORITY_TEXT_BODY: &str = "Read: https://example.invalid\n%%UNSUBSCRIBELINK%%";

    fn empty_stats_identity_inventory() -> StatsIdentityInventory {
        StatsIdentityInventory { rows: Vec::new() }
    }

    fn stats_identity_inventory(rows: &[(u64, u64)]) -> StatsIdentityInventory {
        stats_identity_inventory_for("Campaign Alpha", rows)
    }

    fn stats_identity_inventory_for(
        campaign_label: &str,
        rows: &[(u64, u64)],
    ) -> StatsIdentityInventory {
        StatsIdentityInventory {
            rows: rows
                .iter()
                .enumerate()
                .map(|(index, (stat_id, recipients))| StatsRowIdentity {
                    stat_id: *stat_id,
                    row_ordinal: index + 1,
                    row_summary: format!(
                        "Synthetic Stats row {campaign_label} {stat_id} {recipients}"
                    ),
                    recipients: *recipients,
                })
                .collect(),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ResponseLossReadbackFixture {
        NativeResponseBoundJob,
        SameCampaignAfterConfirmed,
        NoNewJob,
        AmbiguousJobs,
        PostDispatchCappedStats,
        SameCampaignGapJob,
        SameCampaignBetweenCaptures,
        ScheduleOverCap,
        ScheduleExactlyAtCap,
        ManageExactlyAtCap,
        StatsPagination,
        BaselineFreshnessMismatch,
    }

    struct ResponseLossReadbackServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        dispatched: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl ResponseLossReadbackServer {
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap_or_else(|err| panic!("response-loss request lock poisoned: {err}"))
                .clone()
        }

        fn mark_dispatched(&self) {
            self.dispatched.store(true, Ordering::Release);
        }
    }

    impl Drop for ResponseLossReadbackServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("response-loss fixture server thread panicked"));
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AuthorityDriftField {
        Campaign,
        Subject,
        SubjectRedactionCollision,
        Body,
        Sender,
        ReplyTo,
        Bounce,
        Lists,
        RecipientCount,
        Action,
        Token,
        SubmittedPairs,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AuthorityDriftPhase {
        BeforeFirstCapture,
        BetweenCaptures,
        AfterConfirmedCapture,
    }

    struct AuthorityReadbackServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        after_confirmed_drift_armed: Arc<AtomicBool>,
        final_send_posts: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl AuthorityReadbackServer {
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap_or_else(|err| panic!("authority request lock poisoned: {err}"))
                .clone()
        }

        fn final_send_posts(&self) -> usize {
            self.final_send_posts.load(Ordering::Acquire)
        }

        fn after_confirmed_drift_armed(&self) -> bool {
            self.after_confirmed_drift_armed.load(Ordering::Acquire)
        }
    }

    impl Drop for AuthorityReadbackServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("authority fixture server thread panicked"));
            }
        }
    }

    fn spawn_authority_readback_server(
        field: AuthorityDriftField,
        phase: AuthorityDriftPhase,
    ) -> AuthorityReadbackServer {
        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|err| panic!("bind failed: {err}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|err| panic!("set_nonblocking failed: {err}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("local_addr failed: {err}"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let after_confirmed_drift_armed = Arc::new(AtomicBool::new(false));
        let thread_after_confirmed_drift_armed = Arc::clone(&after_confirmed_drift_armed);
        let final_send_posts = Arc::new(AtomicUsize::new(0));
        let thread_final_send_posts = Arc::clone(&final_send_posts);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut campaign_reads = 0usize;
            let mut wizard_renders = 0usize;
            while !thread_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(250)))
                            .unwrap_or_else(|err| panic!("set_read_timeout failed: {err}"));
                        let mut buffer = [0_u8; 16_384];
                        let bytes = stream
                            .read(&mut buffer)
                            .unwrap_or_else(|err| panic!("fixture request read failed: {err}"));
                        let request = String::from_utf8_lossy(&buffer[..bytes]).to_string();
                        thread_requests
                            .lock()
                            .unwrap_or_else(|err| panic!("authority request lock poisoned: {err}"))
                            .push(request.clone());

                        let (status, extra_headers, body) = if request.contains("Page=Lists") {
                            (
                                "200 OK",
                                "",
                                "<html><body><h1>Contact Lists</h1></body></html>".to_string(),
                            )
                        } else if request.contains("Page=Newsletters&Action=Edit&id=9001") {
                            campaign_reads += 1;
                            (
                                "200 OK",
                                "",
                                authority_campaign_html(field, phase, campaign_reads),
                            )
                        } else if request.starts_with("GET ") && request.contains("Page=Send ") {
                            ("200 OK", "", authority_send_start_html())
                        } else if request.starts_with("POST ")
                            && request.contains("Page=Send&Action=Step2")
                        {
                            wizard_renders += 1;
                            let body = authority_final_wizard_html(field, phase, wizard_renders);
                            if phase == AuthorityDriftPhase::AfterConfirmedCapture
                                && wizard_renders == 3
                            {
                                thread_after_confirmed_drift_armed.store(true, Ordering::Release);
                            }
                            ("200 OK", "", body)
                        } else if request.starts_with("POST ")
                            && (request.contains("Page=Send&Action=Step3")
                                || request.contains("Page=Send&Action=Step4")
                                || request.contains("Page=Send&Action=Send"))
                        {
                            thread_final_send_posts.fetch_add(1, Ordering::AcqRel);
                            (
                                    "409 Conflict",
                                    "",
                                    "<html><body>synthetic final send must remain unreachable</body></html>"
                                        .to_string(),
                                )
                        } else if request.contains("Page=Schedule") {
                            ("200 OK", "", queue_schedule_html(&[]))
                        } else if request.contains("Page=Stats") {
                            ("200 OK", "", stats_html(&[70], false))
                        } else {
                            (
                                "404 Not Found",
                                "",
                                "<html><body>unexpected synthetic authority route</body></html>"
                                    .to_string(),
                            )
                        };
                        let response = format!(
                            "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\n{extra_headers}content-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .unwrap_or_else(|err| panic!("fixture response write failed: {err}"));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("authority fixture accept failed: {err}"),
                }
            }
        });
        AuthorityReadbackServer {
            base_url: format!("http://{address}/admin/"),
            requests,
            after_confirmed_drift_armed,
            final_send_posts,
            stop,
            handle: Some(handle),
        }
    }

    fn authority_drifted(phase: AuthorityDriftPhase, ordinal: usize) -> bool {
        match phase {
            AuthorityDriftPhase::BeforeFirstCapture => ordinal >= 1,
            AuthorityDriftPhase::BetweenCaptures => ordinal >= 2,
            AuthorityDriftPhase::AfterConfirmedCapture => false,
        }
    }

    fn authority_campaign_html(
        field: AuthorityDriftField,
        phase: AuthorityDriftPhase,
        ordinal: usize,
    ) -> String {
        let drifted = authority_drifted(phase, ordinal);
        let subject = if field == AuthorityDriftField::SubjectRedactionCollision {
            "token alpha"
        } else if drifted && field == AuthorityDriftField::Subject {
            "Changed synthetic subject"
        } else {
            "Synthetic subject"
        };
        let html_body = if drifted && field == AuthorityDriftField::Body {
            "<html><body><a href=\"https://example.invalid/changed\">Changed</a>%%UNSUBSCRIBELINK%%</body></html>"
        } else {
            AUTHORITY_HTML_BODY
        };
        format!(
            r#"<html><body><form>
              <input name="name" value="Synthetic campaign">
              <input name="subject" value="{subject}">
              <textarea name="htmlbody">{html_body}</textarea>
              <textarea name="textbody">{AUTHORITY_TEXT_BODY}</textarea>
            </form></body></html>"#
        )
    }

    fn authority_send_start_html() -> String {
        r#"<html><body>
          <form action="index.php?Page=Send&Action=Step2">
            <input type="hidden" name="csrfToken" value="synthetic-start-token">
          </form>
        </body></html>"#
            .to_string()
    }

    fn authority_final_wizard_html(
        field: AuthorityDriftField,
        phase: AuthorityDriftPhase,
        ordinal: usize,
    ) -> String {
        let drifted = authority_drifted(phase, ordinal);
        let campaign_id = if drifted && field == AuthorityDriftField::Campaign {
            9002
        } else {
            AUTHORITY_CAMPAIGN_ID
        };
        let list_id = if drifted && field == AuthorityDriftField::Lists {
            8002
        } else {
            AUTHORITY_LIST_ID
        };
        let recipient_count = if drifted && field == AuthorityDriftField::RecipientCount {
            26
        } else {
            AUTHORITY_RECIPIENT_COUNT
        };
        let sender = if drifted && field == AuthorityDriftField::Sender {
            "changed-sender@example.invalid"
        } else {
            "sender@example.invalid"
        };
        let reply_to = if drifted && field == AuthorityDriftField::ReplyTo {
            "changed-reply@example.invalid"
        } else {
            "reply@example.invalid"
        };
        let bounce = if drifted && field == AuthorityDriftField::Bounce {
            "changed-bounce@example.invalid"
        } else {
            "bounce@example.invalid"
        };
        let action = if drifted && field == AuthorityDriftField::Action {
            "Step3"
        } else {
            "Step4"
        };
        let token = if drifted && field == AuthorityDriftField::Token {
            "changed-final-token"
        } else {
            "synthetic-final-token"
        };
        let delivery_mode = if drifted && field == AuthorityDriftField::SubmittedPairs {
            "changed"
        } else {
            "stable"
        };
        format!(
            r#"<html><body>
            <form name="frmSend" action="index.php?Page=Send&Action={action}">
              <input type="hidden" name="csrfToken" value="{token}">
              <select name="newsletter"><option value="{campaign_id}" selected>Synthetic campaign</option></select>
              <input type="hidden" name="lists[]" value="{list_id}">
              <input name="sendfromname" value="Synthetic sender">
              <input name="sendfromemail" value="{sender}">
              <input name="replytoemail" value="{reply_to}">
              <input name="bounceemail" value="{bounce}">
              <input type="checkbox" name="sendimmediately" value="1" checked>
              <input type="checkbox" name="notifyowner" value="1">
              <input type="checkbox" name="trackopens" value="1" checked>
              <input type="checkbox" name="tracklinks" value="1" checked>
              <input type="checkbox" name="sendmultipart" value="1" checked>
              <input type="checkbox" name="embedimages" value="1">
              <input type="hidden" name="deliverymode" value="{delivery_mode}">
              <input type="submit" name="SendButton" value="Send now">
              <p>{recipient_count} recipients selected</p>
            </form>
          </body></html>"#
        )
    }

    fn spawn_response_loss_readback_server(
        mode: ResponseLossReadbackFixture,
    ) -> ResponseLossReadbackServer {
        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|err| panic!("bind failed: {err}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|err| panic!("set_nonblocking failed: {err}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("local_addr failed: {err}"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let dispatched = Arc::new(AtomicBool::new(false));
        let thread_dispatched = Arc::clone(&dispatched);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut schedule_reads = 0usize;
            let mut manage_reads = 0usize;
            let mut stats_reads = 0usize;
            while !thread_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(250)))
                            .unwrap_or_else(|err| panic!("set_read_timeout failed: {err}"));
                        let mut buffer = [0_u8; 8192];
                        let bytes = stream
                            .read(&mut buffer)
                            .unwrap_or_else(|err| panic!("fixture request read failed: {err}"));
                        let request = String::from_utf8_lossy(&buffer[..bytes]).to_string();
                        thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("response-loss request lock poisoned: {err}")
                            })
                            .push(request.clone());
                        if request.starts_with("POST ")
                            && request.contains("Page=Send&Action=Step4")
                        {
                            thread_dispatched.store(true, Ordering::Release);
                            if mode == ResponseLossReadbackFixture::NativeResponseBoundJob {
                                write_fixture_http_response(
                                    &mut stream,
                                    "302 Found",
                                    "location: index.php?Page=Send&Action=Send&job=43&Started=1\r\n",
                                    "",
                                );
                            } else {
                                write_fixture_http_response(
                                    &mut stream,
                                    "409 Conflict",
                                    "",
                                    "<html><body>synthetic response-loss dispatch must be injected</body></html>",
                                );
                            }
                            continue;
                        }
                        if request.starts_with("GET ")
                            && request.contains("Page=Send&Action=Send&job=43")
                        {
                            write_fixture_http_response(&mut stream, "200 OK", "", "");
                            continue;
                        }
                        let (route_read, route_ordinal) = if request.contains("Page=Schedule") {
                            schedule_reads += 1;
                            ("schedule", schedule_reads)
                        } else if request.contains("Page=Stats") {
                            stats_reads += 1;
                            ("stats", stats_reads)
                        } else if request.contains("Page=Newsletters&Action=Manage") {
                            manage_reads += 1;
                            ("manage", manage_reads)
                        } else {
                            ("unexpected", 0)
                        };
                        write_response_loss_readback(
                            &mut stream,
                            route_read,
                            route_ordinal,
                            mode,
                            thread_dispatched.load(Ordering::Acquire),
                        );
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("response-loss fixture accept failed: {err}"),
                }
            }
        });
        ResponseLossReadbackServer {
            base_url: format!("http://{address}/admin/"),
            requests,
            dispatched,
            stop,
            handle: Some(handle),
        }
    }

    fn write_response_loss_readback(
        stream: &mut std::net::TcpStream,
        route: &str,
        route_ordinal: usize,
        mode: ResponseLossReadbackFixture,
        dispatched: bool,
    ) {
        let body = if route == "schedule" {
            response_loss_schedule_html(mode, dispatched, route_ordinal)
        } else if route == "stats" {
            response_loss_stats_html(mode, dispatched)
        } else if route == "manage" {
            response_loss_manage_html(mode, dispatched, route_ordinal)
        } else {
            "<html><body>unexpected synthetic read-only request</body></html>".to_string()
        };
        write_fixture_http_response(stream, "200 OK", "", &body);
    }

    fn write_fixture_http_response(
        stream: &mut std::net::TcpStream,
        status: &str,
        extra_headers: &str,
        body: &str,
    ) {
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\n{extra_headers}content-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|err| panic!("fixture response write failed: {err}"));
    }

    fn response_loss_schedule_html(
        mode: ResponseLossReadbackFixture,
        dispatched: bool,
        read_ordinal: usize,
    ) -> String {
        let jobs = match mode {
            ResponseLossReadbackFixture::NativeResponseBoundJob if dispatched => vec![43],
            ResponseLossReadbackFixture::SameCampaignAfterConfirmed if dispatched => vec![43],
            ResponseLossReadbackFixture::AmbiguousJobs if dispatched => vec![43, 44],
            ResponseLossReadbackFixture::SameCampaignGapJob => vec![43],
            ResponseLossReadbackFixture::SameCampaignBetweenCaptures if read_ordinal >= 2 => {
                vec![43]
            }
            ResponseLossReadbackFixture::ScheduleOverCap => vec![41, 42, 43],
            ResponseLossReadbackFixture::ScheduleExactlyAtCap => vec![41, 42],
            ResponseLossReadbackFixture::BaselineFreshnessMismatch if read_ordinal == 1 => vec![43],
            ResponseLossReadbackFixture::BaselineFreshnessMismatch => vec![44],
            _ => Vec::new(),
        };
        queue_schedule_html(&jobs)
    }

    fn response_loss_manage_html(
        mode: ResponseLossReadbackFixture,
        dispatched: bool,
        read_ordinal: usize,
    ) -> String {
        let jobs = match mode {
            ResponseLossReadbackFixture::NativeResponseBoundJob if dispatched => vec![43],
            ResponseLossReadbackFixture::SameCampaignAfterConfirmed if dispatched => vec![43],
            ResponseLossReadbackFixture::SameCampaignGapJob => vec![43],
            ResponseLossReadbackFixture::SameCampaignBetweenCaptures if read_ordinal >= 2 => {
                vec![43]
            }
            ResponseLossReadbackFixture::ManageExactlyAtCap => vec![41, 42],
            ResponseLossReadbackFixture::BaselineFreshnessMismatch if read_ordinal == 1 => vec![43],
            ResponseLossReadbackFixture::BaselineFreshnessMismatch => vec![44],
            _ => Vec::new(),
        };
        queue_manage_html(&jobs)
    }

    fn response_loss_stats_html(mode: ResponseLossReadbackFixture, dispatched: bool) -> String {
        let ids = if mode == ResponseLossReadbackFixture::PostDispatchCappedStats && dispatched {
            vec![70, 71, 72]
        } else {
            vec![70]
        };
        let pagination = mode == ResponseLossReadbackFixture::StatsPagination;
        stats_html(&ids, pagination)
    }

    fn queue_schedule_html(job_ids: &[u64]) -> String {
        if job_ids.is_empty() {
            return "<html><body><h1>View Scheduled Email Queue</h1><p>There are no emails currently scheduled.</p></body></html>".to_string();
        }
        let rows = job_ids
            .iter()
            .map(|job_id| {
                format!(
                    r#"<tr><td>Synthetic active job {job_id}</td><td><a href="index.php?Page=Schedule&Action=Pause&job={job_id}">Pause</a></td></tr>"#
                )
            })
            .collect::<String>();
        format!(
            "<html><body><h1>View Scheduled Email Queue</h1><table><tr><th>Campaign</th><th>Actions</th></tr>{rows}</table></body></html>"
        )
    }

    fn queue_manage_html(job_ids: &[u64]) -> String {
        if job_ids.is_empty() {
            return "<html><body><h1>View Email Campaigns</h1><p>There are no email campaigns.</p></body></html>".to_string();
        }
        let rows = job_ids
            .iter()
            .map(|job_id| {
                format!(
                    r#"<tr><td>Synthetic campaign {job_id}</td><td><a href="index.php?Page=Newsletters&Action=Edit&id=9001">Edit</a><a href="index.php?Page=Send&Action=PauseSend&Job={job_id}">Pause</a></td></tr>"#
                )
            })
            .collect::<String>();
        format!(
            "<html><body><h1>View Email Campaigns</h1><table><tr><th>Campaign</th><th>Actions</th></tr>{rows}</table></body></html>"
        )
    }

    fn stats_html(stat_ids: &[u64], pagination: bool) -> String {
        let rows = stat_ids
            .iter()
            .map(|stat_id| {
                format!(
                    r#"<tr><td>Synthetic Campaign {stat_id}</td><td>25 0 0</td><td><a href="index.php?Page=Stats&Action=Newsletters&SubAction=Step1&statid={stat_id}">View</a></td></tr>"#
                )
            })
            .collect::<String>();
        let pagination = if pagination {
            r#"<a class="pagination nextpage" href="index.php?Page=Stats&DisplayPage=2">Next</a>"#
        } else {
            ""
        };
        format!(
            "<html><body><h1>Email Campaign Statistics</h1><table><tr><th>Campaign</th><th>Counts</th><th>Actions</th></tr>{rows}</table>{pagination}</body></html>"
        )
    }

    fn response_loss_input(base_url: &str, max_rows: usize) -> GuardedSendRequestInput<'static> {
        let send_form = (
            Url::parse(&format!("{base_url}index.php?Page=Send&Action=Step4"))
                .expect("synthetic send URL"),
            vec![
                ("csrfToken".to_string(), "synthetic-token".to_string()),
                ("newsletter".to_string(), "9001".to_string()),
                ("lists[]".to_string(), "8001".to_string()),
                ("SendButton".to_string(), "Send now".to_string()),
            ],
        );
        let atomic_authority_binding = GuardedSendAtomicAuthorityBinding::synthetic(&send_form);
        GuardedSendRequestInput {
            send_form,
            atomic_authority_binding,
            campaign_id: 9001,
            list_ids: RESPONSE_LOSS_LIST_IDS,
            expected_body_sha256: Some("synthetic-body-sha256".to_string()),
            expected_recipient_count: 25,
            max_rows,
        }
    }

    fn response_loss_client(base_url: &str) -> super::AdminHtmlClient {
        super::AdminHtmlClient::new(AdminHtmlConfig {
            version: InterspireVersion::Auto,
            base_url: Some(base_url.to_string()),
            username: Some("fixture-user".to_string()),
            password: Some("fixture-value".to_string()),
            cloudflare_access: crate::config::CloudflareAccessConfig::default(),
            enrich_limit: 25,
        })
        .unwrap_or_else(|err| panic!("{err}"))
    }

    fn authority_expectation<'a>(
        expected_html_sha256: &'a str,
    ) -> GuardedSendAuthorityExpectation<'a> {
        GuardedSendAuthorityExpectation {
            campaign_id: AUTHORITY_CAMPAIGN_ID,
            list_ids: &[AUTHORITY_LIST_ID],
            expected_recipient_count: AUTHORITY_RECIPIENT_COUNT,
            expected_subject: Some("Synthetic subject"),
            expected_html_sha256: Some(expected_html_sha256),
            expected_from_email: Some("sender@example.invalid"),
            expected_reply_to_email: Some("reply@example.invalid"),
        }
    }

    fn authority_drift_fields() -> [AuthorityDriftField; 11] {
        [
            AuthorityDriftField::Campaign,
            AuthorityDriftField::Subject,
            AuthorityDriftField::Body,
            AuthorityDriftField::Sender,
            AuthorityDriftField::ReplyTo,
            AuthorityDriftField::Bounce,
            AuthorityDriftField::Lists,
            AuthorityDriftField::RecipientCount,
            AuthorityDriftField::Action,
            AuthorityDriftField::Token,
            AuthorityDriftField::SubmittedPairs,
        ]
    }

    #[test]
    fn live_authority_drift_before_first_capture_refuses_without_final_post() {
        let expected_html_sha256 = sha256_hex(AUTHORITY_HTML_BODY);
        for field in authority_drift_fields() {
            let server =
                spawn_authority_readback_server(field, AuthorityDriftPhase::BeforeFirstCapture);
            let client = response_loss_client(&server.base_url);
            let review = client
                .review_guarded_send_live_authority(
                    &authority_expectation(&expected_html_sha256),
                    25,
                )
                .unwrap_or_else(|err| panic!("{field:?}: {err}"));

            assert!(review.atomic_binding.is_none(), "{field:?}");
            assert!(
                review.refusal_reason.is_some(),
                "{field:?} retained dispatch authority"
            );
            assert_eq!(server.final_send_posts(), 0, "{field:?}");
            assert!(server.requests().iter().all(|request| !request
                .starts_with("POST /admin/index.php?Page=Send&Action=Step3")
                && !request.starts_with("POST /admin/index.php?Page=Send&Action=Step4")
                && !request.starts_with("POST /admin/index.php?Page=Send&Action=Send")));
        }
    }

    #[test]
    fn live_authority_drift_between_captures_refuses_without_final_post() {
        let expected_html_sha256 = sha256_hex(AUTHORITY_HTML_BODY);
        for field in authority_drift_fields() {
            let server =
                spawn_authority_readback_server(field, AuthorityDriftPhase::BetweenCaptures);
            let client = response_loss_client(&server.base_url);
            let review = client
                .review_guarded_send_live_authority(
                    &authority_expectation(&expected_html_sha256),
                    25,
                )
                .unwrap_or_else(|err| panic!("{field:?}: {err}"));

            assert!(review.atomic_binding.is_none(), "{field:?}");
            assert!(
                review.refusal_reason.is_some(),
                "{field:?} retained dispatch authority"
            );
            assert_eq!(server.final_send_posts(), 0, "{field:?}");
        }
    }

    #[test]
    fn stable_captures_still_refuse_after_confirmed_window_without_atomic_binding() {
        let expected_html_sha256 = sha256_hex(AUTHORITY_HTML_BODY);
        for field in authority_drift_fields() {
            let server =
                spawn_authority_readback_server(field, AuthorityDriftPhase::AfterConfirmedCapture);
            let client = response_loss_client(&server.base_url);
            let review = client
                .review_guarded_send_live_authority(
                    &authority_expectation(&expected_html_sha256),
                    25,
                )
                .unwrap_or_else(|err| panic!("{field:?}: {err}"));

            assert!(review.atomic_binding.is_none(), "{field:?}");
            assert!(
                review
                    .refusal_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("no authenticated atomic state version")),
                "{field:?}: {:?}",
                review.refusal_reason
            );
            assert!(server.after_confirmed_drift_armed(), "{field:?}");
            assert_eq!(server.final_send_posts(), 0, "{field:?}");
        }
    }

    #[test]
    fn public_seed_send_apply_refuses_at_atomic_authority_gate_without_final_post() {
        let server = spawn_authority_readback_server(
            AuthorityDriftField::Body,
            AuthorityDriftPhase::AfterConfirmedCapture,
        );
        let client = response_loss_client(&server.base_url);
        let report = client
            .seed_send_apply(
                &SeedSendApplyRequest {
                    campaign_id: AUTHORITY_CAMPAIGN_ID,
                    list_ids: vec![AUTHORITY_LIST_ID],
                    expected_recipient_count: AUTHORITY_RECIPIENT_COUNT,
                    expected_from_email: Some("sender@example.invalid".to_string()),
                    expected_reply_to_email: Some("reply@example.invalid".to_string()),
                    expected_subject: Some("Synthetic subject".to_string()),
                    expected_html_sha256: Some(sha256_hex(AUTHORITY_HTML_BODY)),
                    max_queue_rows: Some(25),
                    oci_ledger_preflight: None,
                    acknowledge_seed_send: true,
                },
                true,
                true,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.sent);
        assert_eq!(report.post_status_code, None);
        assert_eq!(report.reconciliation.status, SendApplyStatus::Refused);
        assert!(report.gates.iter().any(|gate| {
            gate.name == "final_atomic_send_authority" && !gate.passed && gate.severity == "blocker"
        }));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("no authenticated atomic state version")));
        assert_eq!(server.final_send_posts(), 0);
    }

    #[test]
    fn public_production_send_apply_refuses_at_atomic_authority_gate_without_final_post() {
        let server = spawn_authority_readback_server(
            AuthorityDriftField::Body,
            AuthorityDriftPhase::AfterConfirmedCapture,
        );
        let client = response_loss_client(&server.base_url);
        let report = client
            .production_send_apply(
                &ProductionSendApplyRequest {
                    campaign_id: AUTHORITY_CAMPAIGN_ID,
                    list_ids: vec![AUTHORITY_LIST_ID],
                    expected_recipient_count: AUTHORITY_RECIPIENT_COUNT,
                    expected_from_email: "sender@example.invalid".to_string(),
                    expected_reply_to_email: "reply@example.invalid".to_string(),
                    expected_subject: "Synthetic subject".to_string(),
                    expected_html_sha256: sha256_hex(AUTHORITY_HTML_BODY),
                    ops_work_item_ref: None,
                    max_queue_rows: Some(25),
                    oci_ledger_preflight: None,
                    acknowledge_production_send: true,
                    confirmation_phrase: "SEND_PRODUCTION_CAMPAIGN".to_string(),
                },
                true,
                true,
                true,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.sent);
        assert!(!report.production_send_authorized);
        assert_eq!(report.post_status_code, None);
        assert_eq!(report.reconciliation.status, SendApplyStatus::Refused);
        assert!(report.gates.iter().any(|gate| {
            gate.name == "final_atomic_send_authority" && !gate.passed && gate.severity == "blocker"
        }));
        assert_eq!(server.final_send_posts(), 0);
    }

    #[test]
    fn live_authority_expected_values_do_not_accept_redaction_collisions() {
        let expected_html_sha256 = sha256_hex(AUTHORITY_HTML_BODY);
        for (expected_from, expected_reply, expected_refusal) in [
            (
                Some("shadow@example.invalid"),
                Some("reply@example.invalid"),
                "sender",
            ),
            (
                Some("sender@example.invalid"),
                Some("random@example.invalid"),
                "reply-to",
            ),
        ] {
            let server = spawn_authority_readback_server(
                AuthorityDriftField::Body,
                AuthorityDriftPhase::AfterConfirmedCapture,
            );
            let client = response_loss_client(&server.base_url);
            let mut expectation = authority_expectation(&expected_html_sha256);
            expectation.expected_from_email = expected_from;
            expectation.expected_reply_to_email = expected_reply;
            let review = client
                .review_guarded_send_live_authority(&expectation, 25)
                .unwrap_or_else(|err| panic!("{err}"));

            assert!(
                review
                    .refusal_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(expected_refusal)),
                "{:?}",
                review.refusal_reason
            );
            assert_eq!(server.final_send_posts(), 0);
        }
    }

    #[test]
    fn live_authority_subject_uses_exact_private_identity_before_public_redaction() {
        let expected_html_sha256 = sha256_hex(AUTHORITY_HTML_BODY);
        let server = spawn_authority_readback_server(
            AuthorityDriftField::SubjectRedactionCollision,
            AuthorityDriftPhase::AfterConfirmedCapture,
        );
        let client = response_loss_client(&server.base_url);
        let mut matching = authority_expectation(&expected_html_sha256);
        matching.expected_subject = Some("token alpha");
        let matching_review = client
            .review_guarded_send_live_authority(&matching, 25)
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(
            matching_review
                .refusal_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no authenticated atomic state version")),
            "{:?}",
            matching_review.refusal_reason
        );

        let server = spawn_authority_readback_server(
            AuthorityDriftField::SubjectRedactionCollision,
            AuthorityDriftPhase::AfterConfirmedCapture,
        );
        let client = response_loss_client(&server.base_url);
        let mut mismatching = authority_expectation(&expected_html_sha256);
        mismatching.expected_subject = Some("token beta");
        let mismatching_review = client
            .review_guarded_send_live_authority(&mismatching, 25)
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(
            mismatching_review
                .refusal_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("campaign-subject")),
            "{:?}",
            mismatching_review.refusal_reason
        );
    }

    #[test]
    fn exact_form_authority_hash_rejects_duplicate_or_empty_aliases() {
        let single = vec![(
            "sendfromemail".to_string(),
            "Sender@Example.INVALID".to_string(),
        )];
        assert_eq!(
            guarded_send_exact_form_value_sha256(&single, &["sendfromemail", "fromemail"], true),
            Some(sha256_hex("sender@example.invalid"))
        );

        let duplicate = vec![
            (
                "sendfromemail".to_string(),
                "sender@example.invalid".to_string(),
            ),
            ("fromemail".to_string(), "other@example.invalid".to_string()),
        ];
        assert!(guarded_send_exact_form_value_sha256(
            &duplicate,
            &["sendfromemail", "fromemail"],
            true
        )
        .is_none());
        assert!(guarded_send_exact_form_value_sha256(
            &[("sendfromemail".to_string(), "  ".to_string())],
            &["sendfromemail", "fromemail"],
            true
        )
        .is_none());
        assert!(guarded_send_exact_form_value_sha256(
            &[
                (
                    "sendfromemail".to_string(),
                    "sender@example.invalid".to_string(),
                ),
                ("fromemail".to_string(), "  ".to_string()),
            ],
            &["sendfromemail", "fromemail"],
            true
        )
        .is_none());
        assert!(guarded_send_form_token(&[("csrfToken".to_string(), "  ".to_string())]).is_err());
        assert!(guarded_send_form_token(&[
            ("csrfToken".to_string(), "provider-token".to_string()),
            ("_token".to_string(), "  ".to_string()),
        ])
        .is_err());
    }

    #[test]
    fn campaign_body_audit_counts_tokens_without_returning_body() {
        let html = r#"
            <form>
              <input name="name" value="Launch">
              <input name="subject" value="Subject">
              <textarea name="htmlbody"><html><body><a href="https://example.invalid">Read</a><img src="x.png" alt="Logo">%%UNSUBSCRIBELINK%%</body></html></textarea>
              <textarea name="textbody">Plain text</textarea>
            </form>
        "#;

        let report = campaign_body_audit_from_html(7, html).expect("campaign body audit");
        let serialized = serde_json::to_string(&report).expect("serialize report");

        assert_eq!(report.unsubscribe_token_count, 1);
        assert_eq!(report.html_unsubscribe_token_count, 1);
        assert_eq!(report.text_unsubscribe_token_count, 0);
        assert_eq!(report.http_url_count, 0);
        assert_eq!(report.https_url_count, 1);
        assert_eq!(report.image_count, 1);
        assert_eq!(report.missing_alt_image_count, 0);
        assert!(report.html_sha256.is_some());
        assert!(!serialized.contains("%%UNSUBSCRIBELINK%%"));
        assert!(!serialized.contains("<html>"));
    }

    #[test]
    fn campaign_body_audit_understands_interspire_8_editor_fields() {
        let html = r#"
            <form action="index.php?Page=Newsletters&Action=Edit&SubAction=Complete&id=7">
              <input name="subject" value="Subject">
              <textarea name="myDevEditControl_html"><div><a href="https://example.invalid">Read</a><img src="x.png" alt="Logo">%%UNSUBSCRIBELINK%%</div></textarea>
              <textarea name="myDevEditControl_text">Plain text</textarea>
            </form>
        "#;

        let report = campaign_body_audit_from_html(7, html).expect("campaign body audit");
        let serialized = serde_json::to_string(&report).expect("serialize report");

        assert_eq!(report.unsubscribe_token_count, 1);
        assert_eq!(report.html_unsubscribe_token_count, 1);
        assert_eq!(report.text_unsubscribe_token_count, 0);
        assert!(report.html_bytes > 0);
        assert_eq!(report.http_url_count, 0);
        assert_eq!(report.https_url_count, 1);
        assert_eq!(report.image_count, 1);
        assert_eq!(report.missing_alt_image_count, 0);
        assert!(!serialized.contains("myDevEditControl_html"));
        assert!(!serialized.contains("%%UNSUBSCRIBELINK%%"));
    }

    #[test]
    fn campaign_body_audit_accepts_one_unsubscribe_per_multipart_alternative() {
        let html = r#"
            <form action="index.php?Page=Newsletters&Action=Edit&SubAction=Complete&id=7">
              <input name="subject" value="Subject">
              <textarea name="myDevEditControl_html"><div><a href="https://example.invalid">%%UNSUBSCRIBELINK%%</a></div></textarea>
              <textarea name="myDevEditControl_text">Unsubscribe: %%UNSUBSCRIBELINK%%</textarea>
            </form>
        "#;

        let report = campaign_body_audit_from_html(7, html).expect("campaign body audit");

        assert_eq!(report.unsubscribe_token_count, 2);
        assert_eq!(report.html_unsubscribe_token_count, 1);
        assert_eq!(report.text_unsubscribe_token_count, 1);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn campaign_test_send_preview_requires_html_hash_not_text_only_body() {
        let html = r#"
            <form action="index.php?Page=Newsletters&Action=Edit&SubAction=Complete&id=7">
              <input name="subject" value="Subject">
              <textarea name="myDevEditControl_text">Plain text %%UNSUBSCRIBELINK%%</textarea>
            </form>
        "#;
        let parts = campaign_body_parts_from_html(html).expect("campaign body parts");
        let report =
            super::campaign_body_audit_from_parts(7, parts.clone()).expect("campaign body audit");

        assert!(parts.html_body.is_empty());
        assert!(report.html_sha256.is_none());
        assert!(!campaign_test_send_has_applyable_html(&parts, &report));
    }

    #[test]
    fn campaign_test_send_digest_binds_text_and_preheader_hashes() {
        let text_sha256 = sha256_hex("plain text");
        let preheader_sha256 = optional_nonempty_sha256(Some("preheader"));
        let digest = campaign_test_send_digest(
            7,
            "recipient@example.invalid",
            "sender@example.invalid",
            "Subject",
            &sha256_hex("<p>html</p>"),
            Some(&text_sha256),
            preheader_sha256.as_deref(),
        );
        let changed_text = campaign_test_send_digest(
            7,
            "recipient@example.invalid",
            "sender@example.invalid",
            "Subject",
            &sha256_hex("<p>html</p>"),
            Some(&sha256_hex("changed text")),
            preheader_sha256.as_deref(),
        );
        let changed_preheader = campaign_test_send_digest(
            7,
            "recipient@example.invalid",
            "sender@example.invalid",
            "Subject",
            &sha256_hex("<p>html</p>"),
            Some(&text_sha256),
            optional_nonempty_sha256(Some("changed preheader")).as_deref(),
        );

        assert_ne!(digest, changed_text);
        assert_ne!(digest, changed_preheader);
    }

    #[test]
    fn campaign_test_send_report_uses_row_equality_not_row_counts() {
        let request = CampaignTestSendApplyRequest {
            campaign_id: 7,
            recipient_email: "recipient@example.invalid".to_string(),
            from_preview_email: "sender@example.invalid".to_string(),
            expected_preview_digest: "0".repeat(64),
            expected_subject: "Subject".to_string(),
            expected_html_sha256: "0".repeat(64),
            max_queue_rows: Some(25),
            acknowledge_test_send: true,
        };
        let mut campaign_body = CampaignBodyAuditReport::fixture();
        campaign_body.campaign_id = request.campaign_id;

        let report = campaign_test_send_report(
            &request,
            false,
            Some(200),
            Some("Interspire reported that the preview email was sent.".to_string()),
            campaign_body,
            Some(request.expected_preview_digest.clone()),
            false,
            1,
            1,
            1,
            1,
            false,
            false,
            vec!["Schedule queue rows changed during campaign test send".to_string()],
            true,
        );

        assert!(!report.ok);
        assert!(!report.queue_unchanged);
        assert!(!report.stats_unchanged);
        assert_eq!(report.queue_rows_before, report.queue_rows_after);
        assert_eq!(report.stats_rows_before, report.stats_rows_after);
        assert!(report.campaign_body.is_none());
    }

    #[test]
    fn campaign_test_send_expected_subject_accepts_public_preview_value() {
        let raw_subject = "Update from editor@example.invalid";
        let public_subject = redact::redact_sensitive_text(raw_subject);

        assert!(expected_public_subject_matches(
            Some(&public_subject),
            &public_subject
        ));
        assert!(!expected_public_subject_matches(
            Some(&public_subject),
            raw_subject
        ));
        assert!(!expected_public_subject_matches(
            Some(&public_subject),
            "Different subject"
        ));
    }

    #[test]
    fn preview_test_send_email_guard_requires_exactly_one_address() {
        assert!(validate_single_preview_email("person@example.invalid", "recipient_email").is_ok());
        for value in [
            "",
            "person",
            "one@example.invalid,two@example.invalid",
            "one@example.invalid;two@example.invalid",
            "one@example.invalid two@example.invalid",
        ] {
            assert!(
                validate_single_preview_email(value, "recipient_email").is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn preview_send_response_parser_distinguishes_success_from_failure() {
        assert!(preview_send_response_success(
            "<html><body>A preview has been sent to the email address [redacted].</body></html>"
        ));
        let echoed_page = format!(
            "<html><body>{} A preview has been sent to the email address [redacted].</body></html>",
            "campaign body ".repeat(80)
        );
        assert!(!preview_send_response_success(&echoed_page));
        for html in [
            "<html><body>Preview email was not sent.</body></html>",
            "<html><body>Permission denied.</body></html>",
            "<html><body>Could not send preview email.</body></html>",
            "<html><body>Send preview form</body></html>",
        ] {
            assert!(
                !preview_send_response_success(html),
                "{html:?} should not be treated as success"
            );
        }
    }

    #[test]
    fn campaign_body_step1_post_preserves_required_fields_without_final_save() {
        let html = r#"
            <form action="index.php?Page=Newsletters&Action=Edit&SubAction=Step2&id=7">
              <input type="hidden" name="csrfToken" value="abc123">
              <input name="Name" value="Launch">
              <input type="radio" name="Format" value="t">
              <input type="radio" name="Format" value="h" checked>
              <input type="hidden" name="usewysiwyg" value="3">
              <input type="submit" name="NextButton" value="Next &gt;&gt;">
            </form>
        "#;

        assert_eq!(
            campaign_body_step2_action_path(7, html)
                .expect("parse action")
                .as_deref(),
            Some("index.php?Page=Newsletters&Action=Edit&SubAction=Step2&id=7")
        );
        let pairs = campaign_body_step1_pairs(7, html).expect("step1 pairs");

        assert!(pairs.contains(&("Name".to_string(), "Launch".to_string())));
        assert!(pairs.contains(&("Format".to_string(), "h".to_string())));
        assert!(!pairs.contains(&("Format".to_string(), "t".to_string())));
        assert!(pairs.contains(&("usewysiwyg".to_string(), "3".to_string())));
        assert!(pairs.contains(&("csrfToken".to_string(), "abc123".to_string())));
    }

    #[test]
    fn csrf_header_token_ignores_non_token_hidden_replay_fields() {
        let mut pairs = vec![("ShowFilteringOptions".to_string(), "2".to_string())];
        assert!(csrf_pair(&pairs).is_none());

        append_csrf_pair_if_missing(
            &mut pairs,
            r#"<script>window.IEM_CSRF_TOKEN = "token-123";</script>"#,
        );

        assert_eq!(
            csrf_pair(&pairs),
            Some(("csrfToken".to_string(), "token-123".to_string()))
        );
    }

    #[test]
    fn send_step2_action_path_finds_only_no_send_step() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Step2&token=abc"></form>
            <form action="index.php?Page=Send&Action=Step3"></form>
        "#;

        assert_eq!(
            send_step2_action_path(html).as_deref(),
            Some("index.php?Page=Send&Action=Step2&token=abc")
        );
    }

    #[test]
    fn final_send_wizard_page_redacts_fields_and_marks_no_action() {
        let html = r#"
            <form name="frmSend" action="index.php?Page=Send&Action=Step3">
              <select name="newsletter">
                <option value="7" selected>Launch campaign</option>
              </select>
              <input type="hidden" name="lists[]" value="3">
              <input name="sendfromname" value="Example Update">
              <input name="sendfromemail" value="sender@example.invalid">
              <input name="replytoemail" value="editor@example.invalid">
              <input name="bounceemail" value="bounces@example.invalid">
              <input type="checkbox" name="sendimmediately" checked>
              <input type="checkbox" name="trackopens" checked>
              <input type="checkbox" name="tracklinks" checked>
              <input type="checkbox" name="sendmultipart" checked>
              <p>2 recipients selected</p>
            </form>
        "#;

        let report = parse_send_wizard_final_page(7, &[3], html).expect("parse final page");
        let serialized = serde_json::to_string(&report).expect("serialize report");

        assert_eq!(report.selected_campaign_id, Some(7));
        assert_eq!(report.selected_list_ids, vec![3]);
        assert_eq!(report.recipient_count, Some(2));
        assert_eq!(report.track_opens_checked, Some(true));
        assert!(report.final_form_posts_to_send_boundary);
        assert!(!report.send_performed);
        assert!(!report.scheduled);
        assert!(!report.production_send_authorized);
        assert!(!serialized.contains("sender@example.invalid"));
        assert!(!serialized.contains("editor@example.invalid"));
        assert!(!serialized.contains("bounces@example.invalid"));
        assert!(!serialized.contains("index.php?Page=Send&Action=Step3"));
    }

    #[test]
    fn final_send_wizard_page_handles_interspire_8_unnamed_send_form() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Step4">
              <select name="newsletter">
                <option value="0" selected>Please select an email campaign</option>
                <option value="7">Launch campaign</option>
              </select>
              <input name="sendfromname" value="Example Update">
              <input name="sendfromemail" value="sender@example.invalid">
              <input name="replytoemail" value="editor@example.invalid">
              <input name="bounceemail" value="bounces@example.invalid">
              <input type="checkbox" name="sendimmediately" checked>
              <input type="checkbox" name="trackopens" checked>
              <input type="checkbox" name="tracklinks" checked>
              <input type="checkbox" name="sendmultipart" checked>
              <p>1 recipient selected</p>
            </form>
        "#;

        let report = parse_send_wizard_final_page(7, &[3], html).expect("parse final page");

        assert_eq!(report.selected_campaign_id, Some(0));
        assert!(report.requested_campaign_available);
        assert_eq!(report.campaign_label.as_deref(), Some("Launch campaign"));
        assert!(report.selected_list_ids.is_empty());
        assert_eq!(report.recipient_count, Some(1));
        assert!(report.final_form_posts_to_send_boundary);
        assert!(!report.send_performed);
        assert!(!report.scheduled);
        assert!(!report.production_send_authorized);
    }

    #[test]
    fn guarded_send_final_form_post_captures_only_guarded_final_send_form() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Step2">
              <input name="newsletter" value="7">
            </form>
            <form action="index.php?Page=Send&Action=Step4&csrfToken=abc">
              <input type="hidden" name="csrfToken" value="abc">
              <input type="hidden" name="newsletter" value="7">
              <input type="hidden" name="lists[]" value="3">
              <input name="sendfromemail" value="sender@example.invalid">
              <input type="checkbox" name="trackopens" value="1" checked>
              <input type="checkbox" name="embedimages" value="1">
              <input type="password" name="smtp_password" value="secret">
              <input type="submit" name="SendButton" value="Send now">
            </form>
        "#;

        let (url, pairs) = guarded_send_final_form_post("https://example.test/admin/", html)
            .expect("guarded send final form post");

        assert!(url.as_str().contains("Page=Send&Action=Step4"));
        assert!(pairs.contains(&("newsletter".to_string(), "7".to_string())));
        assert!(pairs.contains(&("lists[]".to_string(), "3".to_string())));
        assert!(pairs.contains(&("trackopens".to_string(), "1".to_string())));
        assert!(pairs.contains(&("SendButton".to_string(), "Send now".to_string())));
        assert!(!pairs.iter().any(|(name, _)| name == "embedimages"));
        assert!(!pairs.iter().any(|(name, _)| name == "smtp_password"));
    }

    #[test]
    fn guarded_send_final_form_post_rejects_schedule_only_forms() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Schedule">
              <input type="hidden" name="newsletter" value="7">
              <input type="submit" name="ScheduleButton" value="Schedule">
            </form>
        "#;

        assert!(guarded_send_final_form_post("https://example.test/admin/", html).is_err());
    }

    #[test]
    fn guarded_schedule_approval_url_finds_cron_confirmation_button() {
        let html = r#"
            <input type="button" value="Approve Scheduled Send"
              onclick="document.location='index.php?Page=Schedule&amp;A=1';">
        "#;

        let url = guarded_schedule_approval_url("https://example.test/admin/", html)
            .expect("parse approval url")
            .expect("approval url");

        assert_eq!(
            url.as_str(),
            "https://example.test/admin/index.php?Page=Schedule&A=1"
        );
    }

    #[test]
    fn queue_job_identity_delta_requires_one_exact_new_identity() {
        let before = [42_u64].into_iter().collect();
        let after = [42_u64, 43].into_iter().collect();

        assert_eq!(
            queue_job_identity_delta(&before, &after),
            QueueJobIdentityDelta::Unique(43)
        );
    }

    #[test]
    fn queue_job_identity_delta_rejects_no_change_removal_and_multiple_additions() {
        let before = [41_u64, 42].into_iter().collect();
        let unchanged = [41_u64, 42].into_iter().collect();
        let removed = [42_u64].into_iter().collect();
        let multiple_added = [41_u64, 42, 43, 44].into_iter().collect();

        assert_eq!(
            queue_job_identity_delta(&before, &unchanged),
            QueueJobIdentityDelta::None
        );
        assert_eq!(
            queue_job_identity_delta(&before, &removed),
            QueueJobIdentityDelta::Ambiguous {
                added: 0,
                removed: 1,
            }
        );
        assert_eq!(
            queue_job_identity_delta(&before, &multiple_added),
            QueueJobIdentityDelta::Ambiguous {
                added: 2,
                removed: 0,
            }
        );
    }

    #[test]
    fn guarded_send_job_evidence_rejects_conflicting_schedule_and_popup_identities() {
        let mut evidence = GuardedSendJobEvidence::default();
        evidence.observe(Some(43), "popup continuation");
        evidence.observe(Some(44), "Schedule identity delta");

        assert_eq!(evidence.job_id, None);
        assert!(evidence.conflicted);
        assert!(evidence
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("conflicted")));
    }

    #[test]
    fn native_response_bound_job_remains_nonterminal_with_read_only_follow_up() {
        let server = spawn_response_loss_readback_server(
            ResponseLossReadbackFixture::NativeResponseBoundJob,
        );
        let client = response_loss_client(&server.base_url);
        let evidence = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 25),
                |request| request.send().map_err(|_| ()),
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(evidence.status_code, Some(302));
        assert!(evidence.redirected);
        assert_eq!(evidence.reconciliation.status, SendApplyStatus::Queued);
        assert_eq!(evidence.reconciliation.job_id, Some(43));
        assert!(evidence.reconciliation.follow_up_contract.is_some());
        assert!(evidence
            .reconciliation
            .uncertainty_recovery_contract
            .is_none());
        assert!(!evidence.reconciliation.terminal_application_proven());
        assert!(evidence
            .reconciliation
            .notes
            .iter()
            .any(|note| note.contains("native response-bound job")));
        let requests = server.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.starts_with("POST ") && request.contains("Page=Send&Action=Step4")
                })
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("Page=Send&Action=Send&job=43"))
                .count(),
            1
        );
    }

    #[test]
    fn response_loss_never_binds_same_campaign_job_inserted_after_confirmed_capture() {
        let server = spawn_response_loss_readback_server(
            ResponseLossReadbackFixture::SameCampaignAfterConfirmed,
        );
        let client = response_loss_client(&server.base_url);
        let mut attempted = false;
        let evidence = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 25),
                |_| {
                    server.mark_dispatched();
                    attempted = true;
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(attempted);
        assert_eq!(evidence.status_code, None);
        assert!(!evidence.redirected);
        assert_eq!(
            evidence.reconciliation.status,
            SendApplyStatus::ResponseUncertain
        );
        assert!(!evidence.reconciliation.terminal_application_proven());
        assert_eq!(evidence.reconciliation.sent_count, None);
        assert_eq!(evidence.reconciliation.job_id, None);
        assert!(evidence.reconciliation.follow_up_contract.is_none());
        let recovery = evidence
            .reconciliation
            .uncertainty_recovery_contract
            .as_ref()
            .expect("response uncertainty recovery contract");
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
        assert!(recovery.readback_complete);
        assert_eq!(recovery.schedule_job_ids_before, Vec::<u64>::new());
        assert_eq!(recovery.manage_job_ids_before, Vec::<u64>::new());
        assert_eq!(recovery.campaign_job_ids_before, Vec::<u64>::new());
        assert_eq!(
            recovery.identity_state,
            SendUncertaintyIdentityState::AmbiguousOrUnbound
        );
        assert_eq!(recovery.observed_job_id, None);
        assert_eq!(
            recovery.next_action,
            SendUncertaintyNextAction::HoldForBoundedReadOnlyReconciliation
        );
        assert!(recovery.status_follow_up.is_none());
        assert!(recovery.guidance.contains("do not retry or resend"));
        assert!(recovery.guidance.contains("singleton difference"));
        assert!(evidence
            .reconciliation
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("do not bind that concurrent job")));
        assert!(evidence
            .reconciliation
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("whether it reached the application remains uncertain")));
        assert!(evidence
            .reconciliation
            .notes
            .iter()
            .any(|note| note.contains("nonterminal reconciliation receipt")));
        let warnings = seed_send_apply_warnings(&evidence.reconciliation);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("response-uncertain")));
        assert!(warnings.iter().all(|warning| !warning.contains("posted")));
        assert!(evidence
            .reconciliation
            .proof_gaps
            .iter()
            .all(|gap| !gap.contains("posted")));
        let evidence_note =
            guarded_send_boundary_evidence_note(evidence.reconciliation.status, "seed-send");
        assert!(evidence_note.contains("request was attempted"));
        assert!(!evidence_note.contains("posted"));
        let requests = server.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("Page=Schedule"))
                .count(),
            3
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("Page=Stats"))
                .count(),
            3
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("Page=Newsletters&Action=Manage"))
                .count(),
            3
        );
        assert_eq!(requests.len(), 9);
        assert!(requests[0].contains("Page=Schedule"));
        assert!(requests[1].contains("Page=Newsletters&Action=Manage"));
        assert!(requests[2].contains("Page=Stats"));
        assert!(requests[3].contains("Page=Stats"));
        assert!(requests[4].contains("Page=Schedule"));
        assert!(requests[5].contains("Page=Newsletters&Action=Manage"));
        assert!(requests[6].contains("Page=Schedule"));
        assert!(requests[7].contains("Page=Newsletters&Action=Manage"));
        assert!(requests[8].contains("Page=Stats"));
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
        assert!(requests
            .iter()
            .all(|request| !request.contains("Page=Send")));
    }

    #[test]
    fn same_campaign_job_present_before_first_capture_stays_in_the_baseline() {
        let server =
            spawn_response_loss_readback_server(ResponseLossReadbackFixture::SameCampaignGapJob);
        let client = response_loss_client(&server.base_url);
        let evidence = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 25),
                |_| {
                    server.mark_dispatched();
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(evidence.reconciliation.job_id, None);
        let recovery = evidence
            .reconciliation
            .uncertainty_recovery_contract
            .as_ref()
            .expect("response uncertainty recovery contract");
        assert_eq!(
            recovery.identity_state,
            SendUncertaintyIdentityState::NoNewJob
        );
        assert_eq!(recovery.schedule_job_ids_before, vec![43]);
        assert_eq!(recovery.manage_job_ids_before, vec![43]);
        assert_eq!(recovery.campaign_job_ids_before, vec![43]);
        assert_eq!(recovery.observed_job_id, None);
        assert!(recovery.status_follow_up.is_none());
        assert!(!recovery.retry_authorized);
        assert!(!recovery.mutation_authorized);
        assert!(!recovery.terminal_success_authorized);
    }

    #[test]
    fn same_campaign_job_inserted_between_captures_refuses_before_dispatch() {
        let server = spawn_response_loss_readback_server(
            ResponseLossReadbackFixture::SameCampaignBetweenCaptures,
        );
        let client = response_loss_client(&server.base_url);
        let mut attempted = false;
        let error = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 25),
                |_| {
                    attempted = true;
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .expect_err("same-campaign insertion between captures must refuse");

        assert!(!attempted);
        assert!(error
            .to_string()
            .contains("baseline identities changed during bounded capture"));
        assert!(server
            .requests()
            .iter()
            .all(|request| request.starts_with("GET ")));
    }

    #[test]
    fn guarded_send_response_loss_with_one_under_cap_holds_without_retry() {
        let server = spawn_response_loss_readback_server(ResponseLossReadbackFixture::NoNewJob);
        let client = response_loss_client(&server.base_url);
        let evidence = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 3),
                |_| {
                    server.mark_dispatched();
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            evidence.reconciliation.status,
            SendApplyStatus::ResponseUncertain
        );
        assert_eq!(evidence.reconciliation.job_id, None);
        assert!(evidence.reconciliation.follow_up_contract.is_none());
        let recovery = evidence
            .reconciliation
            .uncertainty_recovery_contract
            .as_ref()
            .expect("response uncertainty recovery contract");
        assert!(recovery.readback_complete);
        assert_eq!(recovery.baseline_max_rows, 3);
        assert_eq!(
            recovery.identity_state,
            SendUncertaintyIdentityState::NoNewJob
        );
        assert_eq!(recovery.observed_job_id, None);
        assert!(recovery.status_follow_up.is_none());
        assert_eq!(
            recovery.next_action,
            SendUncertaintyNextAction::HoldForBoundedReadOnlyReconciliation
        );
        assert!(!recovery.retry_authorized);
        assert!(recovery.guidance.contains("absence of a new identity"));
    }

    #[test]
    fn guarded_send_response_loss_with_ambiguous_jobs_holds_without_selection() {
        let server =
            spawn_response_loss_readback_server(ResponseLossReadbackFixture::AmbiguousJobs);
        let client = response_loss_client(&server.base_url);
        let evidence = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 25),
                |_| {
                    server.mark_dispatched();
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            evidence.reconciliation.status,
            SendApplyStatus::ResponseUncertain
        );
        assert_eq!(evidence.reconciliation.job_id, None);
        let recovery = evidence
            .reconciliation
            .uncertainty_recovery_contract
            .as_ref()
            .expect("response uncertainty recovery contract");
        assert!(recovery.readback_complete);
        assert_eq!(
            recovery.identity_state,
            SendUncertaintyIdentityState::AmbiguousOrUnbound
        );
        assert!(recovery.status_follow_up.is_none());
        assert!(!recovery.retry_authorized);
        assert!(recovery.guidance.contains("never choose by row order"));
        assert!(evidence
            .reconciliation
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("2 added")));
    }

    #[test]
    fn guarded_send_response_loss_with_capped_post_readback_marks_recovery_incomplete() {
        let server = spawn_response_loss_readback_server(
            ResponseLossReadbackFixture::PostDispatchCappedStats,
        );
        let client = response_loss_client(&server.base_url);
        let evidence = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 3),
                |_| {
                    server.mark_dispatched();
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            evidence.reconciliation.status,
            SendApplyStatus::ResponseUncertain
        );
        let recovery = evidence
            .reconciliation
            .uncertainty_recovery_contract
            .as_ref()
            .expect("response uncertainty recovery contract");
        assert!(!recovery.readback_complete);
        assert_eq!(
            recovery.identity_state,
            SendUncertaintyIdentityState::ReadbackIncomplete
        );
        assert!(recovery.status_follow_up.is_none());
        assert!(!recovery.retry_authorized);
        assert!(!recovery.mutation_authorized);
        assert!(recovery.guidance.contains("partial or capped state"));
        assert!(evidence
            .reconciliation
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("Stats identity readback was incomplete")));
    }

    #[test]
    fn final_pre_dispatch_baseline_rejects_caps_and_pagination_without_dispatch() {
        for (mode, expected) in [
            (
                ResponseLossReadbackFixture::ScheduleOverCap,
                "reached the configured row cap",
            ),
            (
                ResponseLossReadbackFixture::ScheduleExactlyAtCap,
                "reached the configured row cap",
            ),
            (
                ResponseLossReadbackFixture::ManageExactlyAtCap,
                "reached the configured row cap",
            ),
            (
                ResponseLossReadbackFixture::StatsPagination,
                "exposed pagination",
            ),
        ] {
            let server = spawn_response_loss_readback_server(mode);
            let client = response_loss_client(&server.base_url);
            let mut attempted = false;
            let error = client
                .post_guarded_send_and_reconcile_with_dispatch(
                    response_loss_input(&server.base_url, 3),
                    |_| {
                        attempted = true;
                        Err::<reqwest::blocking::Response, _>(())
                    },
                )
                .expect_err("incomplete pre-dispatch baseline must fail closed");

            assert!(!attempted, "{mode:?} reached the dispatch closure");
            assert!(
                error.to_string().contains(expected),
                "{mode:?} returned unexpected error: {error}"
            );
            assert!(server
                .requests()
                .iter()
                .all(|request| request.starts_with("GET ")));
        }
    }

    #[test]
    fn final_pre_dispatch_baseline_rejects_identity_movement_without_dispatch() {
        let server = spawn_response_loss_readback_server(
            ResponseLossReadbackFixture::BaselineFreshnessMismatch,
        );
        let client = response_loss_client(&server.base_url);
        let mut attempted = false;
        let error = client
            .post_guarded_send_and_reconcile_with_dispatch(
                response_loss_input(&server.base_url, 25),
                |_| {
                    attempted = true;
                    Err::<reqwest::blocking::Response, _>(())
                },
            )
            .expect_err("moving baseline must fail closed");

        assert!(!attempted);
        assert!(error
            .to_string()
            .contains("baseline identities changed during bounded capture"));
    }

    #[test]
    fn final_pre_dispatch_baseline_context_mismatch_cannot_reach_dispatch() {
        let server = spawn_response_loss_readback_server(ResponseLossReadbackFixture::NoNewJob);
        let client = response_loss_client(&server.base_url);
        let mut input = client
            .capture_guarded_send_baseline(response_loss_input(&server.base_url, 25))
            .unwrap_or_else(|err| panic!("{err}"));
        input.baseline_context.campaign_id = 9002;
        let mut attempted = false;
        let error = client
            .post_guarded_send_from_baseline_with_dispatch(input, |_| {
                attempted = true;
                Err::<reqwest::blocking::Response, _>(())
            })
            .expect_err("mismatched context must fail closed");

        assert!(!attempted);
        assert!(error
            .to_string()
            .contains("baseline context or freshness did not match the exact request"));
    }

    #[test]
    fn atomic_authority_mismatch_cannot_reach_baseline_or_dispatch() {
        let server = spawn_response_loss_readback_server(ResponseLossReadbackFixture::NoNewJob);
        let client = response_loss_client(&server.base_url);
        let mut input = response_loss_input(&server.base_url, 25);
        input.atomic_authority_binding.submission_sha256 = "mismatched-submission".to_string();
        let mut attempted = false;
        let error = client
            .post_guarded_send_and_reconcile_with_dispatch(input, |_| {
                attempted = true;
                Err::<reqwest::blocking::Response, _>(())
            })
            .expect_err("mismatched atomic binding must fail closed");

        assert!(!attempted);
        assert!(server.requests().is_empty());
        assert!(error
            .to_string()
            .contains("did not bind the exact final submission"));
    }

    #[test]
    fn guarded_send_uncertainty_preserves_only_a_nonconflicting_job_follow_up() {
        let send_form = (
            Url::parse("https://example.test/admin/index.php?Page=Send&Action=Step4")
                .expect("synthetic send URL"),
            vec![("csrfToken".to_string(), "synthetic-token".to_string())],
        );
        let atomic_authority_binding = GuardedSendAtomicAuthorityBinding::synthetic(&send_form);
        let input = GuardedSendReconcileInput {
            send_form,
            atomic_authority_binding: atomic_authority_binding.clone(),
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            expected_recipient_count: 25,
            max_rows: 25,
            baseline_context: GuardedSendBaselineContext {
                campaign_id: 9001,
                list_ids: vec![8001],
                expected_body_sha256: None,
                expected_recipient_count: 25,
                max_rows: 25,
                authority_submission_sha256: atomic_authority_binding.submission_sha256.clone(),
                authority_state_version: atomic_authority_binding.state_version.clone(),
                capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            },
            queue_before: Vec::new(),
            schedule_job_ids_before: BTreeSet::new(),
            manage_job_ids_before: BTreeSet::new(),
            campaign_job_ids_before: BTreeSet::new(),
            queue_job_ids_before: BTreeSet::new(),
            stats_before: Vec::new(),
            stats_identity_before: empty_stats_identity_inventory(),
            baseline_identity_stable: true,
        };
        let mut progress = GuardedSendProgress {
            status_code: Some(200),
            popup_steps: 1,
            ..GuardedSendProgress::default()
        };
        progress
            .job_evidence
            .observe(Some(43), "popup continuation");

        let evidence = guarded_send_evidence_from_progress(
            &input,
            progress,
            Some("Stats readback was unavailable after request dispatch"),
        );

        assert_eq!(evidence.reconciliation.status, SendApplyStatus::Queued);
        assert_eq!(evidence.reconciliation.job_id, Some(43));
        assert!(evidence.reconciliation.follow_up_contract.is_some());
        assert_eq!(evidence.reconciliation.sent_count, None);
        assert!(!evidence.reconciliation.terminal_application_proven());
        assert!(evidence
            .reconciliation
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("Stats readback was unavailable")));
    }

    #[test]
    fn guarded_send_final_form_post_preserves_provider_authority_without_reconstruction() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Step4">
              <input type="hidden" name="csrfToken" value="provider-token">
              <input type="hidden" name="newsletter" value="2">
              <input type="hidden" name="lists[]" value="1">
              <input type="hidden" name="listid" value="4">
              <input type="submit" name="SendButton" value="Send now">
            </form>
        "#;

        let (_, pairs) = guarded_send_final_form_post("https://example.test/admin/", html)
            .expect("provider-derived guarded send final form post");

        assert_eq!(
            pairs
                .iter()
                .filter(|(name, _)| is_guarded_send_list_selection_name(name))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "4"]
        );
        assert!(pairs
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("newsletter") && value == "2"));
        assert!(pairs.iter().all(|(_, value)| value != "9"));
    }

    #[test]
    fn send_proof_table_rows_ignore_interspire_chrome_timer_churn() {
        let before = vec![
            "Any emails you have scheduled to be sent out are shown below. UpdateCronTimer('173', 300, true);".to_string(),
            "Results per page: 10 50 100".to_string(),
            "Copy of iTWire Update Example Email Campaign 'Clean List' July 1 2026, 11:41 am Complete View Delete".to_string(),
        ];
        let after = vec![
            "Any emails you have scheduled to be sent out are shown below. UpdateCronTimer('169', 300, true);".to_string(),
            "Results per page: 10 50 100".to_string(),
            "Copy of iTWire Update Example Email Campaign 'Clean List' July 1 2026, 11:41 am Complete View Delete".to_string(),
        ];
        let changed_data = vec![
            "Any emails you have scheduled to be sent out are shown below. UpdateCronTimer('168', 300, true);".to_string(),
            "Results per page: 10 50 100".to_string(),
            "Copy of iTWire Update Example Email Campaign 'Another Clean List' July 1 2026, 11:41 am Complete View Delete".to_string(),
        ];

        assert!(rows_unchanged_for_send_proof(&before, &after));
        assert!(rows_changed_for_send_proof(&before, &changed_data));
    }

    #[test]
    fn no_send_stats_stability_allows_existing_row_text_churn_only() {
        let before = vec![
            "Email Campaign Statistics".to_string(),
            "Original Campaign 'Clean List' July 1 2026, 11:41 am July 1 2026, 11:42 am 500 0 0 View Export Print Delete".to_string(),
        ];
        let renamed_existing_row = vec![
            "Email Campaign Statistics".to_string(),
            "Renamed Campaign 'Clean List' July 1 2026, 11:41 am July 1 2026, 11:42 am 500 0 0 View Export Print Delete".to_string(),
        ];
        let added_stats_row = vec![
            "Email Campaign Statistics".to_string(),
            "Renamed Campaign 'Clean List' July 1 2026, 11:41 am July 1 2026, 11:42 am 500 0 0 View Export Print Delete".to_string(),
            "New Campaign 'Clean List' July 1 2026, 11:43 am July 1 2026, 11:44 am 1 0 0 View Export Print Delete".to_string(),
        ];
        let shifted_same_count = vec![
            "Email Campaign Statistics".to_string(),
            "New Campaign 'Another List' July 1 2026, 11:43 am July 1 2026, 11:44 am 1 0 0 View Export Print Delete".to_string(),
        ];

        assert!(!rows_unchanged_for_send_proof(
            &before,
            &renamed_existing_row
        ));
        assert!(stats_rows_stable_for_no_send_proof(
            &before,
            &renamed_existing_row
        ));
        assert!(!stats_rows_stable_for_no_send_proof(
            &before,
            &added_stats_row
        ));
        assert!(!stats_rows_stable_for_no_send_proof(
            &before,
            &shifted_same_count
        ));
    }

    #[test]
    fn no_send_stats_stability_allows_existing_metric_and_encoding_churn() {
        let before = vec![
            "Email Campaign Statistics".to_string(),
            "Daily Update - 2026-07-06 PM 'Primary Clean Segment - 2026-07-03\u{fffd} ... July 6 2026, 8:31 am July 6 2026, 8:52 am 34,019 3 0 View Export Print Delete".to_string(),
        ];
        let after = vec![
            "Email Campaign Statistics".to_string(),
            "Daily Update - 2026-07-06 PM 'Primary Clean Segment - 2026-07-03&# ... July 6 2026, 8:31 am July 6 2026, 8:52 am 34,019 4 1 View Export Print Delete".to_string(),
        ];
        let new_row_same_page = vec![
            "Email Campaign Statistics".to_string(),
            "Daily Update - 2026-07-06 PM 'Primary Clean Segment - 2026-07-03&# ... July 6 2026, 8:31 am July 6 2026, 8:52 am 34,019 4 1 View Export Print Delete".to_string(),
            "Daily Update - Later Probe 'Risk Probe' July 6 2026, 11:06 am July 6 2026, 11:07 am 500 0 0 View Export Print Delete".to_string(),
        ];

        assert!(stats_rows_stable_for_no_send_proof(&before, &after));
        assert!(!stats_rows_stable_for_no_send_proof(
            &before,
            &new_row_same_page
        ));
    }

    #[test]
    fn no_send_stats_stability_uses_final_timestamp_pair_when_labels_have_dates() {
        let before = vec![
            "Email Campaign Statistics".to_string(),
            "Daily Update July 1 2026, 10:00 am July 2 2026, 10:00 am 500 'Primary Segment' July 6 2026, 8:31 am July 6 2026, 8:52 am 34,019 3 0 View Export Print Delete".to_string(),
        ];
        let after_actual_time_changed = vec![
            "Email Campaign Statistics".to_string(),
            "Daily Update July 1 2026, 10:00 am July 2 2026, 10:00 am 500 'Primary Segment' July 6 2026, 8:31 am July 6 2026, 8:53 am 34,019 3 0 View Export Print Delete".to_string(),
        ];

        assert!(!stats_rows_stable_for_no_send_proof(
            &before,
            &after_actual_time_changed
        ));
    }

    #[test]
    fn stable_stats_identity_delta_is_order_independent_and_duplicate_aware() {
        let first = "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0";
        let second = "Campaign Beta 'List Two' July 1 2026, 11:43 am July 1 2026, 11:44 am 25 0 0";
        let before = vec![first.to_string(), first.to_string(), second.to_string()];
        let reordered = vec![second.to_string(), first.to_string(), first.to_string()];
        let duplicate_removed = vec![second.to_string(), first.to_string()];
        let duplicate_added = vec![
            second.to_string(),
            first.to_string(),
            first.to_string(),
            first.to_string(),
        ];

        assert_eq!(
            stable_stats_identity_delta(&before, &reordered),
            StableStatsIdentityDelta {
                added: 0,
                removed: 0,
            }
        );
        assert_eq!(
            stable_stats_identity_delta(&before, &duplicate_removed),
            StableStatsIdentityDelta {
                added: 0,
                removed: 1,
            }
        );
        assert_eq!(
            stable_stats_identity_delta(&before, &duplicate_added),
            StableStatsIdentityDelta {
                added: 1,
                removed: 0,
            }
        );
    }

    #[test]
    fn guarded_send_terminal_reconciliation_rejects_mutable_stats_text_and_popup_job() {
        let queue = Vec::new();
        let stats_before = vec![
            "Email Campaign Statistics".to_string(),
            "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_after = vec![
            "Email Campaign Statistics".to_string(),
            "Campaign Alpha Renamed 'List One&#' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 4 1 View Export Print Delete".to_string(),
        ];
        let stats_identity = stats_identity_inventory(&[(70, 25)]);

        let report = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: Some("synthetic-body-sha256".to_string()),
            queue_before: &queue,
            queue_after: &queue,
            stats_before: &stats_before,
            stats_after: &stats_after,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &stats_identity,
            stats_identity_after: &stats_identity,
            expected_recipient_count: 999,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: Some(7001),
            job_active_after: Some(false),
            smtp_reason: None,
            popup_steps: 2,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: vec!["send popup loop stopped after a repeated route".to_string()],
        });

        assert_eq!(report.status, SendApplyStatus::Queued);
        assert!(!report.terminal_application_proven());
        assert_eq!(report.stat_id, None);
        assert_eq!(report.sent_count, None);
        assert_eq!(report.failed_count, None);
        assert_eq!(report.unsent_count, None);
        assert!(report.follow_up_contract.is_some());
        assert!(report
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("stable Stats identities were unchanged")));
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("repeated route")));
    }

    #[test]
    fn guarded_send_terminal_reconciliation_rejects_same_count_identity_replacement() {
        let queue = Vec::new();
        let stats_before = vec![
            "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_after = vec![
            "Campaign Beta 'List Two' July 1 2026, 11:43 am July 1 2026, 11:44 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_identity_before = stats_identity_inventory(&[(70, 25)]);
        let stats_identity_after = stats_identity_inventory(&[(71, 25)]);

        assert_eq!(
            stable_stats_identity_delta(&stats_before, &stats_after),
            StableStatsIdentityDelta {
                added: 1,
                removed: 1
            }
        );

        let report = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            queue_before: &queue,
            queue_after: &queue,
            stats_before: &stats_before,
            stats_after: &stats_after,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &stats_identity_before,
            stats_identity_after: &stats_identity_after,
            expected_recipient_count: 25,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: Some(7001),
            job_active_after: Some(false),
            smtp_reason: None,
            popup_steps: 1,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: Vec::new(),
        });

        assert_eq!(report.status, SendApplyStatus::Queued);
        assert!(!report.terminal_application_proven());
        assert_eq!(report.sent_count, None);
        assert!(report
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("1 added and 1 removed")));
    }

    #[test]
    fn guarded_send_terminal_reconciliation_rejects_stats_identity_while_job_is_active() {
        let queue_before = Vec::new();
        let queue_after = vec!["Campaign Alpha Waiting Action Job".to_string()];
        let stats_before = vec![
            "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_after = vec![
            "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0 View Export Print Delete".to_string(),
            "Campaign Gamma 'List Three' July 1 2026, 11:45 am July 1 2026, 11:46 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_identity_before = stats_identity_inventory(&[(70, 25)]);
        let stats_identity_after = stats_identity_inventory(&[(70, 25), (71, 25)]);

        let report = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            queue_before: &queue_before,
            queue_after: &queue_after,
            stats_before: &stats_before,
            stats_after: &stats_after,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &stats_identity_before,
            stats_identity_after: &stats_identity_after,
            expected_recipient_count: 25,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: Some(7001),
            job_active_after: Some(true),
            smtp_reason: None,
            popup_steps: 1,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: Vec::new(),
        });

        assert_eq!(report.status, SendApplyStatus::Queued);
        assert!(!report.terminal_application_proven());
        assert_eq!(report.stat_id, None);
        assert_eq!(report.sent_count, None);
        assert!(report.follow_up_contract.is_some());
        assert!(report
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("still exposed an active")));
    }

    #[test]
    fn guarded_send_terminal_reconciliation_rejects_unrelated_same_count_stats_row() {
        let queue = Vec::new();
        let stats_identity_before = stats_identity_inventory(&[(70, 25)]);
        let mut stats_identity_after = stats_identity_before.clone();
        stats_identity_after
            .rows
            .extend(stats_identity_inventory_for("Campaign Beta", &[(71, 25)]).rows);

        let report = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            queue_before: &queue,
            queue_after: &queue,
            stats_before: &queue,
            stats_after: &queue,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &stats_identity_before,
            stats_identity_after: &stats_identity_after,
            expected_recipient_count: 25,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: Some(7001),
            job_active_after: Some(false),
            smtp_reason: None,
            popup_steps: 1,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: Vec::new(),
        });

        assert_eq!(report.status, SendApplyStatus::Queued);
        assert!(!report.terminal_application_proven());
        assert_eq!(report.stat_id, None);
        assert!(report
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("no application-native association")));
    }

    #[test]
    fn concurrent_same_name_same_count_stats_row_remains_nonterminal() {
        let queue = Vec::new();
        let stats_before = vec![
            "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_after = vec![
            "Campaign Alpha 'List One' July 1 2026, 11:41 am July 1 2026, 11:42 am 25 0 0 View Export Print Delete".to_string(),
            "Campaign Alpha 'List Two' July 1 2026, 11:43 am July 1 2026, 11:44 am 25 0 0 View Export Print Delete".to_string(),
        ];
        let stats_identity_before = stats_identity_inventory(&[(70, 25)]);
        let stats_identity_after = stats_identity_inventory(&[(70, 25), (71, 25)]);

        let report = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            queue_before: &queue,
            queue_after: &queue,
            stats_before: &stats_before,
            stats_after: &stats_after,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &stats_identity_before,
            stats_identity_after: &stats_identity_after,
            expected_recipient_count: 25,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: Some(7001),
            job_active_after: Some(false),
            smtp_reason: None,
            popup_steps: 1,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: Vec::new(),
        });

        assert_eq!(report.status, SendApplyStatus::Queued);
        assert!(!report.terminal_application_proven());
        assert_eq!(report.job_id, Some(7001));
        assert_eq!(report.stat_id, None);
        assert_eq!(report.sent_count, None);
        assert_eq!(report.failed_count, None);
        assert_eq!(report.unsent_count, None);
        assert!(report.follow_up_contract.is_some());
        assert!(report
            .proof_gaps
            .iter()
            .any(|gap| gap.contains("no application-native association")));
    }

    #[test]
    fn guarded_send_terminal_reconciliation_preserves_posted_and_transport_controls() {
        let rows = Vec::new();
        let posted = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            queue_before: &rows,
            queue_after: &rows,
            stats_before: &rows,
            stats_after: &rows,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &empty_stats_identity_inventory(),
            stats_identity_after: &empty_stats_identity_inventory(),
            expected_recipient_count: 25,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: None,
            job_active_after: Some(false),
            smtp_reason: None,
            popup_steps: 0,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: Vec::new(),
        });
        let transport_failed = guarded_send_terminal_reconciliation(GuardedSendTerminalInput {
            campaign_id: 9001,
            list_ids: &[8001],
            expected_body_sha256: None,
            queue_before: &rows,
            queue_after: &rows,
            stats_before: &rows,
            stats_after: &rows,
            schedule_job_ids_before: &BTreeSet::new(),
            manage_job_ids_before: &BTreeSet::new(),
            campaign_job_ids_before: &BTreeSet::new(),
            stats_identity_before: &empty_stats_identity_inventory(),
            stats_identity_after: &empty_stats_identity_inventory(),
            expected_recipient_count: 25,
            baseline_max_rows: 25,
            baseline_context_verified: true,
            baseline_identity_stable: true,
            baseline_capture_stage: SendBaselineCaptureStage::FinalPreDispatch,
            job_id: Some(7001),
            job_active_after: Some(false),
            smtp_reason: Some("synthetic transport failure".to_string()),
            popup_steps: 1,
            approved_cron_schedule: false,
            response_uncertain: false,
            reconciliation_readback_complete: true,
            job_identity_ambiguous: false,
            proof_gaps: Vec::new(),
            notes: Vec::new(),
        });

        assert_eq!(posted.status, SendApplyStatus::Posted);
        assert!(posted.follow_up_contract.is_none());
        assert_eq!(transport_failed.status, SendApplyStatus::TransportFailed);
        assert_eq!(transport_failed.sent_count, None);
        assert_eq!(transport_failed.failed_count, None);
        assert_eq!(transport_failed.unsent_count, None);
        assert!(!transport_failed.terminal_application_proven());
    }

    #[test]
    fn production_preflight_refusal_ignores_non_blocking_readiness_warnings() {
        let warnings = send_apply_preflight_refusal_warnings(
            "production",
            true,
            Some("Expected Subject"),
            Some("Expected Subject"),
            Some("expected-html-sha"),
            Some("expected-html-sha"),
        );

        assert!(warnings.is_empty());
    }

    #[test]
    fn production_preflight_refusal_keeps_blocking_subject_and_hash_mismatches() {
        let warnings = send_apply_preflight_refusal_warnings(
            "production",
            true,
            Some("Wrong Subject"),
            Some("Expected Subject"),
            Some("wrong-html-sha"),
            Some("expected-html-sha"),
        );

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("campaign subject did not match")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("campaign HTML SHA-256 did not match")));
    }

    #[test]
    fn seed_preflight_refusal_allows_absent_optional_subject_and_hash_expectations() {
        let warnings = send_apply_preflight_refusal_warnings(
            "seed",
            true,
            Some("Current Subject"),
            None,
            Some("current-html-sha"),
            None,
        );

        assert!(warnings.is_empty());
    }

    #[test]
    fn send_preflight_refusal_keeps_readiness_gate_blocker() {
        let warnings = send_apply_preflight_refusal_warnings(
            "seed",
            false,
            Some("Current Subject"),
            None,
            Some("current-html-sha"),
            None,
        );

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("readiness gates did not pass")));
    }

    #[test]
    fn seed_send_apply_warnings_label_http_200_without_job_as_posted_unproven() {
        let reconciliation = SendReconciliationReport::new(
            SendApplyStatus::Posted,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            0,
            2,
            2,
            3,
            3,
            vec![
                "final send boundary posted but no popup, queue, or stats processing evidence was found"
                    .to_string(),
            ],
            Vec::new(),
        );

        let warnings = seed_send_apply_warnings(&reconciliation);

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("durable application identity")));
        assert!(!warnings
            .iter()
            .any(|warning| warning.contains("recipient render still require")));
    }

    #[test]
    fn seed_send_apply_warnings_name_the_missing_native_stats_association() {
        let reconciliation = SendReconciliationReport::new(
            SendApplyStatus::Queued,
            Some(41),
            None,
            None,
            Some(25),
            Some(0),
            Some(0),
            None,
            2,
            1,
            2,
            1,
            1,
            Vec::new(),
            Vec::new(),
        );

        let warnings = seed_send_apply_warnings(&reconciliation);

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("no application-native job-to-Stats association")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("nonterminal readback context")));
        assert_eq!(reconciliation.sent_count, None);
    }

    #[test]
    fn guarded_send_popup_url_finds_started_continuation() {
        let html = r#"
            <html><body>
              <script>
                window.location = 'index.php?Page=Send&Action=Send&Job=2&Started=1&csrfToken=abc';
              </script>
            </body></html>
        "#;

        let url = guarded_send_popup_url("https://example.test/admin/", html)
            .expect("popup parser")
            .expect("popup continuation");

        assert!(url.as_str().contains("Action=Send"));
        assert!(url.as_str().contains("Started=1"));
    }

    #[test]
    fn transport_failure_reason_is_redacted_and_bounded() {
        let reason = transport_failure_reason(
            "<html><body>SMTP error: authentication failed for recipient@example.invalid using fixture credential</body></html>",
        )
        .expect("failure marker");

        assert!(reason.contains("SMTP error") || reason.contains("smtp error"));
        assert!(!reason.contains("recipient@example.invalid"));
        assert!(reason.len() <= 260);
    }

    #[test]
    fn step4_response_summary_classifies_and_redacts_refusal_text() {
        let summary = step4_response_summary(
            "<html><body>Access denied for recipient@example.invalid while sending campaign</body></html>",
        )
        .expect("summary");

        assert!(summary.starts_with("access_denied;"));
        assert!(!summary.contains("recipient@example.invalid"));
        assert!(summary.len() <= 280);
    }

    #[test]
    fn final_send_wizard_page_requires_list_evidence() {
        let html = r#"
            <form name="frmSend" action="index.php?Page=Send&Action=Step3">
              <select name="newsletter">
                <option value="7" selected>Launch campaign</option>
              </select>
              <p>2 recipients selected</p>
            </form>
        "#;

        let report = parse_send_wizard_final_page(7, &[3], html).expect("parse final page");

        assert!(report.selected_list_ids.is_empty());
        assert!(!report.ok);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("did not expose selected list ids")));
    }

    #[test]
    fn list_ids_warning_accepts_recipient_count_proof() {
        assert!(list_ids_warning(&[], &[1], true).is_none());
        assert!(list_ids_warning(&[1], &[1], false).is_none());

        let missing = list_ids_warning(&[], &[1], false).expect("missing warning");
        assert!(missing.contains("could not be proven"));

        let mismatch = list_ids_warning(&[2], &[1], false).expect("mismatch warning");
        assert!(mismatch.contains("did not match"));
    }

    #[test]
    fn selected_list_ids_ignore_unchecked_controls() {
        let html = r#"
            <form name="frmSend" action="index.php?Page=Send&Action=Step3">
              <input type="checkbox" name="lists[]" value="3">
              <input type="checkbox" name="lists[]" value="4" checked>
              <input type="hidden" name="lists[]" value="5">
            </form>
        "#;

        assert_eq!(selected_or_hidden_list_ids(html).unwrap(), Some(vec![4, 5]));
    }

    #[test]
    fn recipient_count_marker_checks_later_marker_occurrences() {
        let html = "<p>Recipient options</p><p>1,234 recipients selected</p>";

        assert_eq!(recipient_count_marker(html), Some(1_234));
    }
}

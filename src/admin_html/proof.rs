use super::{
    admin_evidence, compact_text, ensure_authenticated_html, extract_login_csrf_token, forms,
    parse_table_rows, redact_field_value, route_fingerprint, AdminHtmlClient,
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
        SeedSendApplyRequest, SendApplyStatus, SendReconciliationReport, SendWizardReadbackReport,
        SendWizardReadbackRequest, MAX_SEED_SEND_RECIPIENTS, PRODUCTION_SEND_CONFIRMATION_PHRASE,
    },
    safety::{self, AdminReadPage},
};
use mcp_toolkit_observability::redaction::truncate;
use reqwest::blocking::RequestBuilder;
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Write, path::Path};
use url::Url;

const MAX_SEND_POPUP_STEPS: usize = 25;

#[derive(Debug, Clone)]
struct GuardedSendEvidence {
    status_code: u16,
    redirected: bool,
    reconciliation: SendReconciliationReport,
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

        let resolved = self.resolve_campaign_body_html(campaign_id)?;
        let mut report = campaign_body_audit_from_html(campaign_id, &resolved.html)?;
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
            return Ok(report);
        }
        report.evidence.notes.push(
            "allowlisted Newsletter edit Step1 POST rendered Interspire 8 Step2 body page; Complete/save form was not posted"
                .to_string(),
        );
        Ok(report)
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
        let stats_before =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
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
        report.queue_unchanged = queue_before == queue_after;
        report.stats_unchanged = stats_before == stats_after;

        if !report.queue_unchanged {
            report
                .warnings
                .push("Schedule queue rows changed during no-send wizard proof".to_string());
        }
        if !report.stats_unchanged {
            report
                .warnings
                .push("Stats rows changed during no-send wizard proof".to_string());
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
            "campaign_has_single_unsubscribe",
            campaign_body.unsubscribe_token_count == 1,
            "blocker",
            format!(
                "unsubscribe token count is {}",
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
            "stats rows unchanged during no-send proof".to_string(),
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
        let mut warnings = readiness.warnings.clone();
        if !readiness.ready_for_seed_approval || !readiness.gates.iter().all(|gate| gate.passed) {
            warnings.push("seed send refused because readiness gates did not pass".to_string());
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

        if let Some(expected_subject) = request.expected_subject.as_deref() {
            if readiness.campaign_body.subject.as_deref() != Some(expected_subject) {
                warnings.push(
                    "seed send refused because campaign subject did not match expected_subject"
                        .to_string(),
                );
            }
        }
        if let Some(expected_hash) = request.expected_html_sha256.as_deref() {
            if readiness.campaign_body.html_sha256.as_deref() != Some(expected_hash) {
                warnings.push(
                    "seed send refused because campaign HTML SHA-256 did not match expected_html_sha256"
                        .to_string(),
                );
            }
        }
        if !warnings.is_empty() {
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
        let queue_before = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_before =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
        let (send_wizard, final_html) = self.render_send_wizard_final_page(
            &SendWizardReadbackRequest {
                campaign_id: request.campaign_id,
                list_ids: request.list_ids.clone(),
                expected_recipient_count: Some(request.expected_recipient_count),
                max_queue_rows: request.max_queue_rows,
            },
            max_rows,
        )?;
        if !send_wizard.ok {
            let mut warnings = send_wizard.warnings.clone();
            warnings
                .push("seed send refused because the final send wizard proof failed".to_string());
            return Ok(self.seed_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                readiness.campaign_body,
                send_wizard,
                readiness.gates,
                false,
                None,
                false,
                queue_before.len(),
                queue_before.len(),
                stats_before.len(),
                stats_before.len(),
                None,
                warnings,
            ));
        }
        if matches!(send_wizard.send_immediately_checked, Some(false)) {
            let warnings = vec![
                "seed send refused because final form did not select immediate send".to_string(),
            ];
            return Ok(self.seed_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                readiness.campaign_body,
                send_wizard,
                readiness.gates,
                false,
                None,
                false,
                queue_before.len(),
                queue_before.len(),
                stats_before.len(),
                stats_before.len(),
                None,
                warnings,
            ));
        }

        let send_evidence = self.post_guarded_send_and_reconcile(
            guarded_send_final_form_post_for_request(
                self.config.base_url.as_deref().unwrap_or_default(),
                &final_html,
                request.campaign_id,
                &request.list_ids,
            )?,
            &queue_before,
            &stats_before,
            request.expected_recipient_count,
            true,
            max_rows,
        )?;
        let sent = matches!(
            send_evidence.reconciliation.status,
            SendApplyStatus::SeedProven
        ) && send_evidence.reconciliation.job_id.is_some();
        let warnings = seed_send_apply_warnings(&send_evidence.reconciliation);

        Ok(self.seed_send_report_from_parts(
            request,
            guarded_writes_enabled,
            send_controls_enabled,
            readiness.campaign_body,
            send_wizard,
            readiness.gates,
            sent,
            Some(send_evidence.status_code),
            send_evidence.redirected,
            queue_before.len(),
            send_evidence.reconciliation.queue_rows_after,
            stats_before.len(),
            send_evidence.reconciliation.stats_rows_after,
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
        let mut warnings = readiness.warnings.clone();
        if !readiness.ready_for_seed_approval || !readiness.gates.iter().all(|gate| gate.passed) {
            warnings
                .push("production send refused because readiness gates did not pass".to_string());
        }
        if readiness.campaign_body.subject.as_deref() != Some(request.expected_subject.as_str()) {
            warnings.push(
                "production send refused because campaign subject did not match expected_subject"
                    .to_string(),
            );
        }
        if readiness.campaign_body.html_sha256.as_deref()
            != Some(request.expected_html_sha256.as_str())
        {
            warnings.push(
                "production send refused because campaign HTML SHA-256 did not match expected_html_sha256"
                    .to_string(),
            );
        }
        if !warnings.is_empty() {
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
        let queue_before = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_before =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
        let (send_wizard, final_html) = self.render_send_wizard_final_page(
            &SendWizardReadbackRequest {
                campaign_id: request.campaign_id,
                list_ids: request.list_ids.clone(),
                expected_recipient_count: Some(request.expected_recipient_count),
                max_queue_rows: request.max_queue_rows,
            },
            max_rows,
        )?;
        if !send_wizard.ok {
            let mut warnings = send_wizard.warnings.clone();
            warnings.push(
                "production send refused because the final send wizard proof failed".to_string(),
            );
            return Ok(self.production_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                readiness.campaign_body,
                send_wizard,
                readiness.gates,
                false,
                None,
                false,
                queue_before.len(),
                queue_before.len(),
                stats_before.len(),
                stats_before.len(),
                None,
                warnings,
            ));
        }
        if matches!(send_wizard.send_immediately_checked, Some(false)) {
            let warnings = vec![
                "production send refused because final form did not select immediate send"
                    .to_string(),
            ];
            return Ok(self.production_send_report_from_parts(
                request,
                guarded_writes_enabled,
                send_controls_enabled,
                production_send_controls_enabled,
                readiness.campaign_body,
                send_wizard,
                readiness.gates,
                false,
                None,
                false,
                queue_before.len(),
                queue_before.len(),
                stats_before.len(),
                stats_before.len(),
                None,
                warnings,
            ));
        }

        let send_evidence = self.post_guarded_send_and_reconcile(
            guarded_send_final_form_post_for_request(
                self.config.base_url.as_deref().unwrap_or_default(),
                &final_html,
                request.campaign_id,
                &request.list_ids,
            )?,
            &queue_before,
            &stats_before,
            request.expected_recipient_count,
            false,
            max_rows,
        )?;
        let sent = send_evidence.reconciliation.status.terminal_success()
            && send_evidence.reconciliation.job_id.is_some();
        let warnings = production_send_apply_warnings(&send_evidence.reconciliation);

        Ok(self.production_send_report_from_parts(
            request,
            guarded_writes_enabled,
            send_controls_enabled,
            production_send_controls_enabled,
            readiness.campaign_body,
            send_wizard,
            readiness.gates,
            sent,
            Some(send_evidence.status_code),
            send_evidence.redirected,
            queue_before.len(),
            send_evidence.reconciliation.queue_rows_after,
            stats_before.len(),
            send_evidence.reconciliation.stats_rows_after,
            Some(send_evidence.reconciliation),
            warnings,
        ))
    }

    fn post_guarded_send_and_reconcile(
        &self,
        send_form: (Url, Vec<(String, String)>),
        queue_before: &[String],
        stats_before: &[String],
        expected_recipient_count: u64,
        seed_send: bool,
        max_rows: usize,
    ) -> Result<GuardedSendEvidence, InterspireError> {
        let (send_url, send_pairs) = send_form;
        let response = self
            .proof_post_with_page_context(send_url, &send_pairs, &AdminReadPage::SendStart.path())?
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        let status = response.status();
        let status_code = status.as_u16();
        let redirected = status.is_redirection();
        let mut popup_steps = 0usize;
        let mut job_id = None;
        let mut smtp_reason = None;
        let mut popup_notes = Vec::new();
        let mut seen_popup_urls = HashSet::new();
        let mut next_popup_url = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|location| {
                safety::ensure_allowed_guarded_send_popup(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    location,
                )
                .ok()
            });

        if status.is_success() {
            let html = response
                .text()
                .map_err(|err| InterspireError::Http(err.to_string()))?;
            if !html.trim().is_empty() {
                ensure_authenticated_html(&html)?;
                smtp_reason = transport_failure_reason(&html);
                next_popup_url = next_popup_url.or(guarded_send_popup_url(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &html,
                )?);
            }
        } else if !redirected {
            return Err(InterspireError::Http(format!(
                "guarded send final form returned HTTP {}",
                status_code
            )));
        }

        while let Some(url) = next_popup_url.take() {
            if popup_steps >= MAX_SEND_POPUP_STEPS {
                popup_notes.push("send popup loop stopped at the maximum step guard".to_string());
                break;
            }
            let url_key = url.as_str().to_string();
            if !seen_popup_urls.insert(url_key) {
                popup_notes.push("send popup loop stopped after a repeated route".to_string());
                break;
            }
            job_id = job_id.or_else(|| send_popup_job_id(&url));
            let response = self
                .with_access_headers(self.http.get(url))
                .send()
                .map_err(|err| InterspireError::Http(err.to_string()))?;
            let popup_status = response.status();
            let popup_location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|location| {
                    safety::ensure_allowed_guarded_send_popup(
                        self.config.base_url.as_deref().unwrap_or_default(),
                        location,
                    )
                    .ok()
                });
            if !popup_status.is_success() && !popup_status.is_redirection() {
                return Err(InterspireError::Http(format!(
                    "send popup route returned HTTP {}",
                    popup_status.as_u16()
                )));
            }
            popup_steps += 1;
            if popup_status.is_redirection() {
                next_popup_url = popup_location;
                continue;
            }
            let html = response
                .text()
                .map_err(|err| InterspireError::Http(err.to_string()))?;
            if !html.trim().is_empty() {
                ensure_authenticated_html(&html)?;
                smtp_reason = smtp_reason.or_else(|| transport_failure_reason(&html));
                next_popup_url = popup_location.or(guarded_send_popup_url(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &html,
                )?);
            }
        }

        let queue_after = parse_table_rows(
            &self.get_allowed(&AdminReadPage::Schedule.path())?,
            max_rows,
        )?;
        let stats_after =
            parse_table_rows(&self.get_allowed(&AdminReadPage::Stats.path())?, max_rows)?;
        let stats_increased = stats_after.len() > stats_before.len();
        let queued = queue_after.len() > queue_before.len();
        let sent_count = if stats_increased || popup_steps > 0 {
            Some(expected_recipient_count)
        } else {
            None
        };
        let failed_count = smtp_reason.as_ref().map(|_| expected_recipient_count);
        let unsent_count = if smtp_reason.is_some() {
            Some(expected_recipient_count)
        } else {
            Some(0).filter(|_| stats_increased || popup_steps > 0)
        };
        let mut proof_gaps = Vec::new();
        let status = if smtp_reason.is_some() {
            SendApplyStatus::TransportFailed
        } else if stats_increased && seed_send {
            proof_gaps.push("provider inbox delivery still requires external readback".to_string());
            SendApplyStatus::SeedProven
        } else if stats_increased {
            proof_gaps.push(
                "provider delivery, bounces, and complaints require external monitoring"
                    .to_string(),
            );
            SendApplyStatus::Processed
        } else if queued || popup_steps > 0 {
            proof_gaps.push("Stats page did not yet show a completed send row".to_string());
            SendApplyStatus::Queued
        } else {
            proof_gaps.push(
                "final send boundary posted but no popup, queue, or stats processing evidence was found"
                    .to_string(),
            );
            SendApplyStatus::Posted
        };
        if job_id.is_none() {
            proof_gaps
                .push("Interspire job id was not found in redacted send-loop evidence".to_string());
        }
        if stats_increased {
            popup_notes.push("Stats row count increased after guarded send loop".to_string());
        }
        if queued {
            popup_notes.push("Schedule row count increased after guarded send loop".to_string());
        }

        Ok(GuardedSendEvidence {
            status_code,
            redirected,
            reconciliation: SendReconciliationReport::new(
                status,
                job_id,
                None,
                None,
                sent_count,
                failed_count,
                unsent_count,
                smtp_reason,
                popup_steps,
                queue_before.len(),
                queue_after.len(),
                stats_before.len(),
                stats_after.len(),
                proof_gaps,
                popup_notes,
            ),
        })
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
        report.queue_unchanged = queue_before == queue_after;
        report.stats_unchanged = stats_before == stats_after;

        if !report.queue_unchanged {
            report
                .warnings
                .push("Schedule queue rows changed during no-send wizard proof".to_string());
        }
        if !report.stats_unchanged {
            report
                .warnings
                .push("Stats rows changed during no-send wizard proof".to_string());
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
            send_wizard,
            campaign_body,
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
                "campaign body audit and send wizard proof passed immediately before final send form post".to_string(),
                "final send form controls were captured from the live Interspire page and posted to the guarded seed-send route".to_string(),
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
            send_wizard,
            campaign_body,
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
                "campaign body audit and send wizard proof passed immediately before final send form post".to_string(),
                "final send form controls were captured from the live Interspire page and posted to the guarded production-send route".to_string(),
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
    let unsubscribe_token_count =
        count_unsubscribe_tokens(&html_body) + count_unsubscribe_tokens(&text_body);
    let mut warnings = Vec::new();
    if unsubscribe_token_count != 1 {
        warnings.push(format!(
            "expected exactly one unsubscribe token, found {unsubscribe_token_count}"
        ));
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
        html_sha256: (!html_body.is_empty()).then(|| sha256_hex(&html_body)),
        html_bytes: html_body.len(),
        text_sha256: (!text_body.is_empty()).then(|| sha256_hex(&text_body)),
        text_bytes: text_body.len(),
        unsubscribe_token_count,
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

fn guarded_send_final_form_post_for_request(
    base_url: &str,
    html: &str,
    campaign_id: u64,
    list_ids: &[u64],
) -> Result<(Url, Vec<(String, String)>), InterspireError> {
    let (action_url, mut pairs) = guarded_send_final_form_post(base_url, html)?;
    bind_guarded_send_request_pairs(&mut pairs, campaign_id, list_ids)?;
    Ok((action_url, pairs))
}

fn bind_guarded_send_request_pairs(
    pairs: &mut Vec<(String, String)>,
    campaign_id: u64,
    list_ids: &[u64],
) -> Result<(), InterspireError> {
    if list_ids.is_empty() {
        return Err(InterspireError::Safety(
            "guarded final send post requires at least one request-bound list id".to_string(),
        ));
    }

    // Interspire 8 can render Step4 with selection state held in the session
    // rather than echoed as final form controls. Only after the no-send proof
    // has accepted the exact request do we bind those campaign/list ids into
    // the final POST, so a de-selected HTML control cannot drift the send.
    upsert_post_pair(pairs, "newsletter", &campaign_id.to_string());
    pairs.retain(|(name, _)| !is_guarded_send_list_selection_name(name));
    for list_id in list_ids {
        pairs.push(("lists[]".to_string(), list_id.to_string()));
    }
    Ok(())
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

fn guarded_send_popup_url(base_url: &str, html: &str) -> Result<Option<Url>, InterspireError> {
    for candidate in send_popup_path_candidates(html) {
        if let Ok(url) = safety::ensure_allowed_guarded_send_popup(base_url, &candidate) {
            return Ok(Some(url));
        }
    }
    Ok(None)
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

fn send_popup_job_id(url: &Url) -> Option<u64> {
    for key in ["job", "Job", "jobid", "JobID", "id", "sendid", "SendID"] {
        if let Some(value) = url
            .query_pairs()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .and_then(|(_, value)| value.as_ref().parse::<u64>().ok())
        {
            return Some(value);
        }
    }
    None
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

fn send_apply_warnings(
    reconciliation: &SendReconciliationReport,
    label: &str,
    external_monitoring_warning: &str,
) -> Vec<String> {
    let mut warnings = match reconciliation.status {
        SendApplyStatus::Posted => vec![format!(
            "{label} final form was posted but remains posted-unproven; no Interspire job, popup, queue, or stats processing proof was found"
        )],
        SendApplyStatus::Queued => vec![format!(
            "{label} reached the guarded Interspire send loop but remains unproven until job id plus queue/stats processing evidence is present"
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
    if reconciliation.status.terminal_success() && reconciliation.job_id.is_none() {
        warnings.push(format!(
            "{label} is not marked sent because the Interspire job id was not proven"
        ));
    }
    warnings
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
    use super::{
        append_csrf_pair_if_missing, campaign_body_audit_from_html, campaign_body_parts_from_html,
        campaign_body_step1_pairs, campaign_body_step2_action_path, campaign_test_send_digest,
        campaign_test_send_has_applyable_html, campaign_test_send_report, csrf_pair,
        expected_public_subject_matches, guarded_send_final_form_post,
        guarded_send_final_form_post_for_request, guarded_send_popup_url, list_ids_warning,
        optional_nonempty_sha256, parse_send_wizard_final_page, preview_send_response_success,
        recipient_count_marker, seed_send_apply_warnings, selected_or_hidden_list_ids,
        send_step2_action_path, sha256_hex, transport_failure_reason,
        validate_single_preview_email,
    };
    use crate::{
        redact,
        response::{
            CampaignBodyAuditReport, CampaignTestSendApplyRequest, SendApplyStatus,
            SendReconciliationReport,
        },
    };

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
        assert!(report.html_bytes > 0);
        assert_eq!(report.http_url_count, 0);
        assert_eq!(report.https_url_count, 1);
        assert_eq!(report.image_count, 1);
        assert_eq!(report.missing_alt_image_count, 0);
        assert!(!serialized.contains("myDevEditControl_html"));
        assert!(!serialized.contains("%%UNSUBSCRIBELINK%%"));
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
    fn guarded_send_final_form_post_binds_interspire_8_request_campaign_and_list() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Step4&csrfToken=abc">
              <input type="hidden" name="csrfToken" value="abc">
              <select name="newsletter">
                <option value="0" selected>Please select an email campaign</option>
                <option value="2">Example Campaign</option>
              </select>
              <input name="sendfromemail" value="sender@example.invalid">
              <input type="checkbox" name="trackopens" value="1" checked>
              <input type="submit" name="SendButton" value="Send now">
            </form>
        "#;

        let (url, pairs) =
            guarded_send_final_form_post_for_request("https://example.test/admin/", html, 2, &[9])
                .expect("request-bound guarded send final form post");

        assert!(url.as_str().contains("Page=Send&Action=Step4"));
        assert_eq!(
            pairs
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("newsletter"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["2"]
        );
        assert_eq!(
            pairs
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("lists[]"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["9"]
        );
        assert!(pairs.contains(&("SendButton".to_string(), "Send now".to_string())));
    }

    #[test]
    fn guarded_send_final_form_post_replaces_stale_list_controls() {
        let html = r#"
            <form action="index.php?Page=Send&Action=Step4">
              <input type="hidden" name="newsletter" value="2">
              <input type="hidden" name="lists[]" value="1">
              <input type="hidden" name="listid" value="4">
              <input type="submit" name="SendButton" value="Send now">
            </form>
        "#;

        let (_, pairs) =
            guarded_send_final_form_post_for_request("https://example.test/admin/", html, 2, &[9])
                .expect("request-bound guarded send final form post");

        assert_eq!(
            pairs
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("lists[]"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["9"]
        );
        assert!(!pairs
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("listid") && value == "4"));
        assert!(!pairs
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("lists[]") && value == "1"));
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
            .any(|warning| warning.contains("posted-unproven")));
        assert!(!warnings
            .iter()
            .any(|warning| warning.contains("recipient render still require")));
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

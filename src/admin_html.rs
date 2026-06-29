//! Authenticated Interspire admin HTML readback adapter.
//!
//! This module owns the brittle admin HTML boundary for allowlisted GET-only
//! pages. It logs in with credentials supplied outside git, reads only pages
//! admitted by `safety`, parses redacted operational fields, and never exposes
//! raw saved HTML, cookies, passwords, contact exports, or send/cron actions.

mod forms;

use crate::{
    config::{AdminHtmlConfig, InterspireVersion, WriteExecutionMode},
    error::InterspireError,
    guarded_write, redact,
    response::{
        CampaignReadbackReport, Evidence, FormFieldUpdate, GuardedWriteApplyReport,
        GuardedWritePreviewReport, ListSummary, QueueControlAction, QueueControlCandidate,
        QueueStatsReadbackReport, RedactedField, SensitiveFieldDenial, SensitiveFieldQueryReport,
        SensitiveFieldQueryRequest, SensitiveFieldTarget, SensitiveFieldValue, SettingsAuditReport,
        SettingsSection, SettingsSectionName, UserSmtpReadbackReport, UserSmtpSummary,
    },
    safety::{self, AdminReadPage, QueueControlRoute},
};
use mcp_toolkit_observability::redaction::truncate;
use mcp_toolkit_policy_core::{sensitive_read_policy_decision, Decision, DecisionCode};
use reqwest::{
    blocking::{Client, RequestBuilder},
    redirect::Policy,
};
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Duration};
use url::Url;

#[derive(Debug, Clone)]
pub struct AdminHtmlClient {
    config: AdminHtmlConfig,
    http: Client,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListEditMetadata {
    pub list_id: u64,
    pub owner_name: Option<String>,
    pub owner_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueueControlApplyEvidence {
    pub before_candidate_count: usize,
    pub before_row_summary: Option<String>,
    pub after_candidate_count: usize,
    pub after_row_still_present: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct QueueControlLink {
    candidate: QueueControlCandidate,
    route: QueueControlRoute,
    url: Url,
    execution: QueueControlExecution,
}

#[derive(Debug, Clone)]
enum QueueControlExecution {
    Get,
    DeletePost {
        checkbox_name: String,
        submit_name: String,
        submit_value: String,
        hidden_pairs: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone)]
struct QueueDeleteForm {
    url: Url,
    submit_name: String,
    submit_value: String,
    hidden_pairs: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoginCsrfToken {
    field_name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct SensitiveFieldQueryContext {
    target: String,
    target_id: Option<u64>,
    section: Option<String>,
}

#[derive(Debug, Clone)]
struct SensitiveFieldQueryReportInput {
    configured: bool,
    sensitive_reads_enabled: bool,
    policy_decision: Decision,
    context: SensitiveFieldQueryContext,
    denied_fields: Vec<SensitiveFieldDenial>,
    values: Vec<SensitiveFieldValue>,
    warnings: Vec<String>,
    evidence: Evidence,
}

impl AdminHtmlClient {
    pub fn new(config: AdminHtmlConfig) -> Result<Self, InterspireError> {
        let http = Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        Ok(Self { config, http })
    }

    pub fn configured(&self) -> bool {
        self.config.is_configured()
    }

    pub fn enrich_lists(&self, lists: &mut [ListSummary]) -> Result<Vec<String>, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let mut notes = Vec::new();
        let limit = self.config.enrich_limit.min(lists.len());
        for list in lists.iter_mut().take(limit) {
            let page = AdminReadPage::ListEdit { id: list.list_id };
            let html = self.get_allowed(&page.path())?;
            match parse_list_edit_metadata(list.list_id, &html) {
                Ok(metadata) => {
                    if metadata.owner_name.is_some() {
                        list.owner_name = metadata.owner_name;
                    }
                    if metadata.owner_email_redacted.is_some() {
                        list.owner_email_redacted = metadata.owner_email_redacted;
                    }
                    if metadata.reply_to_email_redacted.is_some() {
                        list.reply_to_email_redacted = metadata.reply_to_email_redacted;
                    }
                    if metadata.bounce_email_redacted.is_some() {
                        list.bounce_email_redacted = metadata.bounce_email_redacted;
                    }
                    list.source = "xml+html".to_string();
                }
                Err(err) => {
                    notes.push(format!("list {} html parse skipped: {}", list.list_id, err))
                }
            }
        }

        if lists.len() > limit {
            notes.push(format!(
                "html enrichment limited to {limit} of {} lists",
                lists.len()
            ));
        }
        Ok(notes)
    }

    pub fn settings_audit(
        &self,
        include_cron: bool,
    ) -> Result<SettingsAuditReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let mut sections = Vec::new();
        let mut tabs = vec![(1, "application"), (2, "email"), (7, "bounce")];
        if include_cron {
            tabs.push((4, "cron"));
        }

        for (tab, name) in tabs {
            let html = self.get_allowed(&AdminReadPage::Settings { tab }.path())?;
            sections.push(SettingsSection {
                name: name.to_string(),
                fields: parse_settings_fields(name, &html)?,
            });
        }

        Ok(SettingsAuditReport {
            ok: true,
            configured: true,
            sections,
            warnings: Vec::new(),
            evidence: admin_evidence(vec!["allowlisted Settings tab GET reads".to_string()]),
        })
    }

    pub fn sensitive_field_query(
        &self,
        request: &SensitiveFieldQueryRequest,
        sensitive_reads_enabled: bool,
    ) -> Result<SensitiveFieldQueryReport, InterspireError> {
        let (context, read_page) = sensitive_target_context(&request.target);
        let mut warnings = Vec::new();
        let mut denied_fields = Vec::new();
        let requested_fields = normalize_requested_fields(&request.fields);

        if !self.config.is_configured() {
            return Ok(build_sensitive_field_query_report(
                SensitiveFieldQueryReportInput {
                    configured: false,
                    sensitive_reads_enabled,
                    policy_decision: Decision::deny(
                        DecisionCode::CapabilityMissing,
                        Some("admin_html_not_configured"),
                    ),
                    context,
                    denied_fields: deny_requested_fields(
                        &request.fields,
                        "admin HTML fallback is not configured",
                    ),
                    values: Vec::new(),
                    warnings: vec![
                        "admin HTML fallback is not configured; no sensitive read attempted"
                            .to_string(),
                    ],
                    evidence: admin_evidence(vec!["no request sent".to_string()]),
                },
            ));
        }

        let policy_decision = sensitive_read_policy_decision(
            sensitive_reads_enabled,
            request.acknowledge_sensitive_output,
            &requested_fields,
        );
        if !policy_decision.allow {
            return Ok(build_sensitive_field_query_report(
                SensitiveFieldQueryReportInput {
                    configured: true,
                    sensitive_reads_enabled,
                    policy_decision,
                    context,
                    denied_fields: deny_requested_fields(
                        &request.fields,
                        "sensitive-read policy denied this request",
                    ),
                    values: Vec::new(),
                    warnings: vec![
                        "sensitive field query refused by policy core; no admin read attempted"
                            .to_string(),
                    ],
                    evidence: admin_evidence(vec!["no request sent".to_string()]),
                },
            ));
        }

        if request.fields.len() > requested_fields.len() {
            warnings.push("duplicate or blank requested fields were collapsed".to_string());
        }
        let requested_fields = requested_fields.into_iter().take(20).collect::<Vec<_>>();
        if requested_fields.len() == 20 && request.fields.len() > 20 {
            warnings.push("sensitive field query capped to first 20 unique fields".to_string());
        }

        let allowed_fields = sensitive_allowed_fields(&request.target);
        let mut approved_fields = Vec::new();
        for field in requested_fields {
            if is_forbidden_sensitive_field(&field) {
                denied_fields.push(SensitiveFieldDenial {
                    name: field,
                    reason: "password/token/license/key/cookie/API-secret shaped fields cannot be revealed by this tool family".to_string(),
                });
                continue;
            }
            if !allowed_fields.contains(&field.as_str()) {
                denied_fields.push(SensitiveFieldDenial {
                    name: field,
                    reason:
                        "field is outside the approved sensitive setup allowlist for this target"
                            .to_string(),
                });
                continue;
            }
            approved_fields.push(field);
        }

        if approved_fields.is_empty() {
            warnings.push(
                "no approved sensitive setup fields were requested; no admin read attempted"
                    .to_string(),
            );
            return Ok(build_sensitive_field_query_report(
                SensitiveFieldQueryReportInput {
                    configured: true,
                    sensitive_reads_enabled: true,
                    policy_decision,
                    context,
                    denied_fields,
                    values: Vec::new(),
                    warnings,
                    evidence: admin_evidence(vec!["no request sent".to_string()]),
                },
            ));
        }

        self.login()?;
        let html = self.get_allowed(&read_page.path())?;
        let values = parse_form_values(&html)?;

        let mut revealed = Vec::new();
        for field in approved_fields {
            let Some(value) = values.get(&field).filter(|value| !value.trim().is_empty()) else {
                denied_fields.push(SensitiveFieldDenial {
                    name: field,
                    reason: "field was not present or was blank on the approved admin form"
                        .to_string(),
                });
                continue;
            };
            revealed.push(SensitiveFieldValue {
                name: field,
                value: value.clone(),
                sensitive_output: true,
            });
        }

        if !revealed.is_empty() {
            warnings.push(
                "response contains approved unredacted Interspire admin form values".to_string(),
            );
        }

        Ok(build_sensitive_field_query_report(
            SensitiveFieldQueryReportInput {
                configured: true,
                sensitive_reads_enabled: true,
                policy_decision,
                context,
                denied_fields,
                values: revealed,
                warnings,
                evidence: admin_evidence(vec![
                    "allowlisted admin form GET read".to_string(),
                    "exact requested fields only".to_string(),
                ]),
            },
        ))
    }

    pub fn user_smtp_readback(
        &self,
        max_users: usize,
    ) -> Result<UserSmtpReadbackReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let users_html = self.get_allowed(&AdminReadPage::Users.path())?;
        let user_ids = extract_user_ids(&users_html);
        let mut users = Vec::new();
        let mut warnings = Vec::new();
        for user_id in user_ids.iter().take(max_users) {
            let html = self.get_allowed(&AdminReadPage::UserEdit { id: *user_id }.path())?;
            match parse_user_smtp_summary(*user_id, &html) {
                Ok(summary) => users.push(summary),
                Err(err) => warnings.push(format!(
                    "user {user_id} parse skipped: {}",
                    redact::redact_sensitive_text(&err.to_string())
                )),
            }
        }
        if user_ids.len() > max_users {
            warnings.push(format!(
                "user readback limited to {max_users} of {} users",
                user_ids.len()
            ));
        }

        Ok(UserSmtpReadbackReport {
            ok: true,
            configured: true,
            users,
            warnings,
            evidence: admin_evidence(vec!["allowlisted Users and User edit GET reads".to_string()]),
        })
    }

    pub fn queue_stats_readback(
        &self,
        max_rows: usize,
    ) -> Result<QueueStatsReadbackReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let schedule_html = self.get_allowed(&AdminReadPage::Schedule.path())?;
        let stats_html = self.get_allowed(&AdminReadPage::Stats.path())?;
        Ok(QueueStatsReadbackReport {
            ok: true,
            configured: true,
            scheduled_rows: parse_table_rows(&schedule_html, max_rows)?,
            stats_rows: parse_table_rows(&stats_html, max_rows)?,
            warnings: Vec::new(),
            evidence: admin_evidence(vec![
                "allowlisted Schedule GET read".to_string(),
                "allowlisted Stats GET read".to_string(),
            ]),
        })
    }

    pub fn queue_control_candidates(
        &self,
        max_rows: usize,
    ) -> Result<Vec<QueueControlCandidate>, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        Ok(self
            .load_queue_control_links(max_rows)?
            .into_iter()
            .map(|link| link.candidate)
            .collect())
    }

    pub fn apply_queue_control(
        &self,
        plan_id: &str,
        action: QueueControlAction,
        max_rows: usize,
    ) -> Result<QueueControlApplyEvidence, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let before = self.load_queue_control_links(max_rows)?;
        let before_candidate_count = before.len();
        let selected = before
            .iter()
            .find(|link| link.candidate.plan_id == plan_id && link.candidate.action == action)
            .cloned()
            .ok_or_else(|| {
                InterspireError::Safety(
                    "queue control plan id was not found on the current Schedule page; preview again before applying"
                        .to_string(),
                )
            })?;

        let response = match &selected.execution {
            QueueControlExecution::Get => self
                .with_access_headers(self.http.get(selected.url.clone()))
                .send()
                .map_err(|err| InterspireError::Http(err.to_string()))?,
            QueueControlExecution::DeletePost {
                checkbox_name,
                submit_name,
                submit_value,
                hidden_pairs,
            } => {
                let identifier_value = selected.route.identifier_value.to_string();
                let mut post_pairs = hidden_pairs.clone();
                post_pairs.push((checkbox_name.clone(), identifier_value));
                post_pairs.push((submit_name.clone(), submit_value.clone()));
                self.with_access_headers(self.http.post(selected.url.clone()))
                    .form(&post_pairs)
                    .send()
                    .map_err(|err| InterspireError::Http(err.to_string()))?
            }
        };
        let status = response.status();
        if !status.is_success() && !status.is_redirection() {
            return Err(InterspireError::Http(format!(
                "queue control apply returned HTTP {}",
                status.as_u16()
            )));
        }

        if status.is_success() {
            let body = response
                .text()
                .map_err(|err| InterspireError::Http(err.to_string()))?;
            ensure_authenticated_html(&body)?;
        }

        let after = self.load_queue_control_links(max_rows)?;
        let before_row_summary = Some(selected.candidate.row_summary.clone());
        let after_row_still_present = after
            .iter()
            .any(|candidate| same_queue_control_target(&selected.route, &candidate.route));
        if after_row_still_present {
            return Err(InterspireError::Safety(
                "queue control route returned but the same queue target still appears on the Schedule page; treat apply as unconfirmed"
                    .to_string(),
            ));
        }

        Ok(QueueControlApplyEvidence {
            before_candidate_count,
            before_row_summary,
            after_candidate_count: after.len(),
            after_row_still_present,
            notes: vec![
                format!(
                    "allowlisted Schedule queue {} route applied via guarded plan id",
                    action.as_str()
                ),
                format!(
                    "admin returned HTTP {}; Schedule page re-read after apply",
                    status.as_u16()
                ),
            ],
        })
    }

    pub fn campaign_readback(
        &self,
        campaign_id: Option<u64>,
        max_rows: usize,
    ) -> Result<CampaignReadbackReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let (fields, rows, notes) = if let Some(id) = campaign_id {
            let html = self.get_allowed(&AdminReadPage::NewsletterEdit { id }.path())?;
            (
                parse_campaign_fields(&html)?,
                Vec::new(),
                vec![format!(
                    "allowlisted Newsletter edit GET read for campaign {id}"
                )],
            )
        } else {
            let html = self.get_allowed(&AdminReadPage::NewslettersManage.path())?;
            (
                Vec::new(),
                parse_table_rows(&html, max_rows)?,
                vec!["allowlisted Newsletter manage GET read".to_string()],
            )
        };

        Ok(CampaignReadbackReport {
            ok: true,
            configured: true,
            campaign_id,
            campaign_fields: fields,
            campaign_rows: rows,
            warnings: Vec::new(),
            evidence: admin_evidence(notes),
        })
    }

    pub fn campaign_update_preview(
        &self,
        campaign_id: u64,
        updates: &[FormFieldUpdate],
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        forms::guarded_write_preview(
            self,
            forms::GuardedFormTarget::Campaign { campaign_id },
            updates,
        )
    }

    pub fn campaign_update_apply(
        &self,
        campaign_id: u64,
        plan_id: &str,
        updates: &[FormFieldUpdate],
        mode: WriteExecutionMode,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        forms::guarded_write_apply(
            self,
            forms::GuardedFormTarget::Campaign { campaign_id },
            plan_id,
            updates,
            mode,
        )
    }

    pub fn list_update_preview(
        &self,
        list_id: u64,
        updates: &[FormFieldUpdate],
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        forms::guarded_write_preview(self, forms::GuardedFormTarget::List { list_id }, updates)
    }

    pub fn list_update_apply(
        &self,
        list_id: u64,
        plan_id: &str,
        updates: &[FormFieldUpdate],
        mode: WriteExecutionMode,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        forms::guarded_write_apply(
            self,
            forms::GuardedFormTarget::List { list_id },
            plan_id,
            updates,
            mode,
        )
    }

    pub fn user_update_preview(
        &self,
        user_id: u64,
        updates: &[FormFieldUpdate],
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        forms::guarded_write_preview(self, forms::GuardedFormTarget::User { user_id }, updates)
    }

    pub fn user_update_apply(
        &self,
        user_id: u64,
        plan_id: &str,
        updates: &[FormFieldUpdate],
        mode: WriteExecutionMode,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        forms::guarded_write_apply(
            self,
            forms::GuardedFormTarget::User { user_id },
            plan_id,
            updates,
            mode,
        )
    }

    pub fn settings_update_preview(
        &self,
        section: SettingsSectionName,
        updates: &[FormFieldUpdate],
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        forms::guarded_write_preview(
            self,
            forms::GuardedFormTarget::Settings { section },
            updates,
        )
    }

    pub fn settings_update_apply(
        &self,
        section: SettingsSectionName,
        plan_id: &str,
        updates: &[FormFieldUpdate],
        mode: WriteExecutionMode,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        forms::guarded_write_apply(
            self,
            forms::GuardedFormTarget::Settings { section },
            plan_id,
            updates,
            mode,
        )
    }

    fn login(&self) -> Result<(), InterspireError> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let username = self.config.username.as_deref().unwrap_or_default();
        let password = self.config.password.as_deref().unwrap_or_default();
        let login_url = safety::login_url(base_url)?;
        let csrf_token = self.login_csrf_token(&login_url)?;
        let mut form = vec![
            ("ss_username", username.to_string()),
            ("ss_password", password.to_string()),
            ("ss_takemeto", String::new()),
            ("SubmitButton", "Login".to_string()),
        ];
        if let Some(token) = csrf_token.as_ref() {
            form.push((token.field_name.as_str(), token.value.clone()));
        }

        let mut request = self
            .with_access_headers(self.http.post(login_url))
            .form(&form);
        if let Some(token) = csrf_token.as_ref() {
            request = request.header("x-csrf-token", token.value.as_str());
        }
        let response = request
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !response.status().is_success() && !response.status().is_redirection() {
            return Err(InterspireError::Http(format!(
                "admin login returned HTTP {}",
                response.status().as_u16()
            )));
        }
        self.get_allowed(&AdminReadPage::Lists.path()).map(|_| ())
    }

    fn login_csrf_token(&self, login_url: &Url) -> Result<Option<LoginCsrfToken>, InterspireError> {
        let response = match self
            .with_access_headers(self.http.get(login_url.clone()))
            .send()
        {
            Ok(response) => response,
            Err(err) if self.config.version == InterspireVersion::V8 => {
                return Err(InterspireError::Http(err.to_string()));
            }
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            if self.config.version == InterspireVersion::V8 {
                return Err(InterspireError::Http(format!(
                    "admin login token read returned HTTP {}",
                    response.status().as_u16()
                )));
            }
            return Ok(None);
        }

        let html = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        let token = extract_login_csrf_token(&html);
        if token.is_none() && self.config.version == InterspireVersion::V8 {
            return Err(InterspireError::Http(
                "Interspire 8 admin login did not expose a CSRF token".to_string(),
            ));
        }
        Ok(token)
    }

    fn get_allowed(&self, path: &str) -> Result<String, InterspireError> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = safety::ensure_allowed_admin_get(base_url, path)?;
        let response = self
            .with_access_headers(self.http.get(url))
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !response.status().is_success() {
            return Err(InterspireError::Http(format!(
                "admin read returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let html = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        ensure_authenticated_html(&html)?;
        Ok(html)
    }

    fn load_queue_control_links(
        &self,
        max_rows: usize,
    ) -> Result<Vec<QueueControlLink>, InterspireError> {
        let schedule_html = self.get_allowed(&AdminReadPage::Schedule.path())?;
        parse_queue_control_links(
            self.config.base_url.as_deref().unwrap_or_default(),
            &schedule_html,
            max_rows,
        )
    }

    fn with_access_headers(&self, request: RequestBuilder) -> RequestBuilder {
        let access = &self.config.cloudflare_access;
        let Some(client_id) = access.client_id() else {
            return request;
        };
        let Some(client_secret) = access.client_secret() else {
            return request;
        };

        request
            .header("CF-Access-Client-Id", client_id)
            .header("CF-Access-Client-Secret", client_secret)
    }
}

fn summarize_field_value(name: &str, value: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let trimmed = value.trim();
    if is_large_content_like_field(&lower) {
        let excerpt = compact_text(&trimmed.chars().take(80).collect::<String>());
        let digest = Sha256::digest(trimmed.as_bytes());
        return format!(
            "[content len={} sha256={} excerpt=\"{}\"]",
            trimmed.len(),
            &hex::encode(digest)[..12],
            redact::redact_sensitive_text(&excerpt)
        );
    }

    redact_field_value(&lower, trimmed).unwrap_or_default()
}

fn is_large_content_like_field(lower: &str) -> bool {
    lower.contains("html")
        || lower.contains("body")
        || lower.contains("footer")
        || lower.contains("content")
}

fn looks_like_save_submit(control: &forms::FormControl) -> bool {
    control.kind == forms::FormControlKind::Submit
        && (control.lower_name.contains("save")
            || control.value.to_ascii_lowercase().contains("save"))
}

fn ensure_authenticated_html(html: &str) -> Result<(), InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut saw_username = false;
    let mut saw_password = false;

    for input in document.select(&input_selector) {
        let name = input
            .value()
            .attr("name")
            .unwrap_or_default()
            .to_ascii_lowercase();
        saw_username |= name == "ss_username";
        saw_password |= name == "ss_password";
    }

    let saw_login_action = document.select(&form_selector).any(|form| {
        form.value().attr("action").is_some_and(|action| {
            let action = action.to_ascii_lowercase();
            action.contains("page=login") || action.contains("action=login")
        })
    });

    if saw_username || saw_password || saw_login_action {
        return Err(InterspireError::Http(
            "admin read returned login page; authentication was not established".to_string(),
        ));
    }

    Ok(())
}

fn extract_login_csrf_token(html: &str) -> Option<LoginCsrfToken> {
    let document = Html::parse_document(html);
    let input_selector = Selector::parse("input").ok()?;
    for input in document.select(&input_selector) {
        let name = input.value().attr("name").unwrap_or_default();
        if is_login_csrf_field(name) {
            if let Some(value) =
                normalize_csrf_token(input.value().attr("value").unwrap_or_default())
            {
                return Some(LoginCsrfToken {
                    field_name: name.to_string(),
                    value,
                });
            }
        }
    }

    [
        "IEM_CSRF_TOKEN",
        "csrfToken",
        "csrf_token",
        "iem_csrf_token",
    ]
    .iter()
    .find_map(|name| {
        extract_js_string_assignment(html, name).map(|value| LoginCsrfToken {
            field_name: "csrfToken".to_string(),
            value,
        })
    })
}

fn is_login_csrf_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "token" | "csrf" | "csrf_token" | "csrftoken" | "_token" | "form_token" | "iem_csrf_token"
    ) || lower.ends_with("token")
}

fn extract_js_string_assignment(html: &str, name: &str) -> Option<String> {
    let mut remainder = html;
    while let Some(name_offset) = remainder.find(name) {
        if !is_js_identifier_match(remainder, name_offset, name.len()) {
            remainder = &remainder[name_offset + name.len()..];
            continue;
        }
        let after_name = &remainder[name_offset + name.len()..];
        let eq_offset = after_name.find('=')?;
        let after_eq = after_name[eq_offset + 1..].trim_start();
        let Some(quote) = after_eq
            .chars()
            .next()
            .filter(|quote| *quote == '\'' || *quote == '"')
        else {
            remainder = &after_name[eq_offset + 1..];
            continue;
        };
        let token_body = &after_eq[quote.len_utf8()..];
        let end_offset = token_body.find(quote)?;
        if let Some(token) = normalize_csrf_token(&token_body[..end_offset]) {
            return Some(token);
        }
        remainder = &token_body[end_offset + quote.len_utf8()..];
    }
    None
}

fn is_js_identifier_match(input: &str, offset: usize, len: usize) -> bool {
    let before = input[..offset].chars().next_back();
    let after = input[offset + len..].chars().next();
    !before.is_some_and(is_js_identifier_char) && !after.is_some_and(is_js_identifier_char)
}

fn is_js_identifier_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn normalize_csrf_token(value: &str) -> Option<String> {
    let token = value.trim();
    if token.is_empty()
        || token.len() > 512
        || token
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | '&'))
    {
        return None;
    }
    Some(token.to_string())
}

fn admin_evidence(notes: Vec<String>) -> Evidence {
    Evidence {
        source: "interspire_admin_html".to_string(),
        notes,
    }
}

fn build_sensitive_field_query_report(
    input: SensitiveFieldQueryReportInput,
) -> SensitiveFieldQueryReport {
    SensitiveFieldQueryReport {
        ok: true,
        configured: input.configured,
        sensitive_reads_enabled: input.sensitive_reads_enabled,
        policy_decision: input.policy_decision,
        target: input.context.target,
        target_id: input.context.target_id,
        section: input.context.section,
        values: input.values,
        denied_fields: input.denied_fields,
        warnings: input.warnings,
        metadata: crate::response::sensitive_field_query_metadata(),
        evidence: input.evidence,
    }
}

fn sensitive_target_context(
    target: &SensitiveFieldTarget,
) -> (SensitiveFieldQueryContext, AdminReadPage) {
    match target {
        SensitiveFieldTarget::Settings { section } => (
            SensitiveFieldQueryContext {
                target: "settings".to_string(),
                target_id: None,
                section: Some(section.as_str().to_string()),
            },
            AdminReadPage::Settings {
                tab: settings_sensitive_tab(*section),
            },
        ),
        SensitiveFieldTarget::List { list_id } => (
            SensitiveFieldQueryContext {
                target: "list".to_string(),
                target_id: Some(*list_id),
                section: None,
            },
            AdminReadPage::ListEdit { id: *list_id },
        ),
        SensitiveFieldTarget::User { user_id } => (
            SensitiveFieldQueryContext {
                target: "user".to_string(),
                target_id: Some(*user_id),
                section: None,
            },
            AdminReadPage::UserEdit { id: *user_id },
        ),
        SensitiveFieldTarget::Campaign { campaign_id } => (
            SensitiveFieldQueryContext {
                target: "campaign".to_string(),
                target_id: Some(*campaign_id),
                section: None,
            },
            AdminReadPage::NewsletterEdit { id: *campaign_id },
        ),
    }
}

fn settings_sensitive_tab(section: SettingsSectionName) -> u8 {
    match section {
        SettingsSectionName::Application => 1,
        SettingsSectionName::Email => 2,
        SettingsSectionName::Cron => 4,
        SettingsSectionName::Bounce => 7,
    }
}

fn normalize_requested_fields(fields: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for field in fields {
        let field = field.trim().to_ascii_lowercase();
        if field.is_empty() || normalized.contains(&field) {
            continue;
        }
        normalized.push(field);
    }
    normalized
}

fn deny_requested_fields(fields: &[String], reason: &str) -> Vec<SensitiveFieldDenial> {
    normalize_requested_fields(fields)
        .into_iter()
        .take(20)
        .map(|field| SensitiveFieldDenial {
            name: truncate(&field, 128),
            reason: redact::redact_sensitive_text(reason),
        })
        .collect()
}

fn sensitive_allowed_fields(target: &SensitiveFieldTarget) -> &'static [&'static str] {
    match target {
        SensitiveFieldTarget::Settings { section } => match section {
            SettingsSectionName::Application => &[
                "application_url",
                "contact_email",
                "email_address",
                "server_time_zone",
            ],
            SettingsSectionName::Email => &[
                "usesmtp",
                "smtp_server",
                "smtp_u",
                "smtp_port",
                "maxhourlyrate",
                "resend_maximum",
                "force_unsublink",
            ],
            SettingsSectionName::Bounce => &[
                "bounce_process",
                "bounce_address",
                "bounce_server",
                "bounce_username",
                "bounce_imap",
                "bounce_extrasettings",
                "bounce_agreedeleteall",
            ],
            SettingsSectionName::Cron => &[
                "cron_send",
                "cron_bounce",
                "cron_autoresponder",
                "cron_triggeremails_s",
                "cron_maintenance",
            ],
        },
        SensitiveFieldTarget::List { .. } => &["owneremail", "replytoemail", "bounceemail"],
        SensitiveFieldTarget::User { .. } => &[],
        SensitiveFieldTarget::Campaign { .. } => &[],
    }
}

fn is_forbidden_sensitive_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pass",
        "token",
        "secret",
        "license",
        "licence",
        "cookie",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "access_key",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub fn parse_list_edit_metadata(
    list_id: u64,
    html: &str,
) -> Result<ListEditMetadata, InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut values = HashMap::<String, String>::new();

    for input in document.select(&input_selector) {
        let Some(name) = input.value().attr("name") else {
            continue;
        };
        let value = input.value().attr("value").unwrap_or_default().trim();
        if value.is_empty() {
            continue;
        }
        values.insert(name.to_ascii_lowercase(), value.to_string());
    }

    Ok(ListEditMetadata {
        list_id,
        owner_name: first_value(&values, &["ownername", "owner_name", "listownername"])
            .and_then(|value| redact_field_value("ownername", &value)),
        owner_email_redacted: first_value(&values, &["owneremail", "owner_email", "fromemail"])
            .map(|value| redact::redact_email(&value)),
        reply_to_email_redacted: first_value(
            &values,
            &["replytoemail", "reply_to_email", "replyemail"],
        )
        .map(|value| redact::redact_email(&value)),
        bounce_email_redacted: first_value(&values, &["bounceemail", "bounce_email"])
            .map(|value| redact::redact_email(&value)),
    })
}

fn first_value(values: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| values.get(*key).cloned())
        .filter(|value| !value.trim().is_empty())
}

pub fn parse_settings_fields(
    section: &str,
    html: &str,
) -> Result<Vec<RedactedField>, InterspireError> {
    let values = parse_form_values(html)?;
    let allowed = match section {
        "application" => &[
            "application_url",
            "contact_email",
            "email_address",
            "server_time_zone",
        ][..],
        "email" => &[
            "usesmtp",
            "smtp_server",
            "smtp_u",
            "smtp_port",
            "maxhourlyrate",
            "resend_maximum",
            "force_unsublink",
        ][..],
        "bounce" => &[
            "bounce_process",
            "bounce_address",
            "bounce_server",
            "bounce_username",
            "bounce_imap",
            "bounce_extrasettings",
            "bounce_agreedeleteall",
        ][..],
        "cron" => &[
            "cron_send",
            "cron_bounce",
            "cron_autoresponder",
            "cron_triggeremails_s",
            "cron_maintenance",
        ][..],
        _ => &[][..],
    };

    Ok(allowed
        .iter()
        .filter_map(|name| {
            values.get(*name).map(|value| RedactedField {
                name: (*name).to_string(),
                value: redact_field_value(name, value),
            })
        })
        .collect())
}

pub fn extract_user_ids(html: &str) -> Vec<u64> {
    extract_ids_from_links(html, "Page=Users", "UserID")
}

pub fn parse_user_smtp_summary(
    user_id: u64,
    html: &str,
) -> Result<UserSmtpSummary, InterspireError> {
    let values = parse_form_values(html)?;
    Ok(UserSmtpSummary {
        user_id,
        username: redacted_user_label(user_id),
        full_name: first_value(&values, &["fullname", "full_name"])
            .and_then(|value| redact_field_value("fullname", &value)),
        email_redacted: first_value(&values, &["emailaddress", "email_address", "email"])
            .map(|value| redact_email_like(&value)),
        active: checkbox_bool(&values, "status"),
        smtp_type: first_value(&values, &["smtptype", "smtp_type"]),
        smtp_server: first_value(&values, &["smtp_server", "smtpserver"])
            .and_then(|value| redact_field_value("smtp_server", &value)),
        smtp_username_redacted: first_value(&values, &["smtp_u", "smtp_username", "smtpuser"])
            .and_then(|value| redact_field_value("smtp_u", &value)),
        smtp_port: first_value(&values, &["smtp_port", "smtpport"]),
    })
}

pub fn parse_table_rows(html: &str, max_rows: usize) -> Result<Vec<String>, InterspireError> {
    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut rows = Vec::new();
    for row in document.select(&row_selector) {
        if row_contains_nested_rows(&row, &row_selector) {
            continue;
        }
        let text = row.text().collect::<Vec<_>>().join(" ");
        let compact = compact_text(&text);
        if compact.len() < 3 || compact.eq_ignore_ascii_case("actions") {
            continue;
        }
        rows.push(redact::redact_sensitive_text(&compact));
        if rows.len() >= max_rows {
            break;
        }
    }
    Ok(rows)
}

fn parse_queue_control_links(
    base_url: &str,
    html: &str,
    max_rows: usize,
) -> Result<Vec<QueueControlLink>, InterspireError> {
    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let link_selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let delete_form = parse_schedule_delete_form(base_url, &document)?;
    let mut links = Vec::new();
    let mut inspected_rows = 0usize;

    for row in document.select(&row_selector) {
        if row_contains_nested_rows(&row, &row_selector) {
            continue;
        }
        let row_text = compact_text(&row.text().collect::<Vec<_>>().join(" "));
        if row_text.len() < 3 || row_text.eq_ignore_ascii_case("actions") {
            continue;
        }
        inspected_rows += 1;
        if inspected_rows > max_rows {
            break;
        }
        let row_summary = redact::redact_sensitive_text(&row_text);
        let row_checkbox = extract_row_checkbox(&row)?;
        for link in row.select(&link_selector) {
            let action_label = compact_text(&link.text().collect::<Vec<_>>().join(" "));
            if !looks_like_queue_control_label(&action_label) {
                continue;
            }
            let Some(href) = link.value().attr("href") else {
                continue;
            };
            let Some((url, route, execution, route_key)) = parse_queue_control_link_target(
                base_url,
                href,
                row_checkbox.as_ref(),
                delete_form.as_ref(),
            )?
            else {
                continue;
            };
            let plan_id = guarded_write::stable_plan_id(&[
                route.action.as_str(),
                &route.identifier_key,
                &route.identifier_value.to_string(),
                &route_key,
                &row_summary,
            ]);
            links.push(QueueControlLink {
                candidate: QueueControlCandidate {
                    plan_id,
                    action: route.action,
                    action_label: redact::redact_sensitive_text(&action_label),
                    row_summary: row_summary.clone(),
                    route_fingerprint: route_fingerprint(&route_key),
                    requires_guarded_write: true,
                },
                route,
                url,
                execution,
            });
        }
    }

    Ok(links)
}

fn row_contains_nested_rows(row: &ElementRef<'_>, row_selector: &Selector) -> bool {
    row.select(row_selector).next().is_some()
}

fn parse_queue_control_link_target(
    base_url: &str,
    href: &str,
    row_checkbox: Option<&(String, u64)>,
    delete_form: Option<&QueueDeleteForm>,
) -> Result<Option<(Url, QueueControlRoute, QueueControlExecution, String)>, InterspireError> {
    if let Ok((url, route)) = safety::ensure_allowed_queue_control(base_url, href) {
        let route_key = route_key(&url);
        return Ok(Some((url, route, QueueControlExecution::Get, route_key)));
    }

    let Some(delete_form) = delete_form else {
        return Ok(None);
    };
    let Some((checkbox_name, checkbox_value)) = row_checkbox else {
        return Ok(None);
    };
    let Some(confirm_delete_job) = parse_confirm_delete_job(href) else {
        return Ok(None);
    };
    if confirm_delete_job != *checkbox_value {
        return Ok(None);
    }

    let route = QueueControlRoute {
        action: QueueControlAction::Delete,
        identifier_key: checkbox_name.clone(),
        identifier_value: confirm_delete_job,
    };
    let route_key = format!(
        "{}#{}={}",
        route_key(&delete_form.url),
        checkbox_name,
        confirm_delete_job
    );
    Ok(Some((
        delete_form.url.clone(),
        route,
        QueueControlExecution::DeletePost {
            checkbox_name: checkbox_name.clone(),
            submit_name: delete_form.submit_name.clone(),
            submit_value: delete_form.submit_value.clone(),
            hidden_pairs: delete_form.hidden_pairs.clone(),
        },
        route_key,
    )))
}

fn parse_schedule_delete_form(
    base_url: &str,
    document: &Html,
) -> Result<Option<QueueDeleteForm>, InterspireError> {
    let form_selector = Selector::parse("form[name=\"schedulesform\"]")
        .map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;

    for form in document.select(&form_selector) {
        let Some(action) = form.value().attr("action") else {
            continue;
        };
        let Ok(url) = safety::ensure_allowed_queue_control_delete_post(base_url, action) else {
            continue;
        };
        let submit = form.select(&input_selector).find(|input| {
            input
                .value()
                .attr("type")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("submit"))
                && input.value().attr("name").is_some()
        });
        let submit_name = submit
            .and_then(|input| input.value().attr("name"))
            .unwrap_or("DeleteSchedulesButton")
            .to_string();
        let submit_value = submit
            .and_then(|input| input.value().attr("value"))
            .unwrap_or("Delete Selected")
            .to_string();
        let hidden_pairs = forms::parse_form_controls(&form)
            .into_iter()
            .filter(|control| matches!(control.kind, forms::FormControlKind::Hidden))
            .filter(forms::should_replay_hidden_control)
            .map(|control| (control.original_name, control.value))
            .collect::<Vec<_>>();
        return Ok(Some(QueueDeleteForm {
            url,
            submit_name,
            submit_value,
            hidden_pairs,
        }));
    }

    Ok(None)
}

fn extract_row_checkbox(
    row: &scraper::element_ref::ElementRef<'_>,
) -> Result<Option<(String, u64)>, InterspireError> {
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for input in row.select(&input_selector) {
        let Some(input_name) = input.value().attr("name") else {
            continue;
        };
        if !input_name.eq_ignore_ascii_case("jobs[]") {
            continue;
        }
        let Some(value) = input.value().attr("value") else {
            continue;
        };
        let Ok(identifier) = value.trim().parse::<u64>() else {
            continue;
        };
        return Ok(Some((input_name.to_string(), identifier)));
    }
    Ok(None)
}

fn parse_confirm_delete_job(href: &str) -> Option<u64> {
    let compact = compact_text(href);
    let lower = compact.to_ascii_lowercase();
    let start = lower.find("confirmdelete(")?;
    let remainder = &compact[start + "ConfirmDelete(".len()..];
    let quote = remainder.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let closing = remainder[1..].find(quote)?;
    remainder[1..1 + closing].trim().parse::<u64>().ok()
}

fn looks_like_queue_control_label(label: &str) -> bool {
    let label = label.to_ascii_lowercase();
    ["cancel", "delete", "remove", "abort"]
        .iter()
        .any(|needle| label.contains(needle))
}

fn route_key(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn route_fingerprint(route_key: &str) -> String {
    let digest = Sha256::digest(route_key.as_bytes());
    format!("route:{}", &hex::encode(digest)[..12])
}

fn same_queue_control_target(left: &QueueControlRoute, right: &QueueControlRoute) -> bool {
    left.action == right.action
        && left
            .identifier_key
            .eq_ignore_ascii_case(&right.identifier_key)
        && left.identifier_value == right.identifier_value
}

pub fn parse_campaign_fields(html: &str) -> Result<Vec<RedactedField>, InterspireError> {
    let values = parse_form_values(html)?;
    let allowed = [
        "name",
        "subject",
        "sendfromname",
        "sendfromemail",
        "replytoemail",
        "bounceemail",
        "format",
        "sendmultipart",
        "trackopens",
        "tracklinks",
        "embedimages",
    ];
    Ok(allowed
        .iter()
        .filter_map(|name| {
            values.get(*name).map(|value| RedactedField {
                name: (*name).to_string(),
                value: redact_field_value(name, value),
            })
        })
        .collect())
}

fn parse_form_values(html: &str) -> Result<HashMap<String, String>, InterspireError> {
    let document = Html::parse_document(html);
    let input_selector =
        Selector::parse("input").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let textarea_selector =
        Selector::parse("textarea").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let select_selector =
        Selector::parse("select").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let option_selector =
        Selector::parse("option").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut values = HashMap::<String, String>::new();

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
        let value = input.value().attr("value").unwrap_or_default().trim();
        values.insert(name.to_ascii_lowercase(), value.to_string());
    }

    for textarea in document.select(&textarea_selector) {
        let Some(name) = textarea.value().attr("name") else {
            continue;
        };
        values.insert(
            name.to_ascii_lowercase(),
            compact_text(&textarea.text().collect::<Vec<_>>().join(" ")),
        );
    }

    for select in document.select(&select_selector) {
        let Some(name) = select.value().attr("name") else {
            continue;
        };
        let selected = select
            .select(&option_selector)
            .find(|option| option.value().attr("selected").is_some())
            .or_else(|| select.select(&option_selector).next());
        if let Some(option) = selected {
            let value = option
                .value()
                .attr("value")
                .map(ToString::to_string)
                .unwrap_or_else(|| compact_text(&option.text().collect::<Vec<_>>().join(" ")));
            values.insert(name.to_ascii_lowercase(), value);
        }
    }

    Ok(values)
}

fn extract_ids_from_links(html: &str, page_marker: &str, id_key: &str) -> Vec<u64> {
    let document = Html::parse_document(html);
    let selector =
        Selector::parse("a").unwrap_or_else(|err| panic!("selector parse failed: {err}"));
    let mut ids = Vec::new();
    for link in document.select(&selector) {
        let Some(href) = link.value().attr("href") else {
            continue;
        };
        if !href.contains(page_marker) {
            continue;
        }
        if let Some(id) = extract_query_u64(href, id_key) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids
}

fn extract_query_u64(href: &str, key: &str) -> Option<u64> {
    href.split(['?', '&'])
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .and_then(|(_, value)| value.parse::<u64>().ok())
}

fn checkbox_bool(values: &HashMap<String, String>, name: &str) -> Option<bool> {
    values
        .get(name)
        .map(|value| matches!(value.as_str(), "1" | "on" | "yes" | "true"))
}

fn redact_field_value(name: &str, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if is_username_like_field(&lower) {
        return Some(redact_username_like(trimmed));
    }
    if is_person_name_like_field(&lower) {
        return Some("[redacted-name]".to_string());
    }
    if lower.contains("password")
        || lower.contains("token")
        || lower.contains("license")
        || lower.contains("secret")
        || lower.contains("key")
    {
        return Some("[redacted]".to_string());
    }
    if lower.contains("email") || trimmed.contains('@') {
        return Some(redact_email_like(trimmed));
    }
    Some(redact::redact_sensitive_text(trimmed))
}

fn is_username_like_field(lower: &str) -> bool {
    matches!(
        lower,
        "username" | "smtp_u" | "smtp_username" | "smtpuser" | "bounce_username" | "bounceuser"
    ) || lower.ends_with("_username")
}

fn is_person_name_like_field(lower: &str) -> bool {
    matches!(
        lower,
        "fullname" | "full_name" | "ownername" | "owner_name" | "listownername" | "sendfromname"
    )
}

fn redact_username_like(value: &str) -> String {
    if value.contains('@') {
        redact::redact_email(value)
    } else {
        "[redacted-username]".to_string()
    }
}

fn redacted_user_label(user_id: u64) -> String {
    format!("user-{user_id}")
}

fn redact_email_like(value: &str) -> String {
    if value.contains('@') {
        redact::redact_email(value)
    } else {
        redact::redact_sensitive_text(value)
    }
}

fn compact_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use url::Url;

    #[test]
    fn parses_list_edit_metadata_with_redaction() {
        let html = include_str!("../tests/fixtures/list_edit.html");
        let metadata = parse_list_edit_metadata(7, html).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(metadata.owner_name.as_deref(), Some("[redacted-name]"));
        assert_eq!(
            metadata.owner_email_redacted.as_deref(),
            Some("e***@example.com")
        );
        assert_eq!(
            metadata.reply_to_email_redacted.as_deref(),
            Some("r***@example.com")
        );
        assert_eq!(
            metadata.bounce_email_redacted.as_deref(),
            Some("b***@example.com")
        );
        assert!(!format!("{metadata:?}").contains("Newsroom"));
    }

    #[test]
    fn admin_allowed_paths_remain_get_only_reads() {
        let allowed = safety::ensure_allowed_admin_get(
            "https://example.test/admin/",
            "index.php?Page=Lists&Action=Edit&id=7",
        )
        .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(
            allowed,
            Url::parse("https://example.test/admin/index.php?Page=Lists&Action=Edit&id=7")
                .unwrap_or_else(|err| panic!("{err}"))
        );
    }

    #[test]
    fn authenticated_html_check_rejects_login_forms() {
        let html = r#"
            <form method="post" action="index.php?Page=Login&Action=Login">
              <input name="ss_username" value="">
              <input name="ss_password" type="password" value="">
            </form>
        "#;
        let err = ensure_authenticated_html(html)
            .err()
            .unwrap_or_else(|| panic!("login form should be rejected"));
        assert_eq!(err.code(), "http_error");
        assert!(!err.to_string().contains("ss_username"));
        assert!(!err.to_string().contains("ss_password"));
    }

    #[test]
    fn authenticated_html_check_allows_admin_pages_without_secret_output() {
        let html = r#"
            <nav><a href="index.php?Page=Lists">Lists</a></nav>
            <table><tr><td>Campaign summary</td></tr></table>
        "#;
        ensure_authenticated_html(html).unwrap_or_else(|err| panic!("{err}"));
    }

    #[test]
    fn login_csrf_token_prefers_hidden_field() {
        let html = r#"
            <form method="post" action="index.php?Page=Login&Action=Login">
              <input name="csrf_token" value="hidden-token-123">
              <script>var IEM_CSRF_TOKEN = "script-token-456";</script>
            </form>
        "#;

        assert_eq!(
            extract_login_csrf_token(html),
            Some(LoginCsrfToken {
                field_name: "csrf_token".to_string(),
                value: "hidden-token-123".to_string(),
            })
        );
    }

    #[test]
    fn login_csrf_token_extracts_interspire_8_script_value() {
        let html = r#"
            <script>
              window.IEM_CSRF_TOKEN = 'iem8-token-789';
            </script>
        "#;

        assert_eq!(
            extract_login_csrf_token(html),
            Some(LoginCsrfToken {
                field_name: "csrfToken".to_string(),
                value: "iem8-token-789".to_string(),
            })
        );
    }

    #[test]
    fn login_csrf_token_script_value_requires_identifier_boundary() {
        let html = r#"
            <script>
              window.NOT_IEM_CSRF_TOKEN = 'wrong-token';
              window.IEM_CSRF_TOKEN_BACKUP = 'also-wrong';
              window.IEM_CSRF_TOKEN = 'right-token';
            </script>
        "#;

        assert_eq!(
            extract_login_csrf_token(html),
            Some(LoginCsrfToken {
                field_name: "csrfToken".to_string(),
                value: "right-token".to_string(),
            })
        );
    }

    #[test]
    fn login_csrf_token_accepts_generic_token_hidden_field() {
        let html = r#"
            <form method="post" action="index.php?Page=Login&Action=Login">
              <input name="_token" value="generic-token-123">
            </form>
        "#;

        assert_eq!(
            extract_login_csrf_token(html),
            Some(LoginCsrfToken {
                field_name: "_token".to_string(),
                value: "generic-token-123".to_string(),
            })
        );
    }

    #[test]
    fn sensitive_field_policy_normalizes_exact_fields() {
        let fields = normalize_requested_fields(&[
            " SMTP_Server ".to_string(),
            "smtp_server".to_string(),
            String::new(),
            "ReplyToEmail".to_string(),
        ]);

        assert_eq!(fields, vec!["smtp_server", "replytoemail"]);
    }

    #[test]
    fn sensitive_field_allowlist_accepts_setup_fields_only() {
        let email_target = SensitiveFieldTarget::Settings {
            section: SettingsSectionName::Email,
        };
        let allowed = sensitive_allowed_fields(&email_target);

        assert!(allowed.contains(&"smtp_server"));
        assert!(allowed.contains(&"smtp_u"));
        assert!(!allowed.contains(&"smtp_password"));
        assert!(is_forbidden_sensitive_field("smtp_password"));
        assert!(is_forbidden_sensitive_field("license_key"));
        assert!(!is_forbidden_sensitive_field("tracklinks"));
    }

    #[test]
    fn denied_sensitive_field_reasons_are_redacted_and_bounded() {
        let denials = deny_requested_fields(
            &["Access_Token".to_string()],
            "token=super-secret-value for https://example.invalid/path",
        );

        assert_eq!(denials[0].name, "access_token");
        assert!(!denials[0].reason.contains("super-secret-value"));
        assert!(!denials[0].reason.contains("example.invalid"));
    }

    #[test]
    fn sensitive_field_query_disabled_gate_attempts_no_admin_read() {
        let client = AdminHtmlClient::new(test_admin_config("http://127.0.0.1:1/admin/"))
            .unwrap_or_else(|err| panic!("{err}"));
        let report = client
            .sensitive_field_query(
                &sensitive_email_settings_request(&["smtp_server"], true),
                false,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.policy_decision.allow);
        assert!(report.values.is_empty());
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note == "no request sent"));
    }

    #[test]
    fn sensitive_field_query_missing_acknowledgement_attempts_no_admin_read() {
        let client = AdminHtmlClient::new(test_admin_config("http://127.0.0.1:1/admin/"))
            .unwrap_or_else(|err| panic!("{err}"));
        let report = client
            .sensitive_field_query(
                &sensitive_email_settings_request(&["smtp_server"], false),
                true,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.policy_decision.allow);
        assert!(report.values.is_empty());
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note == "no request sent"));
    }

    #[test]
    fn sensitive_field_query_forbidden_field_attempts_no_admin_read() {
        let client = AdminHtmlClient::new(test_admin_config("http://127.0.0.1:1/admin/"))
            .unwrap_or_else(|err| panic!("{err}"));
        let report = client
            .sensitive_field_query(
                &sensitive_email_settings_request(&["smtp_password"], true),
                true,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.policy_decision.allow);
        assert!(report.values.is_empty());
        assert_eq!(report.denied_fields.len(), 1);
        assert_eq!(report.denied_fields[0].name, "smtp_password");
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note == "no request sent"));
    }

    #[test]
    fn sensitive_field_query_reveals_one_allowed_setup_value() {
        let server = spawn_sensitive_read_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));
        let report = client
            .sensitive_field_query(
                &sensitive_email_settings_request(&["smtp_server"], true),
                true,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.policy_decision.allow);
        assert!(report.denied_fields.is_empty());
        assert_eq!(report.values.len(), 1);
        assert_eq!(report.values[0].name, "smtp_server");
        assert_eq!(report.values[0].value, "smtp.example.test");
        assert!(report.values[0].sensitive_output);
        assert_eq!(report.metadata.sensitivity, "unredacted_admin_form_values");
        assert!(server
            .requests()
            .iter()
            .any(|request| request.contains("GET /admin/index.php?Page=Settings&Tab=2 ")));
    }

    #[test]
    fn cloudflare_access_headers_are_attached_to_admin_requests() {
        let server = spawn_sensitive_read_fixture_server();
        let mut config = test_admin_config(&server.base_url);
        config.cloudflare_access = crate::config::CloudflareAccessConfig::from_values_for_test(
            "access-client",
            "access-secret",
        );
        let client = AdminHtmlClient::new(config).unwrap_or_else(|err| panic!("{err}"));

        client
            .sensitive_field_query(
                &sensitive_email_settings_request(&["smtp_server"], true),
                true,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        let requests = server.requests();
        assert!(!requests.is_empty());
        assert!(requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("cf-access-client-id: access-client\r\n")
        }));
        assert!(requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("cf-access-client-secret: access-secret\r\n")
        }));
    }

    #[test]
    fn settings_fields_redact_username_like_values() {
        let email_html = r#"
            <form>
              <input name="smtp_u" value="provider-user">
              <input name="smtp_server" value="smtp.example.com">
            </form>
        "#;
        let email_fields =
            parse_settings_fields("email", email_html).unwrap_or_else(|err| panic!("{err}"));
        let smtp_user = email_fields
            .iter()
            .find(|field| field.name == "smtp_u")
            .unwrap_or_else(|| panic!("smtp_u field should be present"));
        assert_eq!(smtp_user.value.as_deref(), Some("[redacted-username]"));

        let bounce_html = r#"
            <form>
              <input name="bounce_username" value="bounce-user">
              <input name="bounce_server" value="mail.example.com">
            </form>
        "#;
        let bounce_fields =
            parse_settings_fields("bounce", bounce_html).unwrap_or_else(|err| panic!("{err}"));
        let bounce_user = bounce_fields
            .iter()
            .find(|field| field.name == "bounce_username")
            .unwrap_or_else(|| panic!("bounce_username field should be present"));
        assert_eq!(bounce_user.value.as_deref(), Some("[redacted-username]"));

        let rendered = format!("{email_fields:?} {bounce_fields:?}");
        assert!(!rendered.contains("provider-user"));
        assert!(!rendered.contains("bounce-user"));
    }

    #[test]
    fn user_smtp_summary_redacts_user_identity_and_smtp_username() {
        let html = r#"
            <form>
              <input name="username" value="staff-login">
              <input name="fullname" value="Staff Member">
              <input name="emailaddress" value="staff@example.com">
              <input name="status" type="checkbox" checked value="1">
              <input name="smtptype" value="custom">
              <input name="smtp_server" value="smtp.example.com">
              <input name="smtp_username" value="provider-login">
              <input name="smtp_port" value="587">
            </form>
        "#;
        let summary = parse_user_smtp_summary(12, html).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(summary.username, "user-12");
        assert_eq!(summary.full_name.as_deref(), Some("[redacted-name]"));
        assert_eq!(
            summary.smtp_username_redacted.as_deref(),
            Some("[redacted-username]")
        );
        let rendered = format!("{summary:?}");
        assert!(!rendered.contains("staff-login"));
        assert!(!rendered.contains("Staff Member"));
        assert!(!rendered.contains("provider-login"));
    }

    #[test]
    fn campaign_sender_display_name_is_redacted() {
        let html = r#"
            <form>
              <input name="name" value="Campaign label">
              <input name="subject" value="Campaign subject">
              <input name="sendfromname" value="Staff Sender">
              <input name="sendfromemail" value="sender@example.com">
            </form>
        "#;
        let fields = parse_campaign_fields(html).unwrap_or_else(|err| panic!("{err}"));
        let sender_name = fields
            .iter()
            .find(|field| field.name == "sendfromname")
            .unwrap_or_else(|| panic!("sendfromname field should be present"));
        assert_eq!(sender_name.value.as_deref(), Some("[redacted-name]"));
        let body = format!("{fields:?}");
        assert!(body.contains("Campaign label"));
        assert!(body.contains("Campaign subject"));
        assert!(!body.contains("Staff Sender"));
    }

    #[test]
    fn login_form_html_is_rejected_as_unauthenticated() {
        let html = r#"
            <form>
              <input name="ss_username" value="">
              <input name="ss_password" type="password" value="">
            </form>
        "#;

        let err = ensure_authenticated_html(html)
            .err()
            .unwrap_or_else(|| panic!("login form should be rejected"));
        assert_eq!(err.code(), "http_error");
        assert!(err.to_string().contains("login page"));
    }

    struct TestAdminServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl TestAdminServer {
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap_or_else(|err| panic!("test requests lock poisoned: {err}"))
                .clone()
        }
    }

    impl Drop for TestAdminServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("test admin server thread panicked"));
            }
        }
    }

    fn test_admin_config(base_url: &str) -> AdminHtmlConfig {
        AdminHtmlConfig {
            version: InterspireVersion::Auto,
            base_url: Some(base_url.to_string()),
            username: Some("operator".to_string()),
            password: Some("password".to_string()),
            cloudflare_access: crate::config::CloudflareAccessConfig::default(),
            enrich_limit: 25,
        }
    }

    fn sensitive_email_settings_request(
        fields: &[&str],
        acknowledge_sensitive_output: bool,
    ) -> SensitiveFieldQueryRequest {
        SensitiveFieldQueryRequest {
            target: SensitiveFieldTarget::Settings {
                section: SettingsSectionName::Email,
            },
            fields: fields.iter().map(|field| (*field).to_string()).collect(),
            acknowledge_sensitive_output,
        }
    }

    fn spawn_sensitive_read_fixture_server() -> TestAdminServer {
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

        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(250)))
                            .unwrap_or_else(|err| panic!("set_read_timeout failed: {err}"));
                        let mut buffer = [0_u8; 8192];
                        let bytes = stream
                            .read(&mut buffer)
                            .unwrap_or_else(|err| panic!("test request read failed: {err}"));
                        let request = String::from_utf8_lossy(&buffer[..bytes]).to_string();
                        thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("test requests lock poisoned while push: {err}")
                            })
                            .push(request.clone());
                        write_fixture_response(&mut stream, &request);
                        if thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("test requests lock poisoned while count: {err}")
                            })
                            .len()
                            >= 4
                        {
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("test server accept failed: {err}"),
                }
            }
        });

        TestAdminServer {
            base_url: format!("http://{address}/admin/"),
            requests,
            handle: Some(handle),
        }
    }

    fn write_fixture_response(stream: &mut std::net::TcpStream, request: &str) {
        let body = if request.starts_with("GET /admin/index.php?Page=Login&Action=Login ") {
            r#"<form method="post" action="index.php?Page=Login&Action=Login">
                <input type="hidden" name="csrf_token" value="fixture-csrf">
                <input name="ss_username">
                <input name="ss_password">
              </form>"#
        } else if request.starts_with("POST /admin/index.php?Page=Login&Action=Login ") {
            "<html><body>logged in</body></html>"
        } else if request.starts_with("GET /admin/index.php?Page=Lists ") {
            "<html><body><a href=\"index.php?Page=Lists&Action=Edit&id=1\">List</a></body></html>"
        } else if request.starts_with("GET /admin/index.php?Page=Settings&Tab=2 ") {
            r#"<form>
                <input name="smtp_server" value="smtp.example.test">
                <input name="smtp_u" value="smtp-user">
              </form>"#
        } else {
            "<html><body>unexpected request</body></html>"
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|err| panic!("test response write failed: {err}"));
    }

    #[test]
    fn queue_control_links_are_plan_id_only_and_redacted() {
        let html = r#"
            <table>
              <tr>
                <th>Campaign</th><th>Actions</th>
              </tr>
              <tr>
                <td>Breaking news to person@example.com</td>
                <td><a href="index.php?Page=Schedule&Action=Cancel&id=42">Cancel</a></td>
              </tr>
              <tr>
                <td>Unsafe send route</td>
                <td><a href="index.php?Page=Schedule&Action=Send&id=43">Send</a></td>
              </tr>
            </table>
        "#;

        let links = parse_queue_control_links("https://example.test/admin/", html, 25)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].candidate.action, QueueControlAction::Cancel);
        assert!(links[0].candidate.plan_id.starts_with("iqc_"));
        assert_eq!(links[0].candidate.route_fingerprint.len(), 18);
        assert!(!links[0]
            .candidate
            .row_summary
            .contains("person@example.com"));
        assert!(!serde_json::to_string(&links[0].candidate)
            .unwrap_or_else(|err| panic!("{err}"))
            .contains("index.php"));
    }

    #[test]
    fn queue_control_preview_ignores_nested_container_rows() {
        let html = r#"
            <table>
              <tr>
                <td>
                  Results per page: 5 10 20
                  <table>
                    <tr>
                      <td>Campaign Alpha</td>
                      <td><a href="index.php?Page=Schedule&Action=Delete&id=41">Delete</a></td>
                    </tr>
                    <tr>
                      <td>Campaign Beta for person@example.com</td>
                      <td><a href="index.php?Page=Schedule&Action=Cancel&id=42">Cancel</a></td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
        "#;

        let links = parse_queue_control_links("https://example.test/admin/", html, 25)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(links.len(), 2);
        assert!(links
            .iter()
            .all(|link| !link.candidate.row_summary.contains("Results per page")));
        assert!(links
            .iter()
            .any(|link| link.candidate.row_summary.contains("Campaign Alpha")));
        assert!(links
            .iter()
            .any(|link| link.candidate.row_summary.contains("Campaign Beta")));
        assert!(links
            .iter()
            .all(|link| !link.candidate.row_summary.contains("person@example.com")));
    }

    #[test]
    fn queue_control_links_support_legacy_confirm_delete_rows() {
        let html = r#"
            <form name="schedulesform" method="post" action="index.php?Page=Schedule&Action=Delete&token=keepme">
              <input type="submit" name="DeleteSchedulesButton" value="Delete Selected">
              <input type="hidden" name="token" value="abc123">
              <table>
                <tr>
                  <th>Campaign</th><th>Actions</th>
                </tr>
                <tr>
                  <td><input type="checkbox" name="jobs[]" value="182744"></td>
                  <td>Breaking news to person@example.com</td>
                  <td>
                    <a href="index.php?Page=Schedule&Action=Resume&job=182744">Resume</a>
                    <a href="javascript: ConfirmDelete('182744');">Delete</a>
                  </td>
                </tr>
              </table>
            </form>
        "#;

        let links = parse_queue_control_links("https://example.test/admin/", html, 25)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(links.len(), 1);
        let delete = links
            .iter()
            .find(|link| link.candidate.action == QueueControlAction::Delete)
            .unwrap_or_else(|| panic!("delete candidate should be present"));
        match &delete.execution {
            QueueControlExecution::DeletePost {
                checkbox_name,
                submit_name,
                submit_value,
                hidden_pairs,
            } => {
                assert_eq!(checkbox_name, "jobs[]");
                assert_eq!(submit_name, "DeleteSchedulesButton");
                assert_eq!(submit_value, "Delete Selected");
                assert_eq!(
                    hidden_pairs,
                    &vec![("token".to_string(), "abc123".to_string())]
                );
            }
            QueueControlExecution::Get => panic!("delete candidate should use post execution"),
        }
        assert_eq!(delete.route.identifier_value, 182744);
        assert!(!delete.candidate.row_summary.contains("person@example.com"));
        assert_eq!(delete.candidate.route_fingerprint.len(), 18);
    }

    #[test]
    fn parse_table_rows_ignores_nested_container_rows() {
        let html = r#"
            <table>
              <tr>
                <td>
                  Results per page: 5 10 20
                  <table>
                    <tr><td>Campaign Alpha</td><td>Complete</td></tr>
                    <tr><td>Campaign Beta</td><td>Paused</td></tr>
                  </table>
                </td>
              </tr>
            </table>
        "#;

        let rows = parse_table_rows(html, 25).unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            rows,
            vec![
                "Campaign Alpha Complete".to_string(),
                "Campaign Beta Paused".to_string()
            ]
        );
    }

    #[test]
    fn post_pairs_omit_blank_password_controls() {
        let snapshot = forms::FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![
                forms::FormControl {
                    original_name: "name".to_string(),
                    lower_name: "name".to_string(),
                    kind: forms::FormControlKind::Text,
                    value: "List name".to_string(),
                    checked: true,
                },
                forms::FormControl {
                    original_name: "bounce_password".to_string(),
                    lower_name: "bounce_password".to_string(),
                    kind: forms::FormControlKind::Password,
                    value: String::new(),
                    checked: true,
                },
                forms::FormControl {
                    original_name: "csrf_token".to_string(),
                    lower_name: "csrf_token".to_string(),
                    kind: forms::FormControlKind::Hidden,
                    value: "safe-token".to_string(),
                    checked: true,
                },
                forms::FormControl {
                    original_name: "dangerous_hidden_flag".to_string(),
                    lower_name: "dangerous_hidden_flag".to_string(),
                    kind: forms::FormControlKind::Hidden,
                    value: "replay-me".to_string(),
                    checked: true,
                },
                forms::FormControl {
                    original_name: "SubmitButton1".to_string(),
                    lower_name: "submitbutton1".to_string(),
                    kind: forms::FormControlKind::Submit,
                    value: "Save".to_string(),
                    checked: true,
                },
            ],
        };

        let requested_fields = BTreeSet::from(["name".to_string(), "bounce_password".to_string()]);
        let pairs = snapshot.to_post_pairs_for_fields(&requested_fields);
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "name" && value == "List name"));
        assert!(!pairs.iter().any(|(name, _)| name == "bounce_password"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "csrf_token" && value == "safe-token"));
        assert!(!pairs
            .iter()
            .any(|(name, _)| name == "dangerous_hidden_flag"));
    }
}

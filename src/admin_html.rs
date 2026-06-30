//! Authenticated Interspire admin HTML readback adapter.
//!
//! This module owns the brittle admin HTML boundary for allowlisted GET-only
//! pages. It logs in with credentials supplied outside git, reads only pages
//! admitted by `safety`, parses redacted operational fields, and never exposes
//! raw saved HTML, cookies, passwords, contact exports, or send/cron actions.

mod forms;
mod proof;
mod scaffold;

use crate::{
    config::{AdminHtmlConfig, InterspireVersion, WriteExecutionMode},
    error::InterspireError,
    guarded_write, redact,
    response::{
        CampaignManageRow, CampaignReadbackReport, Evidence, FormFieldUpdate,
        GuardedWriteApplyReport, GuardedWritePreviewReport, ListSummary, ListSummaryReport,
        QueueControlAction, QueueControlCandidate, QueueStatsReadbackReport, RedactedField,
        SensitiveFieldDenial, SensitiveFieldQueryReport, SensitiveFieldQueryRequest,
        SensitiveFieldTarget, SensitiveFieldValue, SettingsAuditReport, SettingsSection,
        SettingsSectionName, UserSmtpReadbackReport, UserSmtpSummary,
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
    pub name: Option<String>,
    pub owner_name: Option<String>,
    pub owner_email_redacted: Option<String>,
    pub reply_to_email_redacted: Option<String>,
    pub bounce_email_redacted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactStateHtmlReadback {
    pub found_on_list: Option<bool>,
    pub warnings: Vec<String>,
    pub evidence_notes: Vec<String>,
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
    pause_before_delete: Option<Url>,
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
pub(super) struct LoginCsrfToken {
    pub(super) field_name: String,
    pub(super) value: String,
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

    pub fn list_summary_readback(
        &self,
        max_lists: usize,
    ) -> Result<ListSummaryReport, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let lists_html = self.get_allowed(&AdminReadPage::Lists.path())?;
        let list_ids = extract_ids_from_links(&lists_html, "Page=Lists", "id");
        let mut lists = Vec::new();
        let mut warnings = Vec::new();
        for list_id in list_ids.iter().take(max_lists) {
            let html = self.get_allowed(&AdminReadPage::ListEdit { id: *list_id }.path())?;
            match parse_list_edit_metadata(*list_id, &html) {
                Ok(metadata) => lists.push(ListSummary {
                    list_id: *list_id,
                    name: metadata.name.unwrap_or_else(|| format!("list-{list_id}")),
                    subscribed_count: None,
                    unsubscribed_count: None,
                    autoresponder_count: None,
                    owner_name: metadata.owner_name,
                    owner_email_redacted: metadata.owner_email_redacted,
                    reply_to_email_redacted: metadata.reply_to_email_redacted,
                    bounce_email_redacted: metadata.bounce_email_redacted,
                    source: "admin_html".to_string(),
                }),
                Err(err) => warnings.push(format!(
                    "list {} html parse skipped: {}",
                    list_id,
                    redact::redact_sensitive_text(&err.to_string())
                )),
            }
        }
        if list_ids.len() > max_lists {
            warnings.push(format!(
                "admin HTML list readback limited to {max_lists} of {} lists",
                list_ids.len()
            ));
        }
        if lists.is_empty() {
            warnings.push(
                "admin HTML list readback did not find list edit links on the Lists page"
                    .to_string(),
            );
        }

        Ok(ListSummaryReport {
            ok: true,
            configured: true,
            lists,
            warnings,
            evidence: admin_evidence(vec![
                "allowlisted Lists GET read".to_string(),
                "allowlisted List edit GET reads for redacted metadata".to_string(),
                "subscriber/contact rows were not exported".to_string(),
            ]),
        })
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

    pub fn contact_state_readback(
        &self,
        email: &str,
        list_id: u64,
    ) -> Result<ContactStateHtmlReadback, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::AdminHtmlNotConfigured);
        }
        self.login()?;

        let email = normalize_exact_email_query(email)?;
        let paths = subscriber_exact_search_paths(list_id, &email);
        let mut warnings = Vec::new();
        let mut attempted = 0usize;
        let mut saw_search_page = false;
        let mut route_http_failures = 0usize;

        for path in paths {
            attempted += 1;
            let html = match self.get_allowed(&path) {
                Ok(html) => html,
                Err(err) => {
                    route_http_failures += 1;
                    warnings.push(format!(
                        "subscriber exact-search route candidate skipped: {}",
                        redact::redact_sensitive_text(&err.to_string())
                    ));
                    continue;
                }
            };
            let parsed = parse_subscriber_exact_search_page(&html, &email)?;
            warnings.extend(parsed.warnings);
            saw_search_page |= parsed.looks_like_subscriber_page;
            if parsed.exact_email_found {
                return Ok(ContactStateHtmlReadback {
                    found_on_list: Some(true),
                    warnings,
                    evidence_notes: vec![
                        "allowlisted Subscribers exact-search GET read".to_string(),
                        "exact requested email was found on the selected list page; raw subscriber row was not returned".to_string(),
                    ],
                });
            }
        }

        if attempted == route_http_failures {
            warnings.push(
                "all subscriber exact-search route candidates failed before returning HTML"
                    .to_string(),
            );
            return Ok(ContactStateHtmlReadback {
                found_on_list: None,
                warnings,
                evidence_notes: vec![
                    "allowlisted Subscribers exact-search GET attempted".to_string(),
                    "no subscriber search HTML was available to corroborate contact state"
                        .to_string(),
                ],
            });
        }

        Ok(ContactStateHtmlReadback {
            found_on_list: if saw_search_page { Some(false) } else { None },
            warnings,
            evidence_notes: vec![
                "allowlisted Subscribers exact-search GET read".to_string(),
                "exact requested email was not found; absence remains low-confidence unless corroborated elsewhere".to_string(),
            ],
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

        let mut notes = Vec::new();
        if selected.candidate.action == QueueControlAction::Delete {
            if let Some(pause_url) = selected.pause_before_delete.clone() {
                let response =
                    self.queue_control_get_request(pause_url)?
                        .send()
                        .map_err(|err| {
                            InterspireError::Http(format!(
                                "queue control pause preflight failed: {err}"
                            ))
                        })?;
                let pause_status = response.status();
                if !pause_status.is_success() && !pause_status.is_redirection() {
                    return Err(InterspireError::Http(format!(
                        "queue control pause preflight returned HTTP {}",
                        pause_status.as_u16()
                    )));
                }
                if pause_status.is_success() {
                    let body = response
                        .text()
                        .map_err(|err| InterspireError::Http(err.to_string()))?;
                    ensure_authenticated_html(&body)?;
                }
                notes.push(format!(
                    "allowlisted Schedule pause preflight returned HTTP {} before delete",
                    pause_status.as_u16()
                ));
            }
        }

        let response = match &selected.execution {
            QueueControlExecution::Get => self
                .queue_control_get_request(selected.url.clone())?
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
                self.queue_control_post_request(selected.url.clone(), &post_pairs)?
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

        notes.extend([
            format!(
                "allowlisted Schedule queue {} route applied via guarded plan id",
                action.as_str()
            ),
            format!(
                "admin returned HTTP {}; Schedule page re-read after apply",
                status.as_u16()
            ),
        ]);

        Ok(QueueControlApplyEvidence {
            before_candidate_count,
            before_row_summary,
            after_candidate_count: after.len(),
            after_row_still_present,
            notes,
        })
    }

    fn queue_control_get_request(&self, url: Url) -> Result<RequestBuilder, InterspireError> {
        Ok(self
            .with_access_headers(self.http.get(url))
            .header(
                "referer",
                safety::ensure_allowed_admin_get(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &AdminReadPage::Schedule.path(),
                )?
                .as_str(),
            )
            .header(
                "origin",
                admin_origin(self.config.base_url.as_deref().unwrap_or_default())?,
            ))
    }

    fn queue_control_post_request(
        &self,
        url: Url,
        post_pairs: &[(String, String)],
    ) -> Result<RequestBuilder, InterspireError> {
        let mut request = self
            .with_access_headers(self.http.post(url))
            .header(
                "referer",
                safety::ensure_allowed_admin_get(
                    self.config.base_url.as_deref().unwrap_or_default(),
                    &AdminReadPage::Schedule.path(),
                )?
                .as_str(),
            )
            .header(
                "origin",
                admin_origin(self.config.base_url.as_deref().unwrap_or_default())?,
            );
        if let Some((_, token)) = csrf_pair(post_pairs) {
            request = request.header("x-csrf-token", token);
        }
        Ok(request)
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

        let (fields, manage_rows, rows, notes, warnings) = if let Some(id) = campaign_id {
            let html = self.get_allowed(&AdminReadPage::NewsletterEdit { id }.path())?;
            (
                parse_campaign_fields(&html)?,
                Vec::new(),
                Vec::new(),
                vec![format!(
                    "allowlisted Newsletter edit GET read for campaign {id}"
                )],
                Vec::new(),
            )
        } else {
            let html = self.get_allowed(&AdminReadPage::NewslettersManage.path())?;
            let mut notes = vec!["allowlisted Newsletter manage GET read".to_string()];
            let mut warnings = Vec::new();
            let mut manage_rows = parse_campaign_manage_rows(&html, max_rows.saturating_add(1))?;
            if manage_rows.len() > max_rows {
                manage_rows.truncate(max_rows);
                warnings.push(format!(
                    "campaign manage readback reached max_rows cap {max_rows}; additional campaign rows may exist"
                ));
                notes.push(format!(
                    "campaign manage rows truncated to max_rows cap {max_rows}"
                ));
            }
            let mut rows = parse_table_rows(&html, max_rows.saturating_add(1))?;
            if rows.len() > max_rows {
                rows.truncate(max_rows);
                warnings.push(format!(
                    "redacted campaign row summaries reached max_rows cap {max_rows}; additional table rows may exist"
                ));
                notes.push(format!(
                    "redacted campaign row summaries truncated to max_rows cap {max_rows}"
                ));
            }
            (Vec::new(), manage_rows, rows, notes, warnings)
        };

        Ok(CampaignReadbackReport {
            ok: true,
            configured: true,
            campaign_id,
            campaign_fields: fields,
            campaign_manage_rows: manage_rows,
            campaign_rows: rows,
            warnings,
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

    pub fn list_create_preview(
        &self,
        updates: &[FormFieldUpdate],
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        forms::guarded_write_preview(self, forms::GuardedFormTarget::ListCreate, updates)
    }

    pub fn list_create_apply(
        &self,
        plan_id: &str,
        updates: &[FormFieldUpdate],
        mode: WriteExecutionMode,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        forms::guarded_list_create_apply(self, plan_id, updates, mode)
    }

    pub fn campaign_copy_preview(
        &self,
        source_campaign_id: u64,
        guarded_writes_enabled: bool,
        form_write_controls_enabled: bool,
        mode: WriteExecutionMode,
    ) -> Result<scaffold::CampaignCopyPreviewResult, InterspireError> {
        scaffold::campaign_copy_preview(
            self,
            source_campaign_id,
            guarded_writes_enabled,
            form_write_controls_enabled,
            mode,
        )
    }

    pub fn campaign_copy_apply(
        &self,
        source_campaign_id: u64,
        plan_id: &str,
        guarded_writes_enabled: bool,
        form_write_controls_enabled: bool,
        mode: WriteExecutionMode,
    ) -> Result<scaffold::CampaignCopyApplyResult, InterspireError> {
        scaffold::campaign_copy_apply(
            self,
            source_campaign_id,
            plan_id,
            guarded_writes_enabled,
            form_write_controls_enabled,
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
        if self.get_allowed(&AdminReadPage::Lists.path()).is_ok() {
            return Ok(());
        }

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

    pub(super) fn get_allowed(&self, path: &str) -> Result<String, InterspireError> {
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

    pub(super) fn with_access_headers(&self, request: RequestBuilder) -> RequestBuilder {
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
        let digest = Sha256::digest(trimmed.as_bytes());
        return format!(
            "[content len={} sha256={}]",
            trimmed.len(),
            &hex::encode(digest)[..12],
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

pub(super) fn ensure_authenticated_html(html: &str) -> Result<(), InterspireError> {
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

pub(super) fn extract_login_csrf_token(html: &str) -> Option<LoginCsrfToken> {
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
    is_csrf_field_name(name)
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

pub(super) fn admin_evidence(notes: Vec<String>) -> Evidence {
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
        name: first_value(&values, &["name", "listname", "list_name"])
            .map(|value| redact::redact_sensitive_text(&value)),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriberExactSearchParse {
    exact_email_found: bool,
    looks_like_subscriber_page: bool,
    warnings: Vec<String>,
}

fn subscriber_exact_search_paths(list_id: u64, email: &str) -> Vec<String> {
    let email = url::form_urlencoded::byte_serialize(email.trim().as_bytes()).collect::<String>();
    vec![
        format!(
            "index.php?Page=Subscribers&Action=Manage&SubAction=Step3&Lists%5B%5D={list_id}&emailaddress={email}&search_rule=exact"
        ),
        format!(
            "index.php?Page=Subscribers&Action=Manage&SubAction=SimpleSearch&Lists%5B%5D={list_id}&emailaddress={email}&search_rule=exact"
        ),
        format!(
            "index.php?Page=Subscribers&Action=Manage&Lists%5B%5D={list_id}&emailaddress={email}&search_rule=exact"
        ),
        format!(
            "index.php?Page=Subscribers&Action=Manage&List={list_id}&emailaddress={email}&search_rule=exact"
        ),
        format!(
            "index.php?Page=Subscribers&Action=Manage&Lists={list_id}&emailaddress={email}&search_rule=exact"
        ),
    ]
}

fn normalize_exact_email_query(email: &str) -> Result<String, InterspireError> {
    let email = email.trim().to_ascii_lowercase();
    if email.len() > 254
        || email.chars().any(|ch| ch.is_control())
        || email.contains('*')
        || !email.contains('@')
        || email.starts_with('@')
        || email.ends_with('@')
    {
        return Err(InterspireError::Safety(
            "contact-state HTML fallback requires one exact email address".to_string(),
        ));
    }
    Ok(email)
}

fn parse_subscriber_exact_search_page(
    html: &str,
    email: &str,
) -> Result<SubscriberExactSearchParse, InterspireError> {
    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let link_selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let email = email.trim().to_ascii_lowercase();
    let mut exact_email_found = false;
    let mut looks_like_subscriber_page = false;
    let mut warnings = Vec::new();
    let mut inspected_rows = 0usize;
    let mut email_like_cells = 0usize;

    for row in document.select(&row_selector) {
        if row_contains_nested_rows(&row, &row_selector) {
            continue;
        }
        let row_text = compact_text(&row.text().collect::<Vec<_>>().join(" "));
        if row_text.len() < 3 {
            continue;
        }
        inspected_rows += 1;
        let row_lower = row_text.to_ascii_lowercase();
        looks_like_subscriber_page |= row_lower.contains("subscriber")
            || row_lower.contains("email")
            || row_lower.contains("contact");
        email_like_cells += row_text
            .split_whitespace()
            .filter(|part| part.contains('@'))
            .count();
        if row_contains_exact_email(&row_text, &email) {
            exact_email_found = true;
            break;
        }
        for link in row.select(&link_selector) {
            if let Some(href) = link.value().attr("href") {
                let href_lower = href.to_ascii_lowercase();
                looks_like_subscriber_page |= href_lower.contains("page=subscribers");
            }
        }
    }

    if inspected_rows == 0 {
        warnings.push("subscriber exact-search page contained no parseable rows".to_string());
    }
    if email_like_cells > 5 && !exact_email_found {
        warnings.push(
            "subscriber exact-search page contained multiple email-like values; result treated as low-confidence absence"
                .to_string(),
        );
    }

    Ok(SubscriberExactSearchParse {
        exact_email_found,
        looks_like_subscriber_page,
        warnings,
    })
}

fn row_contains_exact_email(row_text: &str, email: &str) -> bool {
    row_text.split(email_token_separator).any(|part| {
        let candidate = part.trim_matches(email_token_trim).to_ascii_lowercase();
        candidate == email
    })
}

fn email_token_separator(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | '(' | ')' | '[' | ']' | ',')
}

fn email_token_trim(ch: char) -> bool {
    matches!(ch, '.' | ';' | ':' | '!' | '?' | '\u{00a0}')
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

pub fn parse_campaign_manage_rows(
    html: &str,
    max_rows: usize,
) -> Result<Vec<CampaignManageRow>, InterspireError> {
    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let link_selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut rows = Vec::new();

    for row in document.select(&row_selector) {
        if row_contains_nested_rows(&row, &row_selector) {
            continue;
        }

        let mut campaign_id = None;
        let mut action_labels = Vec::new();
        for link in row.select(&link_selector) {
            let Some(href) = link.value().attr("href") else {
                continue;
            };
            if !href.contains("Page=Newsletters") && !href.contains("Page=Send") {
                continue;
            }
            if campaign_id.is_none() {
                campaign_id = extract_query_u64(href, "id");
            }
            let label = compact_text(&link.text().collect::<Vec<_>>().join(" "));
            if let Some(action_label) = campaign_action_label(href, &label) {
                if !action_labels.contains(&action_label) {
                    action_labels.push(action_label);
                }
            }
        }

        let Some(campaign_id) = campaign_id else {
            continue;
        };
        let row_summary =
            redact::redact_sensitive_text(&compact_text(&row.text().collect::<Vec<_>>().join(" ")));
        if row_summary.len() < 3 {
            continue;
        }
        let action_lookup = action_labels
            .iter()
            .map(|label| label.to_ascii_lowercase())
            .collect::<Vec<_>>();
        rows.push(CampaignManageRow {
            campaign_id,
            row_summary,
            can_send: action_lookup.iter().any(|label| label == "send"),
            can_edit: action_lookup.iter().any(|label| label == "edit"),
            can_copy: action_lookup.iter().any(|label| label == "copy"),
            can_delete: action_lookup.iter().any(|label| label == "delete"),
            action_labels,
        });
        if rows.len() >= max_rows {
            break;
        }
    }

    Ok(rows)
}

fn campaign_action_label(href: &str, link_label: &str) -> Option<String> {
    let lower_href = href.to_ascii_lowercase();
    let lower_label = link_label.to_ascii_lowercase();
    let action = if lower_href.contains("page=send") || lower_href.contains("action=send") {
        "Send"
    } else if lower_href.contains("action=edit") || lower_label == "edit" {
        "Edit"
    } else if lower_href.contains("action=copy") || lower_label == "copy" {
        "Copy"
    } else if lower_href.contains("action=delete") || lower_label == "delete" {
        "Delete"
    } else if lower_href.contains("action=view") || lower_label == "view" {
        "View"
    } else if lower_href.contains("action=activate") || lower_label == "activate" {
        "Activate"
    } else if lower_href.contains("action=deactivate") || lower_label == "deactivate" {
        "Deactivate"
    } else {
        return None;
    };
    Some(action.to_string())
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
        let pause_before_delete =
            parse_row_pause_control(base_url, &row, &link_selector, row_checkbox.as_ref())?;
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
            let route_action = route.action;
            links.push(QueueControlLink {
                candidate: QueueControlCandidate {
                    plan_id,
                    action: route_action,
                    action_label: redact::redact_sensitive_text(&action_label),
                    row_summary: row_summary.clone(),
                    route_fingerprint: route_fingerprint(&route_key),
                    requires_guarded_write: true,
                },
                route,
                url,
                execution,
                pause_before_delete: if route_action == QueueControlAction::Delete {
                    pause_before_delete.clone()
                } else {
                    None
                },
            });
        }
    }

    Ok(links)
}

fn parse_row_pause_control(
    base_url: &str,
    row: &ElementRef<'_>,
    link_selector: &Selector,
    row_checkbox: Option<&(String, u64)>,
) -> Result<Option<Url>, InterspireError> {
    for link in row.select(link_selector) {
        let action_label = compact_text(&link.text().collect::<Vec<_>>().join(" "));
        if !action_label.to_ascii_lowercase().contains("pause") {
            continue;
        }
        let Some(href) = link.value().attr("href") else {
            continue;
        };
        let Ok((url, pause_job)) = safety::ensure_allowed_queue_control_pause(base_url, href)
        else {
            continue;
        };
        if let Some((_, row_job)) = row_checkbox {
            if pause_job != *row_job {
                continue;
            }
        }
        return Ok(Some(url));
    }
    Ok(None)
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

fn csrf_pair(pairs: &[(String, String)]) -> Option<(&str, &str)> {
    pairs.iter().find_map(|(name, value)| {
        if is_csrf_field_name(name) && !value.trim().is_empty() {
            Some((name.as_str(), value.as_str()))
        } else {
            None
        }
    })
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

pub(super) fn extract_ids_from_links(html: &str, page_marker: &str, id_key: &str) -> Vec<u64> {
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

pub(super) fn compact_text(value: &str) -> String {
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
    fn content_field_summaries_never_include_body_excerpts() {
        let summary = summarize_field_value(
            "html_body",
            "<html><body>PRIVATE-NEWSLETTER-SENTINEL</body></html>",
        );

        assert!(summary.starts_with("[content len="));
        assert!(summary.contains("sha256="));
        assert!(!summary.contains("PRIVATE-NEWSLETTER-SENTINEL"));
        assert!(!summary.contains("<html>"));
        assert!(!summary.contains("excerpt"));
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
    fn login_csrf_token_ignores_unrelated_token_suffix_fields() {
        let html = r#"
            <form method="post" action="index.php?Page=Login&Action=Login">
              <input name="access_token" value="wrong-token">
              <script>window.IEM_CSRF_TOKEN = 'right-token';</script>
            </form>
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
    fn subscriber_exact_search_parser_detects_exact_email_without_returning_row() {
        let html = r#"
            <table>
              <tr><th>Email</th><th>Status</th></tr>
              <tr>
                <td>person@example.test</td>
                <td>Active Confirmed <a href="index.php?Page=Subscribers&Action=Edit&id=12">Edit</a></td>
              </tr>
            </table>
        "#;

        let parsed = parse_subscriber_exact_search_page(html, "person@example.test")
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(parsed.exact_email_found);
        assert!(parsed.looks_like_subscriber_page);
        assert!(format!("{parsed:?}").contains("exact_email_found"));
        assert!(!format!("{parsed:?}").contains("person@example.test"));
    }

    #[test]
    fn subscriber_exact_search_parser_does_not_match_email_substrings() {
        let html = r#"
            <table>
              <tr><th>Email</th><th>Status</th></tr>
              <tr><td>notperson@example.test</td><td>Active Confirmed</td></tr>
            </table>
        "#;

        let parsed = parse_subscriber_exact_search_page(html, "person@example.test")
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!parsed.exact_email_found);
        assert!(parsed.looks_like_subscriber_page);
    }

    #[test]
    fn subscriber_exact_search_client_uses_allowlisted_read_and_redacts_evidence() {
        let server = spawn_contact_state_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));

        let report = client
            .contact_state_readback("person@example.test", 7)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(report.found_on_list, Some(true));
        assert!(report
            .evidence_notes
            .iter()
            .any(|note| note.contains("Subscribers exact-search GET read")));
        let rendered =
            serde_json::to_string(&report.evidence_notes).unwrap_or_else(|err| panic!("{err}"));
        assert!(!rendered.contains("person@example.test"));
        assert!(server.requests().iter().any(|request| {
            request.starts_with(
                "GET /admin/index.php?Page=Subscribers&Action=Manage&SubAction=Step3&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
            )
        }));
    }

    #[test]
    fn subscriber_exact_search_client_falls_back_to_simple_search() {
        let server = spawn_contact_state_simple_search_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));

        let report = client
            .contact_state_readback("person@example.test", 7)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(report.found_on_list, Some(true));
        let rendered =
            serde_json::to_string(&report.evidence_notes).unwrap_or_else(|err| panic!("{err}"));
        assert!(!rendered.contains("person@example.test"));
        let requests = server.requests();
        assert!(requests.iter().any(|request| {
            request.starts_with(
                "GET /admin/index.php?Page=Subscribers&Action=Manage&SubAction=Step3&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
            )
        }));
        assert!(requests.iter().any(|request| {
            request.starts_with(
                "GET /admin/index.php?Page=Subscribers&Action=Manage&SubAction=SimpleSearch&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
            )
        }));
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
    fn campaign_render_artifact_uses_interspire_8_step2_body_page() {
        let server = spawn_campaign_step2_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));
        let report = client
            .campaign_render_artifact(&crate::response::CampaignRenderArtifactRequest {
                campaign_id: 7,
                output_dir: None,
                artifact_prefix: None,
                include_image_blocked_variant: true,
            })
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.ok);
        assert_eq!(report.subject.as_deref(), Some("Original subject"));
        assert!(report.html_bytes > 0);
        assert_eq!(report.artifacts.len(), 3);
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| { note.contains("Step1 POST rendered Interspire 8 Step2 body page") }));
    }

    #[test]
    fn campaign_template_preview_uses_interspire_8_step2_body_form() {
        let server = spawn_campaign_step2_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));

        let report = client
            .campaign_update_preview(
                7,
                &[FormFieldUpdate {
                    name: "html_body".to_string(),
                    value: Some("<p>Updated body %%UNSUBSCRIBELINK%%</p>".to_string()),
                    checked: None,
                }],
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.ok);
        assert!(report
            .available_fields
            .iter()
            .any(|field| field.name == "mydeveditcontrol_html"));
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].name, "html_body->mydeveditcontrol_html");
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| { note.contains("Step1 POST rendered Interspire 8 Step2 form") }));
    }

    #[test]
    fn campaign_template_apply_posts_step2_body_and_preserves_tracking_flags() {
        let server = spawn_campaign_step2_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));
        let updates = [FormFieldUpdate {
            name: "html_body".to_string(),
            value: Some("<p>Applied body %%UNSUBSCRIBELINK%%</p>".to_string()),
            checked: None,
        }];
        let preview = client
            .campaign_update_preview(7, &updates)
            .unwrap_or_else(|err| panic!("{err}"));

        let apply = client
            .campaign_update_apply(
                7,
                &preview.plan_id,
                &updates,
                crate::config::WriteExecutionMode::PreviewApply,
            )
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(apply.ok);
        assert!(apply.applied);
        assert_eq!(apply.changes.len(), 1);
        assert_eq!(apply.changes[0].name, "html_body->mydeveditcontrol_html");
        let requests = server.requests();
        let complete_post = requests
            .iter()
            .find(|request| {
                request.starts_with(
                    "POST /admin/index.php?Page=Newsletters&Action=Edit&SubAction=Complete&id=7 ",
                )
            })
            .unwrap_or_else(|| panic!("Complete/save request should be posted"));
        assert!(complete_post.contains("myDevEditControl_html=%3Cp%3EApplied+body"));
        assert!(complete_post.contains("Subject=Original+subject"));
        assert!(complete_post.contains("trackopens=1"));
        assert!(complete_post.contains("tracklinks=1"));
        let complete_post_headers = complete_post.to_ascii_lowercase();
        assert!(complete_post_headers.contains("referer: http://"));
        assert!(
            complete_post_headers.contains("/admin/index.php?page=newsletters&action=edit&id=7")
        );
        assert!(complete_post_headers.contains("origin: http://"));
        assert!(complete_post_headers.contains("x-csrf-token: fixture-csrf"));
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

    fn spawn_campaign_step2_fixture_server() -> TestAdminServer {
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
        let body_html = Arc::new(Mutex::new(
            r#"<p>Original body <a href="https://example.invalid">Read</a><img src="x.png" alt="Logo">%%UNSUBSCRIBELINK%%</p>"#
                .to_string(),
        ));
        let thread_body_html = Arc::clone(&body_html);

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
                        write_campaign_step2_fixture_response(
                            &mut stream,
                            &request,
                            &thread_body_html,
                        );
                        if thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("test requests lock poisoned while count: {err}")
                            })
                            .len()
                            >= 12
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

    fn spawn_campaign_manage_fixture_server() -> TestAdminServer {
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
                        write_campaign_manage_fixture_response(&mut stream, &request);
                        if thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("test requests lock poisoned while count: {err}")
                            })
                            .len()
                            >= 3
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

    fn spawn_contact_state_fixture_server() -> TestAdminServer {
        spawn_contact_state_fixture_server_with(false)
    }

    fn spawn_contact_state_simple_search_fixture_server() -> TestAdminServer {
        spawn_contact_state_fixture_server_with(true)
    }

    fn spawn_contact_state_fixture_server_with(simple_search_only: bool) -> TestAdminServer {
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
                        write_contact_state_fixture_response(
                            &mut stream,
                            &request,
                            simple_search_only,
                        );
                        let expected_requests = if simple_search_only { 3 } else { 2 };
                        if thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("test requests lock poisoned while count: {err}")
                            })
                            .len()
                            >= expected_requests
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

    fn write_campaign_step2_fixture_response(
        stream: &mut std::net::TcpStream,
        request: &str,
        body_html: &Arc<Mutex<String>>,
    ) {
        let body = if request.starts_with("GET /admin/index.php?Page=Login&Action=Login ") {
            r#"<form method="post" action="index.php?Page=Login&Action=Login">
                <input type="hidden" name="csrf_token" value="fixture-csrf">
                <input name="ss_username">
                <input name="ss_password">
              </form>"#
                .to_string()
        } else if request.starts_with("POST /admin/index.php?Page=Login&Action=Login ") {
            "<html><body>logged in</body></html>".to_string()
        } else if request.starts_with("GET /admin/index.php?Page=Newsletters&Action=Edit&id=7 ") {
            r#"<form action="index.php?Page=Newsletters&Action=Edit&SubAction=Step2&id=7">
                <input type="hidden" name="csrf_token" value="fixture-csrf">
                <input name="Name" value="Fixture campaign">
                <input type="radio" name="Format" value="t">
                <input type="radio" name="Format" value="h" checked>
                <input type="hidden" name="usewysiwyg" value="3">
                <input type="submit" name="NextButton" value="Next &gt;&gt;">
              </form>"#
                .to_string()
        } else if request
            .starts_with("POST /admin/index.php?Page=Newsletters&Action=Edit&SubAction=Step2&id=7 ")
        {
            let html = body_html
                .lock()
                .unwrap_or_else(|err| panic!("body html lock poisoned: {err}"))
                .clone();
            format!(
                r#"<form action="index.php?Page=Newsletters&Action=Edit&SubAction=Complete&id=7">
                <input type="hidden" name="csrf_token" value="fixture-csrf">
                <input name="Subject" value="Original subject">
                <textarea name="myDevEditControl_html">{html}</textarea>
                <textarea name="myDevEditControl_text">Original text</textarea>
                <input type="checkbox" name="trackopens" value="1" checked>
                <input type="checkbox" name="tracklinks" value="1" checked>
                <input type="submit" name="SaveButton" value="Save">
              </form>"#
            )
        } else if request.starts_with(
            "POST /admin/index.php?Page=Newsletters&Action=Edit&SubAction=Complete&id=7 ",
        ) {
            let request_body = request
                .split_once("\r\n\r\n")
                .map(|(_, body)| body)
                .unwrap_or_default();
            if let Some((_, value)) = url::form_urlencoded::parse(request_body.as_bytes())
                .find(|(name, _)| name == "myDevEditControl_html")
            {
                *body_html
                    .lock()
                    .unwrap_or_else(|err| panic!("body html lock poisoned while update: {err}")) =
                    value.into_owned();
            }
            "<html><body>saved</body></html>".to_string()
        } else {
            "<html><body>unexpected request</body></html>".to_string()
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

    fn write_campaign_manage_fixture_response(stream: &mut std::net::TcpStream, request: &str) {
        let body = if request.starts_with("GET /admin/index.php?Page=Login&Action=Login ") {
            r#"<form method="post" action="index.php?Page=Login&Action=Login">
                <input type="hidden" name="csrf_token" value="fixture-csrf">
                <input name="ss_username">
                <input name="ss_password">
              </form>"#
        } else if request.starts_with("POST /admin/index.php?Page=Login&Action=Login ") {
            "<html><body>logged in</body></html>"
        } else if request.starts_with("GET /admin/index.php?Page=Newsletters&Action=Manage ") {
            r#"<table>
                <tr><th>Name</th><th>Subject</th><th>Action</th></tr>
                <tr>
                  <td><a href="index.php?Page=Newsletters&Action=Edit&id=101&csrfToken=secret">Campaign One</a></td>
                  <td>News for person@example.test</td>
                  <td>
                    <a href="index.php?Page=Send&Action=Step1&id=101&csrfToken=secret">Send</a>
                    <a href="index.php?Page=Newsletters&Action=Edit&id=101&csrfToken=secret">Edit</a>
                    <a href="index.php?Page=Newsletters&Action=Copy&id=101&csrfToken=secret">Copy</a>
                  </td>
                </tr>
                <tr>
                  <td><a href="index.php?Page=Newsletters&Action=Edit&id=102&csrfToken=secret">Campaign Two</a></td>
                  <td>News for other@example.test</td>
                  <td>
                    <a href="index.php?Page=Newsletters&Action=Edit&id=102&csrfToken=secret">Edit</a>
                    <a href="index.php?Page=Newsletters&Action=Delete&id=102&csrfToken=secret">Delete</a>
                  </td>
                </tr>
              </table>"#
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

    fn write_contact_state_fixture_response(
        stream: &mut std::net::TcpStream,
        request: &str,
        simple_search_only: bool,
    ) {
        let body = if request.starts_with("GET /admin/index.php?Page=Lists ") {
            "<html><body><a href=\"index.php?Page=Lists&Action=Edit&id=7\">List</a></body></html>"
        } else if simple_search_only && request.starts_with(
            "GET /admin/index.php?Page=Subscribers&Action=Manage&SubAction=Step3&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
        ) {
            r#"<table>
                <tr><th>Email</th><th>Status</th><th>Action</th></tr>
                <tr>
                  <td>other@example.test</td>
                  <td>Active Confirmed</td>
                  <td><a href="index.php?Page=Subscribers&Action=Edit&id=99">Edit</a></td>
                </tr>
              </table>"#
        } else if (simple_search_only
            && request.starts_with(
                "GET /admin/index.php?Page=Subscribers&Action=Manage&SubAction=SimpleSearch&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
            ))
            || (!simple_search_only
                && (request.starts_with(
                    "GET /admin/index.php?Page=Subscribers&Action=Manage&SubAction=Step3&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
                ) || request.starts_with(
                    "GET /admin/index.php?Page=Subscribers&Action=Manage&Lists%5B%5D=7&emailaddress=person%40example.test&search_rule=exact ",
                )))
        {
            r#"<table>
                <tr><th>Email</th><th>Status</th><th>Action</th></tr>
                <tr>
                  <td>person@example.test</td>
                  <td>Active Confirmed</td>
                  <td><a href="index.php?Page=Subscribers&Action=Edit&id=12">Edit</a></td>
                </tr>
              </table>"#
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
    fn queue_control_delete_candidates_capture_same_job_pause_preflight() {
        let html = r#"
            <table>
              <tr>
                <th>Campaign</th><th>Actions</th>
              </tr>
              <tr>
                <td><input type="checkbox" name="jobs[]" value="2"></td>
                <td>Launch seed send to recipient@example.invalid</td>
                <td>
                  <a href="index.php?Page=Schedule&Action=Pause&job=2&csrfToken=abc">Pause</a>
                  <a href="index.php?Page=Schedule&Action=Delete&job=2&csrfToken=abc">Delete</a>
                </td>
              </tr>
              <tr>
                <td><input type="checkbox" name="jobs[]" value="3"></td>
                <td>Other job</td>
                <td>
                  <a href="index.php?Page=Schedule&Action=Pause&job=99&csrfToken=abc">Pause</a>
                  <a href="index.php?Page=Schedule&Action=Delete&job=3&csrfToken=abc">Delete</a>
                </td>
              </tr>
            </table>
        "#;

        let links = parse_queue_control_links("https://example.test/admin/", html, 25)
            .unwrap_or_else(|err| panic!("{err}"));

        let delete = links
            .iter()
            .find(|link| {
                link.candidate.action == QueueControlAction::Delete
                    && link.route.identifier_value == 2
            })
            .unwrap_or_else(|| panic!("delete candidate should be present"));
        assert!(delete.pause_before_delete.is_some());
        let candidate_json =
            serde_json::to_string(&delete.candidate).unwrap_or_else(|err| panic!("{err}"));
        assert!(!candidate_json.contains("index.php"));
        assert!(!candidate_json.contains("csrfToken"));

        let mismatched = links
            .iter()
            .find(|link| {
                link.candidate.action == QueueControlAction::Delete
                    && link.route.identifier_value == 3
            })
            .unwrap_or_else(|| panic!("second delete candidate should be present"));
        assert!(mismatched.pause_before_delete.is_none());
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
    fn parse_campaign_manage_rows_preserves_ids_without_admin_urls() {
        let html = r#"
            <table>
              <tr>
                <th>Name</th><th>Subject</th><th>Action</th>
              </tr>
              <tr>
                <td><a href="index.php?Page=Newsletters&Action=Edit&id=8287&csrfToken=leak">Fixture Update</a></td>
                <td>Fixture daily for editor@example.invalid</td>
                <td>
                  <a href="index.php?Page=Send&Action=Step1&id=8287&csrfToken=leak">Send</a>
                  <a href="index.php?Page=Newsletters&Action=Edit&id=8287&csrfToken=leak">Edit</a>
                  <a href="index.php?Page=Newsletters&Action=Copy&id=8287&csrfToken=leak">Copy</a>
                  <a href="index.php?Page=Newsletters&Action=Delete&id=8287&csrfToken=leak">Delete</a>
                </td>
              </tr>
            </table>
        "#;

        let rows = parse_campaign_manage_rows(html, 25).unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.campaign_id, 8287);
        assert!(row.can_send);
        assert!(row.can_edit);
        assert!(row.can_copy);
        assert!(row.can_delete);
        assert!(row.action_labels.contains(&"Send".to_string()));
        assert!(row.action_labels.contains(&"Edit".to_string()));
        assert!(row.action_labels.contains(&"Copy".to_string()));
        assert!(row.action_labels.contains(&"Delete".to_string()));
        let json = serde_json::to_string(row).unwrap_or_else(|err| panic!("{err}"));
        assert!(!json.contains("index.php"));
        assert!(!json.contains("csrfToken"));
        assert!(!json.contains("editor@example.invalid"));
    }

    #[test]
    fn campaign_readback_warns_when_manage_rows_are_capped() {
        let server = spawn_campaign_manage_fixture_server();
        let client = AdminHtmlClient::new(test_admin_config(&server.base_url))
            .unwrap_or_else(|err| panic!("{err}"));

        let report = client
            .campaign_readback(None, 1)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(report.campaign_manage_rows.len(), 1);
        assert_eq!(report.campaign_manage_rows[0].campaign_id, 101);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("max_rows cap 1")
                && warning.contains("additional campaign rows may exist")));
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note.contains("campaign manage rows truncated")));
        let json = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));
        assert!(!json.contains("index.php"));
        assert!(!json.contains("csrfToken"));
        assert!(!json.contains("person@example.test"));
        assert!(!json.contains("other@example.test"));
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

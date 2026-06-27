//! Authenticated Interspire admin HTML readback adapter.
//!
//! This module owns the brittle legacy HTML boundary for allowlisted GET-only
//! pages. It logs in with credentials supplied outside git, reads only pages
//! admitted by `safety`, parses redacted operational fields, and never exposes
//! raw saved HTML, cookies, passwords, contact exports, or send/cron actions.

mod forms;

use crate::{
    config::{AdminHtmlConfig, WriteExecutionMode},
    error::InterspireError,
    guarded_write, redact,
    response::{
        CampaignReadbackReport, Evidence, FormFieldUpdate, GuardedWriteApplyReport,
        GuardedWritePreviewReport, ListSummary, QueueControlAction, QueueControlCandidate,
        QueueStatsReadbackReport, RedactedField, SettingsAuditReport, SettingsSection,
        SettingsSectionName, UserSmtpReadbackReport, UserSmtpSummary,
    },
    safety::{self, AdminReadPage, QueueControlRoute},
};
use reqwest::{blocking::Client, redirect::Policy};
use scraper::{Html, Selector};
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

        let response = self
            .http
            .get(selected.url.clone())
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
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
                    "legacy admin returned HTTP {}; Schedule page re-read after apply",
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

        let response = self
            .http
            .post(login_url)
            .form(&[
                ("ss_username", username),
                ("ss_password", password),
                ("ss_takemeto", ""),
                ("SubmitButton", "Login"),
            ])
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

    fn get_allowed(&self, path: &str) -> Result<String, InterspireError> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = safety::ensure_allowed_admin_get(base_url, path)?;
        let response = self
            .http
            .get(url)
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

fn admin_evidence(notes: Vec<String>) -> Evidence {
    Evidence {
        source: "interspire_admin_html".to_string(),
        notes,
    }
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
    let mut links = Vec::new();
    let mut inspected_rows = 0usize;

    for row in document.select(&row_selector) {
        let row_text = compact_text(&row.text().collect::<Vec<_>>().join(" "));
        if row_text.len() < 3 || row_text.eq_ignore_ascii_case("actions") {
            continue;
        }
        inspected_rows += 1;
        if inspected_rows > max_rows {
            break;
        }
        let row_summary = redact::redact_sensitive_text(&row_text);
        for link in row.select(&link_selector) {
            let action_label = compact_text(&link.text().collect::<Vec<_>>().join(" "));
            if !looks_like_queue_control_label(&action_label) {
                continue;
            }
            let Some(href) = link.value().attr("href") else {
                continue;
            };
            let Ok((url, route)) = safety::ensure_allowed_queue_control(base_url, href) else {
                continue;
            };
            let route_key = route_key(&url);
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
            });
        }
    }

    Ok(links)
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

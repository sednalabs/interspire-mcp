use super::{
    admin_evidence, compact_text, ensure_authenticated_html, extract_login_csrf_token, forms,
    parse_table_rows, redact_field_value, route_fingerprint, AdminHtmlClient,
};
use crate::{
    error::InterspireError,
    redact,
    response::{
        AdminSessionProbeReport, CampaignBodyAuditReport, SeedReadinessGate,
        SeedReadinessGateReport, SeedReadinessGateRequest, SendWizardReadbackReport,
        SendWizardReadbackRequest,
    },
    safety::{self, AdminReadPage},
};
use reqwest::blocking::RequestBuilder;
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use url::Url;

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

        let step1_path = AdminReadPage::NewsletterEdit { id: campaign_id }.path();
        let step1_html = self.get_allowed(&step1_path)?;
        let mut report = campaign_body_audit_from_html(campaign_id, &step1_html)?;
        if report.html_bytes > 0 || report.text_bytes > 0 {
            return Ok(report);
        }

        let Some(step2_path) = campaign_body_step2_action_path(campaign_id, &step1_html)? else {
            report.warnings.push(
                "campaign edit page did not expose Interspire 8 Step2 body form; body audit is incomplete"
                    .to_string(),
            );
            return Ok(report);
        };
        let step2_url = safety::ensure_allowed_campaign_body_step2_post(
            self.config.base_url.as_deref().unwrap_or_default(),
            &step2_path,
            campaign_id,
        )?;
        let mut post_pairs = campaign_body_step1_pairs(campaign_id, &step1_html)?;
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

        report = campaign_body_audit_from_html(campaign_id, &step2_html)?;
        let step1_fields = parse_form_values_exact(&step1_html)?;
        if report.name.is_none() {
            report.name = first_present(&step1_fields, &["name"])
                .map(|value| redact::redact_sensitive_text(&value));
        }
        report.evidence.notes.push(
            "allowlisted Newsletter edit Step1 POST rendered Interspire 8 Step2 body page; Complete/save form was not posted"
                .to_string(),
        );
        Ok(report)
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

fn campaign_body_audit_from_html(
    campaign_id: u64,
    html: &str,
) -> Result<CampaignBodyAuditReport, InterspireError> {
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
    let name = first_present(&fields, &["name"]).map(|value| redact::redact_sensitive_text(&value));
    let subject =
        first_present(&fields, &["subject"]).map(|value| redact::redact_sensitive_text(&value));
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
        name,
        subject,
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
    ) || lower.ends_with("token")
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
    ) || lower.ends_with("token")
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
        append_csrf_pair_if_missing, campaign_body_audit_from_html, campaign_body_step1_pairs,
        campaign_body_step2_action_path, csrf_pair, list_ids_warning, parse_send_wizard_final_page,
        recipient_count_marker, selected_or_hidden_list_ids, send_step2_action_path,
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

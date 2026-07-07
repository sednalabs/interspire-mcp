use super::{admin_evidence, ensure_authenticated_html, AdminHtmlClient};
use crate::{
    config::WriteExecutionMode,
    error::InterspireError,
    guarded_write, redact,
    response::{
        FormFieldChange, FormFieldDescriptor, GuardedWriteApplyReport, GuardedWritePreviewReport,
        RedactedField,
    },
    safety::{self, AdminReadPage},
};
use mcp_toolkit_observability::redaction::truncate;
use scraper::{Html, Selector};
use url::Url;

#[derive(Debug, Clone)]
struct CampaignActiveStateSnapshot {
    campaign_id: u64,
    current_active: bool,
    action_href: Option<String>,
    action_label: Option<&'static str>,
}

pub(super) fn campaign_active_state_preview(
    client: &AdminHtmlClient,
    campaign_id: u64,
    active: bool,
) -> Result<GuardedWritePreviewReport, InterspireError> {
    if !client.config.is_configured() {
        return Err(InterspireError::AdminHtmlNotConfigured);
    }
    client.login()?;

    let snapshot = campaign_active_state_snapshot(client, campaign_id, active)?;
    let plan_id = campaign_active_state_plan_id(&snapshot, active);
    let will_change = snapshot.current_active != active;
    let mut warnings = vec![
        "preview only; apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_FORM_WRITE_CONTROLS=1".to_string(),
    ];
    if !will_change {
        warnings.push(
            "campaign already appears to be in the requested active state; apply will only re-read proof"
                .to_string(),
        );
    }

    Ok(GuardedWritePreviewReport {
        ok: true,
        configured: true,
        guarded_writes_enabled: true,
        form_write_controls_enabled: true,
        write_execution_mode: WriteExecutionMode::PreviewApply,
        target: "campaign_active_state".to_string(),
        target_id: Some(campaign_id),
        section: None,
        plan_id,
        apply_directly_allowed: false,
        available_fields: vec![FormFieldDescriptor {
            name: "active".to_string(),
            control_kind: "state_route".to_string(),
        }],
        changes: vec![active_state_change(&snapshot, active)],
        warnings,
        evidence: admin_evidence(vec![
            "allowlisted Newsletter manage GET read for campaign active-state preview".to_string(),
            "campaign active state inferred from Interspire Activate/Deactivate manage action"
                .to_string(),
        ]),
    })
}

pub(super) fn campaign_active_state_apply(
    client: &AdminHtmlClient,
    campaign_id: u64,
    active: bool,
    plan_id: &str,
    mode: WriteExecutionMode,
) -> Result<GuardedWriteApplyReport, InterspireError> {
    if !client.config.is_configured() {
        return Err(InterspireError::AdminHtmlNotConfigured);
    }
    client.login()?;

    let snapshot = campaign_active_state_snapshot(client, campaign_id, active)?;
    let expected_plan_id = campaign_active_state_plan_id(&snapshot, active);
    if plan_id != expected_plan_id {
        return Err(InterspireError::Safety(
            "plan_id does not match the current campaign active-state fingerprint and requested state"
                .to_string(),
        ));
    }

    let mut applied = false;
    let mut notes =
        vec!["allowlisted Newsletter manage GET read for campaign active-state apply".to_string()];
    let mut warnings = Vec::new();

    if snapshot.current_active != active {
        let href = snapshot.action_href.as_deref().ok_or_else(|| {
            InterspireError::Safety(
                "requested campaign active-state route was not available on the manage row"
                    .to_string(),
            )
        })?;
        let base_url = client.config.base_url.as_deref().unwrap_or_default();
        let action_url =
            safety::ensure_allowed_campaign_active_state_get(base_url, href, campaign_id, active)?;
        let referer =
            safety::ensure_allowed_admin_get(base_url, &AdminReadPage::NewslettersManage.path())?;
        let response = client
            .with_access_headers(client.http.get(action_url))
            .header("referer", referer.as_str())
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !response.status().is_success() && !response.status().is_redirection() {
            return Err(InterspireError::Http(format!(
                "campaign active-state route returned HTTP {}",
                response.status().as_u16()
            )));
        }
        if response.status().is_success() {
            let html = response
                .text()
                .map_err(|err| InterspireError::Http(err.to_string()))?;
            ensure_authenticated_html(&html)?;
        }
        applied = true;
        notes.push("allowlisted campaign active-state GET route was requested".to_string());
    } else {
        warnings.push(
            "campaign already matched the requested active state; no state-route was requested"
                .to_string(),
        );
    }

    let fresh_client = AdminHtmlClient::new(client.config.clone())?;
    fresh_client.login()?;
    let after = campaign_active_state_snapshot(&fresh_client, campaign_id, active)?;
    if after.current_active != active {
        return Err(InterspireError::Safety(
            "campaign active-state route returned but fresh readback did not match the requested state; treat apply as unproven"
                .to_string(),
        ));
    }
    notes.push("fresh admin session proved campaign active state from manage page".to_string());

    Ok(GuardedWriteApplyReport {
        ok: true,
        configured: true,
        guarded_writes_enabled: true,
        form_write_controls_enabled: true,
        write_execution_mode: mode,
        target: "campaign_active_state".to_string(),
        target_id: Some(campaign_id),
        section: None,
        applied,
        plan_id: expected_plan_id,
        changes: vec![active_state_change(&snapshot, active)],
        post_apply_fields: vec![RedactedField {
            name: "active".to_string(),
            value: Some(active.to_string()),
        }],
        warnings,
        evidence: admin_evidence(notes),
    })
}

fn campaign_active_state_snapshot(
    client: &AdminHtmlClient,
    campaign_id: u64,
    requested_active: bool,
) -> Result<CampaignActiveStateSnapshot, InterspireError> {
    let html = client.get_allowed(&AdminReadPage::NewslettersManage.path())?;
    parse_campaign_active_state_snapshot(&html, campaign_id, requested_active)
}

fn parse_campaign_active_state_snapshot(
    html: &str,
    campaign_id: u64,
    requested_active: bool,
) -> Result<CampaignActiveStateSnapshot, InterspireError> {
    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let link_selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;

    for row in document.select(&row_selector) {
        let mut row_matches = false;
        let mut activate_href = None;
        let mut deactivate_href = None;
        for link in row.select(&link_selector) {
            let Some(href) = link.value().attr("href") else {
                continue;
            };
            if href_campaign_id(href) == Some(campaign_id) {
                row_matches = true;
            }
            match validated_campaign_state_action(href, campaign_id) {
                Some("Activate") => activate_href = Some(href.to_string()),
                Some("Deactivate") => deactivate_href = Some(href.to_string()),
                _ => {}
            }
        }
        if !row_matches {
            continue;
        }

        let current_active = match (activate_href.is_some(), deactivate_href.is_some()) {
            (true, false) => false,
            (false, true) => true,
            _ => {
                let summary =
                    redact::redact_sensitive_text(&row.text().collect::<Vec<_>>().join(" "));
                return Err(InterspireError::Safety(format!(
                    "campaign {campaign_id} manage row did not expose exactly one Activate/Deactivate state action: {}",
                    compact_for_error(&summary)
                )));
            }
        };
        let (action_href, action_label) = if current_active == requested_active {
            (None, None)
        } else if requested_active {
            (activate_href, Some("Activate"))
        } else {
            (deactivate_href, Some("Deactivate"))
        };
        if current_active != requested_active && action_href.is_none() {
            return Err(InterspireError::Safety(
                "requested campaign active-state action was not available on the manage row"
                    .to_string(),
            ));
        }
        return Ok(CampaignActiveStateSnapshot {
            campaign_id,
            current_active,
            action_href,
            action_label,
        });
    }

    Err(InterspireError::Safety(format!(
        "campaign {campaign_id} was not found on the Newsletter manage page"
    )))
}

fn active_state_change(
    snapshot: &CampaignActiveStateSnapshot,
    requested_active: bool,
) -> FormFieldChange {
    FormFieldChange {
        name: "active".to_string(),
        control_kind: "state_route".to_string(),
        current_value: Some(snapshot.current_active.to_string()),
        requested_value: Some(requested_active.to_string()),
        will_change: snapshot.current_active != requested_active,
    }
}

fn campaign_active_state_plan_id(
    snapshot: &CampaignActiveStateSnapshot,
    requested_active: bool,
) -> String {
    let campaign_id = snapshot.campaign_id.to_string();
    let current = snapshot.current_active.to_string();
    let requested = requested_active.to_string();
    let action = snapshot.action_label.unwrap_or("no-op");
    guarded_write::stable_plan_id(&[
        "campaign_active_state",
        &campaign_id,
        &current,
        &requested,
        action,
    ])
}

fn campaign_state_action(href: &str) -> Option<&'static str> {
    let url = Url::parse("https://example.invalid/admin/")
        .ok()?
        .join(href)
        .ok()?;
    let action = url
        .query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("Action"))
        .map(|(_, value)| value.to_string())?;
    if action.eq_ignore_ascii_case("Activate") {
        Some("Activate")
    } else if action.eq_ignore_ascii_case("Deactivate") {
        Some("Deactivate")
    } else {
        None
    }
}

fn validated_campaign_state_action(href: &str, campaign_id: u64) -> Option<&'static str> {
    let url = Url::parse("https://example.invalid/admin/")
        .ok()?
        .join(href)
        .ok()?;
    let action = campaign_state_action(href)?;
    match action {
        "Activate"
            if safety::classify_allowed_campaign_active_state_get(&url, campaign_id, true)
                .is_ok() =>
        {
            Some("Activate")
        }
        "Deactivate"
            if safety::classify_allowed_campaign_active_state_get(&url, campaign_id, false)
                .is_ok() =>
        {
            Some("Deactivate")
        }
        _ => None,
    }
}

fn href_campaign_id(href: &str) -> Option<u64> {
    let url = Url::parse("https://example.invalid/admin/")
        .ok()?
        .join(href)
        .ok()?;
    url.query_pairs()
        .find(|(key, _)| key.eq_ignore_ascii_case("id"))
        .and_then(|(_, value)| value.parse::<u64>().ok())
}

fn compact_for_error(value: &str) -> String {
    truncate(&value.split_whitespace().collect::<Vec<_>>().join(" "), 240)
}

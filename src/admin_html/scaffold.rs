use super::{
    admin_evidence, compact_text, ensure_authenticated_html, extract_ids_from_links,
    AdminHtmlClient,
};
use crate::{
    config::WriteExecutionMode,
    error::InterspireError,
    guarded_write, redact,
    response::{CampaignCopyApplyReport, CampaignCopyPreviewReport},
    safety::{self, AdminReadPage},
};
use reqwest::blocking::RequestBuilder;
use scraper::{Html, Selector};
use url::Url;

pub(super) type CampaignCopyPreviewResult = CampaignCopyPreviewReport;
pub(super) type CampaignCopyApplyResult = CampaignCopyApplyReport;

#[derive(Debug, Clone)]
struct CampaignCopyCandidate {
    url: Url,
    route_key: String,
    constructed_from_visible_route: bool,
}

pub(super) fn campaign_copy_preview(
    client: &AdminHtmlClient,
    source_campaign_id: u64,
    guarded_writes_enabled: bool,
    form_write_controls_enabled: bool,
    mode: WriteExecutionMode,
) -> Result<CampaignCopyPreviewReport, InterspireError> {
    if !client.config.is_configured() {
        return Ok(CampaignCopyPreviewReport {
            ok: true,
            configured: false,
            guarded_writes_enabled,
            form_write_controls_enabled,
            write_execution_mode: mode,
            source_campaign_id,
            plan_id: String::new(),
            copy_candidate_found: false,
            warnings: vec![
                "admin HTML fallback is not configured; no campaign copy preview attempted"
                    .to_string(),
            ],
            evidence: admin_evidence(vec!["no request sent".to_string()]),
        });
    }

    client.login()?;
    let manage_html = client.get_allowed(&AdminReadPage::NewslettersManage.path())?;
    let candidate = find_campaign_copy_candidate(client, source_campaign_id, &manage_html)?;
    let plan_id = campaign_copy_plan_id(source_campaign_id, &candidate);

    let copy_route_note = if candidate.constructed_from_visible_route {
        "source campaign Copy route was constructed from another allowlisted Copy route because the source row was not visible on the current manager page"
    } else {
        "exact source campaign Copy route found and plan id generated"
    };

    Ok(CampaignCopyPreviewReport {
        ok: true,
        configured: true,
        guarded_writes_enabled,
        form_write_controls_enabled,
        write_execution_mode: mode,
        source_campaign_id,
        plan_id,
        copy_candidate_found: true,
        warnings: vec![
            "preview only; apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_FORM_WRITE_CONTROLS=1".to_string(),
            "campaign copy creates a draft-like duplicate only; it does not send, schedule, trigger cron, import contacts, or mutate provider state".to_string(),
        ],
        evidence: admin_evidence(vec![
            "allowlisted Newsletter manage GET read for campaign copy preview".to_string(),
            copy_route_note.to_string(),
        ]),
    })
}

pub(super) fn campaign_copy_apply(
    client: &AdminHtmlClient,
    source_campaign_id: u64,
    plan_id: &str,
    guarded_writes_enabled: bool,
    form_write_controls_enabled: bool,
    mode: WriteExecutionMode,
) -> Result<CampaignCopyApplyReport, InterspireError> {
    if !client.config.is_configured() {
        return Err(InterspireError::AdminHtmlNotConfigured);
    }

    client.login()?;
    let before_html = client.get_allowed(&AdminReadPage::NewslettersManage.path())?;
    let before_ids = campaign_ids(&before_html);
    let candidate = find_campaign_copy_candidate(client, source_campaign_id, &before_html)?;
    let expected_plan_id = campaign_copy_plan_id(source_campaign_id, &candidate);
    if plan_id != expected_plan_id {
        return Err(InterspireError::Safety(
            "plan_id does not match the current campaign copy route; preview again before applying"
                .to_string(),
        ));
    }

    let copy_route_note = if candidate.constructed_from_visible_route {
        "source campaign Copy route was constructed from another allowlisted Copy route because the source row was not visible on the current manager page"
    } else {
        "exact source campaign Copy route found before apply"
    };

    let response = campaign_copy_get_request(client, candidate.url.clone())?
        .send()
        .map_err(|err| InterspireError::Http(format!("campaign copy request failed: {err}")))?;
    let status = response.status();
    if !status.is_success() && !status.is_redirection() {
        return Err(InterspireError::Http(format!(
            "campaign copy returned HTTP {}",
            status.as_u16()
        )));
    }
    if status.is_success() {
        let body = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        ensure_authenticated_html(&body)?;
    }

    let after_html = client.get_allowed(&AdminReadPage::NewslettersManage.path())?;
    let after_ids = campaign_ids(&after_html);
    let new_ids = after_ids
        .iter()
        .copied()
        .filter(|id| !before_ids.contains(id))
        .collect::<Vec<_>>();
    if new_ids.len() != 1 {
        return Err(InterspireError::Safety(format!(
            "campaign copy returned HTTP {} but new campaign id detection found {} new ids; treat apply as unconfirmed",
            status.as_u16(),
            new_ids.len()
        )));
    }
    let new_campaign_id = new_ids[0];
    let new_campaign_row = campaign_row_summary(&after_html, new_campaign_id)?;
    let source_edit_html = client.get_allowed(
        &AdminReadPage::NewsletterEdit {
            id: source_campaign_id,
        }
        .path(),
    )?;
    ensure_authenticated_html(&source_edit_html)?;
    let new_edit_html = client.get_allowed(
        &AdminReadPage::NewsletterEdit {
            id: new_campaign_id,
        }
        .path(),
    )?;
    ensure_authenticated_html(&new_edit_html)?;

    Ok(CampaignCopyApplyReport {
        ok: true,
        configured: true,
        guarded_writes_enabled,
        form_write_controls_enabled,
        write_execution_mode: mode,
        source_campaign_id,
        plan_id: expected_plan_id,
        applied: true,
        new_campaign_id: Some(new_campaign_id),
        new_campaign_row,
        source_campaign_readback: true,
        new_campaign_readback: true,
        copy_content_verified: false,
        warnings: vec![
            "guarded campaign copy applied; edit the copied campaign and prove no-send wizard state before any send decision".to_string(),
            "campaign copy follow-up confirmed source and copied campaign edit pages are reachable, but this tool does not compare full campaign body/settings".to_string(),
            "This apply did not invoke send, schedule, cron, import, suppression, provider, or DNS routes".to_string(),
        ],
        evidence: admin_evidence(vec![
            "allowlisted Newsletter manage GET read before campaign copy".to_string(),
            copy_route_note.to_string(),
            format!(
                "allowlisted campaign Copy route returned HTTP {}",
                status.as_u16()
            ),
            "allowlisted Newsletter manage GET read after campaign copy".to_string(),
            "exactly one new campaign edit id was detected".to_string(),
            "allowlisted source campaign edit GET read after copy".to_string(),
            "allowlisted copied campaign edit GET read after copy".to_string(),
        ]),
    })
}

fn find_campaign_copy_candidate(
    client: &AdminHtmlClient,
    source_campaign_id: u64,
    manage_html: &str,
) -> Result<CampaignCopyCandidate, InterspireError> {
    let document = Html::parse_document(manage_html);
    let selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut fallback = None;
    for link in document.select(&selector) {
        let Some(href) = link.value().attr("href") else {
            continue;
        };
        let Ok(url) = safety::ensure_allowed_campaign_copy_get(
            client.config.base_url.as_deref().unwrap_or_default(),
            href,
            source_campaign_id,
        ) else {
            if fallback.is_none() {
                fallback = fallback_campaign_copy_candidate(client, href, source_campaign_id)?;
            }
            continue;
        };
        return Ok(CampaignCopyCandidate {
            route_key: route_key(&url),
            url,
            constructed_from_visible_route: false,
        });
    }
    if let Some(candidate) = fallback {
        return Ok(candidate);
    }
    Err(InterspireError::Safety(format!(
        "no allowlisted Copy route found for source campaign {source_campaign_id}"
    )))
}

fn fallback_campaign_copy_candidate(
    client: &AdminHtmlClient,
    href: &str,
    source_campaign_id: u64,
) -> Result<Option<CampaignCopyCandidate>, InterspireError> {
    let Some(visible_campaign_id) = href_campaign_id(href) else {
        return Ok(None);
    };
    let Ok(visible_url) = safety::ensure_allowed_campaign_copy_get(
        client.config.base_url.as_deref().unwrap_or_default(),
        href,
        visible_campaign_id,
    ) else {
        return Ok(None);
    };
    let rewritten = rewrite_campaign_copy_url(&visible_url, source_campaign_id);
    let url = safety::ensure_allowed_campaign_copy_get(
        client.config.base_url.as_deref().unwrap_or_default(),
        rewritten.as_str(),
        source_campaign_id,
    )?;
    Ok(Some(CampaignCopyCandidate {
        route_key: route_key(&url),
        url,
        constructed_from_visible_route: true,
    }))
}

fn campaign_copy_get_request(
    client: &AdminHtmlClient,
    url: Url,
) -> Result<RequestBuilder, InterspireError> {
    Ok(client.with_access_headers(client.http.get(url)).header(
        "referer",
        safety::ensure_allowed_admin_get(
            client.config.base_url.as_deref().unwrap_or_default(),
            &AdminReadPage::NewslettersManage.path(),
        )?
        .as_str(),
    ))
}

fn campaign_ids(html: &str) -> Vec<u64> {
    extract_ids_from_links(html, "Page=Newsletters", "id")
}

fn campaign_row_summary(html: &str, campaign_id: u64) -> Result<Option<String>, InterspireError> {
    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let link_selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    for row in document.select(&row_selector) {
        let has_campaign = row.select(&link_selector).any(|link| {
            link.value()
                .attr("href")
                .is_some_and(|href| href_targets_campaign(href, campaign_id))
        });
        if !has_campaign {
            continue;
        }
        let summary = compact_text(&row.text().collect::<Vec<_>>().join(" "));
        if !summary.is_empty() {
            return Ok(Some(redact::redact_sensitive_text(&summary)));
        }
    }

    Ok(None)
}

fn href_targets_campaign(href: &str, campaign_id: u64) -> bool {
    let Some((_, query)) = href.split_once('?') else {
        return false;
    };
    let mut has_newsletters_page = false;
    let mut has_exact_campaign_id = false;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "Page" if value.eq_ignore_ascii_case("Newsletters") => {
                has_newsletters_page = true;
            }
            "id" if value.parse::<u64>().ok() == Some(campaign_id) => {
                has_exact_campaign_id = true;
            }
            _ => {}
        }
    }
    has_newsletters_page && has_exact_campaign_id
}

fn href_campaign_id(href: &str) -> Option<u64> {
    let (_, query) = href.split_once('?')?;
    let mut has_newsletters_page = false;
    let mut has_copy_action = false;
    let mut id = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "Page" if value.eq_ignore_ascii_case("Newsletters") => {
                has_newsletters_page = true;
            }
            "Action" if value.eq_ignore_ascii_case("Copy") => {
                has_copy_action = true;
            }
            "id" => {
                id = value.parse::<u64>().ok();
            }
            _ => {}
        }
    }
    (has_newsletters_page && has_copy_action)
        .then_some(id)
        .flatten()
}

fn rewrite_campaign_copy_url(url: &Url, source_campaign_id: u64) -> Url {
    let mut rewritten = url.clone();
    let pairs = url
        .query_pairs()
        .map(|(key, value)| {
            if key == "id" {
                (key.to_string(), source_campaign_id.to_string())
            } else {
                (key.to_string(), value.to_string())
            }
        })
        .collect::<Vec<_>>();
    rewritten.set_query(None);
    {
        let mut query = rewritten.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(&key, &value);
        }
    }
    rewritten
}

fn campaign_copy_plan_id(source_campaign_id: u64, candidate: &CampaignCopyCandidate) -> String {
    let parts = [
        "campaign_copy".to_string(),
        source_campaign_id.to_string(),
        candidate.route_key.clone(),
    ];
    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    format!("icp_{}", &guarded_write::stable_plan_id(&refs)[4..])
}

fn route_key(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .filter(|(key, _)| !safety::is_volatile_form_or_query_key(key))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<Vec<_>>();
    pairs.sort();
    if pairs.is_empty() {
        return url.path().to_string();
    }

    let query = pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{query}", url.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_copy_route_key_ignores_volatile_tokens() {
        let one = Url::parse(
            "https://example.test/admin/index.php?Page=Newsletters&Action=Copy&id=7&csrfToken=one",
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let two = Url::parse(
            "https://example.test/admin/index.php?csrfToken=two&id=7&Action=Copy&Page=Newsletters",
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(route_key(&one), route_key(&two));
        assert!(route_key(&one).contains("Action=Copy"));
        assert!(!route_key(&one).contains("csrf"));
    }

    #[test]
    fn can_rewrite_visible_copy_route_for_off_page_campaign() {
        let visible = Url::parse(
            "https://example.test/admin/index.php?Page=Newsletters&Action=Copy&id=13&csrfToken=secret",
        )
        .unwrap_or_else(|err| panic!("{err}"));

        let rewritten = rewrite_campaign_copy_url(&visible, 2);

        assert!(rewritten
            .query_pairs()
            .any(|(key, value)| key == "id" && value == "2"));
        assert!(rewritten
            .query_pairs()
            .any(|(key, value)| key == "csrfToken" && value == "secret"));
        safety::ensure_allowed_campaign_copy_get(
            "https://example.test/admin/",
            rewritten.as_str(),
            2,
        )
        .unwrap_or_else(|err| panic!("{err}"));
    }
}

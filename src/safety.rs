//! URL safety policy for legacy Interspire admin HTML.
//!
//! Only explicitly known GET pages are admitted. Send, schedule, cron, import,
//! export, save, delete, unsubscribe, and parameter-smuggling variants are
//! blocked before the HTTP client can request them. The one mutating exception
//! is a narrow Schedule-page cancel/delete route used by guarded queue-control
//! apply tools.

use crate::{error::InterspireError, response::QueueControlAction};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminReadPage {
    Lists,
    ListEdit { id: u64 },
    Settings { tab: u8 },
    Users,
    UserEdit { id: u64 },
    NewslettersManage,
    NewsletterEdit { id: u64 },
    Schedule,
    Stats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueControlRoute {
    pub action: QueueControlAction,
    pub identifier_key: String,
    pub identifier_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminWriteIntent {
    ListEdit { id: u64 },
    UserEdit { id: u64 },
    NewsletterEdit { id: u64 },
    Settings { tab: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminWriteRoute {
    pub page: String,
    pub action: Option<String>,
    pub identifier_key: Option<String>,
    pub identifier_value: Option<u64>,
    pub tab: Option<u8>,
}

impl AdminReadPage {
    pub fn path(&self) -> String {
        match self {
            Self::Lists => "index.php?Page=Lists".to_string(),
            Self::ListEdit { id } => format!("index.php?Page=Lists&Action=Edit&id={id}"),
            Self::Settings { tab } => format!("index.php?Page=Settings&Tab={tab}"),
            Self::Users => "index.php?Page=Users".to_string(),
            Self::UserEdit { id } => format!("index.php?Page=Users&Action=Edit&UserID={id}"),
            Self::NewslettersManage => "index.php?Page=Newsletters&Action=Manage".to_string(),
            Self::NewsletterEdit { id } => {
                format!("index.php?Page=Newsletters&Action=Edit&id={id}")
            }
            Self::Schedule => "index.php?Page=Schedule".to_string(),
            Self::Stats => "index.php?Page=Stats".to_string(),
        }
    }
}

pub fn ensure_allowed_admin_get(
    base_url: &str,
    relative_path: &str,
) -> Result<Url, InterspireError> {
    let base = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let base = normalize_admin_base(base);
    let url = base
        .join(relative_path)
        .map_err(|err| InterspireError::Safety(format!("invalid admin path: {err}")))?;

    ensure_admin_base_scope(&base, &url)?;
    ensure_admin_front_controller_path(&base, &url)?;
    classify_allowed_admin_get(&url)?;
    Ok(url)
}

pub fn ensure_allowed_queue_control(
    base_url: &str,
    relative_path: &str,
) -> Result<(Url, QueueControlRoute), InterspireError> {
    let base = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let base = normalize_admin_base(base);
    let url = base
        .join(relative_path)
        .map_err(|err| InterspireError::Safety(format!("invalid queue control path: {err}")))?;

    ensure_admin_base_scope(&base, &url)?;
    ensure_admin_front_controller_path(&base, &url)?;
    let route = classify_allowed_queue_control(&url)?;
    Ok((url, route))
}

pub fn ensure_allowed_admin_post_for(
    base_url: &str,
    relative_path: &str,
    expected: &AdminWriteIntent,
) -> Result<Url, InterspireError> {
    let base = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let base = normalize_admin_base(base);
    let url = base
        .join(relative_path)
        .map_err(|err| InterspireError::Safety(format!("invalid admin post path: {err}")))?;

    ensure_admin_base_scope(&base, &url)?;
    ensure_admin_front_controller_path(&base, &url)?;
    let route = classify_allowed_admin_write(&url)?;
    ensure_write_intent_matches(expected, &route)?;
    Ok(url)
}

pub fn classify_allowed_admin_get(url: &Url) -> Result<AdminReadPage, InterspireError> {
    if url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .is_none_or(|segment| segment != "index.php")
    {
        return Err(InterspireError::Safety(
            "admin path is not index.php".to_string(),
        ));
    }

    let pairs = url.query_pairs().collect::<Vec<_>>();
    ensure_no_duplicate_query_keys(&pairs)?;
    let page = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Page"))
        .map(|(_, value)| value.to_string());
    let action = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Action"))
        .map(|(_, value)| value.to_string());

    match (page.as_deref(), action.as_deref()) {
        (Some("Lists"), None) if only_query_keys(&pairs, &["Page"]) => Ok(AdminReadPage::Lists),
        (Some("Lists"), Some("Edit")) => {
            ensure_only_query_keys(&pairs, &["Page", "Action", "id"])?;
            let id = pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("id"))
                .and_then(|(_, value)| value.parse::<u64>().ok())
                .ok_or_else(|| {
                    InterspireError::Safety("list edit page missing numeric id".to_string())
                })?;
            Ok(AdminReadPage::ListEdit { id })
        }
        (Some("Settings"), None) => {
            ensure_only_query_keys(&pairs, &["Page", "Tab"])?;
            let tab = pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("Tab"))
                .and_then(|(_, value)| value.parse::<u8>().ok())
                .ok_or_else(|| {
                    InterspireError::Safety("settings page missing numeric tab".to_string())
                })?;
            match tab {
                1 | 2 | 4 | 7 => Ok(AdminReadPage::Settings { tab }),
                _ => Err(InterspireError::Safety(format!(
                    "settings tab {tab} is not in the read allowlist"
                ))),
            }
        }
        (Some("Users"), None) if only_query_keys(&pairs, &["Page"]) => Ok(AdminReadPage::Users),
        (Some("Users"), Some("Edit")) => {
            ensure_only_query_keys(&pairs, &["Page", "Action", "UserID"])?;
            let id = pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("UserID"))
                .and_then(|(_, value)| value.parse::<u64>().ok())
                .ok_or_else(|| {
                    InterspireError::Safety("user edit page missing numeric id".to_string())
                })?;
            Ok(AdminReadPage::UserEdit { id })
        }
        (Some("Newsletters"), Some("Manage")) if only_query_keys(&pairs, &["Page", "Action"]) => {
            Ok(AdminReadPage::NewslettersManage)
        }
        (Some("Newsletters"), Some("Edit")) => {
            ensure_only_query_keys(&pairs, &["Page", "Action", "id"])?;
            let id = pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("id"))
                .and_then(|(_, value)| value.parse::<u64>().ok())
                .ok_or_else(|| {
                    InterspireError::Safety("newsletter edit page missing numeric id".to_string())
                })?;
            Ok(AdminReadPage::NewsletterEdit { id })
        }
        (Some("Schedule"), None) if only_query_keys(&pairs, &["Page"]) => {
            Ok(AdminReadPage::Schedule)
        }
        (Some("Stats"), None) if only_query_keys(&pairs, &["Page"]) => Ok(AdminReadPage::Stats),
        _ => Err(InterspireError::Safety(format!(
            "admin GET is not in the read allowlist: Page={page:?} Action={action:?}"
        ))),
    }
}

pub fn classify_allowed_queue_control(url: &Url) -> Result<QueueControlRoute, InterspireError> {
    if url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .is_none_or(|segment| segment != "index.php")
    {
        return Err(InterspireError::Safety(
            "queue control path is not index.php".to_string(),
        ));
    }

    let pairs = url.query_pairs().collect::<Vec<_>>();
    ensure_no_duplicate_query_keys(&pairs)?;
    ensure_only_queue_control_query_keys(&pairs)?;

    let page = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Page"))
        .map(|(_, value)| value.to_string());
    let action_raw = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Action"))
        .map(|(_, value)| value.to_string());

    if !matches!(page.as_deref(), Some("Schedule")) {
        return Err(InterspireError::Safety(
            "queue control route must target the Schedule page".to_string(),
        ));
    }

    let action = action_raw
        .as_deref()
        .and_then(classify_queue_control_action)
        .ok_or_else(|| {
            InterspireError::Safety(format!(
                "queue control action is not in the cancel/delete allowlist: {action_raw:?}"
            ))
        })?;

    let (identifier_key, identifier_value) = single_numeric_identifier(&pairs)?;

    Ok(QueueControlRoute {
        action,
        identifier_key,
        identifier_value,
    })
}

pub fn classify_allowed_admin_write(url: &Url) -> Result<AdminWriteRoute, InterspireError> {
    if url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .is_none_or(|segment| segment != "index.php")
    {
        return Err(InterspireError::Safety(
            "admin write path is not index.php".to_string(),
        ));
    }

    let pairs = url.query_pairs().collect::<Vec<_>>();
    ensure_no_duplicate_query_keys(&pairs)?;
    let page = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Page"))
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| InterspireError::Safety("admin write missing Page query".to_string()))?;
    let action = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Action"))
        .map(|(_, value)| value.to_string());

    match page.as_str() {
        "Lists" => {
            ensure_only_query_keys(
                &pairs,
                &[
                    "Page",
                    "Action",
                    "id",
                    "token",
                    "csrf",
                    "csrf_token",
                    "_token",
                ],
            )?;
            ensure_write_action_allowed(action.as_deref())?;
            let (key, id) = required_numeric_query_value(&pairs, "id")?;
            Ok(AdminWriteRoute {
                page,
                action,
                identifier_key: Some(key),
                identifier_value: Some(id),
                tab: None,
            })
        }
        "Users" => {
            ensure_only_query_keys(
                &pairs,
                &[
                    "Page",
                    "Action",
                    "UserID",
                    "token",
                    "csrf",
                    "csrf_token",
                    "_token",
                ],
            )?;
            ensure_write_action_allowed(action.as_deref())?;
            let (key, id) = required_numeric_query_value(&pairs, "UserID")?;
            Ok(AdminWriteRoute {
                page,
                action,
                identifier_key: Some(key),
                identifier_value: Some(id),
                tab: None,
            })
        }
        "Newsletters" => {
            ensure_only_query_keys(
                &pairs,
                &[
                    "Page",
                    "Action",
                    "id",
                    "token",
                    "csrf",
                    "csrf_token",
                    "_token",
                ],
            )?;
            ensure_write_action_allowed(action.as_deref())?;
            let (key, id) = required_numeric_query_value(&pairs, "id")?;
            Ok(AdminWriteRoute {
                page,
                action,
                identifier_key: Some(key),
                identifier_value: Some(id),
                tab: None,
            })
        }
        "Settings" => {
            ensure_only_query_keys(
                &pairs,
                &[
                    "Page",
                    "Action",
                    "Tab",
                    "token",
                    "csrf",
                    "csrf_token",
                    "_token",
                ],
            )?;
            ensure_write_action_allowed(action.as_deref())?;
            let tab = optional_numeric_query_value(&pairs, "Tab")?;
            if let Some(value) = tab {
                if !matches!(value, 1 | 2 | 4 | 7) {
                    return Err(InterspireError::Safety(format!(
                        "settings write tab {value} is not in the guarded allowlist"
                    )));
                }
            }
            Ok(AdminWriteRoute {
                page,
                action,
                identifier_key: None,
                identifier_value: None,
                tab,
            })
        }
        _ => Err(InterspireError::Safety(format!(
            "admin write is not in the guarded allowlist: Page={page:?} Action={action:?}"
        ))),
    }
}

fn ensure_admin_base_scope(base: &Url, url: &Url) -> Result<(), InterspireError> {
    if url.scheme() != base.scheme()
        || url.host_str() != base.host_str()
        || url.port_or_known_default() != base.port_or_known_default()
    {
        return Err(InterspireError::Safety(
            "admin GET escapes the configured admin base origin".to_string(),
        ));
    }

    let prefix = admin_base_path_prefix(base);
    if !url.path().starts_with(&prefix) {
        return Err(InterspireError::Safety(
            "admin GET escapes the configured admin base path".to_string(),
        ));
    }

    Ok(())
}

fn ensure_admin_front_controller_path(base: &Url, url: &Url) -> Result<(), InterspireError> {
    let expected_path = format!("{}index.php", admin_base_path_prefix(base));
    if url.path() != expected_path {
        return Err(InterspireError::Safety(
            "admin GET does not target the configured admin front controller".to_string(),
        ));
    }
    Ok(())
}

fn normalize_admin_base(mut base: Url) -> Url {
    base.set_query(None);
    base.set_fragment(None);

    let path = base.path().to_string();
    if path.ends_with('/') {
        return base;
    }

    let last_segment = path.rsplit('/').next().unwrap_or_default();
    if !last_segment.is_empty() && !last_segment.contains('.') {
        base.set_path(&format!("{}/", path.trim_end_matches('/')));
    }

    base
}

fn admin_base_path_prefix(base: &Url) -> String {
    let path = base.path();
    if path.ends_with('/') {
        return path.to_string();
    }

    let last_segment = path.rsplit('/').next().unwrap_or_default();
    if !last_segment.is_empty() && !last_segment.contains('.') {
        return format!("{}/", path.trim_end_matches('/'));
    }

    path.rfind('/')
        .map(|idx| path[..=idx].to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn ensure_no_duplicate_query_keys(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
) -> Result<(), InterspireError> {
    let mut seen = HashSet::new();
    for (key, _) in pairs {
        if !seen.insert(key.to_ascii_lowercase()) {
            return Err(InterspireError::Safety(
                "admin GET includes duplicate query parameter keys".to_string(),
            ));
        }
    }
    Ok(())
}

fn ensure_only_query_keys(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    allowed: &[&str],
) -> Result<(), InterspireError> {
    if only_query_keys(pairs, allowed) {
        return Ok(());
    }

    Err(InterspireError::Safety(
        "admin GET includes query parameters outside the read allowlist".to_string(),
    ))
}

fn ensure_only_queue_control_query_keys(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
) -> Result<(), InterspireError> {
    let allowed = [
        "Page",
        "Action",
        "id",
        "job",
        "jobid",
        "JobID",
        "queueid",
        "QueueID",
        "sendid",
        "SendID",
        "newsletterid",
        "NewsletterID",
        "campaignid",
        "CampaignID",
        "token",
        "csrf",
        "csrf_token",
        "_token",
    ];
    if only_query_keys(pairs, &allowed) {
        return Ok(());
    }

    Err(InterspireError::Safety(
        "queue control route includes query parameters outside the cancel/delete allowlist"
            .to_string(),
    ))
}

fn ensure_write_action_allowed(action: Option<&str>) -> Result<(), InterspireError> {
    let Some(action) = action else {
        return Ok(());
    };
    if matches!(
        action.to_ascii_lowercase().as_str(),
        "save" | "edit" | "update"
    ) {
        return Ok(());
    }

    Err(InterspireError::Safety(format!(
        "admin write action is not in the guarded allowlist: {action}"
    )))
}

fn classify_queue_control_action(raw: &str) -> Option<QueueControlAction> {
    match raw.to_ascii_lowercase().as_str() {
        "cancel" | "canceljob" | "abort" | "abortjob" => Some(QueueControlAction::Cancel),
        "delete" | "deletejob" | "remove" | "removejob" => Some(QueueControlAction::Delete),
        _ => None,
    }
}

fn single_numeric_identifier(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
) -> Result<(String, u64), InterspireError> {
    let keys = [
        "id",
        "job",
        "jobid",
        "queueid",
        "sendid",
        "newsletterid",
        "campaignid",
    ];
    let matches = keys
        .iter()
        .filter_map(|wanted| {
            pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
                .and_then(|(key, value)| value.parse::<u64>().ok().map(|id| (key.to_string(), id)))
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Err(InterspireError::Safety(
            "queue control route must include exactly one numeric queue identifier".to_string(),
        )),
        [single] => Ok(single.clone()),
        _ => Err(InterspireError::Safety(
            "queue control route includes multiple queue identifiers".to_string(),
        )),
    }
}

fn required_numeric_query_value(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    key_name: &str,
) -> Result<(String, u64), InterspireError> {
    pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(key_name))
        .and_then(|(key, value)| value.parse::<u64>().ok().map(|id| (key.to_string(), id)))
        .ok_or_else(|| {
            InterspireError::Safety(format!(
                "admin write route missing numeric identifier {key_name}"
            ))
        })
}

fn optional_numeric_query_value(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    key_name: &str,
) -> Result<Option<u8>, InterspireError> {
    pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(key_name))
        .map(|(_, value)| {
            value.parse::<u8>().map_err(|_| {
                InterspireError::Safety(format!(
                    "admin write route has non-numeric {key_name} value"
                ))
            })
        })
        .transpose()
}

fn ensure_write_intent_matches(
    expected: &AdminWriteIntent,
    route: &AdminWriteRoute,
) -> Result<(), InterspireError> {
    match expected {
        AdminWriteIntent::ListEdit { id } => {
            if route.page != "Lists" || route.identifier_value != Some(*id) {
                return Err(InterspireError::Safety(
                    "admin write route does not match the requested list target".to_string(),
                ));
            }
        }
        AdminWriteIntent::UserEdit { id } => {
            if route.page != "Users" || route.identifier_value != Some(*id) {
                return Err(InterspireError::Safety(
                    "admin write route does not match the requested user target".to_string(),
                ));
            }
        }
        AdminWriteIntent::NewsletterEdit { id } => {
            if route.page != "Newsletters" || route.identifier_value != Some(*id) {
                return Err(InterspireError::Safety(
                    "admin write route does not match the requested campaign target".to_string(),
                ));
            }
        }
        AdminWriteIntent::Settings { tab } => {
            if route.page != "Settings" {
                return Err(InterspireError::Safety(
                    "admin write route does not target Settings".to_string(),
                ));
            }
            if route.tab.is_some() && route.tab != Some(*tab) {
                return Err(InterspireError::Safety(
                    "admin write route does not match the requested settings tab".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn only_query_keys(
    pairs: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    allowed: &[&str],
) -> bool {
    pairs.iter().all(|(key, _)| {
        allowed
            .iter()
            .any(|allowed_key| key.eq_ignore_ascii_case(allowed_key))
    })
}

pub fn login_url(base_url: &str) -> Result<Url, InterspireError> {
    let base = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let base = normalize_admin_base(base);
    base.join("index.php?Page=Login&Action=Login")
        .map_err(|err| InterspireError::Safety(format!("invalid login path: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(path: &str) -> Url {
        Url::parse(&format!("https://example.test/admin/{path}"))
            .unwrap_or_else(|err| panic!("test url should parse: {err}"))
    }

    #[test]
    fn allows_known_list_read_pages() {
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Lists")).ok(),
            Some(AdminReadPage::Lists)
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Lists&Action=Edit&id=42")).ok(),
            Some(AdminReadPage::ListEdit { id: 42 })
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Settings&Tab=2")).ok(),
            Some(AdminReadPage::Settings { tab: 2 })
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Users")).ok(),
            Some(AdminReadPage::Users)
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Users&Action=Edit&UserID=2")).ok(),
            Some(AdminReadPage::UserEdit { id: 2 })
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Newsletters&Action=Manage")).ok(),
            Some(AdminReadPage::NewslettersManage)
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Newsletters&Action=Edit&id=9")).ok(),
            Some(AdminReadPage::NewsletterEdit { id: 9 })
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Schedule")).ok(),
            Some(AdminReadPage::Schedule)
        );
        assert_eq!(
            classify_allowed_admin_get(&url("index.php?Page=Stats")).ok(),
            Some(AdminReadPage::Stats)
        );
    }

    #[test]
    fn allows_only_cancel_delete_schedule_queue_controls() {
        let cancel =
            classify_allowed_queue_control(&url("index.php?Page=Schedule&Action=Cancel&id=42"))
                .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(cancel.action, QueueControlAction::Cancel);
        assert_eq!(cancel.identifier_value, 42);

        let delete = classify_allowed_queue_control(&url(
            "index.php?Page=Schedule&Action=DeleteJob&JobID=99&token=abc",
        ))
        .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(delete.action, QueueControlAction::Delete);
        assert_eq!(delete.identifier_value, 99);
    }

    #[test]
    fn allows_guarded_form_write_routes_for_expected_targets() {
        let base_url = "https://example.test/admin/";
        let list_url = ensure_allowed_admin_post_for(
            base_url,
            "index.php?Page=Lists&Action=Save&id=7",
            &AdminWriteIntent::ListEdit { id: 7 },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        assert!(list_url.as_str().contains("Page=Lists"));

        let campaign_url = ensure_allowed_admin_post_for(
            base_url,
            "index.php?Page=Newsletters&Action=Save&id=9",
            &AdminWriteIntent::NewsletterEdit { id: 9 },
        )
        .unwrap_or_else(|err| panic!("{err}"));
        assert!(campaign_url.as_str().contains("Page=Newsletters"));
    }

    #[test]
    fn guarded_form_write_routes_block_wrong_targets_and_actions() {
        let base_url = "https://example.test/admin/";
        assert!(ensure_allowed_admin_post_for(
            base_url,
            "index.php?Page=Lists&Action=Save&id=8",
            &AdminWriteIntent::ListEdit { id: 7 },
        )
        .is_err());
        assert!(ensure_allowed_admin_post_for(
            base_url,
            "index.php?Page=Newsletters&Action=Send&id=9",
            &AdminWriteIntent::NewsletterEdit { id: 9 },
        )
        .is_err());
        assert!(ensure_allowed_admin_post_for(
            base_url,
            "index.php?Page=Settings&Action=Save&Tab=3",
            &AdminWriteIntent::Settings { tab: 2 },
        )
        .is_err());
    }

    #[test]
    fn queue_controls_require_exact_admin_front_controller() {
        let base_url = "https://example.test/admin/";
        assert!(ensure_allowed_queue_control(
            base_url,
            "index.php?Page=Schedule&Action=Cancel&id=1"
        )
        .is_ok());

        for path in [
            "cron/index.php?Page=Schedule&Action=Cancel&id=1",
            "notindex.php?Page=Schedule&Action=Cancel&id=1",
            "%2e%2e/index.php?Page=Schedule&Action=Cancel&id=1",
        ] {
            assert!(
                ensure_allowed_queue_control(base_url, path).is_err(),
                "{path} should be blocked"
            );
        }
    }

    #[test]
    fn queue_controls_block_send_and_parameter_smuggling() {
        for path in [
            "index.php?Page=Schedule&Action=Send&id=1",
            "index.php?Page=Schedule&Action=Cancel",
            "index.php?Page=Schedule&Action=Cancel&id=abc",
            "index.php?Page=Schedule&Action=Delete&id=42&sendid=99",
            "index.php?Page=Schedule&Action=Cancel&id=1&Next=Send",
            "index.php?Page=Newsletters&Action=Delete&id=1",
            "index.php?Page=Subscribers&Action=Delete&id=1",
            "index.php?Page=Schedule&Action=Cancel&id=1&Action=Delete",
        ] {
            assert!(
                classify_allowed_queue_control(&url(path)).is_err(),
                "{path} should be blocked"
            );
        }
    }

    #[test]
    fn blocks_send_schedule_cron_import_export_and_settings_paths() {
        for path in [
            "index.php?Page=Send&Action=Step4",
            "index.php?Page=Schedule&A=1",
            "admin/cron/cron.php",
            "index.php?Page=Subscribers&Action=Import",
            "index.php?Page=Subscribers&Action=Export",
            "index.php?Page=Settings&Tab=3",
            "index.php?Page=Lists&Action=Save&id=1",
            "index.php?Page=Users&Action=Save&UserID=1",
            "index.php?Page=Newsletters&Action=Send&id=1",
            "index.php?Page=Schedule&Action=Send&id=1",
            "index.php?Page=Schedule&Action=Cancel",
            "index.php?Page=Schedule&Action=Cancel&id=abc",
            "index.php?Page=Schedule&Action=Cancel&id=1&Next=Send",
            "index.php?Page=Subscribers&Action=Delete",
            "index.php?Page=Subscribers&Action=Unsubscribe",
        ] {
            let blocked = Url::parse(&format!("https://example.test/{path}"))
                .unwrap_or_else(|err| panic!("test url should parse: {err}"));
            assert!(
                classify_allowed_admin_get(&blocked).is_err(),
                "{path} should be blocked"
            );
        }
    }

    #[test]
    fn blocks_duplicate_query_keys_before_matching() {
        for path in [
            "index.php?Page=Newsletters&Action=Edit&id=9&Action=Send",
            "index.php?Page=Lists&page=Send",
            "index.php?Page=Settings&Tab=2&TAB=7",
        ] {
            assert!(
                classify_allowed_admin_get(&url(path)).is_err(),
                "{path} should be blocked"
            );
        }
    }

    #[test]
    fn ensure_allowed_admin_get_blocks_base_escape_urls() {
        for path in [
            "https://evil.test/admin/index.php?Page=Lists",
            "//evil.test/admin/index.php?Page=Lists",
            "https://example.test/other/index.php?Page=Lists",
            "../index.php?Page=Lists",
        ] {
            assert!(
                ensure_allowed_admin_get("https://example.test/admin/", path).is_err(),
                "{path} should be blocked"
            );
        }

        let allowed = ensure_allowed_admin_get(
            "https://example.test/admin/",
            "https://example.test/admin/index.php?Page=Lists",
        )
        .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(allowed, url("index.php?Page=Lists"));
    }

    #[test]
    fn ensure_allowed_admin_get_accepts_directory_base_without_trailing_slash() {
        let url = ensure_allowed_admin_get("https://example.test/admin", "index.php?Page=Lists")
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            url.as_str(),
            "https://example.test/admin/index.php?Page=Lists"
        );
        assert_eq!(
            login_url("https://example.test/admin")
                .unwrap_or_else(|err| panic!("{err}"))
                .as_str(),
            "https://example.test/admin/index.php?Page=Login&Action=Login"
        );
    }
}

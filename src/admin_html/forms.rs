use super::{
    admin_evidence, admin_origin, csrf_pair, extract_ids_from_links, extract_login_csrf_token,
    looks_like_save_submit, parse_form_values, parse_settings_fields, summarize_field_value,
    AdminHtmlClient,
};
use crate::{
    config::WriteExecutionMode,
    error::InterspireError,
    guarded_write,
    response::{
        FormFieldChange, FormFieldDescriptor, FormFieldUpdate, GuardedWriteApplyReport,
        GuardedWritePreviewReport, RedactedField, SettingsSectionName,
    },
    safety::{self, AdminReadPage, AdminWriteIntent},
};
use reqwest::header::LOCATION;
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FormControlKind {
    Text,
    Password,
    Hidden,
    Textarea,
    Select,
    Checkbox,
    Radio,
    Submit,
}

impl FormControlKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Password => "password",
            Self::Hidden => "hidden",
            Self::Textarea => "textarea",
            Self::Select => "select",
            Self::Checkbox => "checkbox",
            Self::Radio => "radio",
            Self::Submit => "submit",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct FormControl {
    pub(super) original_name: String,
    pub(super) lower_name: String,
    pub(super) kind: FormControlKind,
    pub(super) value: String,
    pub(super) checked: bool,
}

#[derive(Debug, Clone)]
pub(super) struct FormSnapshot {
    pub(super) action_url: Url,
    pub(super) controls: Vec<FormControl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GuardedFormTarget {
    ListCreate,
    Campaign { campaign_id: u64 },
    List { list_id: u64 },
    User { user_id: u64 },
    Settings { section: SettingsSectionName },
}

impl GuardedFormTarget {
    fn label(self) -> &'static str {
        match self {
            Self::ListCreate => "list_create",
            Self::Campaign { .. } => "campaign",
            Self::List { .. } => "list",
            Self::User { .. } => "user",
            Self::Settings { .. } => "settings",
        }
    }

    fn target_id(self) -> Option<u64> {
        match self {
            Self::ListCreate => None,
            Self::Campaign { campaign_id } => Some(campaign_id),
            Self::List { list_id } => Some(list_id),
            Self::User { user_id } => Some(user_id),
            Self::Settings { .. } => None,
        }
    }

    fn section_name(self) -> Option<&'static str> {
        match self {
            Self::ListCreate => None,
            Self::Settings { section } => Some(section.as_str()),
            _ => None,
        }
    }

    fn read_page(self) -> AdminReadPage {
        match self {
            Self::ListCreate => AdminReadPage::ListCreate,
            Self::Campaign { campaign_id } => AdminReadPage::NewsletterEdit { id: campaign_id },
            Self::List { list_id } => AdminReadPage::ListEdit { id: list_id },
            Self::User { user_id } => AdminReadPage::UserEdit { id: user_id },
            Self::Settings { section } => AdminReadPage::Settings {
                tab: settings_section_tab(section),
            },
        }
    }

    fn write_intent(self) -> AdminWriteIntent {
        match self {
            Self::ListCreate => AdminWriteIntent::ListCreate,
            Self::Campaign { campaign_id } => AdminWriteIntent::NewsletterEdit { id: campaign_id },
            Self::List { list_id } => AdminWriteIntent::ListEdit { id: list_id },
            Self::User { user_id } => AdminWriteIntent::UserEdit { id: user_id },
            Self::Settings { section } => AdminWriteIntent::Settings {
                tab: settings_section_tab(section),
            },
        }
    }

    fn allowed_fields(self) -> &'static [&'static str] {
        match self {
            Self::ListCreate => &LIST_WRITE_FIELDS,
            Self::Campaign { .. } => &CAMPAIGN_WRITE_FIELDS,
            Self::List { .. } => &LIST_WRITE_FIELDS,
            Self::User { .. } => &USER_WRITE_FIELDS,
            Self::Settings { section } => settings_write_fields(section),
        }
    }
}

const CAMPAIGN_WRITE_FIELDS: [&str; 26] = [
    "name",
    "subject",
    "archive",
    "sendfromname",
    "sendfromemail",
    "replytoemail",
    "bounceemail",
    "format",
    "sendmultipart",
    "trackopens",
    "tracklinks",
    "embedimages",
    "html_body",
    "htmlbody",
    "htmlcontents",
    "mydeveditcontrol_html",
    "mydeveditcontrolhtml",
    "html_content",
    "htmlcontent",
    "text_body",
    "textbody",
    "textcontents",
    "mydeveditcontrol_text",
    "mydeveditcontroltext",
    "text_content",
    "textcontent",
];

const LIST_WRITE_FIELDS: [&str; 12] = [
    "name",
    "ownername",
    "owneremail",
    "replytoemail",
    "bounceemail",
    "notifyowner",
    "unsubscribemailto",
    "surveyid",
    "companyname",
    "companyaddress",
    "companyphone",
    "bounce_process",
];

const USER_WRITE_FIELDS: [&str; 12] = [
    "username",
    "fullname",
    "emailaddress",
    "status",
    "smtptype",
    "smtp_server",
    "smtp_u",
    "smtp_username",
    "smtp_port",
    "htmlfooter",
    "textfooter",
    "footer",
];

const SETTINGS_APPLICATION_FIELDS: [&str; 4] = [
    "application_url",
    "contact_email",
    "email_address",
    "server_time_zone",
];

const SETTINGS_EMAIL_FIELDS: [&str; 7] = [
    "usesmtp",
    "smtp_server",
    "smtp_u",
    "smtp_port",
    "maxhourlyrate",
    "resend_maximum",
    "force_unsublink",
];

const SETTINGS_BOUNCE_FIELDS: [&str; 7] = [
    "bounce_process",
    "bounce_address",
    "bounce_server",
    "bounce_username",
    "bounce_imap",
    "bounce_extrasettings",
    "bounce_agreedeleteall",
];

const SETTINGS_CRON_FIELDS: [&str; 6] = [
    "cron_enabled",
    "cron_send",
    "cron_bounce",
    "cron_autoresponder",
    "cron_triggeremails_s",
    "cron_maintenance",
];

fn settings_write_fields(section: SettingsSectionName) -> &'static [&'static str] {
    match section {
        SettingsSectionName::Application => &SETTINGS_APPLICATION_FIELDS,
        SettingsSectionName::Email => &SETTINGS_EMAIL_FIELDS,
        SettingsSectionName::Bounce => &SETTINGS_BOUNCE_FIELDS,
        SettingsSectionName::Cron => &SETTINGS_CRON_FIELDS,
    }
}

fn settings_section_tab(section: SettingsSectionName) -> u8 {
    match section {
        SettingsSectionName::Application => 1,
        SettingsSectionName::Email => 2,
        SettingsSectionName::Cron => 4,
        SettingsSectionName::Bounce => 7,
    }
}

pub(super) fn guarded_write_preview(
    client: &AdminHtmlClient,
    target: GuardedFormTarget,
    updates: &[FormFieldUpdate],
) -> Result<GuardedWritePreviewReport, InterspireError> {
    if !client.config.is_configured() {
        return Err(InterspireError::AdminHtmlNotConfigured);
    }
    client.login()?;

    let (read_path, html, mut evidence_notes) =
        guarded_form_html_for_updates(client, target, updates)?;
    let snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &read_path,
        &html,
        &target,
    )?;
    let mut staged = snapshot.clone();
    let changes = apply_requested_updates(&mut staged, target.allowed_fields(), updates)?;
    let plan_id = form_plan_id(target, &snapshot, &staged);

    Ok(GuardedWritePreviewReport {
        ok: true,
        configured: true,
        guarded_writes_enabled: true,
        form_write_controls_enabled: true,
        write_execution_mode: WriteExecutionMode::PreviewApply,
        target: target.label().to_string(),
        target_id: target.target_id(),
        section: target.section_name().map(ToString::to_string),
        plan_id,
        apply_directly_allowed: false,
        available_fields: snapshot.available_fields(target.allowed_fields()),
        changes,
        warnings: vec![
            "preview only; apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_FORM_WRITE_CONTROLS=1".to_string(),
        ],
        evidence: admin_evidence({
            evidence_notes.insert(
                0,
                format!(
                    "allowlisted {} form read for guarded write preview",
                    target.label()
                ),
            );
            evidence_notes
        }),
    })
}

pub(super) fn guarded_write_apply(
    client: &AdminHtmlClient,
    target: GuardedFormTarget,
    plan_id: &str,
    updates: &[FormFieldUpdate],
    mode: WriteExecutionMode,
) -> Result<GuardedWriteApplyReport, InterspireError> {
    if !client.config.is_configured() {
        return Err(InterspireError::AdminHtmlNotConfigured);
    }
    client.login()?;

    let (read_path, html, mut evidence_notes) =
        guarded_form_html_for_updates(client, target, updates)?;
    let snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &read_path,
        &html,
        &target,
    )?;
    let mut staged = snapshot.clone();
    let changes = apply_requested_updates(&mut staged, target.allowed_fields(), updates)?;
    let expected_plan_id = form_plan_id(target, &snapshot, &staged);

    if plan_id != expected_plan_id {
        return Err(InterspireError::Safety(
            "plan_id does not match the current form fingerprint and requested changes".to_string(),
        ));
    }

    let requested_fields = changes
        .iter()
        .map(|change| applied_control_name(&change.name))
        .collect::<BTreeSet<_>>();
    let post_fields = staged.to_post_pairs_for_fields(&requested_fields);
    let response = guarded_form_post(client, &snapshot, &post_fields, &html, &read_path)?;
    if !response.status().is_success() && !response.status().is_redirection() {
        return Err(InterspireError::Http(format!(
            "guarded form write returned HTTP {}",
            response.status().as_u16()
        )));
    }

    // Campaign body edits pass through an Interspire wizard. Re-read with a
    // fresh cookie jar so transient Step1/Step2 state cannot satisfy proof.
    let (after_read_path, after_html, mut after_evidence_notes) = if matches!(
        target,
        GuardedFormTarget::Campaign { .. }
    ) {
        let fresh_client = AdminHtmlClient::new(client.config.clone())?;
        fresh_client.login()?;
        let (after_read_path, after_html, mut notes) = guarded_form_html(&fresh_client, target)?;
        notes.push(
            "campaign form readback used a fresh admin session so Step1 wizard state could not satisfy post-apply proof"
                .to_string(),
        );
        (after_read_path, after_html, notes)
    } else {
        guarded_form_html(client, target)?
    };
    let after_snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &after_read_path,
        &after_html,
        &target,
    )?;
    let mismatched_fields = changes
        .iter()
        .filter_map(|change| {
            let field_name = applied_control_name(&change.name);
            (staged.field_fingerprint(&field_name) != after_snapshot.field_fingerprint(&field_name))
                .then_some(change.name.clone())
        })
        .collect::<Vec<_>>();
    if !mismatched_fields.is_empty() {
        return Err(InterspireError::Safety(format!(
            "guarded form write readback did not persist requested fields: {}",
            mismatched_fields.join(", ")
        )));
    }
    let post_apply_fields = parse_redacted_fields_for_target(target, &after_html)?;
    Ok(GuardedWriteApplyReport {
        ok: true,
        configured: true,
        guarded_writes_enabled: true,
        form_write_controls_enabled: true,
        write_execution_mode: mode,
        target: target.label().to_string(),
        target_id: target.target_id(),
        section: target.section_name().map(ToString::to_string),
        applied: true,
        plan_id: expected_plan_id,
        changes,
        post_apply_fields,
        warnings: vec![
            "guarded form write applied; verify downstream queue or delivery state separately before any send decision".to_string(),
        ],
        evidence: admin_evidence({
            let mut notes = vec![format!(
                "allowlisted {} form POST apply succeeded",
                target.label()
            )];
            notes.append(&mut evidence_notes);
            notes.append(&mut after_evidence_notes);
            notes.push(format!(
                "allowlisted {} form readback succeeded",
                target.label()
            ));
            notes
        }),
    })
}

pub(super) fn guarded_list_create_apply(
    client: &AdminHtmlClient,
    plan_id: &str,
    updates: &[FormFieldUpdate],
    mode: WriteExecutionMode,
) -> Result<GuardedWriteApplyReport, InterspireError> {
    let target = GuardedFormTarget::ListCreate;
    if !client.config.is_configured() {
        return Err(InterspireError::AdminHtmlNotConfigured);
    }
    client.login()?;

    let before_ids = list_id_inventory(client)?;

    let (read_path, html, mut evidence_notes) = guarded_form_html(client, target)?;
    let snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &read_path,
        &html,
        &target,
    )?;
    let mut staged = snapshot.clone();
    let changes = apply_requested_updates(&mut staged, target.allowed_fields(), updates)?;
    let expected_plan_id = form_plan_id(target, &snapshot, &staged);

    if plan_id != expected_plan_id {
        return Err(InterspireError::Safety(
            "plan_id does not match the current list create form fingerprint and requested changes"
                .to_string(),
        ));
    }

    let requested_fields = changes
        .iter()
        .map(|change| applied_control_name(&change.name))
        .collect::<BTreeSet<_>>();
    let post_fields = staged.to_post_pairs_for_fields(&requested_fields);
    let response = guarded_form_post(client, &snapshot, &post_fields, &html, &read_path)?;
    if !response.status().is_success() && !response.status().is_redirection() {
        return Err(InterspireError::Http(format!(
            "guarded list create returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let redirect_list_id = list_edit_id_from_response(
        &response,
        client.config.base_url.as_deref().unwrap_or_default(),
    )?;

    let after_ids = list_id_inventory(client)?;
    let new_ids = after_ids
        .iter()
        .copied()
        .filter(|list_id| !before_ids.contains(list_id))
        .collect::<Vec<_>>();
    let mut post_create_notes = Vec::new();
    let mut warnings = vec![
        "guarded list create applied; this did not import contacts or authorize any send"
            .to_string(),
    ];
    let new_list_id = resolve_created_list_id(
        &before_ids,
        &new_ids,
        redirect_list_id,
        &mut post_create_notes,
    )?;
    if new_ids.is_empty() && redirect_list_id.is_some() {
        warnings.push(
            "default Lists inventory did not expose the new id; post-create redirect id was used and then proven from the list edit form"
                .to_string(),
        );
    }
    let after_path = AdminReadPage::ListEdit { id: new_list_id }.path();
    let mut after_html = client.get_allowed(&after_path)?;
    let mut after_snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &after_path,
        &after_html,
        &GuardedFormTarget::List {
            list_id: new_list_id,
        },
    )?;
    if list_create_missing_persisted_fields(&after_snapshot, updates)?.is_some() {
        // Interspire 8's AddList route intentionally ignores some visible
        // metadata, notably BounceEmail, unless local bounce polling is
        // selected. Re-save the newly created list through the normal edit
        // route so metadata can be set without enabling local bounce polling.
        apply_guarded_form_updates(
            client,
            GuardedFormTarget::List {
                list_id: new_list_id,
            },
            updates,
        )?;
        after_html = client.get_allowed(&after_path)?;
        after_snapshot = capture_form_snapshot(
            client.config.base_url.as_deref().unwrap_or_default(),
            &after_path,
            &after_html,
            &GuardedFormTarget::List {
                list_id: new_list_id,
            },
        )?;
    }
    verify_list_create_fields_persisted(&after_snapshot, updates)?;
    let post_apply_fields = parse_redacted_fields_for_target(
        GuardedFormTarget::List {
            list_id: new_list_id,
        },
        &after_html,
    )?;

    Ok(GuardedWriteApplyReport {
        ok: true,
        configured: true,
        guarded_writes_enabled: true,
        form_write_controls_enabled: true,
        write_execution_mode: mode,
        target: target.label().to_string(),
        target_id: Some(new_list_id),
        section: None,
        applied: true,
        plan_id: expected_plan_id,
        changes,
        post_apply_fields,
        warnings,
        evidence: admin_evidence({
            let mut notes = vec![
                "allowlisted list create form POST apply succeeded".to_string(),
                "post-create proof selected exactly one new list id".to_string(),
                "new list metadata was proven from the list edit form after create".to_string(),
            ];
            notes.append(&mut post_create_notes);
            notes.append(&mut evidence_notes);
            notes
        }),
    })
}

fn list_edit_id_from_response(
    response: &reqwest::blocking::Response,
    base_url: &str,
) -> Result<Option<u64>, InterspireError> {
    let Some(location) = response.headers().get(LOCATION) else {
        return Ok(None);
    };
    let location = location.to_str().map_err(|_| {
        InterspireError::Safety("list create redirect Location header was not valid UTF-8".into())
    })?;
    list_edit_id_from_location(base_url, location)
}

fn list_edit_id_from_location(
    base_url: &str,
    location: &str,
) -> Result<Option<u64>, InterspireError> {
    let base = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let url = base
        .join(location)
        .map_err(|err| InterspireError::Safety(format!("invalid list create redirect: {err}")))?;
    if url.scheme() != base.scheme()
        || url.host_str() != base.host_str()
        || url.port_or_known_default() != base.port_or_known_default()
    {
        return Err(InterspireError::Safety(
            "list create redirect left the configured admin origin".to_string(),
        ));
    }
    if !url.path().starts_with(base.path().trim_end_matches('/')) {
        return Err(InterspireError::Safety(
            "list create redirect left the configured admin path".to_string(),
        ));
    }
    let pairs = url.query_pairs().collect::<Vec<_>>();
    let page = pairs
        .iter()
        .find(|(key, _)| key == "Page")
        .map(|(_, value)| value.as_ref());
    let action = pairs
        .iter()
        .find(|(key, _)| key == "Action")
        .map(|(_, value)| value.as_ref());
    let id = pairs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("id"))
        .and_then(|(_, value)| value.parse::<u64>().ok());
    if page == Some("Lists") && action == Some("Edit") {
        if let Some(id) = id {
            safety::ensure_allowed_admin_get(base_url, &AdminReadPage::ListEdit { id }.path())?;
            return Ok(Some(id));
        }
    }
    Ok(None)
}

fn resolve_created_list_id(
    before_ids: &BTreeSet<u64>,
    inventory_new_ids: &[u64],
    redirect_list_id: Option<u64>,
    notes: &mut Vec<String>,
) -> Result<u64, InterspireError> {
    match (inventory_new_ids, redirect_list_id) {
        ([new_id], Some(redirect_id)) if *new_id == redirect_id => {
            notes.push(
                "post-create redirect and refreshed Lists inventory agreed on the new list id"
                    .to_string(),
            );
            Ok(*new_id)
        }
        ([new_id], Some(redirect_id)) => Err(InterspireError::Safety(format!(
            "guarded list create returned conflicting new-list proof: inventory id {new_id}, redirect id {redirect_id}; treat apply as unconfirmed"
        ))),
        ([new_id], None) => {
            notes.push("refreshed Lists inventory detected exactly one new list id".to_string());
            Ok(*new_id)
        }
        ([], Some(redirect_id)) if !before_ids.contains(&redirect_id) => {
            notes.push(
                "post-create redirect exposed the new list id when refreshed Lists inventory did not"
                    .to_string(),
            );
            Ok(redirect_id)
        }
        ([], Some(redirect_id)) => Err(InterspireError::Safety(format!(
            "guarded list create redirected to existing list id {redirect_id}; treat apply as unconfirmed"
        ))),
        ([], None) => Err(InterspireError::Safety(
            "guarded list create returned but neither refreshed Lists inventory nor post-create redirect proved a new list id; treat apply as unconfirmed"
                .to_string(),
        )),
        (ids, _) => Err(InterspireError::Safety(format!(
            "guarded list create returned but new list id detection found {} new ids; treat apply as unconfirmed",
            ids.len()
        ))),
    }
}

fn apply_guarded_form_updates(
    client: &AdminHtmlClient,
    target: GuardedFormTarget,
    updates: &[FormFieldUpdate],
) -> Result<(), InterspireError> {
    let (read_path, html, _) = guarded_form_html(client, target)?;
    let snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &read_path,
        &html,
        &target,
    )?;
    let mut staged = snapshot.clone();
    let changes = apply_requested_updates(&mut staged, target.allowed_fields(), updates)?;
    let requested_fields = changes
        .iter()
        .map(|change| applied_control_name(&change.name))
        .collect::<BTreeSet<_>>();
    let post_fields = staged.to_post_pairs_for_fields(&requested_fields);
    let response = guarded_form_post(client, &snapshot, &post_fields, &html, &read_path)?;
    if !response.status().is_success() && !response.status().is_redirection() {
        return Err(InterspireError::Http(format!(
            "guarded post-create list metadata update returned HTTP {}",
            response.status().as_u16()
        )));
    }

    Ok(())
}

fn list_id_inventory(client: &AdminHtmlClient) -> Result<BTreeSet<u64>, InterspireError> {
    let html = client.get_allowed(&AdminReadPage::Lists.path())?;
    let ids = extract_ids_from_links(&html, "Page=Lists", "id");
    Ok(ids.into_iter().collect())
}

fn guarded_form_post(
    client: &AdminHtmlClient,
    snapshot: &FormSnapshot,
    post_fields: &[(String, String)],
    page_html: &str,
    referer_path: &str,
) -> Result<reqwest::blocking::Response, InterspireError> {
    let base_url = client.config.base_url.as_deref().unwrap_or_default();
    let post_fields = post_pairs_with_page_csrf(post_fields, page_html);
    let mut request = client
        .with_access_headers(client.http.post(snapshot.action_url.clone()))
        .form(&post_fields)
        .header(
            "referer",
            safety::ensure_allowed_admin_get(base_url, referer_path)?.as_str(),
        )
        .header("origin", admin_origin(base_url)?);
    if let Some((_, token)) = csrf_pair(&post_fields) {
        request = request.header("x-csrf-token", token);
    }
    request
        .send()
        .map_err(|err| InterspireError::Http(err.to_string()))
}

fn post_pairs_with_page_csrf(
    post_fields: &[(String, String)],
    page_html: &str,
) -> Vec<(String, String)> {
    let mut pairs = post_fields.to_vec();
    if csrf_pair(&pairs).is_some() {
        return pairs;
    }

    // Interspire 8 can publish the current CSRF token as page JavaScript
    // instead of a hidden input on the target form. Browsers still submit from
    // the current page context, so guarded form writes must replay that token.
    if let Some(token) = extract_login_csrf_token(page_html) {
        pairs.push((token.field_name, token.value));
    }
    pairs
}

fn verify_list_create_fields_persisted(
    snapshot: &FormSnapshot,
    updates: &[FormFieldUpdate],
) -> Result<(), InterspireError> {
    if let Some(missing) = list_create_missing_persisted_fields(snapshot, updates)? {
        return Err(InterspireError::Safety(format!(
            "new list readback did not persist requested fields: {}",
            missing.join(", ")
        )));
    }

    Ok(())
}

fn list_create_missing_persisted_fields(
    snapshot: &FormSnapshot,
    updates: &[FormFieldUpdate],
) -> Result<Option<Vec<String>>, InterspireError> {
    let mut missing = Vec::new();
    for update in updates {
        let Some(expected) = update.value.as_deref() else {
            continue;
        };
        let lower_name = update.name.trim().to_ascii_lowercase();
        let target_lower_name = resolve_semantic_field_name(snapshot, &lower_name);
        let Some(actual) = snapshot.raw_field_value(&target_lower_name) else {
            missing.push(lower_name);
            continue;
        };
        if actual.trim() != expected.trim() {
            missing.push(lower_name);
        }
    }
    if missing.is_empty() {
        Ok(None)
    } else {
        Ok(Some(missing))
    }
}

fn guarded_form_html(
    client: &AdminHtmlClient,
    target: GuardedFormTarget,
) -> Result<(String, String, Vec<String>), InterspireError> {
    guarded_form_html_for_updates(client, target, &[])
}

fn guarded_form_html_for_updates(
    client: &AdminHtmlClient,
    target: GuardedFormTarget,
    updates: &[FormFieldUpdate],
) -> Result<(String, String, Vec<String>), InterspireError> {
    let read_path = target.read_page().path();
    match target {
        GuardedFormTarget::Campaign { campaign_id } => {
            let step1_format_override = campaign_step1_format_override(updates)?;
            let text_body_requested = campaign_text_body_requested(updates);
            let resolved = client
                .resolve_campaign_body_html_with_format(campaign_id, step1_format_override)?;
            let mut notes = vec![format!(
                "allowlisted campaign edit GET read for campaign {campaign_id}"
            )];
            if resolved.used_step2 {
                notes.push(
                    "allowlisted campaign Step1 POST rendered Interspire 8 Step2 form; Complete/save form was not posted during preview/readback"
                        .to_string(),
                );
            }
            if step1_format_override.is_some() {
                if text_body_requested && step1_format_override == Some("b") {
                    notes.push(
                        "text body update requested; allowlisted campaign Step1 proof selected Text+HTML format before rendering Step2"
                            .to_string(),
                    );
                } else {
                    notes.push(
                        "allowlisted campaign Step1 proof selected requested format before rendering Step2"
                            .to_string(),
                    );
                }
            }
            Ok((read_path, resolved.html, notes))
        }
        _ => Ok((
            read_path.clone(),
            client.get_allowed(&read_path)?,
            Vec::new(),
        )),
    }
}

fn campaign_step1_format_override(
    updates: &[FormFieldUpdate],
) -> Result<Option<&'static str>, InterspireError> {
    let mut explicit_format = None;
    for update in updates {
        let lower_name = update.name.trim().to_ascii_lowercase();
        if lower_name == "format" {
            explicit_format = update.value.as_deref();
        }
    }

    let text_body_requested = campaign_text_body_requested(updates);
    if let Some(value) = explicit_format {
        let Some(format) = canonical_campaign_format(value) else {
            return Err(InterspireError::Safety(
                "campaign format update must be one of text, html, or text+html".to_string(),
            ));
        };
        if text_body_requested && format != "b" {
            return Err(InterspireError::Safety(
                "text body updates require Text+HTML campaign format; remove the format override or set it to text+html"
                    .to_string(),
            ));
        }
        return Ok(Some(format));
    }

    Ok(text_body_requested.then_some("b"))
}

fn campaign_text_body_requested(updates: &[FormFieldUpdate]) -> bool {
    updates.iter().any(|update| {
        let lower_name = update.name.trim().to_ascii_lowercase();
        matches!(
            lower_name.as_str(),
            "text_body"
                | "textbody"
                | "textcontents"
                | "mydeveditcontrol_text"
                | "mydeveditcontroltext"
                | "text_content"
                | "textcontent"
        )
    })
}

fn canonical_campaign_format(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "b" | "both" | "textandhtml" | "text_and_html" | "htmlandtext" | "html_and_text" => {
            Some("b")
        }
        "h" | "html" => Some("h"),
        "t" | "text" => Some("t"),
        _ => None,
    }
}

impl FormSnapshot {
    fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(stable_action_key(&self.action_url).as_bytes());
        for control in &self.controls {
            if matches!(control.kind, FormControlKind::Hidden)
                && safety::is_volatile_form_or_query_key(&control.lower_name)
            {
                continue;
            }
            hasher.update([0]);
            hasher.update(control.lower_name.as_bytes());
            hasher.update([0]);
            hasher.update(control.kind.as_str().as_bytes());
            hasher.update([0]);
            hasher.update(control.value.as_bytes());
            hasher.update([0]);
            hasher.update(if control.checked { b"1" } else { b"0" });
        }
        hex::encode(hasher.finalize())
    }

    fn available_fields(&self, allowed_fields: &[&str]) -> Vec<FormFieldDescriptor> {
        let allowed = allowed_fields
            .iter()
            .map(|field| field.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        let mut fields = Vec::new();
        for control in &self.controls {
            if matches!(
                control.kind,
                FormControlKind::Hidden | FormControlKind::Password | FormControlKind::Submit
            ) {
                continue;
            }
            if !allowed.contains(&control.lower_name) || !seen.insert(control.lower_name.clone()) {
                continue;
            }
            fields.push(FormFieldDescriptor {
                name: control.lower_name.clone(),
                control_kind: control.kind.as_str().to_string(),
            });
        }
        fields
    }

    fn current_field_summary(&self, lower_name: &str) -> Option<(String, String)> {
        let control = self
            .controls
            .iter()
            .find(|control| control.lower_name == lower_name)?;
        let value = if matches!(control.kind, FormControlKind::Checkbox) {
            if control.checked {
                "[checked]".to_string()
            } else {
                "[unchecked]".to_string()
            }
        } else {
            summarize_field_value(lower_name, &control.value)
        };
        Some((control.kind.as_str().to_string(), value))
    }

    fn raw_field_value(&self, lower_name: &str) -> Option<&str> {
        self.controls
            .iter()
            .find(|control| control.lower_name == lower_name)
            .map(|control| control.value.as_str())
    }

    fn field_fingerprint(&self, lower_name: &str) -> Option<String> {
        let matching = self
            .controls
            .iter()
            .filter(|control| control.lower_name == lower_name)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return None;
        }

        let mut hasher = Sha256::new();
        for control in matching {
            hasher.update(control.kind.as_str().as_bytes());
            hasher.update([0]);
            hasher.update(control.value.as_bytes());
            hasher.update([0]);
            hasher.update(if control.checked { b"1" } else { b"0" });
            hasher.update([0]);
        }
        Some(hex::encode(hasher.finalize()))
    }

    pub(super) fn to_post_pairs_for_fields(
        &self,
        requested_fields: &BTreeSet<String>,
    ) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        let mut included_submit = false;
        for control in &self.controls {
            match control.kind {
                FormControlKind::Hidden => {
                    if should_replay_hidden_control(control) {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                    }
                }
                FormControlKind::Submit => {
                    if included_submit {
                        continue;
                    }
                    if looks_like_save_submit(control) {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                        included_submit = true;
                    }
                }
                FormControlKind::Checkbox | FormControlKind::Radio => {
                    if control.checked {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                    }
                }
                FormControlKind::Password => {
                    if requested_fields.contains(&control.lower_name) && !control.value.is_empty() {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                    }
                }
                _ => {
                    pairs.push((control.original_name.clone(), control.value.clone()));
                }
            }
        }
        pairs
    }
}

fn stable_action_key(url: &Url) -> String {
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

fn capture_form_snapshot(
    base_url: &str,
    current_path: &str,
    html: &str,
    target: &GuardedFormTarget,
) -> Result<FormSnapshot, InterspireError> {
    let base = Url::parse(base_url)
        .map_err(|err| InterspireError::Safety(format!("invalid admin base url: {err}")))?;
    let current_url = base
        .join(current_path)
        .map_err(|err| InterspireError::Safety(format!("invalid current admin path: {err}")))?;
    let document = Html::parse_document(html);
    let form_selector =
        Selector::parse("form").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;

    for form in document.select(&form_selector) {
        let action = form.value().attr("action").unwrap_or(current_path);
        let action_url =
            match safety::ensure_allowed_admin_post_for(base_url, action, &target.write_intent()) {
                Ok(url) => url,
                Err(_) => continue,
            };
        let controls = parse_form_controls(&form);
        if controls.is_empty() {
            continue;
        }
        let allowlist = target.allowed_fields();
        if !controls.iter().any(|control| {
            allowlist
                .iter()
                .any(|allowed| control.lower_name == allowed.to_ascii_lowercase())
        }) {
            continue;
        }
        return Ok(FormSnapshot {
            action_url,
            controls,
        });
    }

    Err(InterspireError::HtmlParse(format!(
        "no guarded-write form matched target {} on {}",
        target.label(),
        current_url
    )))
}

pub(super) fn parse_form_controls(form: &ElementRef<'_>) -> Vec<FormControl> {
    let input_selector =
        Selector::parse("input").unwrap_or_else(|err| panic!("selector parse failed: {err}"));
    let textarea_selector =
        Selector::parse("textarea").unwrap_or_else(|err| panic!("selector parse failed: {err}"));
    let select_selector =
        Selector::parse("select").unwrap_or_else(|err| panic!("selector parse failed: {err}"));
    let option_selector =
        Selector::parse("option").unwrap_or_else(|err| panic!("selector parse failed: {err}"));
    let mut controls = Vec::new();

    for input in form.select(&input_selector) {
        let Some(name) = input.value().attr("name") else {
            continue;
        };
        if input.value().attr("disabled").is_some() {
            continue;
        }
        let kind = match input
            .value()
            .attr("type")
            .unwrap_or("text")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "password" => FormControlKind::Password,
            "hidden" => FormControlKind::Hidden,
            "checkbox" => FormControlKind::Checkbox,
            "radio" => FormControlKind::Radio,
            "submit" => FormControlKind::Submit,
            "button" | "image" | "reset" => continue,
            _ => FormControlKind::Text,
        };
        controls.push(FormControl {
            original_name: name.to_string(),
            lower_name: name.to_ascii_lowercase(),
            kind,
            value: input.value().attr("value").unwrap_or_default().to_string(),
            checked: input.value().attr("checked").is_some(),
        });
    }

    for textarea in form.select(&textarea_selector) {
        let Some(name) = textarea.value().attr("name") else {
            continue;
        };
        if textarea.value().attr("disabled").is_some() {
            continue;
        }
        controls.push(FormControl {
            original_name: name.to_string(),
            lower_name: name.to_ascii_lowercase(),
            kind: FormControlKind::Textarea,
            value: textarea.text().collect::<Vec<_>>().join(""),
            checked: true,
        });
    }

    for select in form.select(&select_selector) {
        let Some(name) = select.value().attr("name") else {
            continue;
        };
        if select.value().attr("disabled").is_some() {
            continue;
        }
        let selected_options = select
            .select(&option_selector)
            .filter(|option| option.value().attr("selected").is_some())
            .collect::<Vec<_>>();
        let selected_options =
            if selected_options.is_empty() && select.value().attr("multiple").is_none() {
                select.select(&option_selector).next().into_iter().collect()
            } else {
                selected_options
            };
        for option in selected_options {
            let value = option.value().attr("value").unwrap_or_default().to_string();
            controls.push(FormControl {
                original_name: name.to_string(),
                lower_name: name.to_ascii_lowercase(),
                kind: FormControlKind::Select,
                value,
                checked: true,
            });
        }
    }

    controls
}

fn apply_requested_updates(
    snapshot: &mut FormSnapshot,
    allowed_fields: &[&str],
    updates: &[FormFieldUpdate],
) -> Result<Vec<FormFieldChange>, InterspireError> {
    if updates.is_empty() {
        return Err(InterspireError::Safety(
            "guarded write requires at least one requested field change".to_string(),
        ));
    }

    let allowed = allowed_fields
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();

    for update in updates {
        let lower_name = update.name.trim().to_ascii_lowercase();
        if lower_name.is_empty() {
            return Err(InterspireError::Safety(
                "guarded write update includes an empty field name".to_string(),
            ));
        }
        if !allowed.contains(&lower_name) {
            return Err(InterspireError::Safety(format!(
                "field {lower_name} is outside the guarded allowlist for this target"
            )));
        }
        if !seen.insert(lower_name.clone()) {
            return Err(InterspireError::Safety(format!(
                "field {lower_name} was provided more than once"
            )));
        }

        let target_lower_name = resolve_semantic_field_name(snapshot, &lower_name);
        let matched_indices = snapshot
            .controls
            .iter()
            .enumerate()
            .filter_map(|(index, control)| {
                (control.lower_name == target_lower_name).then_some(index)
            })
            .collect::<Vec<_>>();
        if matched_indices.is_empty() {
            return Err(InterspireError::HtmlParse(format!(
                "requested field {lower_name} was not present on the current form"
            )));
        }

        let before_fingerprint = snapshot.field_fingerprint(&target_lower_name);
        let (control_kind, current_value) = snapshot
            .current_field_summary(&target_lower_name)
            .unwrap_or_else(|| ("unknown".to_string(), String::new()));
        let first_control = snapshot.controls[matched_indices[0]].clone();
        let requested_value = preview_requested_value(update, &first_control);

        if let Some(checked) = update.checked {
            if !matched_indices.iter().all(|index| {
                matches!(
                    snapshot.controls[*index].kind,
                    FormControlKind::Checkbox | FormControlKind::Radio
                )
            }) {
                return Err(InterspireError::Safety(format!(
                    "field {lower_name} is not a checkbox/radio field; use value instead of checked"
                )));
            }
            let radio_group = matched_indices
                .iter()
                .all(|index| snapshot.controls[*index].kind == FormControlKind::Radio);
            if matched_indices.len() > 1 && !radio_group {
                return Err(InterspireError::Safety(format!(
                    "field {lower_name} maps to multiple checkbox inputs and is not supported by the guarded write surface"
                )));
            }
            if radio_group && matched_indices.len() > 1 {
                let Some(selected_value) = update.value.as_deref() else {
                    return Err(InterspireError::Safety(format!(
                        "field {lower_name} is a radio group; provide checked plus the selected value"
                    )));
                };
                let mut matched_any = false;
                for index in &matched_indices {
                    let control = &mut snapshot.controls[*index];
                    let is_selected = checked && control.value == selected_value;
                    matched_any |= is_selected;
                    control.checked = is_selected;
                }
                if checked && !matched_any {
                    return Err(InterspireError::Safety(format!(
                        "field {lower_name} radio group does not contain value {selected_value}"
                    )));
                }
            } else {
                for index in &matched_indices {
                    let control = &mut snapshot.controls[*index];
                    control.checked = checked;
                    if checked {
                        if let Some(value) = &update.value {
                            control.value = value.clone();
                        } else if control.value.is_empty() {
                            control.value = "1".to_string();
                        }
                    }
                }
            }
        } else if let Some(value) = &update.value {
            if matched_indices.len() > 1
                && matched_indices
                    .iter()
                    .all(|index| snapshot.controls[*index].kind == FormControlKind::Select)
            {
                return Err(InterspireError::Safety(format!(
                    "field {lower_name} maps to a multi-select control; guarded value updates for multi-select fields are not supported"
                )));
            }
            if matched_indices.iter().any(|index| {
                matches!(
                    snapshot.controls[*index].kind,
                    FormControlKind::Checkbox | FormControlKind::Radio
                )
            }) {
                return Err(InterspireError::Safety(format!(
                    "field {lower_name} is a checkbox/radio field; use checked instead of value"
                )));
            }
            for index in &matched_indices {
                snapshot.controls[*index].value = value.clone();
            }
        } else {
            return Err(InterspireError::Safety(format!(
                "field {lower_name} must provide either value or checked"
            )));
        }

        let after_value = snapshot
            .current_field_summary(&target_lower_name)
            .map(|(_, value)| value);
        let after_fingerprint = snapshot.field_fingerprint(&target_lower_name);
        let requested_value = requested_value.or(after_value.clone());
        let will_change = before_fingerprint != after_fingerprint;
        changes.push(FormFieldChange {
            name: if target_lower_name == lower_name {
                lower_name
            } else {
                format!("{lower_name}->{target_lower_name}")
            },
            control_kind,
            current_value: Some(current_value),
            requested_value,
            will_change,
        });
    }

    if changes.iter().all(|change| !change.will_change) {
        return Err(InterspireError::Safety(
            "guarded write request did not change any persisted form values".to_string(),
        ));
    }

    Ok(changes)
}

fn resolve_semantic_field_name(snapshot: &FormSnapshot, lower_name: &str) -> String {
    let candidates: &[&str] = match lower_name {
        "html_body" => &[
            "htmlbody",
            "htmlcontents",
            "mydeveditcontrol_html",
            "mydeveditcontrolhtml",
            "html_content",
            "htmlcontent",
        ],
        "text_body" => &[
            "textbody",
            "textcontents",
            "mydeveditcontrol_text",
            "mydeveditcontroltext",
            "text_content",
            "textcontent",
        ],
        _ => return lower_name.to_string(),
    };
    candidates
        .iter()
        .find(|candidate| {
            snapshot
                .controls
                .iter()
                .any(|control| control.lower_name == **candidate)
        })
        .copied()
        .unwrap_or(lower_name)
        .to_string()
}

fn applied_control_name(change_name: &str) -> String {
    change_name
        .rsplit_once("->")
        .map(|(_, actual)| actual.to_string())
        .unwrap_or_else(|| change_name.to_string())
}

fn preview_requested_value(update: &FormFieldUpdate, control: &FormControl) -> Option<String> {
    if let Some(checked) = update.checked {
        return Some(if checked {
            summarize_field_value(
                &control.lower_name,
                update.value.as_deref().unwrap_or(&control.value),
            )
        } else {
            "[unchecked]".to_string()
        });
    }

    update
        .value
        .as_deref()
        .map(|value| summarize_field_value(&control.lower_name, value))
}

fn form_plan_id(
    target: GuardedFormTarget,
    snapshot: &FormSnapshot,
    staged: &FormSnapshot,
) -> String {
    let parts = [
        target.label().to_string(),
        target
            .target_id()
            .map(|value| value.to_string())
            .unwrap_or_default(),
        target.section_name().unwrap_or_default().to_string(),
        snapshot.fingerprint(),
        staged.fingerprint(),
    ];
    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    format!("ifw_{}", &guarded_write::stable_plan_id(&refs)[4..])
}

fn parse_redacted_fields_for_target(
    target: GuardedFormTarget,
    html: &str,
) -> Result<Vec<RedactedField>, InterspireError> {
    match target {
        GuardedFormTarget::Campaign { .. } => {
            parse_redacted_fields_by_names(html, target.allowed_fields())
        }
        GuardedFormTarget::ListCreate => {
            parse_redacted_fields_by_names(html, target.allowed_fields())
        }
        GuardedFormTarget::List { .. } => {
            parse_redacted_fields_by_names(html, target.allowed_fields())
        }
        GuardedFormTarget::User { .. } => {
            parse_redacted_fields_by_names(html, target.allowed_fields())
        }
        GuardedFormTarget::Settings { section } => parse_settings_fields(section.as_str(), html),
    }
}

fn parse_redacted_fields_by_names(
    html: &str,
    field_names: &[&str],
) -> Result<Vec<RedactedField>, InterspireError> {
    let values = parse_form_values(html)?;
    Ok(field_names
        .iter()
        .filter_map(|name| {
            values.get(*name).map(|value| RedactedField {
                name: (*name).to_string(),
                value: Some(summarize_field_value(name, value)),
            })
        })
        .collect())
}

pub(super) fn should_replay_hidden_control(control: &FormControl) -> bool {
    matches!(
        control.lower_name.as_str(),
        "token"
            | "csrf"
            | "csrf_token"
            | "_token"
            | "form_token"
            | "total_webhooks"
            | "page"
            | "action"
            | "tab"
            | "tab_num"
            | "tabnum"
            | "currenttab"
            | "id"
            | "userid"
            | "listid"
            | "newsletterid"
            | "campaignid"
            | "templateid"
            | "segmentid"
            // Interspire 8 renders Application URL as a disabled text field
            // plus this hidden control, and Settings::Save rebuilds the full
            // config file from POST on every settings tab save.
            | "application_url"
            // Interspire campaign Step2 can carry the selected Step1 body
            // format as hidden wizard state into the final Complete save.
            | "format"
            | "ss_takemeto"
    ) || control.lower_name.ends_with("token")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_snapshot(name: &str, value: &str) -> FormSnapshot {
        FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![FormControl {
                original_name: name.to_string(),
                lower_name: name.to_ascii_lowercase(),
                kind: FormControlKind::Text,
                value: value.to_string(),
                checked: true,
            }],
        }
    }

    fn checkbox_snapshot(name: &str, value: &str, checked: bool) -> FormSnapshot {
        FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![FormControl {
                original_name: name.to_string(),
                lower_name: name.to_ascii_lowercase(),
                kind: FormControlKind::Checkbox,
                value: value.to_string(),
                checked,
            }],
        }
    }

    #[test]
    fn apply_requested_updates_rejects_empty_and_noop_requests() {
        let mut empty = text_snapshot("subject", "Original");
        let err = apply_requested_updates(&mut empty, &["subject"], &[])
            .err()
            .unwrap_or_else(|| panic!("empty update set should fail"));
        assert!(err
            .to_string()
            .contains("at least one requested field change"));

        let mut noop = text_snapshot("subject", "Original");
        let err = apply_requested_updates(
            &mut noop,
            &["subject"],
            &[FormFieldUpdate {
                name: "subject".to_string(),
                value: Some("Original".to_string()),
                checked: None,
            }],
        )
        .err()
        .unwrap_or_else(|| panic!("no-op update should fail"));
        assert!(err
            .to_string()
            .contains("did not change any persisted form values"));
    }

    #[test]
    fn cron_settings_updates_use_guarded_cron_allowlist() {
        let target = GuardedFormTarget::Settings {
            section: SettingsSectionName::Cron,
        };
        let mut value_only_checkbox = checkbox_snapshot("cron_enabled", "1", false);
        let err = apply_requested_updates(
            &mut value_only_checkbox,
            target.allowed_fields(),
            &[FormFieldUpdate {
                name: "cron_enabled".to_string(),
                value: Some("1".to_string()),
                checked: None,
            }],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("use checked instead of value"));

        let mut snapshot = checkbox_snapshot("cron_enabled", "1", false);
        let (_, current_value) = snapshot
            .current_field_summary("cron_enabled")
            .unwrap_or_else(|| panic!("cron_enabled should be present"));
        assert_eq!(current_value, "[unchecked]");

        let changes = apply_requested_updates(
            &mut snapshot,
            target.allowed_fields(),
            &[FormFieldUpdate {
                name: "cron_enabled".to_string(),
                value: None,
                checked: Some(true),
            }],
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].current_value.as_deref(), Some("[unchecked]"));
        assert_eq!(changes[0].requested_value.as_deref(), Some("1"));
        assert!(snapshot
            .controls
            .iter()
            .any(|control| control.lower_name == "cron_enabled" && control.checked));

        let mut wrong_section = text_snapshot("maxhourlyrate", "1000");
        let err = apply_requested_updates(
            &mut wrong_section,
            target.allowed_fields(),
            &[FormFieldUpdate {
                name: "maxhourlyrate".to_string(),
                value: Some("1100".to_string()),
                checked: None,
            }],
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("outside the guarded allowlist"));
    }

    #[test]
    fn campaign_archive_checkbox_is_guarded_metadata() {
        let target = GuardedFormTarget::Campaign { campaign_id: 2 };
        let mut snapshot = checkbox_snapshot("archive", "1", false);

        let changes = apply_requested_updates(
            &mut snapshot,
            target.allowed_fields(),
            &[FormFieldUpdate {
                name: "archive".to_string(),
                value: None,
                checked: Some(true),
            }],
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].current_value.as_deref(), Some("[unchecked]"));
        assert_eq!(changes[0].requested_value.as_deref(), Some("1"));
        assert!(snapshot
            .controls
            .iter()
            .any(|control| control.lower_name == "archive" && control.checked));
    }

    #[test]
    fn radio_group_updates_require_selected_value_and_only_check_one_option() {
        let mut snapshot = FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![
                FormControl {
                    original_name: "format".to_string(),
                    lower_name: "format".to_string(),
                    kind: FormControlKind::Radio,
                    value: "html".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "format".to_string(),
                    lower_name: "format".to_string(),
                    kind: FormControlKind::Radio,
                    value: "text".to_string(),
                    checked: false,
                },
            ],
        };

        let err = apply_requested_updates(
            &mut snapshot.clone(),
            &["format"],
            &[FormFieldUpdate {
                name: "format".to_string(),
                value: None,
                checked: Some(true),
            }],
        )
        .err()
        .unwrap_or_else(|| panic!("radio update without selected value should fail"));
        assert!(err.to_string().contains("radio group"));

        let changes = apply_requested_updates(
            &mut snapshot,
            &["format"],
            &[FormFieldUpdate {
                name: "format".to_string(),
                value: Some("text".to_string()),
                checked: Some(true),
            }],
        )
        .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(changes.len(), 1);
        assert_eq!(
            snapshot
                .controls
                .iter()
                .filter(|control| control.checked)
                .map(|control| control.value.as_str())
                .collect::<Vec<_>>(),
            vec!["text"]
        );
    }

    #[test]
    fn post_pairs_preserve_current_form_state_plus_safe_hidden_controls() {
        let snapshot = FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![
                FormControl {
                    original_name: "name".to_string(),
                    lower_name: "name".to_string(),
                    kind: FormControlKind::Text,
                    value: "Primary list".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "replytoemail".to_string(),
                    lower_name: "replytoemail".to_string(),
                    kind: FormControlKind::Text,
                    value: "reply@example.test".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "format".to_string(),
                    lower_name: "format".to_string(),
                    kind: FormControlKind::Radio,
                    value: "html".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "format".to_string(),
                    lower_name: "format".to_string(),
                    kind: FormControlKind::Radio,
                    value: "text".to_string(),
                    checked: false,
                },
                FormControl {
                    original_name: "csrf_token".to_string(),
                    lower_name: "csrf_token".to_string(),
                    kind: FormControlKind::Hidden,
                    value: "safe-token".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "total_webhooks".to_string(),
                    lower_name: "total_webhooks".to_string(),
                    kind: FormControlKind::Hidden,
                    value: "1".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "tab_num".to_string(),
                    lower_name: "tab_num".to_string(),
                    kind: FormControlKind::Hidden,
                    value: "4".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "application_url".to_string(),
                    lower_name: "application_url".to_string(),
                    kind: FormControlKind::Hidden,
                    value: "https://newsletter.example.invalid".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "dangerous_hidden_flag".to_string(),
                    lower_name: "dangerous_hidden_flag".to_string(),
                    kind: FormControlKind::Hidden,
                    value: "replay-me".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "SubmitButton1".to_string(),
                    lower_name: "submitbutton1".to_string(),
                    kind: FormControlKind::Submit,
                    value: "Save".to_string(),
                    checked: true,
                },
            ],
        };

        let requested_fields = BTreeSet::from(["replytoemail".to_string(), "format".to_string()]);
        let pairs = snapshot.to_post_pairs_for_fields(&requested_fields);

        assert!(pairs
            .iter()
            .any(|(name, value)| name == "name" && value == "Primary list"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "replytoemail" && value == "reply@example.test"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "format" && value == "html"));
        assert!(!pairs
            .iter()
            .any(|(name, value)| name == "format" && value == "text"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "csrf_token" && value == "safe-token"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "total_webhooks" && value == "1"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "tab_num" && value == "4"));
        assert!(pairs.iter().any(|(name, value)| {
            name == "application_url" && value == "https://newsletter.example.invalid"
        }));
        assert!(!pairs
            .iter()
            .any(|(name, _)| name == "dangerous_hidden_flag"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "SubmitButton1" && value == "Save"));
    }

    #[test]
    fn disabled_application_url_text_is_not_posted_but_hidden_state_is_preserved() {
        let html = r#"
            <form method="post" action="index.php?Page=Settings&Action=Save">
                <input type="text" name="Application_URL" value="http://stale.example.invalid" disabled>
                <input type="hidden" name="application_url" value="https://newsletter.example.invalid">
                <input type="checkbox" name="cron_enabled" value="1" checked>
                <input type="submit" name="SubmitButton1" value="Save">
            </form>
        "#;
        let document = Html::parse_document(html);
        let form_selector =
            Selector::parse("form").unwrap_or_else(|err| panic!("selector parse failed: {err}"));
        let form = document
            .select(&form_selector)
            .next()
            .unwrap_or_else(|| panic!("expected form"));
        let controls = parse_form_controls(&form);

        assert!(controls.iter().any(|control| {
            control.lower_name == "application_url"
                && control.kind == FormControlKind::Hidden
                && control.value == "https://newsletter.example.invalid"
        }));
        assert!(!controls.iter().any(|control| {
            control.original_name == "Application_URL" && control.kind == FormControlKind::Text
        }));

        let snapshot = FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls,
        };
        let requested_fields = BTreeSet::from(["cron_enabled".to_string()]);
        let pairs = snapshot.to_post_pairs_for_fields(&requested_fields);

        assert!(pairs.iter().any(|(name, value)| {
            name == "application_url" && value == "https://newsletter.example.invalid"
        }));
        assert!(!pairs.iter().any(|(name, _)| name == "Application_URL"));
    }

    #[test]
    fn source_derived_interspire8_list_create_form_is_matched() {
        let html = r#"
            <form name="frmListEditor" id="frmListEditor" method="post" action="index.php?Page=Lists&Action=AddList">
                <input type="text" name="Name" value="">
                <input type="text" name="OwnerName" value="Operator">
                <input type="text" name="OwnerEmail" value="owner@example.invalid">
                <input type="text" name="ReplyToEmail" value="reply@example.invalid">
                <input type="text" name="BounceEmail" value="bounce@example.invalid">
                <input type="checkbox" name="NotifyOwner" id="NotifyOwner" value="1" checked>
                <input type="text" name="UnsubscribeMailto" value="">
                <select name="SurveyID"><option value="" selected>No Survey</option></select>
                <select name="webhook_event_1"><option value="1" selected>On Subscribe</option></select>
                <input type="text" name="WebhookUrl_1" value="https://hooks.example.invalid/list">
                <input type="hidden" name="total_webhooks" value="1">
                <select id="availablefields" name="AvailableFields[]" multiple="multiple">
                    <option value="7" selected>Global field</option>
                </select>
                <select id="fields" name="VisibleFields[]" multiple="multiple">
                    <option value="emailaddress" selected>Email</option>
                    <option value="format" selected>Format</option>
                </select>
                <input class="FormButton SubmitButton" type="submit" value="Save">
            </form>
        "#;

        let snapshot = capture_form_snapshot(
            "https://example.test/admin/",
            "index.php?Page=Lists&Action=create",
            html,
            &GuardedFormTarget::ListCreate,
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(
            snapshot
                .action_url
                .query_pairs()
                .find(|(key, _)| key == "Action")
                .map(|(_, value)| value.to_string()),
            Some("AddList".to_string())
        );
        let available = snapshot
            .available_fields(GuardedFormTarget::ListCreate.allowed_fields())
            .into_iter()
            .map(|field| field.name)
            .collect::<Vec<_>>();
        assert!(available.contains(&"name".to_string()));
        assert!(available.contains(&"owneremail".to_string()));
        assert!(available.contains(&"unsubscribemailto".to_string()));

        let pairs = snapshot.to_post_pairs_for_fields(&BTreeSet::from(["name".to_string()]));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "total_webhooks" && value == "1"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "VisibleFields[]" && value == "emailaddress"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "VisibleFields[]" && value == "format"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "AvailableFields[]" && value == "7"));
    }

    #[test]
    fn source_derived_list_create_post_pairs_use_page_csrf_not_unrelated_tokens() {
        let html = r#"
            <script>window.IEM_CSRF_TOKEN = "page-token-list-create";</script>
            <form name="frmListEditor" id="frmListEditor" method="post" action="index.php?Page=Lists&Action=AddList">
                <input type="text" name="Name" value="Example Update">
                <input type="text" name="OwnerName" value="Operator">
                <input type="text" name="OwnerEmail" value="owner@example.invalid">
                <input type="text" name="ReplyToEmail" value="reply@example.invalid">
                <input type="text" name="BounceEmail" value="bounce@example.invalid">
                <input type="hidden" name="access_token" value="not-csrf">
                <input type="hidden" name="total_webhooks" value="0">
                <select id="fields" name="VisibleFields[]" multiple="multiple">
                    <option value="emailaddress" selected>Email</option>
                    <option value="format" selected>Format</option>
                </select>
                <input class="FormButton SubmitButton" type="submit" value="Save">
            </form>
        "#;

        let snapshot = capture_form_snapshot(
            "https://example.test/admin/",
            "index.php?Page=Lists&Action=create",
            html,
            &GuardedFormTarget::ListCreate,
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let pairs = snapshot.to_post_pairs_for_fields(&BTreeSet::from(["name".to_string()]));
        let pairs = post_pairs_with_page_csrf(&pairs, html);

        assert!(pairs
            .iter()
            .any(|(name, value)| name == "csrfToken" && value == "page-token-list-create"));
        assert!(!pairs
            .iter()
            .any(|(name, value)| name == "x-csrf-token" && value == "not-csrf"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "VisibleFields[]" && value == "emailaddress"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "VisibleFields[]" && value == "format"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "total_webhooks" && value == "0"));
    }

    #[test]
    fn list_create_redirect_location_can_prove_new_list_id() {
        let id = list_edit_id_from_location(
            "https://example.test/admin/",
            "index.php?Page=Lists&Action=Edit&id=42&csrfToken=private",
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(id, Some(42));
    }

    #[test]
    fn list_create_redirect_location_ignores_non_edit_routes() {
        let id = list_edit_id_from_location(
            "https://example.test/admin/",
            "index.php?Page=Lists&Action=Delete&id=42&csrfToken=private",
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(id, None);
    }

    #[test]
    fn list_create_redirect_location_rejects_external_origin() {
        let err = list_edit_id_from_location(
            "https://example.test/admin/",
            "https://evil.example.invalid/admin/index.php?Page=Lists&Action=Edit&id=42",
        )
        .expect_err("external redirect must fail closed");

        assert!(err.to_string().contains("configured admin origin"));
    }

    #[test]
    fn list_create_resolver_uses_redirect_when_inventory_is_empty() {
        let before_ids = BTreeSet::from([40, 41]);
        let mut notes = Vec::new();
        let id = resolve_created_list_id(&before_ids, &[], Some(42), &mut notes)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(id, 42);
        assert!(notes
            .iter()
            .any(|note| note.contains("redirect exposed the new list id")));
    }

    #[test]
    fn list_create_resolver_rejects_redirect_to_existing_id() {
        let before_ids = BTreeSet::from([40, 41]);
        let mut notes = Vec::new();
        let err = resolve_created_list_id(&before_ids, &[], Some(41), &mut notes)
            .expect_err("existing redirect id must not prove a new list");

        assert!(err.to_string().contains("existing list id 41"));
    }

    #[test]
    fn list_create_resolver_rejects_inventory_redirect_mismatch() {
        let before_ids = BTreeSet::from([40, 41]);
        let mut notes = Vec::new();
        let err = resolve_created_list_id(&before_ids, &[42], Some(43), &mut notes)
            .expect_err("conflicting proof must fail closed");

        assert!(err.to_string().contains("conflicting new-list proof"));
    }

    #[test]
    fn post_pairs_append_page_level_csrf_when_target_form_lacks_token() {
        let pairs = vec![("Name".to_string(), "Example Update".to_string())];
        let with_csrf = post_pairs_with_page_csrf(
            &pairs,
            r#"<script>window.IEM_CSRF_TOKEN = "page-token-123";</script>"#,
        );

        assert!(with_csrf
            .iter()
            .any(|(name, value)| name == "csrfToken" && value == "page-token-123"));
        assert!(with_csrf
            .iter()
            .any(|(name, value)| name == "Name" && value == "Example Update"));
    }

    #[test]
    fn post_pairs_replace_empty_form_csrf_with_page_level_token() {
        let pairs = vec![
            ("csrf_token".to_string(), "   ".to_string()),
            ("Name".to_string(), "Example Update".to_string()),
        ];
        let with_csrf = post_pairs_with_page_csrf(
            &pairs,
            r#"<script>window.IEM_CSRF_TOKEN = "page-token-456";</script>"#,
        );

        assert!(with_csrf
            .iter()
            .any(|(name, value)| name == "csrfToken" && value == "page-token-456"));
    }

    #[test]
    fn post_pairs_ignore_unrelated_token_suffix_fields_for_csrf() {
        let pairs = vec![
            ("access_token".to_string(), "not-csrf".to_string()),
            ("Name".to_string(), "Example Update".to_string()),
        ];
        let with_csrf = post_pairs_with_page_csrf(
            &pairs,
            r#"<script>window.IEM_CSRF_TOKEN = "page-token-999";</script>"#,
        );

        assert!(with_csrf
            .iter()
            .any(|(name, value)| name == "access_token" && value == "not-csrf"));
        assert!(with_csrf
            .iter()
            .any(|(name, value)| name == "csrfToken" && value == "page-token-999"));
    }

    #[test]
    fn post_pairs_keep_existing_non_empty_form_csrf() {
        let pairs = vec![
            ("csrf_token".to_string(), "form-token".to_string()),
            ("Name".to_string(), "Example Update".to_string()),
        ];
        let with_csrf = post_pairs_with_page_csrf(
            &pairs,
            r#"<script>window.IEM_CSRF_TOKEN = "page-token-789";</script>"#,
        );

        assert!(with_csrf
            .iter()
            .any(|(name, value)| name == "csrf_token" && value == "form-token"));
        assert!(!with_csrf
            .iter()
            .any(|(name, value)| name == "csrfToken" && value == "page-token-789"));
    }

    #[test]
    fn multi_select_updates_are_rejected_until_explicitly_modelled() {
        let mut snapshot = FormSnapshot {
            action_url: Url::parse("https://example.test/admin/index.php")
                .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![
                FormControl {
                    original_name: "VisibleFields[]".to_string(),
                    lower_name: "visiblefields[]".to_string(),
                    kind: FormControlKind::Select,
                    value: "emailaddress".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "VisibleFields[]".to_string(),
                    lower_name: "visiblefields[]".to_string(),
                    kind: FormControlKind::Select,
                    value: "format".to_string(),
                    checked: true,
                },
            ],
        };

        let err = apply_requested_updates(
            &mut snapshot,
            &["visiblefields[]"],
            &[FormFieldUpdate {
                name: "visiblefields[]".to_string(),
                value: Some("emailaddress".to_string()),
                checked: None,
            }],
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("multi-select"));
    }

    #[test]
    fn form_plan_id_ignores_volatile_tokens_but_keeps_real_fields() {
        let base = FormSnapshot {
            action_url: Url::parse(
                "https://example.test/admin/index.php?Page=Lists&Action=AddList&csrfToken=one",
            )
            .unwrap_or_else(|err| panic!("{err}")),
            controls: vec![
                FormControl {
                    original_name: "csrf_token".to_string(),
                    lower_name: "csrf_token".to_string(),
                    kind: FormControlKind::Hidden,
                    value: "one".to_string(),
                    checked: true,
                },
                FormControl {
                    original_name: "name".to_string(),
                    lower_name: "name".to_string(),
                    kind: FormControlKind::Text,
                    value: "Primary list".to_string(),
                    checked: true,
                },
            ],
        };
        let mut refreshed = base.clone();
        refreshed.action_url = Url::parse(
            "https://example.test/admin/index.php?Action=AddList&Page=Lists&csrfToken=two",
        )
        .unwrap_or_else(|err| panic!("{err}"));
        refreshed.controls[0].value = "two".to_string();

        assert_eq!(base.fingerprint(), refreshed.fingerprint());

        refreshed.controls[1].value = "Changed list".to_string();
        assert_ne!(base.fingerprint(), refreshed.fingerprint());
    }
}

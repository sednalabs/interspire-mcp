use super::{
    admin_evidence, looks_like_save_submit, parse_form_values, parse_settings_fields,
    summarize_field_value, AdminHtmlClient,
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
    Campaign { campaign_id: u64 },
    List { list_id: u64 },
    User { user_id: u64 },
    Settings { section: SettingsSectionName },
}

impl GuardedFormTarget {
    fn label(self) -> &'static str {
        match self {
            Self::Campaign { .. } => "campaign",
            Self::List { .. } => "list",
            Self::User { .. } => "user",
            Self::Settings { .. } => "settings",
        }
    }

    fn target_id(self) -> Option<u64> {
        match self {
            Self::Campaign { campaign_id } => Some(campaign_id),
            Self::List { list_id } => Some(list_id),
            Self::User { user_id } => Some(user_id),
            Self::Settings { .. } => None,
        }
    }

    fn section_name(self) -> Option<&'static str> {
        match self {
            Self::Settings { section } => Some(section.as_str()),
            _ => None,
        }
    }

    fn read_page(self) -> AdminReadPage {
        match self {
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
            Self::Campaign { .. } => &CAMPAIGN_WRITE_FIELDS,
            Self::List { .. } => &LIST_WRITE_FIELDS,
            Self::User { .. } => &USER_WRITE_FIELDS,
            Self::Settings { section } => settings_write_fields(section),
        }
    }
}

const CAMPAIGN_WRITE_FIELDS: [&str; 14] = [
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
    "htmlbody",
    "htmlcontents",
    "textbody",
];

const LIST_WRITE_FIELDS: [&str; 5] = [
    "name",
    "ownername",
    "owneremail",
    "replytoemail",
    "bounceemail",
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

const SETTINGS_CRON_FIELDS: [&str; 5] = [
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

    let read_page = target.read_page();
    let read_path = read_page.path();
    let html = client.get_allowed(&read_path)?;
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
        evidence: admin_evidence(vec![format!(
            "allowlisted {} form GET read for guarded write preview",
            target.label()
        )]),
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

    let read_page = target.read_page();
    let read_path = read_page.path();
    let html = client.get_allowed(&read_path)?;
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
        .map(|change| change.name.clone())
        .collect::<BTreeSet<_>>();
    let post_fields = staged.to_post_pairs_for_fields(&requested_fields);
    let response = client
        .with_access_headers(client.http.post(snapshot.action_url.clone()))
        .form(&post_fields)
        .send()
        .map_err(|err| InterspireError::Http(err.to_string()))?;
    if !response.status().is_success() && !response.status().is_redirection() {
        return Err(InterspireError::Http(format!(
            "guarded form write returned HTTP {}",
            response.status().as_u16()
        )));
    }

    let after_html = client.get_allowed(&read_path)?;
    let after_snapshot = capture_form_snapshot(
        client.config.base_url.as_deref().unwrap_or_default(),
        &read_path,
        &after_html,
        &target,
    )?;
    let mismatched_fields = changes
        .iter()
        .filter_map(|change| {
            (staged.field_fingerprint(&change.name)
                != after_snapshot.field_fingerprint(&change.name))
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
        evidence: admin_evidence(vec![
            format!("allowlisted {} form POST apply succeeded", target.label()),
            format!("allowlisted {} form GET readback succeeded", target.label()),
        ]),
    })
}

impl FormSnapshot {
    fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.action_url.as_str().as_bytes());
        for control in &self.controls {
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
        Some((
            control.kind.as_str().to_string(),
            summarize_field_value(lower_name, &control.value),
        ))
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
                    if requested_fields.contains(&control.lower_name) && control.checked {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                    }
                }
                FormControlKind::Password => {
                    if requested_fields.contains(&control.lower_name) && !control.value.is_empty() {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                    }
                }
                _ => {
                    if requested_fields.contains(&control.lower_name) {
                        pairs.push((control.original_name.clone(), control.value.clone()));
                    }
                }
            }
        }
        pairs
    }
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
        let selected = select
            .select(&option_selector)
            .find(|option| option.value().attr("selected").is_some())
            .or_else(|| select.select(&option_selector).next());
        let value = selected
            .and_then(|option| option.value().attr("value").map(ToString::to_string))
            .unwrap_or_default();
        controls.push(FormControl {
            original_name: name.to_string(),
            lower_name: name.to_ascii_lowercase(),
            kind: FormControlKind::Select,
            value,
            checked: true,
        });
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

        let matched_indices = snapshot
            .controls
            .iter()
            .enumerate()
            .filter_map(|(index, control)| (control.lower_name == lower_name).then_some(index))
            .collect::<Vec<_>>();
        if matched_indices.is_empty() {
            return Err(InterspireError::HtmlParse(format!(
                "requested field {lower_name} was not present on the current form"
            )));
        }

        let before_fingerprint = snapshot.field_fingerprint(&lower_name);
        let (control_kind, current_value) = snapshot
            .current_field_summary(&lower_name)
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
            .current_field_summary(&lower_name)
            .map(|(_, value)| value);
        let after_fingerprint = snapshot.field_fingerprint(&lower_name);
        let requested_value = requested_value.or(after_value.clone());
        let will_change = before_fingerprint != after_fingerprint;
        changes.push(FormFieldChange {
            name: lower_name,
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
            | "page"
            | "action"
            | "tab"
            | "currenttab"
            | "id"
            | "userid"
            | "listid"
            | "newsletterid"
            | "campaignid"
            | "templateid"
            | "segmentid"
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
    fn post_pairs_only_include_requested_fields_plus_safe_hidden_controls() {
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

        assert!(!pairs.iter().any(|(name, _)| name == "name"));
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
        assert!(!pairs
            .iter()
            .any(|(name, _)| name == "dangerous_hidden_flag"));
        assert!(pairs
            .iter()
            .any(|(name, value)| name == "SubmitButton1" && value == "Save"));
    }
}

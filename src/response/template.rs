use super::FormFieldUpdate;

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTemplateUpdatePreviewRequest {
    pub campaign_id: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
    #[serde(default)]
    pub send_multipart: Option<bool>,
    #[serde(default)]
    pub track_opens: Option<bool>,
    #[serde(default)]
    pub track_links: Option<bool>,
    #[serde(default)]
    pub embed_images: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct CampaignTemplateUpdateApplyRequest {
    pub campaign_id: u64,
    pub plan_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
    #[serde(default)]
    pub send_multipart: Option<bool>,
    #[serde(default)]
    pub track_opens: Option<bool>,
    #[serde(default)]
    pub track_links: Option<bool>,
    #[serde(default)]
    pub embed_images: Option<bool>,
}

impl CampaignTemplateUpdatePreviewRequest {
    pub fn updates(&self) -> Vec<FormFieldUpdate> {
        template_updates(
            self.name.as_deref(),
            self.subject.as_deref(),
            self.html_body.as_deref(),
            self.text_body.as_deref(),
            self.send_multipart,
            self.track_opens,
            self.track_links,
            self.embed_images,
        )
    }
}

impl CampaignTemplateUpdateApplyRequest {
    pub fn updates(&self) -> Vec<FormFieldUpdate> {
        template_updates(
            self.name.as_deref(),
            self.subject.as_deref(),
            self.html_body.as_deref(),
            self.text_body.as_deref(),
            self.send_multipart,
            self.track_opens,
            self.track_links,
            self.embed_images,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn template_updates(
    name: Option<&str>,
    subject: Option<&str>,
    html_body: Option<&str>,
    text_body: Option<&str>,
    send_multipart: Option<bool>,
    track_opens: Option<bool>,
    track_links: Option<bool>,
    embed_images: Option<bool>,
) -> Vec<FormFieldUpdate> {
    let mut updates = Vec::new();
    push_value(&mut updates, "name", name);
    push_value(&mut updates, "subject", subject);
    push_value(&mut updates, "html_body", html_body);
    push_value(&mut updates, "text_body", text_body);
    push_checked(&mut updates, "sendmultipart", send_multipart);
    push_checked(&mut updates, "trackopens", track_opens);
    push_checked(&mut updates, "tracklinks", track_links);
    push_checked(&mut updates, "embedimages", embed_images);
    updates
}

fn push_value(updates: &mut Vec<FormFieldUpdate>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        updates.push(FormFieldUpdate {
            name: name.to_string(),
            value: Some(value.to_string()),
            checked: None,
        });
    }
}

fn push_checked(updates: &mut Vec<FormFieldUpdate>, name: &str, checked: Option<bool>) {
    if let Some(checked) = checked {
        updates.push(FormFieldUpdate {
            name: name.to_string(),
            value: None,
            checked: Some(checked),
        });
    }
}

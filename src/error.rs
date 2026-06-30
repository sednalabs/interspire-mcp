#[derive(Debug, thiserror::Error)]
pub enum InterspireError {
    #[error("Interspire XML API is not configured")]
    XmlNotConfigured,
    #[error("Interspire admin HTML fallback is not configured")]
    AdminHtmlNotConfigured,
    #[error("Interspire request was blocked by read-only safety policy: {0}")]
    Safety(String),
    #[error("Interspire HTTP request failed: {0}")]
    Http(String),
    #[error("Interspire XML response could not be parsed: {0}")]
    XmlParse(String),
    #[error("Interspire XML authentication failed: {0}")]
    XmlAuth(String),
    #[error("Interspire HTML response could not be parsed: {0}")]
    HtmlParse(String),
    #[error("Interspire local artifact operation failed: {0}")]
    Io(String),
    #[error("Interspire API returned an error: {0}")]
    Api(String),
}

impl InterspireError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::XmlNotConfigured => "xml_not_configured",
            Self::AdminHtmlNotConfigured => "admin_html_not_configured",
            Self::Safety(_) => "safety_policy_blocked",
            Self::Http(_) => "http_error",
            Self::XmlParse(_) => "xml_parse_error",
            Self::XmlAuth(_) => "xml_auth_error",
            Self::HtmlParse(_) => "html_parse_error",
            Self::Io(_) => "io_error",
            Self::Api(_) => "api_error",
        }
    }
}

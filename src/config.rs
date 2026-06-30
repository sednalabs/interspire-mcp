//! Runtime configuration loading for the Interspire read-only MCP.
//!
//! Credentials are supplied by environment variables outside the repository.
//! This module deliberately keeps values opaque and only reports
//! configured/not-configured state to callers.

use std::{env, fmt};

#[derive(Clone, Default)]
pub struct InterspireServerConfig {
    pub version: InterspireVersion,
    pub cloudflare_access: CloudflareAccessConfig,
    pub xml: XmlApiConfig,
    pub admin_html: AdminHtmlConfig,
    pub guarded_writes: GuardedWriteConfig,
    pub sensitive_reads: SensitiveReadConfig,
    pub import_preflight: ImportPreflightConfig,
    pub oci_send_ledger: OciSendLedgerConfig,
}

impl InterspireServerConfig {
    pub fn from_env() -> Self {
        let version = InterspireVersion::from_env();
        let cloudflare_access = CloudflareAccessConfig {
            client_id: env_non_blank("INTERSPIRE_CF_ACCESS_CLIENT_ID"),
            client_secret: env_non_blank("INTERSPIRE_CF_ACCESS_CLIENT_SECRET"),
        };

        let admin_html = AdminHtmlConfig {
            version,
            base_url: env_non_blank("INTERSPIRE_ADMIN_BASE_URL"),
            username: env_non_blank("INTERSPIRE_ADMIN_USERNAME"),
            password: env_non_blank("INTERSPIRE_ADMIN_PASSWORD"),
            cloudflare_access: cloudflare_access.clone(),
            enrich_limit: env::var("INTERSPIRE_HTML_LIST_ENRICH_LIMIT")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
                .unwrap_or(25),
        };

        let xml = XmlApiConfig {
            endpoint: env_non_blank("INTERSPIRE_XML_ENDPOINT"),
            username: env_non_blank("INTERSPIRE_XML_USERNAME"),
            token: env_non_blank("INTERSPIRE_XML_TOKEN"),
            cloudflare_access: cloudflare_access.clone(),
        };

        let guarded_writes = GuardedWriteConfig::from_env();
        let sensitive_reads = SensitiveReadConfig::from_env();
        let import_preflight = ImportPreflightConfig::from_env();
        let oci_send_ledger = OciSendLedgerConfig::from_env();

        Self {
            version,
            cloudflare_access,
            xml,
            admin_html,
            guarded_writes,
            sensitive_reads,
            import_preflight,
            oci_send_ledger,
        }
    }
}

impl fmt::Debug for InterspireServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterspireServerConfig")
            .field("version", &self.version)
            .field("cloudflare_access", &self.cloudflare_access)
            .field("xml", &self.xml)
            .field("admin_html", &self.admin_html)
            .field("guarded_writes", &self.guarded_writes)
            .field("sensitive_reads", &self.sensitive_reads)
            .field("import_preflight", &self.import_preflight)
            .field("oci_send_ledger", &self.oci_send_ledger)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterspireVersion {
    #[default]
    Auto,
    V6_2_3,
    V8,
}

impl InterspireVersion {
    fn from_env() -> Self {
        env::var("INTERSPIRE_VERSION")
            .ok()
            .and_then(|raw| Self::parse(&raw))
            .unwrap_or(Self::Auto)
    }

    fn parse(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "" | "auto" | "detect" => Some(Self::Auto),
            "6" | "6.x" | "6.2" | "6.2.3" | "iem6" | "interspire6" => Some(Self::V6_2_3),
            "8" | "8.x" | "8.0" | "iem8" | "interspire8" => Some(Self::V8),
            value if value.starts_with("8.") => Some(Self::V8),
            value if value.starts_with("6.") => Some(Self::V6_2_3),
            _ => None,
        }
    }
}

#[derive(Clone, Default)]
pub struct CloudflareAccessConfig {
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl fmt::Debug for CloudflareAccessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareAccessConfig")
            .field(
                "client_id_configured",
                &self.client_id.as_deref().is_some_and(not_blank),
            )
            .field(
                "client_secret_configured",
                &self.client_secret.as_deref().is_some_and(not_blank),
            )
            .finish()
    }
}

impl CloudflareAccessConfig {
    #[cfg(test)]
    pub(crate) fn from_values_for_test(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: Some(client_id.to_string()),
            client_secret: Some(client_secret.to_string()),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.client_id.as_deref().is_some_and(not_blank)
            && self.client_secret.as_deref().is_some_and(not_blank)
    }

    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref().filter(|value| not_blank(value))
    }

    pub fn client_secret(&self) -> Option<&str> {
        self.client_secret
            .as_deref()
            .filter(|value| not_blank(value))
    }
}

#[derive(Debug, Clone, Default)]
pub struct GuardedWriteConfig {
    pub enabled: bool,
    pub queue_controls_enabled: bool,
    pub form_write_controls_enabled: bool,
    pub contact_write_controls_enabled: bool,
    pub send_controls_enabled: bool,
    pub production_send_controls_enabled: bool,
    pub execution_mode: WriteExecutionMode,
}

#[derive(Debug, Clone, Default)]
pub struct SensitiveReadConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ImportPreflightConfig {
    pub allowed_roots: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OciSendLedgerConfig {
    pub path: Option<String>,
    pub required_for_sends: bool,
}

impl SensitiveReadConfig {
    fn from_env() -> Self {
        Self {
            enabled: env_truthy("INTERSPIRE_SENSITIVE_READS"),
        }
    }
}

impl ImportPreflightConfig {
    fn from_env() -> Self {
        let Some(raw) = env_non_blank("INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS") else {
            return Self {
                allowed_roots: Vec::new(),
            };
        };
        let allowed_roots = raw
            .split([':', ','])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        Self { allowed_roots }
    }
}

impl OciSendLedgerConfig {
    fn from_env() -> Self {
        Self {
            path: env_non_blank("INTERSPIRE_OCI_SEND_LEDGER_PATH"),
            required_for_sends: env_truthy("INTERSPIRE_REQUIRE_OCI_SEND_LEDGER"),
        }
    }
}

impl GuardedWriteConfig {
    fn from_env() -> Self {
        Self {
            enabled: env_truthy("INTERSPIRE_GUARDED_WRITES"),
            queue_controls_enabled: env_truthy("INTERSPIRE_QUEUE_WRITE_CONTROLS"),
            form_write_controls_enabled: env_truthy("INTERSPIRE_FORM_WRITE_CONTROLS"),
            contact_write_controls_enabled: env_truthy("INTERSPIRE_CONTACT_WRITE_CONTROLS"),
            send_controls_enabled: env_truthy("INTERSPIRE_SEND_CONTROLS"),
            production_send_controls_enabled: env_truthy("INTERSPIRE_PRODUCTION_SEND_CONTROLS"),
            execution_mode: write_execution_mode_from_env(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteExecutionMode {
    #[default]
    PreviewApply,
}

fn write_execution_mode_from_env() -> WriteExecutionMode {
    let _ = env::var("INTERSPIRE_WRITE_EXECUTION_MODE");
    WriteExecutionMode::PreviewApply
}

#[derive(Clone, Default)]
pub struct XmlApiConfig {
    pub endpoint: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
    pub cloudflare_access: CloudflareAccessConfig,
}

impl fmt::Debug for XmlApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XmlApiConfig")
            .field(
                "endpoint_configured",
                &self.endpoint.as_deref().is_some_and(not_blank),
            )
            .field(
                "username_configured",
                &self.username.as_deref().is_some_and(not_blank),
            )
            .field(
                "token_configured",
                &self.token.as_deref().is_some_and(not_blank),
            )
            .field("cloudflare_access", &self.cloudflare_access)
            .finish()
    }
}

impl XmlApiConfig {
    pub fn is_configured(&self) -> bool {
        self.endpoint.as_deref().is_some_and(not_blank)
            && self.username.as_deref().is_some_and(not_blank)
            && self.token.as_deref().is_some_and(not_blank)
    }
}

#[derive(Clone)]
pub struct AdminHtmlConfig {
    pub version: InterspireVersion,
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cloudflare_access: CloudflareAccessConfig,
    pub enrich_limit: usize,
}

impl fmt::Debug for AdminHtmlConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminHtmlConfig")
            .field("version", &self.version)
            .field(
                "base_url_configured",
                &self.base_url.as_deref().is_some_and(not_blank),
            )
            .field(
                "username_configured",
                &self.username.as_deref().is_some_and(not_blank),
            )
            .field(
                "password_configured",
                &self.password.as_deref().is_some_and(not_blank),
            )
            .field("cloudflare_access", &self.cloudflare_access)
            .field("enrich_limit", &self.enrich_limit)
            .finish()
    }
}

impl Default for AdminHtmlConfig {
    fn default() -> Self {
        Self {
            version: InterspireVersion::Auto,
            base_url: None,
            username: None,
            password: None,
            cloudflare_access: CloudflareAccessConfig::default(),
            enrich_limit: 25,
        }
    }
}

impl AdminHtmlConfig {
    pub fn is_configured(&self) -> bool {
        self.base_url.as_deref().is_some_and(not_blank)
            && self.username.as_deref().is_some_and(not_blank)
            && self.password.as_deref().is_some_and(not_blank)
    }
}

fn not_blank(value: &str) -> bool {
    !value.trim().is_empty()
}

fn env_non_blank(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| not_blank(value))
}

fn env_truthy(key: &str) -> bool {
    env::var(key).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "allow" | "enabled"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AdminHtmlConfig, CloudflareAccessConfig, GuardedWriteConfig, ImportPreflightConfig,
        InterspireServerConfig, InterspireVersion, XmlApiConfig,
    };
    use std::{
        env,
        sync::{Mutex, MutexGuard},
    };

    const CONFIG_ENV_KEYS: &[&str] = &[
        "INTERSPIRE_VERSION",
        "INTERSPIRE_CF_ACCESS_CLIENT_ID",
        "INTERSPIRE_CF_ACCESS_CLIENT_SECRET",
        "INTERSPIRE_CF_ACCESS_CREDENTIALS_FILE",
        "INTERSPIRE_ADMIN_BASE_URL",
        "INTERSPIRE_ADMIN_USERNAME",
        "INTERSPIRE_ADMIN_PASSWORD",
        "INTERSPIRE_ADMIN_CREDENTIALS_FILE",
        "INTERSPIRE_HTML_LIST_ENRICH_LIMIT",
        "INTERSPIRE_XML_ENDPOINT",
        "INTERSPIRE_XML_USERNAME",
        "INTERSPIRE_XML_TOKEN",
        "INTERSPIRE_XML_CREDENTIALS_FILE",
        "INTERSPIRE_GUARDED_WRITES",
        "INTERSPIRE_QUEUE_WRITE_CONTROLS",
        "INTERSPIRE_FORM_WRITE_CONTROLS",
        "INTERSPIRE_CONTACT_WRITE_CONTROLS",
        "INTERSPIRE_SEND_CONTROLS",
        "INTERSPIRE_PRODUCTION_SEND_CONTROLS",
        "INTERSPIRE_SENSITIVE_READS",
        "INTERSPIRE_IMPORT_PREFLIGHT_ALLOWED_ROOTS",
        "INTERSPIRE_OCI_SEND_LEDGER_PATH",
        "INTERSPIRE_REQUIRE_OCI_SEND_LEDGER",
    ];

    struct EnvRestore(Vec<(&'static str, Option<String>)>);

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                if let Some(value) = value {
                    env::set_var(key, value);
                } else {
                    env::remove_var(key);
                }
            }
        }
    }

    fn config_env_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().expect("lock config env")
    }

    fn isolate_config_env() -> EnvRestore {
        let saved = CONFIG_ENV_KEYS
            .iter()
            .map(|key| (*key, env::var(key).ok()))
            .collect::<Vec<_>>();
        for key in CONFIG_ENV_KEYS {
            env::remove_var(key);
        }
        EnvRestore(saved)
    }

    #[test]
    fn guarded_write_config_defaults_off() {
        let config = GuardedWriteConfig::default();

        assert!(!config.enabled);
        assert!(!config.queue_controls_enabled);
        assert!(!config.form_write_controls_enabled);
        assert!(!config.contact_write_controls_enabled);
        assert!(!config.send_controls_enabled);
        assert!(!config.production_send_controls_enabled);
        assert_eq!(
            config.execution_mode,
            super::WriteExecutionMode::PreviewApply
        );
    }

    #[test]
    fn import_preflight_defaults_to_disabled_without_explicit_roots() {
        let config = ImportPreflightConfig::default();
        assert!(config.allowed_roots.is_empty());
    }

    #[test]
    fn parses_interspire_version_aliases() {
        assert_eq!(
            InterspireVersion::parse("auto"),
            Some(InterspireVersion::Auto)
        );
        assert_eq!(
            InterspireVersion::parse("6.2.3"),
            Some(InterspireVersion::V6_2_3)
        );
        assert_eq!(
            InterspireVersion::parse("8.7.4"),
            Some(InterspireVersion::V8)
        );
        assert_eq!(InterspireVersion::parse("unknown"), None);
    }

    #[test]
    fn from_env_uses_direct_values_and_ignores_credential_file_vars() {
        let _lock = config_env_lock();
        let _restore = isolate_config_env();

        env::set_var("INTERSPIRE_CF_ACCESS_CREDENTIALS_FILE", "cloudflare.env");
        env::set_var("INTERSPIRE_ADMIN_CREDENTIALS_FILE", "admin.env");
        env::set_var("INTERSPIRE_XML_CREDENTIALS_FILE", "xml.env");
        let file_only = InterspireServerConfig::from_env();
        assert!(!file_only.cloudflare_access.is_configured());
        assert!(!file_only.admin_html.is_configured());
        assert!(!file_only.xml.is_configured());

        env::set_var("INTERSPIRE_VERSION", "8.x");
        env::set_var("INTERSPIRE_CF_ACCESS_CLIENT_ID", "client-id");
        env::set_var("INTERSPIRE_CF_ACCESS_CLIENT_SECRET", "client-secret");
        env::set_var("INTERSPIRE_ADMIN_BASE_URL", "https://example.test/admin/");
        env::set_var("INTERSPIRE_ADMIN_USERNAME", "admin");
        env::set_var("INTERSPIRE_ADMIN_PASSWORD", "admin-secret");
        env::set_var("INTERSPIRE_XML_ENDPOINT", "https://example.test/xml.php");
        env::set_var("INTERSPIRE_XML_USERNAME", "xml-user");
        env::set_var("INTERSPIRE_XML_TOKEN", "xml-token");
        env::set_var("INTERSPIRE_HTML_LIST_ENRICH_LIMIT", "7");

        let direct = InterspireServerConfig::from_env();
        assert_eq!(direct.version, InterspireVersion::V8);
        assert!(direct.cloudflare_access.is_configured());
        assert!(direct.admin_html.is_configured());
        assert!(direct.xml.is_configured());
        assert_eq!(direct.admin_html.enrich_limit, 7);
    }

    #[test]
    fn admin_html_config_uses_direct_values() {
        let config = AdminHtmlConfig {
            base_url: Some("https://example.test/admin".to_string()),
            username: Some("admin".to_string()),
            password: Some("secret".to_string()),
            version: InterspireVersion::Auto,
            cloudflare_access: CloudflareAccessConfig::default(),
            enrich_limit: 25,
        };

        assert!(config.is_configured());
    }

    #[test]
    fn xml_config_uses_direct_values() {
        let config = XmlApiConfig {
            endpoint: Some("https://example.test/xml.php".to_string()),
            username: Some("xml-user".to_string()),
            token: Some("xml-token".to_string()),
            cloudflare_access: CloudflareAccessConfig::default(),
        };

        assert!(config.is_configured());
    }

    #[test]
    fn cloudflare_access_config_uses_direct_values_without_debug_leak() {
        let config = CloudflareAccessConfig::from_values_for_test("client-id", "client-secret");
        assert!(config.is_configured());
        assert_eq!(config.client_id(), Some("client-id"));
        assert_eq!(config.client_secret(), Some("client-secret"));
        assert!(!format!("{config:?}").contains("client-secret"));
    }

    #[test]
    fn config_debug_output_redacts_direct_secret_values() {
        let config = InterspireServerConfig {
            cloudflare_access: CloudflareAccessConfig::from_values_for_test(
                "client-id",
                "client-secret",
            ),
            xml: XmlApiConfig {
                endpoint: Some("https://example.test/xml.php".to_string()),
                username: Some("xml-user".to_string()),
                token: Some("xml-token".to_string()),
                cloudflare_access: CloudflareAccessConfig::default(),
            },
            admin_html: AdminHtmlConfig {
                base_url: Some("https://example.test/admin".to_string()),
                username: Some("direct-admin-user".to_string()),
                password: Some("admin-secret".to_string()),
                version: InterspireVersion::Auto,
                cloudflare_access: CloudflareAccessConfig::default(),
                enrich_limit: 25,
            },
            ..InterspireServerConfig::default()
        };
        let debug = format!("{config:?}");

        for forbidden in [
            "client-secret",
            "xml-token",
            "admin-secret",
            "xml-user",
            "direct-admin-user",
            "https://example.test/xml.php",
            "https://example.test/admin",
        ] {
            assert!(
                !debug.contains(forbidden),
                "debug output leaked {forbidden}"
            );
        }
    }
}

//! Runtime configuration loading for the Interspire read-only MCP.
//!
//! Credentials are supplied by environment variables or secret files outside
//! the repository. This module deliberately keeps values opaque and only
//! reports configured/not-configured state to callers.

use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
};

#[cfg(not(test))]
const SECRET_FILE_ROOT: &str = "/run/secrets/interspire-mcp";

#[derive(Debug, Clone, Default)]
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
        let mut cloudflare_access = CloudflareAccessConfig {
            client_id: env_non_blank("INTERSPIRE_CF_ACCESS_CLIENT_ID"),
            client_secret: env_non_blank("INTERSPIRE_CF_ACCESS_CLIENT_SECRET"),
        };
        if let Ok(path) = env::var("INTERSPIRE_CF_ACCESS_CREDENTIALS_FILE") {
            cloudflare_access.apply_secret_file(Path::new(&path));
        }

        let mut admin_html = AdminHtmlConfig {
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

        if let Ok(path) = env::var("INTERSPIRE_ADMIN_CREDENTIALS_FILE") {
            admin_html.apply_secret_file(Path::new(&path));
        }

        let mut xml = XmlApiConfig {
            endpoint: env_non_blank("INTERSPIRE_XML_ENDPOINT"),
            username: env_non_blank("INTERSPIRE_XML_USERNAME"),
            token: env_non_blank("INTERSPIRE_XML_TOKEN"),
            cloudflare_access: cloudflare_access.clone(),
        };

        if let Ok(path) = env::var("INTERSPIRE_XML_CREDENTIALS_FILE") {
            xml.apply_secret_file(Path::new(&path));
        }

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

    fn apply_secret_file(&mut self, path: &Path) {
        let Some(contents) = read_secret_file(path, SecretFileSlot::CloudflareAccess) else {
            return;
        };

        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            match key.trim() {
                "INTERSPIRE_CF_ACCESS_CLIENT_ID" if option_blank_or_absent(&self.client_id) => {
                    self.client_id = Some(normalize_secret_file_value(value));
                }
                "INTERSPIRE_CF_ACCESS_CLIENT_SECRET"
                    if option_blank_or_absent(&self.client_secret) =>
                {
                    self.client_secret = Some(normalize_secret_file_value(value));
                }
                _ => {}
            }
        }
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

#[derive(Debug, Clone, Default)]
pub struct XmlApiConfig {
    pub endpoint: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
    pub cloudflare_access: CloudflareAccessConfig,
}

impl XmlApiConfig {
    pub fn is_configured(&self) -> bool {
        self.endpoint.as_deref().is_some_and(not_blank)
            && self.username.as_deref().is_some_and(not_blank)
            && self.token.as_deref().is_some_and(not_blank)
    }

    fn apply_secret_file(&mut self, path: &Path) {
        let Some(contents) = read_secret_file(path, SecretFileSlot::XmlApi) else {
            return;
        };

        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            match key.trim() {
                "INTERSPIRE_XML_ENDPOINT" if option_blank_or_absent(&self.endpoint) => {
                    self.endpoint = Some(value.trim().to_string());
                }
                "INTERSPIRE_XML_USERNAME" if option_blank_or_absent(&self.username) => {
                    self.username = Some(value.trim().to_string());
                }
                "INTERSPIRE_XML_TOKEN" if option_blank_or_absent(&self.token) => {
                    self.token = Some(value.trim().to_string());
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdminHtmlConfig {
    pub version: InterspireVersion,
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cloudflare_access: CloudflareAccessConfig,
    pub enrich_limit: usize,
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

    fn apply_secret_file(&mut self, path: &Path) {
        let Some(contents) = read_secret_file(path, SecretFileSlot::AdminHtml) else {
            return;
        };

        let mut positional_values = Vec::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                positional_values.push(trimmed.to_string());
                continue;
            };
            match key.trim() {
                "INTERSPIRE_ADMIN_USERNAME" if option_blank_or_absent(&self.username) => {
                    self.username = Some(value.trim().to_string());
                }
                "INTERSPIRE_ADMIN_PASSWORD" if option_blank_or_absent(&self.password) => {
                    self.password = Some(value.trim().to_string());
                }
                "INTERSPIRE_ADMIN_BASE_URL" if option_blank_or_absent(&self.base_url) => {
                    self.base_url = Some(value.trim().to_string());
                }
                _ => {}
            }
        }

        if option_blank_or_absent(&self.username) && !positional_values.is_empty() {
            self.username = Some(positional_values[0].clone());
        }
        if option_blank_or_absent(&self.password) && positional_values.len() >= 2 {
            self.password = Some(positional_values[1].clone());
        }
    }
}

fn normalize_secret_file_value(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'')
        .to_string()
}

#[derive(Debug, Clone, Copy)]
enum SecretFileSlot {
    CloudflareAccess,
    AdminHtml,
    XmlApi,
}

impl SecretFileSlot {
    fn file_name(self) -> &'static str {
        match self {
            Self::CloudflareAccess => "interspire-cloudflare-access.env",
            Self::AdminHtml => "interspire-admin.env",
            Self::XmlApi => "interspire-xml.env",
        }
    }
}

fn read_secret_file(path: &Path, slot: SecretFileSlot) -> Option<String> {
    let path = validated_secret_file_path(path, slot)?;
    fs::read_to_string(path).ok()
}

fn validated_secret_file_path(path: &Path, slot: SecretFileSlot) -> Option<PathBuf> {
    let file_name = safe_secret_file_name(path)?;
    if file_name != std::ffi::OsStr::new(slot.file_name()) {
        return None;
    }
    let root = secret_file_root().canonicalize().ok()?;
    let candidate = root.join(slot.file_name());
    let metadata = fs::symlink_metadata(&candidate).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let canonical = candidate.canonicalize().ok()?;
    if !canonical.starts_with(&root) {
        return None;
    }

    Some(canonical)
}

fn safe_secret_file_name(path: &Path) -> Option<&std::ffi::OsStr> {
    let mut components = path.components();
    let first = components.next()?;
    if components.next().is_some() {
        return None;
    }
    let file_name = path.file_name()?;
    let value = file_name.to_str()?;
    if value.is_empty() || value == "." || value == ".." {
        return None;
    }
    match first {
        std::path::Component::Normal(_) => Some(file_name),
        _ => None,
    }
}

fn secret_file_root() -> PathBuf {
    #[cfg(test)]
    {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("interspire-config-tests")
            .join("secrets")
    }

    #[cfg(not(test))]
    {
        PathBuf::from(SECRET_FILE_ROOT)
    }
}

fn not_blank(value: &str) -> bool {
    !value.trim().is_empty()
}

fn env_non_blank(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| not_blank(value))
}

fn option_blank_or_absent(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|value| !not_blank(value))
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
        safe_secret_file_name, secret_file_root, validated_secret_file_path, AdminHtmlConfig,
        CloudflareAccessConfig, GuardedWriteConfig, ImportPreflightConfig, InterspireVersion,
        SecretFileSlot, XmlApiConfig,
    };
    use std::{
        fs,
        path::PathBuf,
        sync::{Mutex, MutexGuard},
    };

    fn secret_file_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().expect("lock secret-file fixtures")
    }

    fn write_secret_file(slot: SecretFileSlot, contents: &str) -> PathBuf {
        let root = secret_file_root();
        fs::create_dir_all(&root).expect("create secret-file test root");
        let path = PathBuf::from(slot.file_name());
        fs::write(root.join(&path), contents).expect("write secret-file fixture");
        path
    }

    fn remove_secret_file(path: &PathBuf) {
        fs::remove_file(secret_file_root().join(path)).expect("remove secret-file fixture");
    }

    #[test]
    fn secret_file_path_validation_rejects_paths_traversal_and_missing_files() {
        let _guard = secret_file_lock();
        let root = secret_file_root();
        fs::create_dir_all(&root).expect("create secret-file test root");
        let alternate = root.join("admin-key-value.env");
        fs::write(&alternate, "INTERSPIRE_ADMIN_USERNAME=wrong\n")
            .expect("write alternate secret-file fixture");

        assert!(safe_secret_file_name(PathBuf::from("interspire.env").as_path()).is_some());
        assert!(safe_secret_file_name(PathBuf::from("/tmp/interspire.env").as_path()).is_none());
        assert!(safe_secret_file_name(PathBuf::from("../interspire.env").as_path()).is_none());
        assert!(safe_secret_file_name(PathBuf::from("nested/interspire.env").as_path()).is_none());
        assert!(validated_secret_file_path(
            PathBuf::from("interspire-admin.env").as_path(),
            SecretFileSlot::AdminHtml,
        )
        .is_none());
        assert!(validated_secret_file_path(
            PathBuf::from("interspire-xml.env").as_path(),
            SecretFileSlot::AdminHtml,
        )
        .is_none());
        assert!(validated_secret_file_path(
            PathBuf::from("admin-key-value.env").as_path(),
            SecretFileSlot::AdminHtml,
        )
        .is_none());

        fs::remove_file(&alternate).expect("remove alternate secret-file fixture");
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_path_validation_rejects_symlinks() {
        let _guard = secret_file_lock();
        let root = secret_file_root();
        fs::create_dir_all(&root).expect("create secret-file test root");
        let target = root.join("secret-file-target.env");
        fs::write(&target, "INTERSPIRE_ADMIN_USERNAME=admin\n").expect("write symlink target");
        let configured_path = PathBuf::from(SecretFileSlot::AdminHtml.file_name());
        let link_path = root.join(&configured_path);
        let _ = fs::remove_file(&link_path);
        std::os::unix::fs::symlink(&target, &link_path).expect("create symlink");

        assert!(validated_secret_file_path(&configured_path, SecretFileSlot::AdminHtml).is_none());

        fs::remove_file(&link_path).expect("remove symlink");
        fs::remove_file(&target).expect("remove symlink target");
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
    fn applies_key_value_secret_file() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::AdminHtml,
            "INTERSPIRE_ADMIN_USERNAME=admin\nINTERSPIRE_ADMIN_PASSWORD=secret\nINTERSPIRE_ADMIN_BASE_URL=https://example.test/admin\n",
        );
        let mut config = AdminHtmlConfig::default();
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(config.username.as_deref(), Some("admin"));
        assert_eq!(config.password.as_deref(), Some("secret"));
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://example.test/admin")
        );
    }

    #[test]
    fn applies_two_line_secret_file() {
        let _guard = secret_file_lock();
        let path = write_secret_file(SecretFileSlot::AdminHtml, "admin\nsuper-secret-password\n");
        let mut config = AdminHtmlConfig::default();
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(config.username.as_deref(), Some("admin"));
        assert_eq!(config.password.as_deref(), Some("super-secret-password"));
        assert_eq!(config.base_url, None);
    }

    #[test]
    fn two_line_secret_file_preserves_env_username_and_fills_missing_password() {
        let _guard = secret_file_lock();
        let path = write_secret_file(SecretFileSlot::AdminHtml, "file-admin\nfile-password\n");
        let mut config = AdminHtmlConfig {
            username: Some("env-admin".to_string()),
            ..AdminHtmlConfig::default()
        };
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(config.username.as_deref(), Some("env-admin"));
        assert_eq!(config.password.as_deref(), Some("file-password"));
    }

    #[test]
    fn two_line_secret_file_preserves_env_password_and_fills_missing_username() {
        let _guard = secret_file_lock();
        let path = write_secret_file(SecretFileSlot::AdminHtml, "file-admin\nfile-password\n");
        let mut config = AdminHtmlConfig {
            password: Some("env-password".to_string()),
            ..AdminHtmlConfig::default()
        };
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(config.username.as_deref(), Some("file-admin"));
        assert_eq!(config.password.as_deref(), Some("env-password"));
    }

    #[test]
    fn admin_secret_file_fills_blank_existing_values() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::AdminHtml,
            "INTERSPIRE_ADMIN_USERNAME=file-admin\nINTERSPIRE_ADMIN_PASSWORD=file-password\nINTERSPIRE_ADMIN_BASE_URL=https://file.example.test/admin\n",
        );
        let mut config = AdminHtmlConfig {
            base_url: Some("  ".to_string()),
            username: Some("\n\t".to_string()),
            password: Some("env-password".to_string()),
            version: InterspireVersion::Auto,
            cloudflare_access: CloudflareAccessConfig::default(),
            enrich_limit: 25,
        };
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(
            config.base_url.as_deref(),
            Some("https://file.example.test/admin")
        );
        assert_eq!(config.username.as_deref(), Some("file-admin"));
        assert_eq!(config.password.as_deref(), Some("env-password"));
    }

    #[test]
    fn applies_xml_key_value_secret_file() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::XmlApi,
            "INTERSPIRE_XML_ENDPOINT=https://example.test/xml.php\nINTERSPIRE_XML_USERNAME=xml-user\nINTERSPIRE_XML_TOKEN=xml-token\n",
        );
        let mut config = XmlApiConfig::default();
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://example.test/xml.php")
        );
        assert_eq!(config.username.as_deref(), Some("xml-user"));
        assert_eq!(config.token.as_deref(), Some("xml-token"));
    }

    #[test]
    fn xml_secret_file_preserves_explicit_env_values() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::XmlApi,
            "INTERSPIRE_XML_ENDPOINT=https://file.example.test/xml.php\nINTERSPIRE_XML_USERNAME=file-user\nINTERSPIRE_XML_TOKEN=file-token\n",
        );
        let mut config = XmlApiConfig {
            endpoint: Some("https://env.example.test/xml.php".to_string()),
            username: None,
            token: Some("env-token".to_string()),
            cloudflare_access: CloudflareAccessConfig::default(),
        };
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://env.example.test/xml.php")
        );
        assert_eq!(config.username.as_deref(), Some("file-user"));
        assert_eq!(config.token.as_deref(), Some("env-token"));
    }

    #[test]
    fn xml_secret_file_fills_blank_existing_values() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::XmlApi,
            "INTERSPIRE_XML_ENDPOINT=https://file.example.test/xml.php\nINTERSPIRE_XML_USERNAME=file-user\nINTERSPIRE_XML_TOKEN=file-token\n",
        );
        let mut config = XmlApiConfig {
            endpoint: Some("   ".to_string()),
            username: Some("\n\t".to_string()),
            token: Some("env-token".to_string()),
            cloudflare_access: CloudflareAccessConfig::default(),
        };
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://file.example.test/xml.php")
        );
        assert_eq!(config.username.as_deref(), Some("file-user"));
        assert_eq!(config.token.as_deref(), Some("env-token"));
    }

    #[test]
    fn cloudflare_access_secret_file_configures_headers_without_exposing_values() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::CloudflareAccess,
            "INTERSPIRE_CF_ACCESS_CLIENT_ID=\"client-id\"\nINTERSPIRE_CF_ACCESS_CLIENT_SECRET='client-secret'\n",
        );
        let mut config = CloudflareAccessConfig::default();
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert!(config.is_configured());
        assert_eq!(config.client_id(), Some("client-id"));
        assert_eq!(config.client_secret(), Some("client-secret"));
        assert!(!format!("{config:?}").contains("client-secret"));
    }

    #[test]
    fn cloudflare_access_secret_file_preserves_explicit_values() {
        let _guard = secret_file_lock();
        let path = write_secret_file(
            SecretFileSlot::CloudflareAccess,
            "INTERSPIRE_CF_ACCESS_CLIENT_ID=file-id\nINTERSPIRE_CF_ACCESS_CLIENT_SECRET=file-secret\n",
        );
        let mut config = CloudflareAccessConfig {
            client_id: Some("env-id".to_string()),
            client_secret: Some(" ".to_string()),
        };
        config.apply_secret_file(&path);
        remove_secret_file(&path);

        assert_eq!(config.client_id(), Some("env-id"));
        assert_eq!(config.client_secret(), Some("file-secret"));
    }
}

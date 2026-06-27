//! Runtime configuration loading for the Interspire read-only MCP.
//!
//! Credentials are supplied by environment variables or secret files outside
//! the repository. This module deliberately keeps values opaque and only
//! reports configured/not-configured state to callers.

use std::{env, fs, path::Path};

#[derive(Debug, Clone, Default)]
pub struct InterspireServerConfig {
    pub xml: XmlApiConfig,
    pub admin_html: AdminHtmlConfig,
    pub guarded_writes: GuardedWriteConfig,
}

impl InterspireServerConfig {
    pub fn from_env() -> Self {
        let mut admin_html = AdminHtmlConfig {
            base_url: env_non_blank("INTERSPIRE_ADMIN_BASE_URL"),
            username: env_non_blank("INTERSPIRE_ADMIN_USERNAME"),
            password: env_non_blank("INTERSPIRE_ADMIN_PASSWORD"),
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
        };

        if let Ok(path) = env::var("INTERSPIRE_XML_CREDENTIALS_FILE") {
            xml.apply_secret_file(Path::new(&path));
        }

        let guarded_writes = GuardedWriteConfig::from_env();

        Self {
            xml,
            admin_html,
            guarded_writes,
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
}

impl XmlApiConfig {
    pub fn is_configured(&self) -> bool {
        self.endpoint.as_deref().is_some_and(not_blank)
            && self.username.as_deref().is_some_and(not_blank)
            && self.token.as_deref().is_some_and(not_blank)
    }

    fn apply_secret_file(&mut self, path: &Path) {
        let Ok(contents) = fs::read_to_string(path) else {
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
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enrich_limit: usize,
}

impl Default for AdminHtmlConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            username: None,
            password: None,
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
        let Ok(contents) = fs::read_to_string(path) else {
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
    use super::{AdminHtmlConfig, GuardedWriteConfig, XmlApiConfig};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn write_temp_file(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("interspire-config-test-{unique}.txt"));
        fs::write(&path, contents).expect("write temp config");
        path
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
    fn applies_key_value_secret_file() {
        let path = write_temp_file(
            "INTERSPIRE_ADMIN_USERNAME=admin\nINTERSPIRE_ADMIN_PASSWORD=secret\nINTERSPIRE_ADMIN_BASE_URL=https://example.test/admin\n",
        );
        let mut config = AdminHtmlConfig::default();
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(config.username.as_deref(), Some("admin"));
        assert_eq!(config.password.as_deref(), Some("secret"));
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://example.test/admin")
        );
    }

    #[test]
    fn applies_two_line_secret_file() {
        let path = write_temp_file("admin\nsuper-secret-password\n");
        let mut config = AdminHtmlConfig::default();
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(config.username.as_deref(), Some("admin"));
        assert_eq!(config.password.as_deref(), Some("super-secret-password"));
        assert_eq!(config.base_url, None);
    }

    #[test]
    fn two_line_secret_file_preserves_env_username_and_fills_missing_password() {
        let path = write_temp_file("file-admin\nfile-password\n");
        let mut config = AdminHtmlConfig {
            username: Some("env-admin".to_string()),
            ..AdminHtmlConfig::default()
        };
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(config.username.as_deref(), Some("env-admin"));
        assert_eq!(config.password.as_deref(), Some("file-password"));
    }

    #[test]
    fn two_line_secret_file_preserves_env_password_and_fills_missing_username() {
        let path = write_temp_file("file-admin\nfile-password\n");
        let mut config = AdminHtmlConfig {
            password: Some("env-password".to_string()),
            ..AdminHtmlConfig::default()
        };
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(config.username.as_deref(), Some("file-admin"));
        assert_eq!(config.password.as_deref(), Some("env-password"));
    }

    #[test]
    fn admin_secret_file_fills_blank_existing_values() {
        let path = write_temp_file(
            "INTERSPIRE_ADMIN_USERNAME=file-admin\nINTERSPIRE_ADMIN_PASSWORD=file-password\nINTERSPIRE_ADMIN_BASE_URL=https://file.example.test/admin\n",
        );
        let mut config = AdminHtmlConfig {
            base_url: Some("  ".to_string()),
            username: Some("\n\t".to_string()),
            password: Some("env-password".to_string()),
            enrich_limit: 25,
        };
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(
            config.base_url.as_deref(),
            Some("https://file.example.test/admin")
        );
        assert_eq!(config.username.as_deref(), Some("file-admin"));
        assert_eq!(config.password.as_deref(), Some("env-password"));
    }

    #[test]
    fn applies_xml_key_value_secret_file() {
        let path = write_temp_file(
            "INTERSPIRE_XML_ENDPOINT=https://example.test/xml.php\nINTERSPIRE_XML_USERNAME=xml-user\nINTERSPIRE_XML_TOKEN=xml-token\n",
        );
        let mut config = XmlApiConfig::default();
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://example.test/xml.php")
        );
        assert_eq!(config.username.as_deref(), Some("xml-user"));
        assert_eq!(config.token.as_deref(), Some("xml-token"));
    }

    #[test]
    fn xml_secret_file_preserves_explicit_env_values() {
        let path = write_temp_file(
            "INTERSPIRE_XML_ENDPOINT=https://file.example.test/xml.php\nINTERSPIRE_XML_USERNAME=file-user\nINTERSPIRE_XML_TOKEN=file-token\n",
        );
        let mut config = XmlApiConfig {
            endpoint: Some("https://env.example.test/xml.php".to_string()),
            username: None,
            token: Some("env-token".to_string()),
        };
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://env.example.test/xml.php")
        );
        assert_eq!(config.username.as_deref(), Some("file-user"));
        assert_eq!(config.token.as_deref(), Some("env-token"));
    }

    #[test]
    fn xml_secret_file_fills_blank_existing_values() {
        let path = write_temp_file(
            "INTERSPIRE_XML_ENDPOINT=https://file.example.test/xml.php\nINTERSPIRE_XML_USERNAME=file-user\nINTERSPIRE_XML_TOKEN=file-token\n",
        );
        let mut config = XmlApiConfig {
            endpoint: Some("   ".to_string()),
            username: Some("\n\t".to_string()),
            token: Some("env-token".to_string()),
        };
        config.apply_secret_file(&path);
        fs::remove_file(&path).expect("remove temp config");

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://file.example.test/xml.php")
        );
        assert_eq!(config.username.as_deref(), Some("file-user"));
        assert_eq!(config.token.as_deref(), Some("env-token"));
    }
}

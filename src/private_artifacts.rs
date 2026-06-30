use crate::error::InterspireError;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const RENDER_OUTPUT_DIR: &str = "/tmp/interspire-mcp-render-artifacts";
const MAX_TEMPLATE_ARTIFACT_BYTES: u64 = 2_000_000;

#[derive(Debug, Clone)]
pub(crate) struct PrivateTextArtifact {
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
    pub contents: String,
}

pub(crate) fn prepare_private_render_output_dir(
    raw_output_dir: Option<&str>,
) -> Result<PathBuf, InterspireError> {
    if raw_output_dir.is_some_and(|value| !value.trim().is_empty()) {
        return Err(InterspireError::Safety(
            "render artifact output_dir request values are disabled in the public build"
                .to_string(),
        ));
    }

    let path = PathBuf::from(RENDER_OUTPUT_DIR);
    fs::create_dir_all(&path).map_err(|err| {
        InterspireError::Io(format!(
            "failed to create private render artifact directory: {err}"
        ))
    })?;
    ensure_fixed_render_dir(&path)?;
    set_private_dir_permissions(&path)?;
    ensure_fixed_render_dir(&path)?;
    Ok(path)
}

pub(crate) fn create_private_file(path: &Path, label: &str) -> Result<fs::File, InterspireError> {
    ensure_direct_render_artifact_child(path, label)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| {
            InterspireError::Io(format!(
                "failed to create private {} artifact: {err}",
                label
            ))
        })
}

pub(crate) fn set_private_file_permissions(path: &Path) -> Result<(), InterspireError> {
    ensure_direct_render_artifact_child(path, "render")?;
    let mut perms = fs::symlink_metadata(path)
        .map_err(|err| InterspireError::Io(format!("failed to stat private artifact: {err}")))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .map_err(|err| InterspireError::Io(format!("failed to set artifact permissions: {err}")))
}

pub(crate) fn fixed_render_prefix(raw: Option<&str>) -> Result<&'static str, InterspireError> {
    if raw.is_some_and(|value| !value.trim().is_empty()) {
        return Err(InterspireError::Safety(
            "render artifact artifact_prefix request values are disabled in the public build"
                .to_string(),
        ));
    }
    Ok("interspire-campaign-render")
}

pub(crate) fn read_private_render_text_artifact(
    raw_path: &str,
    label: &str,
    expected_sha256: Option<&str>,
    expected_bytes: Option<u64>,
) -> Result<PrivateTextArtifact, InterspireError> {
    let path = PathBuf::from(raw_path.trim());
    ensure_direct_render_artifact_child(&path, label)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|err| InterspireError::Io(format!("failed to stat private {label}: {err}")))?;
    if metadata.file_type().is_symlink() {
        return Err(InterspireError::Safety(format!(
            "private {label} must not be a symlink"
        )));
    }
    if !metadata.is_file() {
        return Err(InterspireError::Safety(format!(
            "private {label} must be a regular file"
        )));
    }
    let bytes_len = metadata.len();
    if bytes_len == 0 || bytes_len > MAX_TEMPLATE_ARTIFACT_BYTES {
        return Err(InterspireError::Safety(format!(
            "private {label} size must be between 1 and {MAX_TEMPLATE_ARTIFACT_BYTES} bytes"
        )));
    }
    if let Some(expected) = expected_bytes {
        if expected != bytes_len {
            return Err(InterspireError::Safety(format!(
                "private {label} byte count did not match expected value"
            )));
        }
    }

    let bytes = fs::read(&path)
        .map_err(|err| InterspireError::Io(format!("failed to read private {label}: {err}")))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if let Some(expected) = expected_sha256 {
        let expected = expected.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(InterspireError::Safety(format!(
                "private {label} expected SHA-256 must be a 64-character hex digest"
            )));
        }
        if expected != sha256 {
            return Err(InterspireError::Safety(format!(
                "private {label} SHA-256 did not match expected value"
            )));
        }
    }

    let contents = String::from_utf8(bytes).map_err(|_| {
        InterspireError::Safety(format!("private {label} must be valid UTF-8 text"))
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();

    Ok(PrivateTextArtifact {
        file_name,
        bytes: bytes_len,
        sha256,
        contents,
    })
}

pub(crate) fn unix_timestamp_nanos() -> Result<u128, InterspireError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|err| InterspireError::Io(format!("system time before unix epoch: {err}")))
}

fn set_private_dir_permissions(path: &Path) -> Result<(), InterspireError> {
    let mut perms = fs::symlink_metadata(path)
        .map_err(|err| InterspireError::Io(format!("failed to stat private directory: {err}")))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
        .map_err(|err| InterspireError::Io(format!("failed to set directory permissions: {err}")))
}

fn ensure_fixed_render_dir(path: &Path) -> Result<(), InterspireError> {
    if path != Path::new(RENDER_OUTPUT_DIR) {
        return Err(InterspireError::Safety(
            "render artifact output_dir must be the fixed private render directory".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        InterspireError::Io(format!(
            "failed to stat private render artifact directory: {err}"
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(InterspireError::Safety(
            "render artifact output_dir must not be a symlink".to_string(),
        ));
    }
    if !metadata.is_dir() {
        return Err(InterspireError::Safety(
            "render artifact output_dir must be a directory".to_string(),
        ));
    }
    Ok(())
}

fn ensure_direct_render_artifact_child(path: &Path, label: &str) -> Result<(), InterspireError> {
    if path.parent() != Some(Path::new(RENDER_OUTPUT_DIR)) {
        return Err(InterspireError::Safety(format!(
            "{} artifact path must be a direct child of the fixed private render directory",
            label
        )));
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(InterspireError::Safety(format!(
            "{} artifact filename is invalid",
            label
        )));
    };
    if file_name.is_empty()
        || file_name.len() > 160
        || file_name.contains("..")
        || !file_name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(InterspireError::Safety(format!(
            "{} artifact filename is outside the generated filename policy",
            label
        )));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(InterspireError::Safety(format!(
            "{} artifact path must not contain dot path components",
            label
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    fn test_artifact_path(name: &str) -> PathBuf {
        let dir = prepare_private_render_output_dir(None).unwrap_or_else(|err| panic!("{err}"));
        dir.join(format!(
            "interspire-campaign-render-test-{}-{name}.html",
            process::id()
        ))
    }

    #[test]
    fn reads_fixed_private_render_text_artifact_with_expected_digest() {
        let path = test_artifact_path("read-ok");
        let contents = "<html><body>Example Update</body></html>";
        fs::write(&path, contents).unwrap_or_else(|err| panic!("{err}"));
        let expected_sha = hex::encode(Sha256::digest(contents.as_bytes()));

        let artifact = read_private_render_text_artifact(
            path.to_str().unwrap_or_default(),
            "HTML template artifact",
            Some(&expected_sha),
            Some(contents.len() as u64),
        )
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(artifact.contents, contents);
        assert_eq!(artifact.sha256, expected_sha);
        assert_eq!(artifact.bytes, contents.len() as u64);
        assert!(artifact
            .file_name
            .contains("interspire-campaign-render-test"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_private_render_artifact_digest_mismatch() {
        let path = test_artifact_path("bad-digest");
        fs::write(&path, "template").unwrap_or_else(|err| panic!("{err}"));

        let err = read_private_render_text_artifact(
            path.to_str().unwrap_or_default(),
            "HTML template artifact",
            Some(&"0".repeat(64)),
            None,
        )
        .err()
        .unwrap_or_else(|| panic!("digest mismatch should fail"));

        assert!(err.to_string().contains("SHA-256 did not match"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_private_render_artifact_path_traversal() {
        let err = read_private_render_text_artifact(
            "/tmp/interspire-mcp-render-artifacts/../escape.html",
            "HTML template artifact",
            None,
            None,
        )
        .err()
        .unwrap_or_else(|| panic!("path traversal should fail"));

        assert!(err.to_string().contains("direct child"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_private_render_artifact_symlink() {
        let path = test_artifact_path("symlink");
        let target = test_artifact_path("symlink-target");
        fs::write(&target, "target").unwrap_or_else(|err| panic!("{err}"));
        let _ = fs::remove_file(&path);
        std::os::unix::fs::symlink(&target, &path).unwrap_or_else(|err| panic!("{err}"));

        let err = read_private_render_text_artifact(
            path.to_str().unwrap_or_default(),
            "HTML template artifact",
            None,
            None,
        )
        .err()
        .unwrap_or_else(|| panic!("symlink should fail"));

        assert!(err.to_string().contains("must not be a symlink"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(target);
    }
}

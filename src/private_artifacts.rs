use crate::error::InterspireError;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const RENDER_OUTPUT_DIR: &str = "/tmp/interspire-mcp-render-artifacts";

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

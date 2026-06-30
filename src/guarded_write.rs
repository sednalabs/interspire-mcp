//! Guarded write primitives for narrowly approved Interspire admin actions.
//!
//! Interspire uses admin HTML routes for some operational workflows. This
//! module keeps mutation controls explicit: preview is
//! read-only, apply requires a deterministic plan id plus runtime write
//! enablement, and every consumer must re-read state after applying.
//!
//! ## Security Boundaries
//!
//! * Writes are disabled by default.
//! * Queue controls require both global guarded writes and queue controls.
//! * Seed sends require both global guarded writes and send controls.
//! * Production sends require global guarded writes, send controls, and
//!   production-send controls.
//! * Plan ids are bound to a current Interspire admin row and action route.
//! * This module does not expose schedule, generic send, contact, suppression,
//!   import, provider, DNS, or credential mutation helpers.

use crate::{config::GuardedWriteConfig, error::InterspireError};
use sha2::{Digest, Sha256};

const PLAN_ID_VERSION: &str = "interspire-guarded-write-v1";

pub fn stable_plan_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_ID_VERSION.as_bytes());
    for part in parts {
        hasher.update([0]);
        hasher.update(part.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!("iqc_{}", &digest[..24])
}

pub fn require_queue_controls_enabled(config: &GuardedWriteConfig) -> Result<(), InterspireError> {
    if !config.enabled {
        return Err(InterspireError::Safety(
            "guarded writes are disabled; set INTERSPIRE_GUARDED_WRITES=1 to allow apply tools"
                .to_string(),
        ));
    }
    if !config.queue_controls_enabled {
        return Err(InterspireError::Safety(
            "queue write controls are disabled; set INTERSPIRE_QUEUE_WRITE_CONTROLS=1 to allow queue apply tools"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn require_form_write_controls_enabled(
    config: &GuardedWriteConfig,
) -> Result<(), InterspireError> {
    if !config.enabled {
        return Err(InterspireError::Safety(
            "guarded writes are disabled; set INTERSPIRE_GUARDED_WRITES=1 to allow apply tools"
                .to_string(),
        ));
    }
    if !config.form_write_controls_enabled {
        return Err(InterspireError::Safety(
            "form write controls are disabled; set INTERSPIRE_FORM_WRITE_CONTROLS=1 to allow form apply tools"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn require_send_controls_enabled(config: &GuardedWriteConfig) -> Result<(), InterspireError> {
    if !config.enabled {
        return Err(InterspireError::Safety(
            "guarded writes are disabled; set INTERSPIRE_GUARDED_WRITES=1 to allow apply tools"
                .to_string(),
        ));
    }
    if !config.send_controls_enabled {
        return Err(InterspireError::Safety(
            "send controls are disabled; set INTERSPIRE_SEND_CONTROLS=1 to allow seed send apply tools"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn require_production_send_controls_enabled(
    config: &GuardedWriteConfig,
) -> Result<(), InterspireError> {
    require_send_controls_enabled(config)?;
    if !config.production_send_controls_enabled {
        return Err(InterspireError::Safety(
            "production send controls are disabled; set INTERSPIRE_PRODUCTION_SEND_CONTROLS=1 to allow production send apply tools"
                .to_string(),
        ));
    }
    Ok(())
}

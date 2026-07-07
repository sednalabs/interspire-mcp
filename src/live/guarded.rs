use super::support::cap_usize;
use super::LiveInterspireBackend;
use crate::{
    error::InterspireError,
    guarded_write,
    response::{
        CampaignActiveStateApplyRequest, CampaignActiveStatePreviewRequest,
        CampaignUpdateApplyRequest, CampaignUpdatePreviewRequest, Evidence,
        GuardedWriteApplyReport, GuardedWritePreviewReport, ListUpdateApplyRequest,
        ListUpdatePreviewRequest, QueueControlApplyReport, QueueControlApplyRequest,
        QueueControlApplyStatus, QueueControlPreviewReport, QueueControlPreviewRequest,
        SettingsUpdateApplyRequest, SettingsUpdatePreviewRequest, UserUpdateApplyRequest,
        UserUpdatePreviewRequest,
    },
};

impl LiveInterspireBackend {
    pub(super) fn queue_control_preview_impl(
        &self,
        request: &QueueControlPreviewRequest,
    ) -> Result<QueueControlPreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(QueueControlPreviewReport {
                ok: true,
                configured: false,
                guarded_writes_enabled: self.config.guarded_writes.enabled,
                queue_controls_enabled: self.config.guarded_writes.queue_controls_enabled,
                candidates: Vec::new(),
                production_send_authorized: false,
                warnings: vec![
                    "admin HTML fallback is not configured; no queue-control preview attempted"
                        .to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }

        let candidates =
            html.queue_control_candidates(cap_usize(request.max_rows.unwrap_or(25), 100))?;
        Ok(QueueControlPreviewReport {
            ok: true,
            configured: true,
            guarded_writes_enabled: self.config.guarded_writes.enabled,
            queue_controls_enabled: self.config.guarded_writes.queue_controls_enabled,
            candidates,
            production_send_authorized: false,
            warnings: vec![
                "preview only; apply requires INTERSPIRE_GUARDED_WRITES=1 and INTERSPIRE_QUEUE_WRITE_CONTROLS=1".to_string(),
                "queue controls can cancel/delete/pause/resume scheduled rows only; they do not send, schedule, import, export, or mutate contacts".to_string(),
            ],
            evidence: Evidence {
                source: "interspire_admin_html".to_string(),
                notes: vec!["allowlisted Schedule GET read for queue-control preview".to_string()],
            },
        })
    }

    pub(super) fn queue_control_apply_impl(
        &self,
        request: &QueueControlApplyRequest,
    ) -> Result<QueueControlApplyReport, InterspireError> {
        guarded_write::require_queue_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(QueueControlApplyReport {
                ok: true,
                configured: false,
                guarded_writes_enabled: self.config.guarded_writes.enabled,
                queue_controls_enabled: self.config.guarded_writes.queue_controls_enabled,
                status: QueueControlApplyStatus::Blocked,
                applied: false,
                plan_id: Some(request.plan_id.clone()),
                action: request.action,
                before_candidate_count: 0,
                before_row_summary: None,
                after_candidate_count: 0,
                after_row_still_present: false,
                after_matching_action_still_available: false,
                after_target_actions: Vec::new(),
                legacy_lists_mutated: false,
                production_send_authorized: false,
                warnings: vec![
                    "admin HTML fallback is not configured; no queue-control apply attempted"
                        .to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }

        let evidence = html.apply_queue_control(&request.plan_id, request.action, 100)?;
        Ok(QueueControlApplyReport {
            ok: true,
            configured: true,
            guarded_writes_enabled: self.config.guarded_writes.enabled,
            queue_controls_enabled: self.config.guarded_writes.queue_controls_enabled,
            status: QueueControlApplyStatus::AppliedProven,
            applied: true,
            plan_id: Some(request.plan_id.clone()),
            action: request.action,
            before_candidate_count: evidence.before_candidate_count,
            before_row_summary: evidence.before_row_summary,
            after_candidate_count: evidence.after_candidate_count,
            after_row_still_present: evidence.after_row_still_present,
            after_matching_action_still_available: evidence.after_matching_action_still_available,
            after_target_actions: evidence.after_target_actions,
            legacy_lists_mutated: false,
            production_send_authorized: false,
            warnings: vec![
                "Applied a guarded queue-control route only; verify campaign state before any other operational decision".to_string(),
                "This apply did not authorize sending and did not mutate lists, contacts, suppressions, providers, DNS, or SMTP settings".to_string(),
            ],
            evidence: Evidence {
                source: "interspire_admin_html".to_string(),
                notes: evidence.notes,
            },
        })
    }

    pub(super) fn campaign_update_preview_impl(
        &self,
        request: &CampaignUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(unconfigured_preview(
                &self.config.guarded_writes,
                "campaign",
                Some(request.campaign_id),
                None,
                "admin HTML fallback is not configured; no campaign update preview attempted",
            ));
        }

        let mut report = html.campaign_update_preview(request.campaign_id, &request.updates)?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        report.write_execution_mode = self.config.guarded_writes.execution_mode;
        report.apply_directly_allowed = false;
        Ok(report)
    }

    pub(super) fn campaign_update_apply_impl(
        &self,
        request: &CampaignUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        let mut report = html.campaign_update_apply(
            request.campaign_id,
            &request.plan_id,
            &request.updates,
            self.config.guarded_writes.execution_mode,
        )?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        Ok(report)
    }

    pub(super) fn campaign_active_state_preview_impl(
        &self,
        request: &CampaignActiveStatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(unconfigured_preview(
                &self.config.guarded_writes,
                "campaign_active_state",
                Some(request.campaign_id),
                None,
                "admin HTML fallback is not configured; no campaign active-state preview attempted",
            ));
        }

        let mut report = html.campaign_active_state_preview(request.campaign_id, request.active)?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        report.write_execution_mode = self.config.guarded_writes.execution_mode;
        report.apply_directly_allowed = false;
        Ok(report)
    }

    pub(super) fn campaign_active_state_apply_impl(
        &self,
        request: &CampaignActiveStateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        let mut report = html.campaign_active_state_apply(
            request.campaign_id,
            request.active,
            &request.plan_id,
            self.config.guarded_writes.execution_mode,
        )?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        Ok(report)
    }

    pub(super) fn list_update_preview_impl(
        &self,
        request: &ListUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(unconfigured_preview(
                &self.config.guarded_writes,
                "list",
                Some(request.list_id),
                None,
                "admin HTML fallback is not configured; no list update preview attempted",
            ));
        }

        let mut report = html.list_update_preview(request.list_id, &request.updates)?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        report.write_execution_mode = self.config.guarded_writes.execution_mode;
        report.apply_directly_allowed = false;
        Ok(report)
    }

    pub(super) fn list_update_apply_impl(
        &self,
        request: &ListUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        let mut report = html.list_update_apply(
            request.list_id,
            &request.plan_id,
            &request.updates,
            self.config.guarded_writes.execution_mode,
        )?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        Ok(report)
    }

    pub(super) fn user_update_preview_impl(
        &self,
        request: &UserUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(unconfigured_preview(
                &self.config.guarded_writes,
                "user",
                Some(request.user_id),
                None,
                "admin HTML fallback is not configured; no user update preview attempted",
            ));
        }

        let mut report = html.user_update_preview(request.user_id, &request.updates)?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        report.write_execution_mode = self.config.guarded_writes.execution_mode;
        report.apply_directly_allowed = false;
        Ok(report)
    }

    pub(super) fn user_update_apply_impl(
        &self,
        request: &UserUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        let mut report = html.user_update_apply(
            request.user_id,
            &request.plan_id,
            &request.updates,
            self.config.guarded_writes.execution_mode,
        )?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        Ok(report)
    }

    pub(super) fn settings_update_preview_impl(
        &self,
        request: &SettingsUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(unconfigured_preview(
                &self.config.guarded_writes,
                "settings",
                None,
                Some(request.section.as_str().to_string()),
                "admin HTML fallback is not configured; no settings update preview attempted",
            ));
        }

        let mut report = html.settings_update_preview(request.section, &request.updates)?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        report.write_execution_mode = self.config.guarded_writes.execution_mode;
        report.apply_directly_allowed = false;
        Ok(report)
    }

    pub(super) fn settings_update_apply_impl(
        &self,
        request: &SettingsUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        guarded_write::require_form_write_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        let mut report = html.settings_update_apply(
            request.section,
            &request.plan_id,
            &request.updates,
            self.config.guarded_writes.execution_mode,
        )?;
        report.guarded_writes_enabled = self.config.guarded_writes.enabled;
        report.form_write_controls_enabled = self.config.guarded_writes.form_write_controls_enabled;
        Ok(report)
    }
}

fn unconfigured_preview(
    guarded_writes: &crate::config::GuardedWriteConfig,
    target: &str,
    target_id: Option<u64>,
    section: Option<String>,
    warning: &str,
) -> GuardedWritePreviewReport {
    GuardedWritePreviewReport {
        ok: true,
        configured: false,
        guarded_writes_enabled: guarded_writes.enabled,
        form_write_controls_enabled: guarded_writes.form_write_controls_enabled,
        write_execution_mode: guarded_writes.execution_mode,
        target: target.to_string(),
        target_id,
        section,
        plan_id: String::new(),
        apply_directly_allowed: false,
        available_fields: Vec::new(),
        changes: Vec::new(),
        warnings: vec![warning.to_string()],
        evidence: Evidence {
            source: "interspire_admin_html".to_string(),
            notes: vec!["no request sent".to_string()],
        },
    }
}

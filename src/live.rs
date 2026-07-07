//! Live Interspire backend implementation for MCP tool handlers.
//!
//! The backend composes XML API reads with explicitly allowlisted admin HTML
//! readback. It returns compact, redacted reports and marks unconfigured
//! sources as skipped instead of inventing evidence.

mod audience;
mod checkpoint;
mod guarded;
mod reads;
mod scaffold;
mod send;
mod support;

use crate::{
    admin_html::AdminHtmlClient,
    config::InterspireServerConfig,
    error::InterspireError,
    response::{
        AdminSessionProbeReport, AdminSessionProbeRequest, AudienceHygieneExportBeginRequest,
        AudienceHygieneExportReport, AudienceHygieneExportRequest,
        AudienceHygieneExportResumeRequest, AudienceHygieneExportStatusRequest,
        CampaignActiveStateApplyRequest, CampaignActiveStatePreviewRequest,
        CampaignBodyAuditReport, CampaignBodyAuditRequest, CampaignCopyApplyReport,
        CampaignCopyApplyRequest, CampaignCopyPreviewReport, CampaignCopyPreviewRequest,
        CampaignReadbackReport, CampaignReadbackRequest, CampaignRenderArtifactReport,
        CampaignRenderArtifactRequest, CampaignTestSendApplyReport, CampaignTestSendApplyRequest,
        CampaignTestSendPreviewReport, CampaignTestSendPreviewRequest, CampaignUpdateApplyRequest,
        CampaignUpdatePreviewRequest, ContactImportPreflightReport, ContactImportPreflightRequest,
        ContactStateReport, ContactStateRequest, CronReadinessReport, CronReadinessRequest,
        GuardedWriteApplyReport, GuardedWritePreviewReport, ListCreateApplyRequest,
        ListCreatePreviewRequest, ListOwnerReadbackReport, ListOwnerReadbackRequest,
        ListSummaryReport, ListSummaryRequest, ListUpdateApplyRequest, ListUpdatePreviewRequest,
        OciSendLedgerPrepareApplyRequest, OciSendLedgerPreparePreviewRequest,
        OciSendLedgerPrepareReport, ProductionSendApplyReport, ProductionSendApplyRequest,
        QueueControlApplyReport, QueueControlApplyRequest, QueueControlPreviewReport,
        QueueControlPreviewRequest, QueueStatsReadbackReport, QueueStatsReadbackRequest,
        SeedReadinessGateReport, SeedReadinessGateRequest, SeedSendApplyReport,
        SeedSendApplyRequest, SendJobStatusReadbackReport, SendJobStatusReadbackRequest,
        SendStopGateReadinessReport, SendStopGateReadinessRequest, SendWizardReadbackReport,
        SendWizardReadbackRequest, SensitiveFieldQueryReport, SensitiveFieldQueryRequest,
        SettingsAuditReport, SettingsAuditRequest, SettingsInventoryReport,
        SettingsInventoryRequest, SettingsUpdateApplyRequest, SettingsUpdatePreviewRequest,
        StatusReport, StatusRequest, UserSmtpReadbackReport, UserSmtpReadbackRequest,
        UserUpdateApplyRequest, UserUpdatePreviewRequest, WarmupAudienceReadinessReport,
        WarmupAudienceReadinessRequest, XmlAuthProbeReport, XmlAuthProbeRequest,
    },
    xml_api::XmlApiClient,
    InterspireReadBackend,
};
use std::{
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Debug, Clone)]
pub struct LiveInterspireBackend {
    config: InterspireServerConfig,
    admin_html: Arc<Mutex<Option<AdminHtmlClient>>>,
    xml_api: Arc<Mutex<Option<Arc<XmlApiClient>>>>,
}

struct AdminHtmlSessionGuard<'a> {
    guard: MutexGuard<'a, Option<AdminHtmlClient>>,
}

impl Deref for AdminHtmlSessionGuard<'_> {
    type Target = AdminHtmlClient;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .expect("admin HTML session guard always contains a client")
    }
}

impl LiveInterspireBackend {
    pub fn new(config: InterspireServerConfig) -> Self {
        Self {
            config,
            admin_html: Arc::new(Mutex::new(None)),
            xml_api: Arc::new(Mutex::new(None)),
        }
    }

    fn xml_client(&self) -> Result<Arc<XmlApiClient>, InterspireError> {
        // XML reads do not carry an Interspire admin cookie jar, so callers
        // get a cloned Arc and release this lock before any network request.
        // Keeping one process-local client avoids repeated blocking-runtime
        // construction while still allowing long XML calls to run without
        // blocking unrelated admin-session reads.
        let mut guard = self
            .xml_api
            .lock()
            .map_err(|_| InterspireError::Http("XML API client lock was poisoned".to_string()))?;
        if guard.is_none() {
            *guard = Some(Arc::new(XmlApiClient::new(self.config.xml.clone())?));
        }
        Ok(guard
            .as_ref()
            .expect("XML API client was initialized above")
            .clone())
    }

    fn html_client(&self) -> Result<AdminHtmlSessionGuard<'_>, InterspireError> {
        // Interspire's admin UI is session-oriented and repeated rapid logins
        // can invalidate adjacent proof calls. Lazily create one serialized
        // admin client per live backend so MCP startup/tool-listing does not
        // touch the admin boundary, while actual admin tools reuse the same
        // cookie jar and accidental parallel calls wait behind the same
        // session.
        let mut guard = self.admin_html.lock().map_err(|_| {
            InterspireError::Http("admin HTML client session lock was poisoned".to_string())
        })?;
        if guard.is_none() {
            *guard = Some(AdminHtmlClient::new(self.config.admin_html.clone())?);
        }
        Ok(AdminHtmlSessionGuard { guard })
    }
}

impl InterspireReadBackend for LiveInterspireBackend {
    fn status(&self, request: &StatusRequest) -> Result<StatusReport, InterspireError> {
        self.status_impl(request)
    }

    fn xml_auth_probe(
        &self,
        _request: &XmlAuthProbeRequest,
    ) -> Result<XmlAuthProbeReport, InterspireError> {
        Ok(self.xml_client()?.auth_probe())
    }

    fn list_summary(
        &self,
        request: &ListSummaryRequest,
    ) -> Result<ListSummaryReport, InterspireError> {
        self.list_summary_impl(request)
    }

    fn contact_state(
        &self,
        request: &ContactStateRequest,
    ) -> Result<ContactStateReport, InterspireError> {
        self.contact_state_impl(request)
    }

    fn list_owner_readback(
        &self,
        request: &ListOwnerReadbackRequest,
    ) -> Result<ListOwnerReadbackReport, InterspireError> {
        self.list_owner_readback_impl(request)
    }

    fn settings_audit(
        &self,
        request: &SettingsAuditRequest,
    ) -> Result<SettingsAuditReport, InterspireError> {
        self.settings_audit_impl(request)
    }

    fn settings_inventory(
        &self,
        request: &SettingsInventoryRequest,
    ) -> Result<SettingsInventoryReport, InterspireError> {
        self.settings_inventory_impl(request)
    }

    fn admin_session_probe(
        &self,
        request: &AdminSessionProbeRequest,
    ) -> Result<AdminSessionProbeReport, InterspireError> {
        let html = self.html_client()?;
        html.admin_session_probe(request.include_send_start)
    }

    fn user_smtp_readback(
        &self,
        request: &UserSmtpReadbackRequest,
    ) -> Result<UserSmtpReadbackReport, InterspireError> {
        self.user_smtp_readback_impl(request)
    }

    fn queue_stats_readback(
        &self,
        request: &QueueStatsReadbackRequest,
    ) -> Result<QueueStatsReadbackReport, InterspireError> {
        self.queue_stats_readback_impl(request)
    }

    fn queue_control_preview(
        &self,
        request: &QueueControlPreviewRequest,
    ) -> Result<QueueControlPreviewReport, InterspireError> {
        self.queue_control_preview_impl(request)
    }

    fn queue_control_apply(
        &self,
        request: &QueueControlApplyRequest,
    ) -> Result<QueueControlApplyReport, InterspireError> {
        self.queue_control_apply_impl(request)
    }

    fn send_job_status_readback(
        &self,
        request: &SendJobStatusReadbackRequest,
    ) -> Result<SendJobStatusReadbackReport, InterspireError> {
        self.send_job_status_readback_impl(request)
    }

    fn cron_readiness(
        &self,
        request: &CronReadinessRequest,
    ) -> Result<CronReadinessReport, InterspireError> {
        self.cron_readiness_impl(request)
    }

    fn send_stop_gate_readiness(
        &self,
        request: &SendStopGateReadinessRequest,
    ) -> Result<SendStopGateReadinessReport, InterspireError> {
        self.send_stop_gate_readiness_impl(request)
    }

    fn campaign_readback(
        &self,
        request: &CampaignReadbackRequest,
    ) -> Result<CampaignReadbackReport, InterspireError> {
        self.campaign_readback_impl(request)
    }

    fn campaign_body_audit(
        &self,
        request: &CampaignBodyAuditRequest,
    ) -> Result<CampaignBodyAuditReport, InterspireError> {
        let html = self.html_client()?;
        html.campaign_body_audit(request.campaign_id)
    }

    fn campaign_render_artifact(
        &self,
        request: &CampaignRenderArtifactRequest,
    ) -> Result<CampaignRenderArtifactReport, InterspireError> {
        let html = self.html_client()?;
        html.campaign_render_artifact(request)
    }

    fn campaign_test_send_preview(
        &self,
        request: &CampaignTestSendPreviewRequest,
    ) -> Result<CampaignTestSendPreviewReport, InterspireError> {
        let html = self.html_client()?;
        html.campaign_test_send_preview(request)
    }

    fn campaign_test_send_apply(
        &self,
        request: &CampaignTestSendApplyRequest,
    ) -> Result<CampaignTestSendApplyReport, InterspireError> {
        self.campaign_test_send_apply_impl(request)
    }

    fn oci_send_ledger_prepare_preview(
        &self,
        request: &OciSendLedgerPreparePreviewRequest,
    ) -> Result<OciSendLedgerPrepareReport, InterspireError> {
        self.oci_send_ledger_prepare_preview_impl(request)
    }

    fn oci_send_ledger_prepare_apply(
        &self,
        request: &OciSendLedgerPrepareApplyRequest,
    ) -> Result<OciSendLedgerPrepareReport, InterspireError> {
        self.oci_send_ledger_prepare_apply_impl(request)
    }

    fn send_wizard_readback(
        &self,
        request: &SendWizardReadbackRequest,
    ) -> Result<SendWizardReadbackReport, InterspireError> {
        let html = self.html_client()?;
        html.send_wizard_readback(request)
    }

    fn seed_readiness_gate(
        &self,
        request: &SeedReadinessGateRequest,
    ) -> Result<SeedReadinessGateReport, InterspireError> {
        let html = self.html_client()?;
        html.seed_readiness_gate(request)
    }

    fn seed_send_apply(
        &self,
        request: &SeedSendApplyRequest,
    ) -> Result<SeedSendApplyReport, InterspireError> {
        self.seed_send_apply_impl(request)
    }

    fn production_send_apply(
        &self,
        request: &ProductionSendApplyRequest,
    ) -> Result<ProductionSendApplyReport, InterspireError> {
        self.production_send_apply_impl(request)
    }

    fn campaign_update_preview(
        &self,
        request: &CampaignUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        self.campaign_update_preview_impl(request)
    }

    fn campaign_update_apply(
        &self,
        request: &CampaignUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        self.campaign_update_apply_impl(request)
    }

    fn campaign_active_state_preview(
        &self,
        request: &CampaignActiveStatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        self.campaign_active_state_preview_impl(request)
    }

    fn campaign_active_state_apply(
        &self,
        request: &CampaignActiveStateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        self.campaign_active_state_apply_impl(request)
    }

    fn list_update_preview(
        &self,
        request: &ListUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        self.list_update_preview_impl(request)
    }

    fn list_update_apply(
        &self,
        request: &ListUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        self.list_update_apply_impl(request)
    }

    fn list_create_preview(
        &self,
        request: &ListCreatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        self.list_create_preview_impl(request)
    }

    fn list_create_apply(
        &self,
        request: &ListCreateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        self.list_create_apply_impl(request)
    }

    fn campaign_copy_preview(
        &self,
        request: &CampaignCopyPreviewRequest,
    ) -> Result<CampaignCopyPreviewReport, InterspireError> {
        self.campaign_copy_preview_impl(request)
    }

    fn campaign_copy_apply(
        &self,
        request: &CampaignCopyApplyRequest,
    ) -> Result<CampaignCopyApplyReport, InterspireError> {
        self.campaign_copy_apply_impl(request)
    }

    fn contact_import_preflight(
        &self,
        request: &ContactImportPreflightRequest,
    ) -> Result<ContactImportPreflightReport, InterspireError> {
        self.contact_import_preflight_impl(request)
    }

    fn user_update_preview(
        &self,
        request: &UserUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        self.user_update_preview_impl(request)
    }

    fn user_update_apply(
        &self,
        request: &UserUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        self.user_update_apply_impl(request)
    }

    fn settings_update_preview(
        &self,
        request: &SettingsUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        self.settings_update_preview_impl(request)
    }

    fn settings_update_apply(
        &self,
        request: &SettingsUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        self.settings_update_apply_impl(request)
    }

    fn sensitive_field_query(
        &self,
        request: &SensitiveFieldQueryRequest,
    ) -> Result<SensitiveFieldQueryReport, InterspireError> {
        let html = self.html_client()?;
        html.sensitive_field_query(request, self.config.sensitive_reads.enabled)
    }

    fn warmup_audience_readiness(
        &self,
        request: &WarmupAudienceReadinessRequest,
    ) -> Result<WarmupAudienceReadinessReport, InterspireError> {
        self.warmup_audience_readiness_impl(request)
    }

    fn audience_hygiene_export(
        &self,
        request: &AudienceHygieneExportRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        self.audience_hygiene_export_impl(request)
    }

    fn audience_hygiene_export_begin(
        &self,
        request: &AudienceHygieneExportBeginRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        self.audience_hygiene_export_begin_impl(request)
    }

    fn audience_hygiene_export_resume(
        &self,
        request: &AudienceHygieneExportResumeRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        self.audience_hygiene_export_resume_impl(request)
    }

    fn audience_hygiene_export_status(
        &self,
        request: &AudienceHygieneExportStatusRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        self.audience_hygiene_export_status_impl(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_backend_clones_share_serialized_admin_client() {
        let backend = LiveInterspireBackend::new(InterspireServerConfig::default());
        let cloned = backend.clone();

        assert!(Arc::ptr_eq(&backend.admin_html, &cloned.admin_html));
        assert!(backend.admin_html.lock().unwrap().is_none());
        assert!(backend.xml_api.lock().unwrap().is_none());

        let guard = backend.html_client().expect("admin client lock");
        assert!(backend.admin_html.try_lock().is_err());
        assert!(cloned.admin_html.try_lock().is_err());
        drop(guard);

        assert!(cloned.html_client().is_ok());

        let first_xml = backend.xml_client().expect("XML client");
        let second_xml = cloned.xml_client().expect("shared XML client");
        assert!(Arc::ptr_eq(&first_xml, &second_xml));
    }
}

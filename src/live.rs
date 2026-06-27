//! Live Interspire backend implementation for MCP tool handlers.
//!
//! The backend composes XML API reads with explicitly allowlisted admin HTML
//! readback. It returns compact, redacted reports and marks unconfigured
//! sources as skipped instead of inventing evidence.

mod audience;
mod checkpoint;
mod guarded;
mod reads;
mod support;

use crate::{
    admin_html::AdminHtmlClient,
    config::InterspireServerConfig,
    error::InterspireError,
    response::{
        AudienceHygieneExportBeginRequest, AudienceHygieneExportReport,
        AudienceHygieneExportRequest, AudienceHygieneExportResumeRequest,
        AudienceHygieneExportStatusRequest, CampaignReadbackReport, CampaignReadbackRequest,
        CampaignUpdateApplyRequest, CampaignUpdatePreviewRequest, ContactStateReport,
        ContactStateRequest, GuardedWriteApplyReport, GuardedWritePreviewReport,
        ListOwnerReadbackReport, ListOwnerReadbackRequest, ListSummaryReport, ListSummaryRequest,
        ListUpdateApplyRequest, ListUpdatePreviewRequest, QueueControlApplyReport,
        QueueControlApplyRequest, QueueControlPreviewReport, QueueControlPreviewRequest,
        QueueStatsReadbackReport, QueueStatsReadbackRequest, SettingsAuditReport,
        SettingsAuditRequest, SettingsUpdateApplyRequest, SettingsUpdatePreviewRequest,
        StatusReport, StatusRequest, UserSmtpReadbackReport, UserSmtpReadbackRequest,
        UserUpdateApplyRequest, UserUpdatePreviewRequest, WarmupAudienceReadinessReport,
        WarmupAudienceReadinessRequest,
    },
    xml_api::XmlApiClient,
    InterspireReadBackend,
};

#[derive(Debug, Clone)]
pub struct LiveInterspireBackend {
    config: InterspireServerConfig,
}

impl LiveInterspireBackend {
    pub fn new(config: InterspireServerConfig) -> Self {
        Self { config }
    }

    fn xml_client(&self) -> Result<XmlApiClient, InterspireError> {
        XmlApiClient::new(self.config.xml.clone())
    }

    fn html_client(&self) -> Result<AdminHtmlClient, InterspireError> {
        AdminHtmlClient::new(self.config.admin_html.clone())
    }
}

impl InterspireReadBackend for LiveInterspireBackend {
    fn status(&self, request: &StatusRequest) -> Result<StatusReport, InterspireError> {
        self.status_impl(request)
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

    fn campaign_readback(
        &self,
        request: &CampaignReadbackRequest,
    ) -> Result<CampaignReadbackReport, InterspireError> {
        self.campaign_readback_impl(request)
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

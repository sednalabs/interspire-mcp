use interspire_mcp::{
    AdminSessionProbeReport, AdminSessionProbeRequest, AudienceHygieneExportBeginRequest,
    AudienceHygieneExportReport, AudienceHygieneExportRequest, AudienceHygieneExportResumeRequest,
    AudienceHygieneExportStatusRequest, CampaignBodyAuditReport, CampaignBodyAuditRequest,
    CampaignCopyApplyReport, CampaignCopyApplyRequest, CampaignCopyPreviewReport,
    CampaignCopyPreviewRequest, CampaignReadbackReport, CampaignReadbackRequest,
    CampaignRenderArtifactReport, CampaignRenderArtifactRequest, CampaignTestSendApplyReport,
    CampaignTestSendApplyRequest, CampaignTestSendPreviewReport, CampaignTestSendPreviewRequest,
    CampaignUpdateApplyRequest, CampaignUpdatePreviewRequest, ContactImportPreflightReport,
    ContactImportPreflightRequest, ContactStateReport, ContactStateRequest,
    GuardedWriteApplyReport, GuardedWritePreviewReport, InterspireError, InterspireMcpServer,
    InterspireReadBackend, ListCreateApplyRequest, ListCreatePreviewRequest,
    ListOwnerReadbackReport, ListOwnerReadbackRequest, ListSummaryReport, ListSummaryRequest,
    ListUpdateApplyRequest, ListUpdatePreviewRequest, OciSendLedgerPrepareApplyRequest,
    OciSendLedgerPreparePreviewRequest, OciSendLedgerPrepareReport, ProductionSendApplyReport,
    ProductionSendApplyRequest, QueueControlApplyReport, QueueControlApplyRequest,
    QueueControlPreviewReport, QueueControlPreviewRequest, QueueStatsReadbackReport,
    QueueStatsReadbackRequest, SeedReadinessGateReport, SeedReadinessGateRequest,
    SeedSendApplyReport, SeedSendApplyRequest, SendWizardReadbackReport, SendWizardReadbackRequest,
    SensitiveFieldQueryReport, SensitiveFieldQueryRequest, SettingsAuditReport,
    SettingsAuditRequest, SettingsInventoryReport, SettingsInventoryRequest,
    SettingsUpdateApplyRequest, SettingsUpdatePreviewRequest, StatusReport, StatusRequest,
    UserSmtpReadbackReport, UserSmtpReadbackRequest, UserUpdateApplyRequest,
    UserUpdatePreviewRequest, WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest,
    XmlAuthProbeReport, XmlAuthProbeRequest,
};
use mcp_toolkit_testing::assert_tool_schema_snapshot;
use std::{path::PathBuf, sync::Arc};

#[derive(Debug)]
struct FixtureBackend;

impl InterspireReadBackend for FixtureBackend {
    fn status(&self, _request: &StatusRequest) -> Result<StatusReport, InterspireError> {
        Ok(StatusReport::fixture())
    }

    fn xml_auth_probe(
        &self,
        _request: &XmlAuthProbeRequest,
    ) -> Result<XmlAuthProbeReport, InterspireError> {
        Ok(XmlAuthProbeReport::fixture())
    }

    fn list_summary(
        &self,
        _request: &ListSummaryRequest,
    ) -> Result<ListSummaryReport, InterspireError> {
        Ok(ListSummaryReport::fixture())
    }

    fn contact_state(
        &self,
        request: &ContactStateRequest,
    ) -> Result<ContactStateReport, InterspireError> {
        Ok(ContactStateReport::fixture(&request.email, request.list_id))
    }

    fn list_owner_readback(
        &self,
        _request: &ListOwnerReadbackRequest,
    ) -> Result<ListOwnerReadbackReport, InterspireError> {
        Ok(ListOwnerReadbackReport::fixture())
    }

    fn settings_audit(
        &self,
        _request: &SettingsAuditRequest,
    ) -> Result<SettingsAuditReport, InterspireError> {
        Ok(SettingsAuditReport::fixture())
    }

    fn settings_inventory(
        &self,
        _request: &SettingsInventoryRequest,
    ) -> Result<SettingsInventoryReport, InterspireError> {
        Ok(SettingsInventoryReport::fixture())
    }

    fn admin_session_probe(
        &self,
        _request: &AdminSessionProbeRequest,
    ) -> Result<AdminSessionProbeReport, InterspireError> {
        Ok(AdminSessionProbeReport::fixture())
    }

    fn user_smtp_readback(
        &self,
        _request: &UserSmtpReadbackRequest,
    ) -> Result<UserSmtpReadbackReport, InterspireError> {
        Ok(UserSmtpReadbackReport::fixture())
    }

    fn queue_stats_readback(
        &self,
        _request: &QueueStatsReadbackRequest,
    ) -> Result<QueueStatsReadbackReport, InterspireError> {
        Ok(QueueStatsReadbackReport::fixture())
    }

    fn queue_control_preview(
        &self,
        _request: &QueueControlPreviewRequest,
    ) -> Result<QueueControlPreviewReport, InterspireError> {
        Ok(QueueControlPreviewReport::fixture())
    }

    fn queue_control_apply(
        &self,
        _request: &QueueControlApplyRequest,
    ) -> Result<QueueControlApplyReport, InterspireError> {
        Ok(QueueControlApplyReport::fixture())
    }

    fn campaign_readback(
        &self,
        _request: &CampaignReadbackRequest,
    ) -> Result<CampaignReadbackReport, InterspireError> {
        Ok(CampaignReadbackReport::fixture())
    }

    fn campaign_body_audit(
        &self,
        _request: &CampaignBodyAuditRequest,
    ) -> Result<CampaignBodyAuditReport, InterspireError> {
        Ok(CampaignBodyAuditReport::fixture())
    }

    fn campaign_render_artifact(
        &self,
        _request: &CampaignRenderArtifactRequest,
    ) -> Result<CampaignRenderArtifactReport, InterspireError> {
        Ok(CampaignRenderArtifactReport::fixture())
    }

    fn campaign_test_send_preview(
        &self,
        _request: &CampaignTestSendPreviewRequest,
    ) -> Result<CampaignTestSendPreviewReport, InterspireError> {
        Ok(CampaignTestSendPreviewReport::fixture())
    }

    fn campaign_test_send_apply(
        &self,
        _request: &CampaignTestSendApplyRequest,
    ) -> Result<CampaignTestSendApplyReport, InterspireError> {
        Ok(CampaignTestSendApplyReport::fixture())
    }

    fn oci_send_ledger_prepare_preview(
        &self,
        _request: &OciSendLedgerPreparePreviewRequest,
    ) -> Result<OciSendLedgerPrepareReport, InterspireError> {
        Ok(OciSendLedgerPrepareReport::fixture())
    }

    fn oci_send_ledger_prepare_apply(
        &self,
        _request: &OciSendLedgerPrepareApplyRequest,
    ) -> Result<OciSendLedgerPrepareReport, InterspireError> {
        Ok(OciSendLedgerPrepareReport::fixture())
    }

    fn send_wizard_readback(
        &self,
        _request: &SendWizardReadbackRequest,
    ) -> Result<SendWizardReadbackReport, InterspireError> {
        Ok(SendWizardReadbackReport::fixture())
    }

    fn seed_readiness_gate(
        &self,
        _request: &SeedReadinessGateRequest,
    ) -> Result<SeedReadinessGateReport, InterspireError> {
        Ok(SeedReadinessGateReport::fixture())
    }

    fn seed_send_apply(
        &self,
        _request: &SeedSendApplyRequest,
    ) -> Result<SeedSendApplyReport, InterspireError> {
        Ok(SeedSendApplyReport::fixture())
    }

    fn production_send_apply(
        &self,
        _request: &ProductionSendApplyRequest,
    ) -> Result<ProductionSendApplyReport, InterspireError> {
        Ok(ProductionSendApplyReport::fixture())
    }

    fn campaign_update_preview(
        &self,
        request: &CampaignUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        Ok(GuardedWritePreviewReport::fixture(
            "campaign",
            Some(request.campaign_id),
            None,
        ))
    }

    fn campaign_update_apply(
        &self,
        request: &CampaignUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        Ok(GuardedWriteApplyReport::fixture(
            "campaign",
            Some(request.campaign_id),
            None,
        ))
    }

    fn list_update_preview(
        &self,
        request: &ListUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        Ok(GuardedWritePreviewReport::fixture(
            "list",
            Some(request.list_id),
            None,
        ))
    }

    fn list_update_apply(
        &self,
        request: &ListUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        Ok(GuardedWriteApplyReport::fixture(
            "list",
            Some(request.list_id),
            None,
        ))
    }

    fn list_create_preview(
        &self,
        _request: &ListCreatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        Ok(GuardedWritePreviewReport::fixture(
            "list_create",
            None,
            None,
        ))
    }

    fn list_create_apply(
        &self,
        _request: &ListCreateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        Ok(GuardedWriteApplyReport::fixture(
            "list_create",
            Some(8),
            None,
        ))
    }

    fn campaign_copy_preview(
        &self,
        _request: &CampaignCopyPreviewRequest,
    ) -> Result<CampaignCopyPreviewReport, InterspireError> {
        Ok(CampaignCopyPreviewReport::fixture())
    }

    fn campaign_copy_apply(
        &self,
        _request: &CampaignCopyApplyRequest,
    ) -> Result<CampaignCopyApplyReport, InterspireError> {
        Ok(CampaignCopyApplyReport::fixture())
    }

    fn contact_import_preflight(
        &self,
        _request: &ContactImportPreflightRequest,
    ) -> Result<ContactImportPreflightReport, InterspireError> {
        Ok(ContactImportPreflightReport::fixture())
    }

    fn user_update_preview(
        &self,
        request: &UserUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        Ok(GuardedWritePreviewReport::fixture(
            "user",
            Some(request.user_id),
            None,
        ))
    }

    fn user_update_apply(
        &self,
        request: &UserUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        Ok(GuardedWriteApplyReport::fixture(
            "user",
            Some(request.user_id),
            None,
        ))
    }

    fn settings_update_preview(
        &self,
        request: &SettingsUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError> {
        Ok(GuardedWritePreviewReport::fixture(
            "settings",
            None,
            Some(request.section.as_str()),
        ))
    }

    fn settings_update_apply(
        &self,
        request: &SettingsUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError> {
        Ok(GuardedWriteApplyReport::fixture(
            "settings",
            None,
            Some(request.section.as_str()),
        ))
    }

    fn sensitive_field_query(
        &self,
        _request: &SensitiveFieldQueryRequest,
    ) -> Result<SensitiveFieldQueryReport, InterspireError> {
        Ok(SensitiveFieldQueryReport::fixture())
    }

    fn warmup_audience_readiness(
        &self,
        _request: &WarmupAudienceReadinessRequest,
    ) -> Result<WarmupAudienceReadinessReport, InterspireError> {
        Ok(WarmupAudienceReadinessReport::fixture())
    }

    fn audience_hygiene_export(
        &self,
        _request: &AudienceHygieneExportRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        Ok(AudienceHygieneExportReport::fixture())
    }

    fn audience_hygiene_export_begin(
        &self,
        _request: &AudienceHygieneExportBeginRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        Ok(AudienceHygieneExportReport::fixture())
    }

    fn audience_hygiene_export_resume(
        &self,
        _request: &AudienceHygieneExportResumeRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        Ok(AudienceHygieneExportReport::fixture())
    }

    fn audience_hygiene_export_status(
        &self,
        _request: &AudienceHygieneExportStatusRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        Ok(AudienceHygieneExportReport::fixture())
    }
}

#[test]
fn tool_schema_snapshot_contract_is_stable() {
    let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend))
        .unwrap_or_else(|err| panic!("server should build: {err}"));
    let snapshot_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/tool_schema_snapshot.v1.json");
    assert_tool_schema_snapshot(snapshot_path, &server.tool_schema_snapshot());
}

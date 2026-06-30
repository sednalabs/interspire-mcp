use interspire_mcp::{
    AdminSessionProbeReport, AdminSessionProbeRequest, AudienceHygieneExportBeginRequest,
    AudienceHygieneExportReport, AudienceHygieneExportRequest, AudienceHygieneExportResumeRequest,
    AudienceHygieneExportStatusRequest, CampaignBodyAuditReport, CampaignBodyAuditRequest,
    CampaignCopyApplyReport, CampaignCopyApplyRequest, CampaignCopyPreviewReport,
    CampaignCopyPreviewRequest, CampaignReadbackReport, CampaignReadbackRequest,
    CampaignRenderArtifactReport, CampaignRenderArtifactRequest, CampaignUpdateApplyRequest,
    CampaignUpdatePreviewRequest, ContactImportPreflightReport, ContactImportPreflightRequest,
    ContactStateReport, ContactStateRequest, Evidence, GuardedWriteApplyReport,
    GuardedWritePreviewReport, InterspireError, InterspireMcpServer, InterspireReadBackend,
    ListCreateApplyRequest, ListCreatePreviewRequest, ListOwnerReadbackReport,
    ListOwnerReadbackRequest, ListSummary, ListSummaryReport, ListSummaryRequest,
    ListUpdateApplyRequest, ListUpdatePreviewRequest, ProductionSendApplyReport,
    ProductionSendApplyRequest, QueueControlApplyReport, QueueControlApplyRequest,
    QueueControlPreviewReport, QueueControlPreviewRequest, QueueStatsReadbackReport,
    QueueStatsReadbackRequest, SeedReadinessGateReport, SeedReadinessGateRequest,
    SeedSendApplyReport, SeedSendApplyRequest, SendApplyStatus, SendWizardReadbackReport,
    SendWizardReadbackRequest, SensitiveFieldQueryReport, SensitiveFieldQueryRequest,
    SettingsAuditReport, SettingsAuditRequest, SettingsUpdateApplyRequest,
    SettingsUpdatePreviewRequest, StatusReport, StatusRequest, UserSmtpReadbackReport,
    UserSmtpReadbackRequest, UserUpdateApplyRequest, UserUpdatePreviewRequest,
    WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest, XmlAuthProbeReport,
    XmlAuthProbeRequest, DEFAULT_LIST_READ_LIMIT, HARD_LIST_READ_LIMIT,
};
use mcp_toolkit_testing::response_safety_contract::{
    assert_json_bool_field_false, assert_payload_excludes_substrings,
};
use std::sync::Arc;

#[derive(Debug)]
struct ContractBackend;

impl InterspireReadBackend for ContractBackend {
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
        request: &ListSummaryRequest,
    ) -> Result<ListSummaryReport, InterspireError> {
        Ok(contract_list_summary(request))
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

fn contract_list_summary(request: &ListSummaryRequest) -> ListSummaryReport {
    let mut lists = contract_lists();
    let original_count = lists.len();
    let max_lists = request.max_lists.clamp(1, HARD_LIST_READ_LIMIT);
    let mut warnings = Vec::new();
    let mut notes = vec!["lists/GetLists XML API read".to_string()];

    if original_count > max_lists {
        lists.truncate(max_lists);
        warnings.push(format!(
            "XML list readback returned {original_count} lists; list summary applied max_lists cap {max_lists}"
        ));
        notes.push(format!(
            "list summary XML results truncated from {original_count} lists to applied cap {max_lists}"
        ));
    }

    ListSummaryReport {
        ok: true,
        configured: true,
        lists,
        warnings,
        evidence: Evidence {
            source: "interspire_xml_api".to_string(),
            notes,
        },
    }
}

fn contract_lists() -> Vec<ListSummary> {
    let mut lists = ListSummaryReport::fixture().lists;
    lists.extend((8..=112).map(synthetic_list));
    lists
}

fn synthetic_list(list_id: u64) -> ListSummary {
    ListSummary {
        list_id,
        name: format!("List {list_id}"),
        subscribed_count: Some(list_id * 10),
        unsubscribed_count: Some(list_id),
        autoresponder_count: Some(0),
        owner_name: Some("[redacted-name]".to_string()),
        owner_email_redacted: Some(format!("l***{}@example.com", list_id)),
        reply_to_email_redacted: None,
        bounce_email_redacted: None,
        source: "fixture+xml+html".to_string(),
    }
}

#[test]
fn status_contract_is_redacted_and_read_only() {
    let report = ContractBackend
        .status(&StatusRequest {
            include_html_probe: false,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    assert!(report.ok);
    assert!(report.safe_mode);
    assert!(report
        .blocked_operations
        .contains(&"generic_send_without_guarded_send_tool".to_string()));
    assert!(report
        .blocked_operations
        .contains(&"production_send_without_guarded_production_tool".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_contact_state".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_xml_auth_probe".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_warmup_audience_readiness".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_audience_hygiene_export".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_audience_hygiene_export_begin".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_audience_hygiene_export_resume".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_audience_hygiene_export_status".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_queue_control_preview".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_queue_control_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_sensitive_field_query".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_admin_session_probe".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_body_audit".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_render_artifact".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_send_wizard_readback".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_seed_readiness_gate".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_seed_send_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_production_send_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_template_update_preview".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_template_update_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_template_artifact_update_preview".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_template_artifact_update_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_list_create_preview".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_list_create_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_copy_preview".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_campaign_copy_apply".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_contact_import_preflight".to_string()));
    assert!(!report.guarded_writes_enabled);
    assert!(!report.import_preflight_configured);
    assert!(!report.queue_controls_enabled);
}

#[test]
fn xml_auth_probe_contract_does_not_expose_credentials() {
    let report = ContractBackend
        .xml_auth_probe(&XmlAuthProbeRequest::default())
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(report.authenticated);
    assert!(!body.contains("token"));
    assert!(!body.contains("password"));
}

#[test]
fn list_summary_contract_keeps_owner_email_redacted() {
    let report = ContractBackend
        .list_summary(&ListSummaryRequest {
            include_html_enrichment: true,
            max_lists: DEFAULT_LIST_READ_LIMIT,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let first = report
        .lists
        .first()
        .unwrap_or_else(|| panic!("fixture should include a list"));
    assert_eq!(first.owner_name.as_deref(), Some("[redacted-name]"));
    assert_eq!(
        first.owner_email_redacted.as_deref(),
        Some("e***@example.com")
    );
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));
    assert!(!body.contains("editor@example.com"));
    assert!(!body.contains("Newsroom"));
}

#[test]
fn list_summary_contract_applies_default_cap_with_truncation_evidence() {
    let report = ContractBackend
        .list_summary(&ListSummaryRequest {
            include_html_enrichment: true,
            max_lists: DEFAULT_LIST_READ_LIMIT,
        })
        .unwrap_or_else(|err| panic!("{err}"));

    assert_eq!(report.lists.len(), DEFAULT_LIST_READ_LIMIT);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("returned 106 lists")
            && warning.contains("list summary applied max_lists cap 25")));
    assert!(report
        .evidence
        .notes
        .iter()
        .any(|note| note.contains("list summary XML results truncated from 106 lists")));
}

#[test]
fn list_summary_contract_applies_explicit_cap_and_hard_ceiling() {
    let explicit = ContractBackend
        .list_summary(&ListSummaryRequest {
            include_html_enrichment: true,
            max_lists: 2,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let hard_ceiling = ContractBackend
        .list_summary(&ListSummaryRequest {
            include_html_enrichment: true,
            max_lists: 500,
        })
        .unwrap_or_else(|err| panic!("{err}"));

    assert_eq!(
        explicit
            .lists
            .iter()
            .map(|list| list.list_id)
            .collect::<Vec<_>>(),
        vec![7, 8]
    );
    assert!(explicit
        .warnings
        .iter()
        .any(|warning| warning.contains("list summary applied max_lists cap 2")));
    assert_eq!(hard_ceiling.lists.len(), HARD_LIST_READ_LIMIT);
    assert!(hard_ceiling
        .warnings
        .iter()
        .any(|warning| warning.contains("list summary applied max_lists cap 100")));
}

#[test]
fn contact_state_contract_returns_hash_not_raw_email() {
    let report = ContractBackend
        .contact_state(&ContactStateRequest {
            email: "person@example.com".to_string(),
            list_id: 7,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(report.email_redacted, "p***@example.com");
    assert_eq!(report.email_hash.len(), 24);
    assert!(!body.contains("person@example.com"));
}

#[test]
fn settings_audit_contract_redacts_secret_and_host_context() {
    let report = ContractBackend
        .settings_audit(&SettingsAuditRequest { include_cron: true })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));
    assert!(report.ok);
    assert!(!body.contains("smtp.example.com"));
    assert!(!body.contains("secret"));
    assert!(body.contains("[redacted-host]"));
}

#[test]
fn warmup_readiness_is_read_only_and_does_not_claim_exact_eligibility() {
    let report = ContractBackend
        .warmup_audience_readiness(&WarmupAudienceReadinessRequest {
            source_list_ids: vec![7],
            priority_list_ids: vec![7],
            tranche_sizes: vec![100],
            include_html_enrichment: true,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(!report.production_send_authorized);
    assert!(report
        .eligibility_rules
        .contains(&"dedupe by normalized email before tranche selection".to_string()));
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("Gross counts are not deduped")));
    assert!(!body.contains("editor@example.com"));
}

#[test]
fn audience_hygiene_export_contract_is_aggregate_and_not_send_authorization() {
    let report = ContractBackend
        .audience_hygiene_export(&AudienceHygieneExportRequest::default())
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(!report.legacy_lists_mutated);
    assert!(!report.production_send_authorized);
    assert_eq!(report.deduped_eligible_count, 1);
    assert!(report
        .artifacts
        .iter()
        .any(|artifact| !artifact.contains_raw_recipient_data));
    assert!(!body.contains("@example.com"));
    assert!(!body.contains("first@"));
    assert!(!body.contains("subscriberid"));
}

#[test]
fn queue_control_preview_contract_is_redacted_and_not_apply() {
    let report = ContractBackend
        .queue_control_preview(&QueueControlPreviewRequest { max_rows: Some(25) })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(!report.guarded_writes_enabled);
    assert!(!report.queue_controls_enabled);
    assert!(!report.production_send_authorized);
    assert_eq!(report.candidates.len(), 1);
    assert!(report.candidates[0].requires_guarded_write);
    assert!(report.candidates[0].plan_id.starts_with("iqc_"));
    assert!(!body.contains("index.php"));
    assert!(!body.contains("@example.com"));
}

#[test]
fn queue_control_apply_contract_does_not_mutate_lists_or_authorize_send() {
    let report = ContractBackend
        .queue_control_apply(&QueueControlApplyRequest {
            plan_id: "iqc_000000000000000000000000".to_string(),
            action: interspire_mcp::QueueControlAction::Cancel,
        })
        .unwrap_or_else(|err| panic!("{err}"));

    assert!(report.applied);
    assert!(!report.legacy_lists_mutated);
    assert!(!report.production_send_authorized);
    assert!(!report.after_row_still_present);
}

#[test]
fn admin_session_probe_contract_is_read_only() {
    let report = ContractBackend
        .admin_session_probe(&AdminSessionProbeRequest {
            include_send_start: true,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(report.login_established);
    assert_eq!(report.send_start_page_read, Some(true));
    assert!(!body.contains("password"));
    assert!(!body.contains("cookie"));
}

#[test]
fn campaign_body_audit_contract_is_redacted_and_not_send_authorization() {
    let report = ContractBackend
        .campaign_body_audit(&CampaignBodyAuditRequest { campaign_id: 7 })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert_eq!(report.unsubscribe_token_count, 1);
    assert_eq!(report.http_url_count, 0);
    assert!(!report.visible_tracking_copy_detected);
    assert!(!report.production_send_authorized);
    assert!(report.html_sha256.is_some());
    assert!(!body.contains("<html"));
    assert!(!body.contains("%%UNSUBSCRIBELINK%%"));
}

#[test]
fn campaign_render_artifact_contract_points_to_private_visual_artifacts() {
    let report = ContractBackend
        .campaign_render_artifact(&CampaignRenderArtifactRequest {
            campaign_id: 7,
            output_dir: Some("/tmp/interspire-render".to_string()),
            artifact_prefix: Some("fixture".to_string()),
            include_image_blocked_variant: true,
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(report
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == "preview_index_html"));
    assert!(report.native_browser_next_step.contains("native browser"));
    assert!(!report.production_send_authorized);
    assert!(!body.contains("<html"));
    assert!(!body.contains("%%UNSUBSCRIBELINK%%"));
}

#[test]
fn contact_import_preflight_contract_is_aggregate_only() {
    let report = ContractBackend
        .contact_import_preflight(&ContactImportPreflightRequest {
            csv_path: "/private/fixture.csv".to_string(),
            target_list_id: Some(1),
            email_column: Some("email".to_string()),
            expected_unique_emails: Some(1),
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert_eq!(report.csv_sha256.len(), 64);
    assert!(!report.import_apply_authorized);
    assert_payload_excludes_substrings(
        &report,
        &[
            "person@example.invalid",
            "grant@example.invalid",
            "raw_rows",
            "/private/fixture.csv",
        ],
    );
    assert!(body.contains("preflight only"));
}

#[test]
fn send_wizard_readback_contract_is_no_send_boundary() {
    let report = ContractBackend
        .send_wizard_readback(&SendWizardReadbackRequest {
            campaign_id: 7,
            list_ids: vec![3],
            expected_recipient_count: Some(1),
            max_queue_rows: Some(25),
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert_eq!(report.selected_campaign_id, Some(7));
    assert_eq!(report.selected_list_ids, vec![3]);
    assert!(report.final_form_posts_to_send_boundary);
    assert!(report.queue_unchanged);
    assert!(report.stats_unchanged);
    assert_json_bool_field_false(&report, "send_performed");
    assert_json_bool_field_false(&report, "scheduled");
    assert_json_bool_field_false(&report, "production_send_authorized");
    assert_payload_excludes_substrings(
        &report,
        &[
            "sender@example.invalid",
            "editor@example.invalid",
            "bounces@example.invalid",
        ],
    );
    assert!(!body.contains("index.php"));
}

#[test]
fn seed_readiness_gate_contract_is_not_send_approval() {
    let report = ContractBackend
        .seed_readiness_gate(&SeedReadinessGateRequest {
            campaign_id: 7,
            list_ids: vec![3],
            expected_recipient_count: Some(1),
            expected_from_email: Some("sender@example.invalid".to_string()),
            expected_reply_to_email: Some("editor@example.invalid".to_string()),
        })
        .unwrap_or_else(|err| panic!("{err}"));
    let body = serde_json::to_string(&report).unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(report.ready_for_seed_approval);
    assert_json_bool_field_false(&report, "production_send_authorized");
    assert!(report.gates.iter().all(|gate| gate.passed));
    assert_payload_excludes_substrings(
        &report,
        &["sender@example.invalid", "editor@example.invalid"],
    );
    assert!(!body.contains("smtp-password"));
}

#[test]
fn seed_send_apply_contract_is_seed_only_and_redacted() {
    let report = ContractBackend
        .seed_send_apply(&SeedSendApplyRequest {
            campaign_id: 7,
            list_ids: vec![3],
            expected_recipient_count: 1,
            expected_from_email: Some("sender@example.invalid".to_string()),
            expected_reply_to_email: Some("editor@example.invalid".to_string()),
            expected_subject: Some("Launch subject".to_string()),
            expected_html_sha256: None,
            max_queue_rows: Some(25),
            acknowledge_seed_send: true,
        })
        .unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(report.sent);
    assert_eq!(report.reconciliation.status, SendApplyStatus::SeedProven);
    assert_eq!(report.recipient_count, Some(1));
    assert_json_bool_field_false(&report, "production_send_authorized");
    assert_payload_excludes_substrings(
        &report,
        &[
            "sender@example.invalid",
            "editor@example.invalid",
            "bounces@example.invalid",
        ],
    );
}

#[test]
fn production_send_apply_contract_requires_explicit_authorization_and_redacts() {
    let report = ContractBackend
        .production_send_apply(&ProductionSendApplyRequest {
            campaign_id: 7,
            list_ids: vec![3],
            expected_recipient_count: 1,
            expected_from_email: "sender@example.invalid".to_string(),
            expected_reply_to_email: "editor@example.invalid".to_string(),
            expected_subject: "Launch subject".to_string(),
            expected_html_sha256:
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ops_work_item_ref: Some("w0000".to_string()),
            max_queue_rows: Some(25),
            acknowledge_production_send: true,
            confirmation_phrase: "SEND_PRODUCTION_CAMPAIGN".to_string(),
        })
        .unwrap_or_else(|err| panic!("{err}"));

    assert!(report.ok);
    assert!(report.sent);
    assert_eq!(report.reconciliation.status, SendApplyStatus::Processed);
    assert!(report.production_send_authorized);
    assert_payload_excludes_substrings(
        &report,
        &[
            "sender@example.invalid",
            "editor@example.invalid",
            "bounces@example.invalid",
        ],
    );
}

#[test]
fn server_can_be_constructed_with_fixture_backend() {
    let server = InterspireMcpServer::with_backend(Arc::new(ContractBackend))
        .unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(server.tool_schema_snapshot().len(), 41);
}

#[test]
fn evidence_shape_is_compact() {
    let evidence = Evidence {
        source: "fixture".to_string(),
        notes: vec!["redacted".to_string()],
    };
    let value = serde_json::to_value(evidence).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(value["source"], "fixture");
    assert_eq!(value["notes"][0], "redacted");
}

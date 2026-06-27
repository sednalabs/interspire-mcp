use interspire_6_mcp::{
    AudienceHygieneExportBeginRequest, AudienceHygieneExportReport, AudienceHygieneExportRequest,
    AudienceHygieneExportResumeRequest, AudienceHygieneExportStatusRequest, CampaignReadbackReport,
    CampaignReadbackRequest, ContactStateReport, ContactStateRequest, Evidence, InterspireError,
    InterspireMcpServer, InterspireReadBackend, ListOwnerReadbackReport, ListOwnerReadbackRequest,
    ListSummary, ListSummaryReport, ListSummaryRequest, QueueControlApplyReport,
    QueueControlApplyRequest, QueueControlPreviewReport, QueueControlPreviewRequest,
    QueueStatsReadbackReport, QueueStatsReadbackRequest, SettingsAuditReport, SettingsAuditRequest,
    StatusReport, StatusRequest, UserSmtpReadbackReport, UserSmtpReadbackRequest,
    WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest, DEFAULT_LIST_READ_LIMIT,
    HARD_LIST_READ_LIMIT,
};
use std::sync::Arc;

#[derive(Debug)]
struct ContractBackend;

impl InterspireReadBackend for ContractBackend {
    fn status(&self, _request: &StatusRequest) -> Result<StatusReport, InterspireError> {
        Ok(StatusReport::fixture())
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
    let mut notes = vec!["user/GetLists XML API read".to_string()];

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
    assert!(report.blocked_operations.contains(&"send".to_string()));
    assert!(report
        .capabilities
        .contains(&"interspire_contact_state".to_string()));
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
    assert!(!report.guarded_writes_enabled);
    assert!(!report.queue_controls_enabled);
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
            action: interspire_6_mcp::QueueControlAction::Cancel,
        })
        .unwrap_or_else(|err| panic!("{err}"));

    assert!(report.applied);
    assert!(!report.legacy_lists_mutated);
    assert!(!report.production_send_authorized);
    assert!(!report.after_row_still_present);
}

#[test]
fn server_can_be_constructed_with_fixture_backend() {
    let server = InterspireMcpServer::with_backend(Arc::new(ContractBackend))
        .unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(server.tool_schema_snapshot().len(), 15);
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

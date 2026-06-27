use super::support::{apply_list_result_cap, cap_usize};
use super::LiveInterspireBackend;
use crate::{
    error::InterspireError,
    redact,
    response::{
        blocked_operations, CampaignReadbackReport, CampaignReadbackRequest, ContactStateReport,
        ContactStateRequest, Evidence, ListOwnerReadbackReport, ListOwnerReadbackRequest,
        ListSummaryReport, ListSummaryRequest, QueueStatsReadbackReport, QueueStatsReadbackRequest,
        SettingsAuditReport, SettingsAuditRequest, StatusReport, StatusRequest,
        UserSmtpReadbackReport, UserSmtpReadbackRequest, DEFAULT_LIST_READ_LIMIT,
        HARD_LIST_READ_LIMIT,
    },
    xml_api,
};

impl LiveInterspireBackend {
    pub(super) fn status_impl(
        &self,
        request: &StatusRequest,
    ) -> Result<StatusReport, InterspireError> {
        let xml_configured = self.config.xml.is_configured();
        let admin_html_configured = self.config.admin_html.is_configured();
        let mut warnings = Vec::new();
        if !xml_configured {
            warnings.push(
                "INTERSPIRE_XML_ENDPOINT, INTERSPIRE_XML_USERNAME, or INTERSPIRE_XML_TOKEN missing"
                    .to_string(),
            );
        }
        if !admin_html_configured {
            warnings.push(
                "admin HTML fallback not configured; list owner enrichment disabled".to_string(),
            );
        }
        if request.include_html_probe && admin_html_configured {
            warnings.push(
                "HTML probe requested; v1 reports configuration only and probes during read tools"
                    .to_string(),
            );
        }

        Ok(StatusReport {
            ok: true,
            configured: xml_configured || admin_html_configured,
            xml_configured,
            admin_html_configured,
            guarded_writes_enabled: self.config.guarded_writes.enabled,
            queue_controls_enabled: self.config.guarded_writes.queue_controls_enabled,
            form_write_controls_enabled: self.config.guarded_writes.form_write_controls_enabled,
            contact_write_controls_enabled: self
                .config
                .guarded_writes
                .contact_write_controls_enabled,
            send_controls_enabled: self.config.guarded_writes.send_controls_enabled,
            production_send_controls_enabled: self
                .config
                .guarded_writes
                .production_send_controls_enabled,
            write_execution_mode: self.config.guarded_writes.execution_mode,
            safe_mode: true,
            capabilities: vec![
                "interspire_status".to_string(),
                "interspire_list_summary".to_string(),
                "interspire_contact_state".to_string(),
                "interspire_list_owner_readback".to_string(),
                "interspire_settings_audit".to_string(),
                "interspire_user_smtp_readback".to_string(),
                "interspire_queue_stats_readback".to_string(),
                "interspire_queue_control_preview".to_string(),
                "interspire_queue_control_apply".to_string(),
                "interspire_campaign_readback".to_string(),
                "interspire_campaign_update_preview".to_string(),
                "interspire_campaign_update_apply".to_string(),
                "interspire_list_update_preview".to_string(),
                "interspire_list_update_apply".to_string(),
                "interspire_user_update_preview".to_string(),
                "interspire_user_update_apply".to_string(),
                "interspire_settings_update_preview".to_string(),
                "interspire_settings_update_apply".to_string(),
                "interspire_warmup_audience_readiness".to_string(),
                "interspire_audience_hygiene_export".to_string(),
                "interspire_audience_hygiene_export_begin".to_string(),
                "interspire_audience_hygiene_export_resume".to_string(),
                "interspire_audience_hygiene_export_status".to_string(),
            ],
            blocked_operations: blocked_operations(),
            warnings,
            evidence: Evidence {
                source: "environment".to_string(),
                notes: vec![
                    "stdio MCP only".to_string(),
                    "XML API read methods are user/GetLists, subscribers/IsSubscriberOnList, and subscribers/GetSubscribers for the guarded audience hygiene export".to_string(),
                    "admin HTML fallback is limited to login plus explicitly allowlisted GET read pages".to_string(),
                    "audience hygiene export writes private local artifacts only and returns aggregate metadata".to_string(),
                    "queue control apply tools are disabled unless guarded write environment flags are explicitly enabled".to_string(),
                    "guarded form-write tools are disabled unless guarded write environment flags are explicitly enabled".to_string(),
                ],
            },
        })
    }

    pub(super) fn list_summary_impl(
        &self,
        request: &ListSummaryRequest,
    ) -> Result<ListSummaryReport, InterspireError> {
        let xml = self.xml_client()?;
        if !xml.configured() {
            return Ok(ListSummaryReport {
                ok: true,
                configured: false,
                lists: Vec::new(),
                warnings: vec!["XML API is not configured; no live list read attempted".to_string()],
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let mut lists = xml.get_lists()?;
        let mut warnings = Vec::new();
        let mut notes = vec!["user/GetLists XML API read".to_string()];
        let max_lists = cap_usize(request.max_lists, HARD_LIST_READ_LIMIT);
        apply_list_result_cap(
            &mut lists,
            max_lists,
            "list summary",
            &mut warnings,
            &mut notes,
        );

        if request.include_html_enrichment {
            let html = self.html_client()?;
            if html.configured() {
                match html.enrich_lists(&mut lists) {
                    Ok(mut html_notes) => {
                        notes.push("admin list edit GET enrichment applied".to_string());
                        notes.append(&mut html_notes);
                    }
                    Err(err) => warnings.push(format!(
                        "HTML enrichment skipped: {}",
                        redact::redact_sensitive_text(&err.to_string())
                    )),
                }
            } else {
                warnings.push(
                    "admin HTML fallback not configured; XML list counts returned only".to_string(),
                );
            }
        }

        Ok(ListSummaryReport {
            ok: true,
            configured: true,
            lists,
            warnings,
            evidence: xml_api::xml_evidence(notes),
        })
    }

    pub(super) fn contact_state_impl(
        &self,
        request: &ContactStateRequest,
    ) -> Result<ContactStateReport, InterspireError> {
        let xml = self.xml_client()?;
        if !xml.configured() {
            return Ok(ContactStateReport {
                ok: true,
                configured: false,
                list_id: request.list_id,
                email_redacted: redact::redact_email(&request.email),
                email_hash: redact::email_hash(&request.email),
                found_on_list: None,
                state: "unknown_xml_not_configured".to_string(),
                warnings: vec![
                    "XML API is not configured; no live contact read attempted".to_string()
                ],
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let found = xml.is_subscriber_on_list(&request.email, request.list_id)?;
        Ok(ContactStateReport {
            ok: true,
            configured: true,
            list_id: request.list_id,
            email_redacted: redact::redact_email(&request.email),
            email_hash: redact::email_hash(&request.email),
            found_on_list: Some(found),
            state: if found {
                "present_on_list".to_string()
            } else {
                "not_found_on_list".to_string()
            },
            warnings: vec![
                "XML IsSubscriberOnList proves presence only; it does not prove bounce, unsubscribe, or provider suppression reconciliation".to_string(),
            ],
            evidence: xml_api::xml_evidence(vec![
                "subscribers/IsSubscriberOnList XML API read".to_string(),
                "admin HTML contact fallback intentionally omitted in v1".to_string(),
            ]),
        })
    }

    pub(super) fn list_owner_readback_impl(
        &self,
        request: &ListOwnerReadbackRequest,
    ) -> Result<ListOwnerReadbackReport, InterspireError> {
        let xml = self.xml_client()?;
        if !xml.configured() {
            return Ok(ListOwnerReadbackReport {
                ok: true,
                configured: false,
                lists: Vec::new(),
                warnings: vec![
                    "XML API is not configured; no live list owner read attempted".to_string(),
                ],
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let mut lists = xml.get_lists()?;
        let max_lists = cap_usize(
            request.max_lists.unwrap_or(DEFAULT_LIST_READ_LIMIT),
            HARD_LIST_READ_LIMIT,
        );

        let mut warnings = Vec::new();
        let mut notes = vec!["user/GetLists XML API read".to_string()];
        apply_list_result_cap(
            &mut lists,
            max_lists,
            "list owner readback",
            &mut warnings,
            &mut notes,
        );
        let html = self.html_client()?;
        if html.configured() {
            match html.enrich_lists(&mut lists) {
                Ok(mut html_notes) => {
                    notes.push("admin list edit GET owner enrichment applied".to_string());
                    notes.append(&mut html_notes);
                }
                Err(err) => warnings.push(format!(
                    "HTML owner enrichment skipped: {}",
                    redact::redact_sensitive_text(&err.to_string())
                )),
            }
        } else {
            warnings.push(
                "admin HTML fallback not configured; owner/reply/bounce fields unavailable"
                    .to_string(),
            );
        }

        Ok(ListOwnerReadbackReport {
            ok: true,
            configured: true,
            lists,
            warnings,
            evidence: xml_api::xml_evidence(notes),
        })
    }

    pub(super) fn settings_audit_impl(
        &self,
        request: &SettingsAuditRequest,
    ) -> Result<SettingsAuditReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(SettingsAuditReport {
                ok: true,
                configured: false,
                sections: Vec::new(),
                warnings: vec![
                    "admin HTML fallback is not configured; no settings read attempted".to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }

        html.settings_audit(request.include_cron)
    }

    pub(super) fn user_smtp_readback_impl(
        &self,
        request: &UserSmtpReadbackRequest,
    ) -> Result<UserSmtpReadbackReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(UserSmtpReadbackReport {
                ok: true,
                configured: false,
                users: Vec::new(),
                warnings: vec![
                    "admin HTML fallback is not configured; no user SMTP read attempted"
                        .to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }

        html.user_smtp_readback(cap_usize(request.max_users.unwrap_or(25), 100))
    }

    pub(super) fn queue_stats_readback_impl(
        &self,
        request: &QueueStatsReadbackRequest,
    ) -> Result<QueueStatsReadbackReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(QueueStatsReadbackReport {
                ok: true,
                configured: false,
                scheduled_rows: Vec::new(),
                stats_rows: Vec::new(),
                warnings: vec![
                    "admin HTML fallback is not configured; no queue/stats read attempted"
                        .to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }

        html.queue_stats_readback(cap_usize(request.max_rows.unwrap_or(25), 100))
    }

    pub(super) fn campaign_readback_impl(
        &self,
        request: &CampaignReadbackRequest,
    ) -> Result<CampaignReadbackReport, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(CampaignReadbackReport {
                ok: true,
                configured: false,
                campaign_id: request.campaign_id,
                campaign_fields: Vec::new(),
                campaign_rows: Vec::new(),
                warnings: vec![
                    "admin HTML fallback is not configured; no campaign read attempted".to_string(),
                ],
                evidence: Evidence {
                    source: "interspire_admin_html".to_string(),
                    notes: vec!["no request sent".to_string()],
                },
            });
        }

        html.campaign_readback(
            request.campaign_id,
            cap_usize(request.max_rows.unwrap_or(25), 100),
        )
    }
}

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
    fn html_list_summary_fallback(
        &self,
        max_lists: usize,
    ) -> Result<Option<ListSummaryReport>, InterspireError> {
        let html = self.html_client()?;
        if !html.configured() {
            return Ok(None);
        }
        Ok(Some(html.list_summary_readback(max_lists)?))
    }

    fn html_list_owner_fallback(
        &self,
        max_lists: usize,
    ) -> Result<Option<ListOwnerReadbackReport>, InterspireError> {
        let Some(summary) = self.html_list_summary_fallback(max_lists)? else {
            return Ok(None);
        };
        let mut warnings = summary.warnings;
        warnings.insert(
            0,
            "admin HTML list owner readback fallback used without XML list counts".to_string(),
        );
        Ok(Some(ListOwnerReadbackReport {
            ok: summary.ok,
            configured: summary.configured,
            lists: summary.lists,
            warnings,
            evidence: summary.evidence,
        }))
    }

    pub(super) fn status_impl(
        &self,
        request: &StatusRequest,
    ) -> Result<StatusReport, InterspireError> {
        let xml_configured = self.config.xml.is_configured();
        let admin_html_configured = self.config.admin_html.is_configured();
        let cloudflare_access_configured = self.config.cloudflare_access.is_configured();
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
            interspire_version: self.config.version,
            xml_configured,
            admin_html_configured,
            cloudflare_access_configured,
            guarded_writes_enabled: self.config.guarded_writes.enabled,
            sensitive_reads_enabled: self.config.sensitive_reads.enabled,
            import_preflight_configured: !self.config.import_preflight.allowed_roots.is_empty(),
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
                "interspire_xml_auth_probe".to_string(),
                "interspire_list_summary".to_string(),
                "interspire_contact_state".to_string(),
                "interspire_list_owner_readback".to_string(),
                "interspire_settings_audit".to_string(),
                "interspire_admin_session_probe".to_string(),
                "interspire_user_smtp_readback".to_string(),
                "interspire_queue_stats_readback".to_string(),
                "interspire_queue_control_preview".to_string(),
                "interspire_queue_control_apply".to_string(),
                "interspire_campaign_readback".to_string(),
                "interspire_campaign_body_audit".to_string(),
                "interspire_campaign_render_artifact".to_string(),
                "interspire_send_wizard_readback".to_string(),
                "interspire_seed_readiness_gate".to_string(),
                "interspire_seed_send_apply".to_string(),
                "interspire_production_send_apply".to_string(),
                "interspire_campaign_template_update_preview".to_string(),
                "interspire_campaign_template_update_apply".to_string(),
                "interspire_campaign_update_preview".to_string(),
                "interspire_campaign_update_apply".to_string(),
                "interspire_list_update_preview".to_string(),
                "interspire_list_update_apply".to_string(),
                "interspire_list_create_preview".to_string(),
                "interspire_list_create_apply".to_string(),
                "interspire_campaign_copy_preview".to_string(),
                "interspire_campaign_copy_apply".to_string(),
                "interspire_contact_import_preflight".to_string(),
                "interspire_user_update_preview".to_string(),
                "interspire_user_update_apply".to_string(),
                "interspire_settings_update_preview".to_string(),
                "interspire_settings_update_apply".to_string(),
                "interspire_sensitive_field_query".to_string(),
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
                    "XML API read methods are lists/GetLists, subscribers/IsSubscriberOnList, and subscribers/GetSubscribers for the guarded audience hygiene export".to_string(),
                    "XML auth probe uses authentication/XmlApiTest and performs no list, contact, send, queue, or form mutation".to_string(),
                    "admin HTML fallback is limited to login plus explicitly allowlisted GET read pages".to_string(),
                    "send wizard proof is limited to an allowlisted no-send Step2 render and queue/stat invariant readback".to_string(),
                    "campaign render artifacts write private local preview files for native-browser screenshots; they do not mutate Interspire".to_string(),
                    "seed send apply tools are disabled unless guarded write and send-control environment flags are explicitly enabled".to_string(),
                    "production send apply tools are disabled unless guarded write, send-control, and production-send-control environment flags are explicitly enabled".to_string(),
                    "audience hygiene export writes private local artifacts only and returns aggregate metadata".to_string(),
                    "queue control apply tools are disabled unless guarded write environment flags are explicitly enabled".to_string(),
                    "guarded form-write tools are disabled unless guarded write environment flags are explicitly enabled".to_string(),
                    "Cloudflare Access service-token headers are attached to Interspire HTTP requests when INTERSPIRE_CF_ACCESS_* configuration is present".to_string(),
                ],
            },
        })
    }

    pub(super) fn list_summary_impl(
        &self,
        request: &ListSummaryRequest,
    ) -> Result<ListSummaryReport, InterspireError> {
        let max_lists = cap_usize(request.max_lists, HARD_LIST_READ_LIMIT);
        let mut warnings = Vec::new();
        let mut notes = vec!["lists/GetLists XML API read".to_string()];
        let xml = self.xml_client()?;
        if !xml.configured() {
            if let Some(mut report) = self.html_list_summary_fallback(max_lists)? {
                report.warnings.insert(
                    0,
                    "XML API is not configured; admin HTML list readback fallback used".to_string(),
                );
                return Ok(report);
            }
            return Ok(ListSummaryReport {
                ok: true,
                configured: false,
                lists: Vec::new(),
                warnings: vec![
                    "XML API is not configured and admin HTML fallback is not configured; no live list read attempted".to_string(),
                ],
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let mut lists = match xml.get_lists() {
            Ok(lists) => lists,
            Err(err) => {
                if let Some(mut report) = self.html_list_summary_fallback(max_lists)? {
                    report.warnings.insert(
                        0,
                        format!(
                            "XML list read failed; admin HTML fallback used: {}",
                            redact::redact_sensitive_text(&err.to_string())
                        ),
                    );
                    return Ok(report);
                }
                return Ok(ListSummaryReport {
                    ok: true,
                    configured: true,
                    lists: Vec::new(),
                    warnings: vec![format!(
                        "XML list read failed and admin HTML fallback is not configured: {}",
                        redact::redact_sensitive_text(&err.to_string())
                    )],
                    evidence: xml_api::xml_evidence(vec![
                        "lists/GetLists XML API read attempted".to_string()
                    ]),
                });
            }
        };
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
        let html = self.html_client()?;
        let mut xml_found_on_list = None;
        let mut admin_html_found_on_list = None;
        let mut verification_sources = Vec::new();
        let mut warnings = Vec::new();
        let mut notes = Vec::new();

        if xml.configured() {
            match xml.is_subscriber_on_list(&request.email, request.list_id) {
                Ok(found) => {
                    xml_found_on_list = Some(found);
                    verification_sources.push("interspire_xml_api".to_string());
                    notes.push("subscribers/IsSubscriberOnList XML API read".to_string());
                    notes.push(contact_state_outcome(found).evidence_note.to_string());
                }
                Err(err) => {
                    verification_sources.push("interspire_xml_api_attempted".to_string());
                    notes.push("subscribers/IsSubscriberOnList XML API read attempted".to_string());
                    notes.push(
                        "XML failure was returned as degraded evidence rather than authoritative absence"
                            .to_string(),
                    );
                    warnings.push(format!(
                        "XML contact-state read failed: {}",
                        redact::redact_sensitive_text(&err.to_string())
                    ));
                }
            }
        } else {
            warnings.push("XML API is not configured; XML contact read skipped".to_string());
            notes.push(
                "XML contact-state read skipped because XML API is not configured".to_string(),
            );
        }

        if xml_found_on_list != Some(true) {
            if html.configured() {
                match html.contact_state_readback(&request.email, request.list_id) {
                    Ok(html_state) => {
                        admin_html_found_on_list = html_state.found_on_list;
                        verification_sources.push("interspire_admin_html_exact_search".to_string());
                        notes.extend(html_state.evidence_notes);
                        warnings.extend(html_state.warnings);
                    }
                    Err(err) => warnings.push(format!(
                        "admin HTML contact-state corroboration skipped: {}",
                        redact::redact_sensitive_text(&err.to_string())
                    )),
                }
            } else {
                warnings.push(
                    "admin HTML fallback is not configured; contact-state corroboration skipped"
                        .to_string(),
                );
                notes.push(
                    "admin HTML contact-state read skipped because admin HTML is not configured"
                        .to_string(),
                );
            }
        }

        let outcome = combined_contact_state_outcome(xml_found_on_list, admin_html_found_on_list);
        warnings.extend(outcome.warnings.iter().map(|value| (*value).to_string()));
        Ok(ContactStateReport {
            ok: true,
            configured: xml.configured() || html.configured(),
            list_id: request.list_id,
            email_redacted: redact::redact_email(&request.email),
            email_hash: redact::email_hash(&request.email),
            found_on_list: outcome.found_on_list,
            xml_found_on_list,
            admin_html_found_on_list,
            state: outcome.state.to_string(),
            source_authority: outcome.source_authority.to_string(),
            confidence: outcome.confidence.to_string(),
            verification_sources,
            warnings,
            evidence: Evidence {
                source: contact_state_evidence_source(xml.configured(), html.configured()),
                notes,
            },
        })
    }

    pub(super) fn list_owner_readback_impl(
        &self,
        request: &ListOwnerReadbackRequest,
    ) -> Result<ListOwnerReadbackReport, InterspireError> {
        let xml = self.xml_client()?;
        let max_lists = cap_usize(
            request.max_lists.unwrap_or(DEFAULT_LIST_READ_LIMIT),
            HARD_LIST_READ_LIMIT,
        );
        if !xml.configured() {
            if let Some(report) = self.html_list_owner_fallback(max_lists)? {
                return Ok(report);
            }
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

        let mut lists = match xml.get_lists() {
            Ok(lists) => lists,
            Err(err) => {
                if let Some(mut report) = self.html_list_owner_fallback(max_lists)? {
                    report.warnings.insert(
                        0,
                        format!(
                            "XML list owner read failed; admin HTML fallback used: {}",
                            redact::redact_sensitive_text(&err.to_string())
                        ),
                    );
                    return Ok(report);
                }
                return Ok(ListOwnerReadbackReport {
                    ok: true,
                    configured: true,
                    lists: Vec::new(),
                    warnings: vec![format!(
                        "XML list owner read failed and admin HTML fallback is not configured: {}",
                        redact::redact_sensitive_text(&err.to_string())
                    )],
                    evidence: xml_api::xml_evidence(vec![
                        "lists/GetLists XML API read attempted".to_string()
                    ]),
                });
            }
        };

        let mut warnings = Vec::new();
        let mut notes = vec!["lists/GetLists XML API read".to_string()];
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
                campaign_manage_rows: Vec::new(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContactStateOutcome {
    found_on_list: Option<bool>,
    state: &'static str,
    source_authority: &'static str,
    confidence: &'static str,
    evidence_note: &'static str,
    warnings: &'static [&'static str],
}

fn contact_state_outcome(found: bool) -> ContactStateOutcome {
    if found {
        return ContactStateOutcome {
            found_on_list: Some(true),
            state: "present_on_list",
            source_authority: "interspire_xml_api",
            confidence: "high_presence",
            evidence_note: "XML positive membership is treated as list-presence evidence",
            warnings: &[
                "XML IsSubscriberOnList proves list presence only; it does not prove bounce, unsubscribe, or provider suppression reconciliation",
            ],
        };
    }

    ContactStateOutcome {
        found_on_list: None,
        state: "not_found_on_list_uncorroborated",
        source_authority: "interspire_xml_api_presence_probe",
        confidence: "low_absence",
        evidence_note: "admin HTML/contact export absence corroboration not performed",
        warnings: &[
            "XML IsSubscriberOnList false is not authoritative absence; confirm with admin HTML, contact export, or another authoritative contact-state read before send-readiness decisions",
            "This avoids treating API-scope gaps as definitive list absence for newly created, resubscribed, or UI-visible contacts",
            "XML IsSubscriberOnList does not prove bounce, unsubscribe, or provider suppression reconciliation",
        ],
    }
}

fn combined_contact_state_outcome(
    xml_found_on_list: Option<bool>,
    admin_html_found_on_list: Option<bool>,
) -> ContactStateOutcome {
    if xml_found_on_list == Some(true) {
        return contact_state_outcome(true);
    }

    if admin_html_found_on_list == Some(true) {
        return ContactStateOutcome {
            found_on_list: Some(true),
            state: "present_on_list_html_corroborated",
            source_authority: "interspire_admin_html_exact_search",
            confidence: "medium_presence",
            evidence_note: "admin HTML exact-search positive membership is treated as list-presence evidence",
            warnings: &[
                "admin HTML exact-search proves page-visible list presence only; it does not prove bounce, unsubscribe, complaint, or provider suppression reconciliation",
                "HTML readback is a brittle fallback used only when XML cannot prove presence",
            ],
        };
    }

    if matches!(xml_found_on_list, Some(false)) || matches!(admin_html_found_on_list, Some(false)) {
        return ContactStateOutcome {
            found_on_list: None,
            state: "not_found_on_list_uncorroborated",
            source_authority: "interspire_contact_state_degraded_probe",
            confidence: "low_absence",
            evidence_note: "one or more readbacks did not find the contact, but absence remains low-confidence",
            warnings: &[
                "negative contact-state readback is not treated as authoritative absence",
                "confirm with a full hygiene ledger or another authoritative contact-state source before making send-readiness decisions",
            ],
        };
    }

    ContactStateOutcome {
        found_on_list: None,
        state: "unknown_contact_state",
        source_authority: "none",
        confidence: "unknown",
        evidence_note: "no configured source could prove contact state",
        warnings: &["contact-state proof is unavailable from the configured sources"],
    }
}

fn contact_state_evidence_source(xml_configured: bool, html_configured: bool) -> String {
    match (xml_configured, html_configured) {
        (true, true) => "interspire_xml_api+admin_html".to_string(),
        (true, false) => "interspire_xml_api".to_string(),
        (false, true) => "interspire_admin_html".to_string(),
        (false, false) => "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{combined_contact_state_outcome, contact_state_outcome};

    #[test]
    fn xml_negative_contact_state_is_low_confidence_absence() {
        let outcome = contact_state_outcome(false);

        assert_eq!(outcome.state, "not_found_on_list_uncorroborated");
        assert_eq!(outcome.found_on_list, None);
        assert_eq!(outcome.confidence, "low_absence");
        assert!(outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("not authoritative absence")));
    }

    #[test]
    fn xml_positive_contact_state_is_high_confidence_presence_only() {
        let outcome = contact_state_outcome(true);

        assert_eq!(outcome.state, "present_on_list");
        assert_eq!(outcome.found_on_list, Some(true));
        assert_eq!(outcome.confidence, "high_presence");
        assert!(outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("list presence only")));
    }

    #[test]
    fn html_positive_contact_state_can_corroborate_xml_error() {
        let outcome = combined_contact_state_outcome(None, Some(true));

        assert_eq!(outcome.state, "present_on_list_html_corroborated");
        assert_eq!(outcome.found_on_list, Some(true));
        assert_eq!(outcome.confidence, "medium_presence");
        assert_eq!(
            outcome.source_authority,
            "interspire_admin_html_exact_search"
        );
    }

    #[test]
    fn negative_html_contact_state_remains_low_confidence_absence() {
        let outcome = combined_contact_state_outcome(None, Some(false));

        assert_eq!(outcome.state, "not_found_on_list_uncorroborated");
        assert_eq!(outcome.found_on_list, None);
        assert_eq!(outcome.confidence, "low_absence");
    }
}

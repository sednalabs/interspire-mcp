//! Live Interspire backend implementation for MCP tool handlers.
//!
//! The backend composes XML API reads with explicitly allowlisted admin HTML
//! readback. It returns compact, redacted reports and marks unconfigured
//! sources as skipped instead of inventing evidence.

use crate::{
    admin_html::AdminHtmlClient,
    audience_hygiene::{self, HygieneListInput},
    audience_hygiene_checkpoint,
    config::InterspireServerConfig,
    error::InterspireError,
    guarded_write, redact,
    response::{
        approved_hygiene_source_list_ids, approved_warmup_source_list_ids,
        blocked_hygiene_source_list_ids, blocked_operations, AudienceHygieneExportBeginRequest,
        AudienceHygieneExportReport, AudienceHygieneExportRequest,
        AudienceHygieneExportResumeRequest, AudienceHygieneExportStatusRequest,
        CampaignReadbackReport, CampaignReadbackRequest, ContactStateReport, ContactStateRequest,
        Evidence, ListOwnerReadbackReport, ListOwnerReadbackRequest, ListSummary,
        ListSummaryReport, ListSummaryRequest, QueueControlApplyReport, QueueControlApplyRequest,
        QueueControlPreviewReport, QueueControlPreviewRequest, QueueStatsReadbackReport,
        QueueStatsReadbackRequest, SettingsAuditReport, SettingsAuditRequest, StatusReport,
        StatusRequest, UserSmtpReadbackReport, UserSmtpReadbackRequest,
        WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest, DEFAULT_LIST_READ_LIMIT,
        HARD_LIST_READ_LIMIT,
    },
    xml_api::{self, XmlApiClient},
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
                ],
            },
        })
    }

    fn list_summary(
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
                        crate::redact::redact_sensitive_text(&err.to_string())
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

    fn contact_state(
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

    fn list_owner_readback(
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
                    crate::redact::redact_sensitive_text(&err.to_string())
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

    fn settings_audit(
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

    fn user_smtp_readback(
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

    fn queue_stats_readback(
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

    fn queue_control_preview(
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
                "queue controls can cancel/delete scheduled rows only; they do not send, schedule, import, export, or mutate contacts".to_string(),
            ],
            evidence: Evidence {
                source: "interspire_admin_html".to_string(),
                notes: vec!["allowlisted Schedule GET read for queue-control preview".to_string()],
            },
        })
    }

    fn queue_control_apply(
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
                applied: false,
                plan_id: request.plan_id.clone(),
                action: request.action,
                before_candidate_count: 0,
                before_row_summary: None,
                after_candidate_count: 0,
                after_row_still_present: false,
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
            applied: true,
            plan_id: request.plan_id.clone(),
            action: request.action,
            before_candidate_count: evidence.before_candidate_count,
            before_row_summary: evidence.before_row_summary,
            after_candidate_count: evidence.after_candidate_count,
            after_row_still_present: evidence.after_row_still_present,
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

    fn campaign_readback(
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

    fn warmup_audience_readiness(
        &self,
        request: &WarmupAudienceReadinessRequest,
    ) -> Result<WarmupAudienceReadinessReport, InterspireError> {
        let xml = self.xml_client()?;
        if !xml.configured() {
            let source_list_ids = approved_warmup_source_list_ids(request);
            let mut warnings =
                vec!["XML API is not configured; no warm-up audience read attempted".to_string()];
            if source_list_ids.is_empty() {
                warnings.push(
                    "no explicit warm-up source list ids were provided after safety filtering"
                        .to_string(),
                );
            }
            return Ok(WarmupAudienceReadinessReport {
                ok: true,
                configured: false,
                source_list_ids: source_list_ids.clone(),
                matched_lists: Vec::new(),
                missing_list_ids: source_list_ids,
                gross_subscribed_count: 0,
                gross_unsubscribed_count: 0,
                gross_autoresponder_count: 0,
                eligibility_rules: Vec::new(),
                tranche_plan: Vec::new(),
                production_send_authorized: false,
                warnings,
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let lists = xml.get_lists()?;
        let source_list_ids = approved_warmup_source_list_ids(request);
        let mut lists = filter_requested_source_lists(lists, &source_list_ids);
        let mut warnings = Vec::new();
        let mut notes = vec!["user/GetLists XML API read".to_string()];

        if request.include_html_enrichment {
            let html = self.html_client()?;
            if html.configured() {
                match html.enrich_lists(&mut lists) {
                    Ok(mut html_notes) => {
                        notes.push("admin list edit GET owner enrichment applied".to_string());
                        notes.append(&mut html_notes);
                    }
                    Err(err) => warnings.push(format!(
                        "HTML owner enrichment skipped: {}",
                        crate::redact::redact_sensitive_text(&err.to_string())
                    )),
                }
            } else {
                warnings.push(
                    "admin HTML fallback not configured; sender metadata enrichment skipped"
                        .to_string(),
                );
            }
        }

        Ok(WarmupAudienceReadinessReport::from_lists(
            request,
            lists,
            warnings,
            xml_api::xml_evidence(notes),
        ))
    }

    fn audience_hygiene_export(
        &self,
        request: &AudienceHygieneExportRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        let source_list_ids = approved_hygiene_source_list_ids(request);
        let blocked_source_list_ids = blocked_hygiene_source_list_ids(request);
        let mut warnings = Vec::new();
        if !blocked_source_list_ids.is_empty() {
            warnings.push(format!(
                "ignored source list ids outside the audience hygiene request policy: {}",
                join_ids_for_warning(&blocked_source_list_ids)
            ));
        }
        if source_list_ids.is_empty() {
            warnings.push(
                "no explicit audience hygiene source list ids were provided after safety filtering"
                    .to_string(),
            );
            return Ok(AudienceHygieneExportReport {
                ok: true,
                configured: true,
                job_id: None,
                phase: None,
                job_dir: None,
                source_list_ids,
                processed_list_count: 0,
                remaining_list_ids: Vec::new(),
                missing_list_ids: Vec::new(),
                active_list_id: None,
                active_list_name: None,
                queries_processed_this_call: 0,
                completed_query_count: 0,
                remaining_query_count: 0,
                lists: Vec::new(),
                gross_api_items: 0,
                eligible_items_before_dedupe: 0,
                deduped_eligible_count: 0,
                duplicate_eligible_items_removed: 0,
                excluded_unconfirmed: 0,
                excluded_unsubscribed: 0,
                excluded_bounced: 0,
                invalid_syntax_count: 0,
                role_localpart_count: 0,
                disposable_domain_hint_count: 0,
                checkpoint_artifacts: Vec::new(),
                artifacts: Vec::new(),
                legacy_lists_mutated: false,
                production_send_authorized: false,
                warnings,
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let xml = self.xml_client()?;
        if !xml.configured() {
            let missing_list_ids = source_list_ids.clone();
            warnings.push(
                "XML API is not configured; no audience hygiene export attempted".to_string(),
            );
            return Ok(AudienceHygieneExportReport {
                ok: true,
                configured: false,
                job_id: None,
                phase: None,
                job_dir: None,
                source_list_ids,
                processed_list_count: 0,
                remaining_list_ids: Vec::new(),
                missing_list_ids,
                active_list_id: None,
                active_list_name: None,
                queries_processed_this_call: 0,
                completed_query_count: 0,
                remaining_query_count: 0,
                lists: Vec::new(),
                gross_api_items: 0,
                eligible_items_before_dedupe: 0,
                deduped_eligible_count: 0,
                duplicate_eligible_items_removed: 0,
                excluded_unconfirmed: 0,
                excluded_unsubscribed: 0,
                excluded_bounced: 0,
                invalid_syntax_count: 0,
                role_localpart_count: 0,
                disposable_domain_hint_count: 0,
                checkpoint_artifacts: Vec::new(),
                artifacts: Vec::new(),
                legacy_lists_mutated: false,
                production_send_authorized: false,
                warnings,
                evidence: xml_api::xml_evidence(vec!["no request sent".to_string()]),
            });
        }

        let lists = filter_requested_source_lists(xml.get_lists()?, &source_list_ids);
        let matched_list_ids = lists.iter().map(|list| list.list_id).collect::<Vec<_>>();
        let missing_list_ids = source_list_ids
            .iter()
            .copied()
            .filter(|list_id| !matched_list_ids.contains(list_id))
            .collect::<Vec<_>>();

        if !missing_list_ids.is_empty() {
            warnings.push(format!(
                "missing specified audience hygiene source list ids: {}",
                join_ids_for_warning(&missing_list_ids)
            ));
        }

        let mut inputs = Vec::new();
        for list in lists {
            let records = if list.subscribed_count.unwrap_or_default() > 500 {
                xml.get_subscribers_for_list_by_domain_prefix_shards(list.list_id)?
            } else {
                match xml.get_subscribers_for_list(list.list_id) {
                    Ok(records) => records,
                    Err(err)
                        if xml_api::XmlApiClient::should_retry_subscriber_read_with_shards(
                            &err,
                        ) =>
                    {
                        xml.get_subscribers_for_list_by_domain_prefix_shards(list.list_id)?
                    }
                    Err(err) => return Err(err),
                }
            };
            inputs.push(HygieneListInput {
                list_id: list.list_id,
                name: list.name,
                declared_subscribed_count: list.subscribed_count,
                declared_unsubscribed_count: list.unsubscribed_count,
                records,
            });
        }

        audience_hygiene::build_audience_hygiene_export(
            request,
            source_list_ids,
            missing_list_ids,
            inputs,
            xml_api::xml_evidence(vec![
                "user/GetLists XML API read".to_string(),
                "subscribers/GetSubscribers XML API read for each matched explicit source list; large lists use bounded domain-prefix shards to avoid truncated XML responses".to_string(),
                "private local artifacts written outside repository with aggregate MCP response"
                    .to_string(),
            ]),
            warnings,
        )
    }

    fn audience_hygiene_export_begin(
        &self,
        request: &AudienceHygieneExportBeginRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        let xml = self.xml_client()?;
        audience_hygiene_checkpoint::begin_export(&xml, request)
    }

    fn audience_hygiene_export_resume(
        &self,
        request: &AudienceHygieneExportResumeRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        let xml = self.xml_client()?;
        audience_hygiene_checkpoint::resume_export(&xml, request)
    }

    fn audience_hygiene_export_status(
        &self,
        request: &AudienceHygieneExportStatusRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        audience_hygiene_checkpoint::export_status(request)
    }
}

fn cap_usize(value: usize, max: usize) -> usize {
    value.clamp(1, max)
}

fn apply_list_result_cap(
    lists: &mut Vec<ListSummary>,
    max_lists: usize,
    label: &str,
    warnings: &mut Vec<String>,
    notes: &mut Vec<String>,
) {
    let original_count = lists.len();
    if original_count <= max_lists {
        return;
    }

    lists.truncate(max_lists);
    warnings.push(format!(
        "XML list readback returned {original_count} lists; {label} applied max_lists cap {max_lists}"
    ));
    notes.push(format!(
        "{label} XML results truncated from {original_count} lists to applied cap {max_lists}"
    ));
}

fn filter_requested_source_lists(
    lists: Vec<ListSummary>,
    requested_source_list_ids: &[u64],
) -> Vec<ListSummary> {
    let mut selected = Vec::new();
    let mut remaining = lists;
    let mut seen = Vec::new();

    for list_id in requested_source_list_ids
        .iter()
        .copied()
        .filter(|list_id| *list_id > 0)
    {
        if seen.contains(&list_id) {
            continue;
        }
        seen.push(list_id);

        if let Some(index) = remaining
            .iter()
            .position(|candidate| candidate.list_id == list_id)
        {
            selected.push(remaining.remove(index));
        }
    }

    selected
}

fn join_ids_for_warning(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{apply_list_result_cap, filter_requested_source_lists, LiveInterspireBackend};
    use crate::response::{
        AudienceHygieneExportRequest, Evidence, ListSummary, WarmupAudienceReadinessReport,
        WarmupAudienceReadinessRequest,
    };
    use crate::{config::InterspireServerConfig, InterspireReadBackend};

    fn list_summary(list_id: u64) -> ListSummary {
        ListSummary {
            list_id,
            name: format!("List {list_id}"),
            subscribed_count: Some(list_id * 10),
            unsubscribed_count: Some(list_id),
            autoresponder_count: Some(0),
            owner_name: None,
            owner_email_redacted: None,
            reply_to_email_redacted: None,
            bounce_email_redacted: None,
            source: "xml".to_string(),
        }
    }

    #[test]
    fn owner_cap_records_warning_and_evidence() {
        let mut lists = vec![list_summary(1), list_summary(2), list_summary(3)];
        let mut warnings = Vec::new();
        let mut notes = Vec::new();

        apply_list_result_cap(
            &mut lists,
            2,
            "list owner readback",
            &mut warnings,
            &mut notes,
        );

        assert_eq!(
            lists.iter().map(|list| list.list_id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("returned 3 lists")
                && warning.contains("applied max_lists cap 2")));
        assert!(notes
            .iter()
            .any(|note| note.contains("truncated from 3 lists to applied cap 2")));
    }

    #[test]
    fn list_summary_cap_uses_explicit_label_in_warning_and_evidence() {
        let mut lists = vec![list_summary(1), list_summary(2), list_summary(3)];
        let mut warnings = Vec::new();
        let mut notes = Vec::new();

        apply_list_result_cap(&mut lists, 1, "list summary", &mut warnings, &mut notes);

        assert_eq!(
            lists.iter().map(|list| list.list_id).collect::<Vec<_>>(),
            vec![1]
        );
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("list summary applied max_lists cap 1")));
        assert!(notes
            .iter()
            .any(|note| note.contains("list summary XML results truncated from 3 lists")));
    }

    #[test]
    fn warmup_filter_keeps_only_requested_lists_in_request_order() {
        let lists = vec![list_summary(1), list_summary(2), list_summary(3)];

        let filtered = filter_requested_source_lists(lists, &[3, 9, 1, 3, 0]);

        assert_eq!(
            filtered.iter().map(|list| list.list_id).collect::<Vec<_>>(),
            vec![3, 1]
        );
    }

    #[test]
    fn warmup_filter_still_allows_missing_list_detection() {
        let request = WarmupAudienceReadinessRequest {
            source_list_ids: vec![72, 111, 114],
            priority_list_ids: Vec::new(),
            tranche_sizes: vec![10],
            include_html_enrichment: true,
        };
        let filtered =
            filter_requested_source_lists(vec![list_summary(111)], &request.source_list_ids);

        let report = WarmupAudienceReadinessReport::from_lists(
            &request,
            filtered,
            Vec::new(),
            Evidence {
                source: "test".to_string(),
                notes: Vec::new(),
            },
        );

        assert_eq!(report.missing_list_ids, vec![72, 114]);
        assert_eq!(report.gross_subscribed_count, 1110);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning == "missing specified source list ids: 72, 114"));
    }

    #[test]
    fn hygiene_export_with_no_explicit_sources_writes_no_artifacts() {
        let backend = LiveInterspireBackend::new(InterspireServerConfig::default());
        let report = backend
            .audience_hygiene_export(&AudienceHygieneExportRequest {
                source_list_ids: Vec::new(),
                output_dir: Some(std::env::temp_dir().display().to_string()),
                artifact_prefix: Some("blocked".to_string()),
                include_sqlite: true,
            })
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(report.ok);
        assert!(report.source_list_ids.is_empty());
        assert!(report.artifacts.is_empty());
        assert!(!report.legacy_lists_mutated);
        assert!(!report.production_send_authorized);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("no explicit audience hygiene source list ids")));
    }
}

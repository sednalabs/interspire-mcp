use super::support::{filter_requested_source_lists, join_ids_for_warning};
use super::LiveInterspireBackend;
use crate::{
    audience_hygiene::{self, HygieneListInput},
    error::InterspireError,
    response::{
        approved_hygiene_source_list_ids, approved_warmup_source_list_ids,
        blocked_hygiene_source_list_ids, AudienceHygieneExportReport, AudienceHygieneExportRequest,
        WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest,
    },
    xml_api,
};

impl LiveInterspireBackend {
    pub(super) fn warmup_audience_readiness_impl(
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
        let mut notes = vec!["lists/GetLists XML API read".to_string()];

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

    pub(super) fn audience_hygiene_export_impl(
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
                "lists/GetLists XML API read".to_string(),
                "subscribers/GetSubscribers XML API read for each matched explicit source list; large lists use bounded domain-prefix shards to avoid truncated XML responses".to_string(),
                "private local artifacts written outside repository with aggregate MCP response"
                    .to_string(),
            ]),
            warnings,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::LiveInterspireBackend;
    use crate::{
        config::InterspireServerConfig, response::AudienceHygieneExportRequest,
        InterspireReadBackend,
    };

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

use super::LiveInterspireBackend;
use crate::{
    error::InterspireError,
    guarded_write, oci_ledger,
    response::{
        CampaignTestSendApplyReport, CampaignTestSendApplyRequest, OciLedgerPreflightReport,
        OciSendLedgerPrepareApplyRequest, OciSendLedgerPreparePreviewRequest,
        OciSendLedgerPrepareReport, ProductionSendApplyReport, ProductionSendApplyRequest,
        SeedSendApplyReport, SeedSendApplyRequest,
    },
};

impl LiveInterspireBackend {
    pub(super) fn campaign_test_send_apply_impl(
        &self,
        request: &CampaignTestSendApplyRequest,
    ) -> Result<CampaignTestSendApplyReport, InterspireError> {
        guarded_write::require_send_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        html.campaign_test_send_apply(request)
    }

    pub(super) fn oci_send_ledger_prepare_preview_impl(
        &self,
        request: &OciSendLedgerPreparePreviewRequest,
    ) -> Result<OciSendLedgerPrepareReport, InterspireError> {
        oci_ledger::prepare_preview(&self.config.oci_send_ledger, request)
    }

    pub(super) fn oci_send_ledger_prepare_apply_impl(
        &self,
        request: &OciSendLedgerPrepareApplyRequest,
    ) -> Result<OciSendLedgerPrepareReport, InterspireError> {
        oci_ledger::prepare_apply(
            &self.config.guarded_writes,
            &self.config.oci_send_ledger,
            request,
        )
    }

    pub(super) fn seed_send_apply_impl(
        &self,
        request: &SeedSendApplyRequest,
    ) -> Result<SeedSendApplyReport, InterspireError> {
        guarded_write::require_send_controls_enabled(&self.config.guarded_writes)?;
        let oci_preflight = oci_ledger::verify_preflight(
            &self.config.oci_send_ledger,
            request.oci_ledger_preflight.as_ref(),
            request.expected_recipient_count,
            Some(request.campaign_id),
        );
        if oci_preflight_blocks_seed(request, &oci_preflight) {
            return Ok(SeedSendApplyReport::denied(
                request,
                self.config.guarded_writes.enabled,
                self.config.guarded_writes.send_controls_enabled,
                oci_preflight_refusal_note(&oci_preflight),
            )
            .with_oci_ledger_preflight(oci_preflight));
        }
        let html = self.html_client()?;
        html.seed_send_apply(
            request,
            self.config.guarded_writes.enabled,
            self.config.guarded_writes.send_controls_enabled,
        )
        .map(|report| report.with_oci_ledger_preflight(oci_preflight))
    }

    pub(super) fn production_send_apply_impl(
        &self,
        request: &ProductionSendApplyRequest,
    ) -> Result<ProductionSendApplyReport, InterspireError> {
        guarded_write::require_production_send_controls_enabled(&self.config.guarded_writes)?;
        let oci_preflight = oci_ledger::verify_preflight(
            &self.config.oci_send_ledger,
            request.oci_ledger_preflight.as_ref(),
            request.expected_recipient_count,
            Some(request.campaign_id),
        );
        if oci_preflight_blocks_production(request, &oci_preflight) {
            return Ok(ProductionSendApplyReport::denied(
                request,
                self.config.guarded_writes.enabled,
                self.config.guarded_writes.send_controls_enabled,
                self.config.guarded_writes.production_send_controls_enabled,
                oci_preflight_refusal_note(&oci_preflight),
            )
            .with_oci_ledger_preflight(oci_preflight));
        }
        let html = self.html_client()?;
        html.production_send_apply(
            request,
            self.config.guarded_writes.enabled,
            self.config.guarded_writes.send_controls_enabled,
            self.config.guarded_writes.production_send_controls_enabled,
        )
        .map(|report| report.with_oci_ledger_preflight(oci_preflight))
    }
}

fn oci_preflight_blocks_seed(
    request: &SeedSendApplyRequest,
    report: &OciLedgerPreflightReport,
) -> bool {
    !report.verified && (report.required || request.oci_ledger_preflight.is_some())
}

fn oci_preflight_blocks_production(
    request: &ProductionSendApplyRequest,
    report: &OciLedgerPreflightReport,
) -> bool {
    !report.verified && (report.required || request.oci_ledger_preflight.is_some())
}

fn oci_preflight_refusal_note(report: &OciLedgerPreflightReport) -> String {
    report
        .warnings
        .first()
        .cloned()
        .unwrap_or_else(|| {
            "OCI send ledger preflight did not verify; send refused before the Interspire final send boundary".to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{GuardedWriteConfig, OciSendLedgerConfig},
        response::OciLedgerPreflightRequest,
        InterspireServerConfig,
    };
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn required_oci_ledger_blocks_seed_send_before_admin_html() {
        let backend = LiveInterspireBackend::new(InterspireServerConfig {
            guarded_writes: GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            oci_send_ledger: OciSendLedgerConfig {
                path: None,
                required_for_sends: true,
            },
            ..InterspireServerConfig::default()
        });

        let report = backend
            .seed_send_apply_impl(&SeedSendApplyRequest {
                campaign_id: 7,
                list_ids: vec![3],
                expected_recipient_count: 1,
                expected_from_email: Some("sender@example.invalid".to_string()),
                expected_reply_to_email: Some("editor@example.invalid".to_string()),
                expected_subject: Some("Launch subject".to_string()),
                expected_html_sha256: None,
                max_queue_rows: Some(25),
                oci_ledger_preflight: Some(OciLedgerPreflightRequest {
                    campaign_id: "7".to_string(),
                    batch_id: "batch-private".to_string(),
                    expected_rows: 1,
                    sender_domain: Some("example.invalid".to_string()),
                    expected_manifest_sha256: None,
                }),
                acknowledge_seed_send: true,
            })
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.sent);
        assert!(report.oci_ledger_preflight.required);
        assert!(!report.oci_ledger_preflight.configured);
        assert!(!report.oci_ledger_preflight.verified);
        assert!(!report.oci_ledger_preflight.warnings.is_empty());
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note == "no send request sent"));
    }

    #[test]
    fn required_oci_ledger_blocks_seed_send_when_ledger_campaign_does_not_match_request() {
        let path = fixture_path("wrong-campaign");
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(
            &path,
            "{\"campaign_id\":\"other-campaign\",\"batch_id\":\"batch-private\",\"sender_domain\":\"example.invalid\",\"recipient_hash\":\"recipient\",\"message_id_hash\":\"message\"}\n",
        )
        .expect("write fixture");
        let backend = LiveInterspireBackend::new(InterspireServerConfig {
            guarded_writes: GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            oci_send_ledger: OciSendLedgerConfig {
                path: Some(path.to_string_lossy().to_string()),
                required_for_sends: true,
            },
            ..InterspireServerConfig::default()
        });

        let report = backend
            .seed_send_apply_impl(&SeedSendApplyRequest {
                campaign_id: 7,
                list_ids: vec![3],
                expected_recipient_count: 1,
                expected_from_email: Some("sender@example.invalid".to_string()),
                expected_reply_to_email: Some("editor@example.invalid".to_string()),
                expected_subject: Some("Launch subject".to_string()),
                expected_html_sha256: None,
                max_queue_rows: Some(25),
                oci_ledger_preflight: Some(OciLedgerPreflightRequest {
                    campaign_id: "other-campaign".to_string(),
                    batch_id: "batch-private".to_string(),
                    expected_rows: 1,
                    sender_domain: Some("example.invalid".to_string()),
                    expected_manifest_sha256: None,
                }),
                acknowledge_seed_send: true,
            })
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.sent);
        assert!(!report.oci_ledger_preflight.verified);
        assert!(report
            .oci_ledger_preflight
            .warnings
            .iter()
            .any(|warning| warning.contains("must match the Interspire campaign")));
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note == "no send request sent"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn required_oci_ledger_blocks_production_send_before_admin_html() {
        let backend = LiveInterspireBackend::new(InterspireServerConfig {
            guarded_writes: GuardedWriteConfig {
                enabled: true,
                send_controls_enabled: true,
                production_send_controls_enabled: true,
                ..GuardedWriteConfig::default()
            },
            oci_send_ledger: OciSendLedgerConfig {
                path: None,
                required_for_sends: true,
            },
            ..InterspireServerConfig::default()
        });

        let report = backend
            .production_send_apply_impl(&ProductionSendApplyRequest {
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
                oci_ledger_preflight: None,
                acknowledge_production_send: true,
                confirmation_phrase: "SEND_PRODUCTION_CAMPAIGN".to_string(),
            })
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(!report.ok);
        assert!(!report.sent);
        assert!(report.oci_ledger_preflight.required);
        assert!(!report.oci_ledger_preflight.configured);
        assert!(!report.oci_ledger_preflight.requested);
        assert!(!report.oci_ledger_preflight.verified);
        assert!(report
            .oci_ledger_preflight
            .warnings
            .iter()
            .any(|warning| warning.contains("was not requested")));
        assert!(report
            .evidence
            .notes
            .iter()
            .any(|note| note == "no production send request sent"));
    }

    fn fixture_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        PathBuf::from(format!(
            "target/interspire-live-oci-ledger-tests/{label}-{unique}.jsonl"
        ))
    }
}

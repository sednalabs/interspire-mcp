//! # Interspire MCP
//!
//! Curated stdio MCP server for safe Interspire Email Marketer
//! operational readback plus guarded queue, form-write, template, artifact, and
//! send paths.
//!
//! ## Rationale
//!
//! Agents need structured evidence from Interspire before comparing Mailgun
//! provider events with campaign/list/contact state. This crate keeps that
//! evidence-gathering surface narrow by default and treats every write as an
//! explicitly enabled preview/apply operation.
//!
//! ## Security Boundaries
//!
//! * Exposes read-only intent tools by default.
//! * Uses the Interspire XML API first.
//! * Allows authenticated admin HTML only for login plus explicitly allowlisted
//!   safe GET pages and guarded queue/form apply routes.
//! * Blocks generic send, schedule, cron, generic import/export, contact
//!   mutation, suppression mutation, provider mutation, and raw admin escape
//!   paths.
//! * Allows one narrow, explicit audience-hygiene artifact export that writes
//!   private local files and returns aggregate metadata only.
//! * Allows queue cancel/delete plus guarded campaign/list/user/settings edits
//!   only through deterministic preview/apply plan ids and explicit runtime
//!   write flags.
//! * Allows a guarded seed-send apply tool only when send controls are
//!   explicitly enabled and the immediate seed-readiness proof passes.
//! * Allows a guarded production-send apply tool only when production send
//!   controls are explicitly enabled and the strict immediate readiness proof
//!   plus confirmation phrase pass.
//! * Redacts credentials, cookies, raw contacts, private headers, SMTP secrets,
//!   bounce secrets, and license values from tool output.
//!
//! ## References
//!
//! * `AGENTS.md`
//! * `docs/architecture.md`
//! * `docs/safety-model.md`

mod admin_html;
mod audience_hygiene;
mod audience_hygiene_checkpoint;
mod config;
mod error;
mod guarded_write;
mod live;
mod oci_ledger;
mod private_artifacts;
mod redact;
mod response;
mod safety;
mod xml_api;

use std::{future::Future, sync::Arc};

pub use config::{AdminHtmlConfig, InterspireServerConfig, InterspireVersion, XmlApiConfig};
pub use error::InterspireError;
use mcp_toolkit_core::{
    guarded_action::GuardedActionPosture,
    mcp_apps::{with_mcp_apps_no_mutation_proof_metadata, with_mcp_apps_sensitive_output_metadata},
    tool_inventory::{ToolCapability, ToolDiscoveryMetadata, ToolInventory, ToolInventoryError},
};
pub use response::{
    AdminSessionProbeReport, AdminSessionProbeRequest, AudienceHygieneArtifact,
    AudienceHygieneExportBeginRequest, AudienceHygieneExportReport, AudienceHygieneExportRequest,
    AudienceHygieneExportResumeRequest, AudienceHygieneExportStatusRequest,
    AudienceHygieneListSummary, CampaignBodyAuditReport, CampaignBodyAuditRequest,
    CampaignCopyApplyReport, CampaignCopyApplyRequest, CampaignCopyPreviewReport,
    CampaignCopyPreviewRequest, CampaignReadbackReport, CampaignReadbackRequest,
    CampaignRenderArtifactReport, CampaignRenderArtifactRequest,
    CampaignTemplateArtifactUpdateApplyReport, CampaignTemplateArtifactUpdateApplyRequest,
    CampaignTemplateArtifactUpdatePreviewReport, CampaignTemplateArtifactUpdatePreviewRequest,
    CampaignTemplateUpdateApplyRequest, CampaignTemplateUpdatePreviewRequest,
    CampaignTestSendApplyReport, CampaignTestSendApplyRequest, CampaignTestSendPreviewReport,
    CampaignTestSendPreviewRequest, CampaignUpdateApplyRequest, CampaignUpdatePreviewRequest,
    ContactImportPreflightReport, ContactImportPreflightRequest, ContactStateReport,
    ContactStateRequest, Evidence, FormFieldChange, FormFieldDescriptor, FormFieldUpdate,
    GuardedWriteApplyReport, GuardedWritePreviewReport, ListCreateApplyRequest,
    ListCreatePreviewRequest, ListOwnerReadbackReport, ListOwnerReadbackRequest, ListSummary,
    ListSummaryReport, ListSummaryRequest, ListUpdateApplyRequest, ListUpdatePreviewRequest,
    OciLedgerPreflightReport, OciLedgerPreflightRequest, ProductionSendApplyReport,
    ProductionSendApplyRequest, QueueControlAction, QueueControlApplyReport,
    QueueControlApplyRequest, QueueControlCandidate, QueueControlPreviewReport,
    QueueControlPreviewRequest, QueueStatsReadbackReport, QueueStatsReadbackRequest,
    RenderArtifact, SeedReadinessGate, SeedReadinessGateReport, SeedReadinessGateRequest,
    SeedSendApplyReport, SeedSendApplyRequest, SendApplyStatus, SendReconciliationReport,
    SendWizardReadbackReport, SendWizardReadbackRequest, SensitiveFieldDenial,
    SensitiveFieldQueryReport, SensitiveFieldQueryRequest, SensitiveFieldTarget,
    SensitiveFieldValue, SensitiveToolMetadata, SettingsAuditReport, SettingsAuditRequest,
    SettingsInventoryReport, SettingsInventoryRequest, SettingsSectionName,
    SettingsUpdateApplyRequest, SettingsUpdatePreviewRequest, StatusReport, StatusRequest,
    UserSmtpReadbackReport, UserSmtpReadbackRequest, UserUpdateApplyRequest,
    UserUpdatePreviewRequest, WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest,
    XmlAuthProbeReport, XmlAuthProbeRequest, DEFAULT_HYGIENE_QUERY_BUDGET, DEFAULT_LIST_READ_LIMIT,
    HARD_HYGIENE_QUERY_BUDGET, HARD_LIST_READ_LIMIT,
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        ListToolsResult, Meta, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
        ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};

pub fn run_audience_hygiene_export(
    config: InterspireServerConfig,
    request: &AudienceHygieneExportRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let backend = live::LiveInterspireBackend::new(config);
    backend.audience_hygiene_export(request)
}

pub fn run_audience_hygiene_export_begin(
    config: InterspireServerConfig,
    request: &AudienceHygieneExportBeginRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let backend = live::LiveInterspireBackend::new(config);
    backend.audience_hygiene_export_begin(request)
}

pub fn run_audience_hygiene_export_resume(
    config: InterspireServerConfig,
    request: &AudienceHygieneExportResumeRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let backend = live::LiveInterspireBackend::new(config);
    backend.audience_hygiene_export_resume(request)
}

pub fn run_audience_hygiene_export_status(
    config: InterspireServerConfig,
    request: &AudienceHygieneExportStatusRequest,
) -> Result<AudienceHygieneExportReport, InterspireError> {
    let backend = live::LiveInterspireBackend::new(config);
    backend.audience_hygiene_export_status(request)
}

pub trait InterspireReadBackend: Send + Sync {
    fn status(&self, request: &StatusRequest) -> Result<StatusReport, InterspireError>;
    fn xml_auth_probe(
        &self,
        request: &XmlAuthProbeRequest,
    ) -> Result<XmlAuthProbeReport, InterspireError>;
    fn list_summary(
        &self,
        request: &ListSummaryRequest,
    ) -> Result<ListSummaryReport, InterspireError>;
    fn contact_state(
        &self,
        request: &ContactStateRequest,
    ) -> Result<ContactStateReport, InterspireError>;
    fn list_owner_readback(
        &self,
        request: &ListOwnerReadbackRequest,
    ) -> Result<ListOwnerReadbackReport, InterspireError>;
    fn settings_audit(
        &self,
        request: &SettingsAuditRequest,
    ) -> Result<SettingsAuditReport, InterspireError>;
    fn settings_inventory(
        &self,
        request: &SettingsInventoryRequest,
    ) -> Result<SettingsInventoryReport, InterspireError>;
    fn admin_session_probe(
        &self,
        request: &AdminSessionProbeRequest,
    ) -> Result<AdminSessionProbeReport, InterspireError>;
    fn user_smtp_readback(
        &self,
        request: &UserSmtpReadbackRequest,
    ) -> Result<UserSmtpReadbackReport, InterspireError>;
    fn queue_stats_readback(
        &self,
        request: &QueueStatsReadbackRequest,
    ) -> Result<QueueStatsReadbackReport, InterspireError>;
    fn queue_control_preview(
        &self,
        request: &QueueControlPreviewRequest,
    ) -> Result<QueueControlPreviewReport, InterspireError>;
    fn queue_control_apply(
        &self,
        request: &QueueControlApplyRequest,
    ) -> Result<QueueControlApplyReport, InterspireError>;
    fn campaign_readback(
        &self,
        request: &CampaignReadbackRequest,
    ) -> Result<CampaignReadbackReport, InterspireError>;
    fn campaign_body_audit(
        &self,
        request: &CampaignBodyAuditRequest,
    ) -> Result<CampaignBodyAuditReport, InterspireError>;
    fn campaign_render_artifact(
        &self,
        request: &CampaignRenderArtifactRequest,
    ) -> Result<CampaignRenderArtifactReport, InterspireError>;
    fn campaign_test_send_preview(
        &self,
        request: &CampaignTestSendPreviewRequest,
    ) -> Result<CampaignTestSendPreviewReport, InterspireError>;
    fn campaign_test_send_apply(
        &self,
        request: &CampaignTestSendApplyRequest,
    ) -> Result<CampaignTestSendApplyReport, InterspireError>;
    fn send_wizard_readback(
        &self,
        request: &SendWizardReadbackRequest,
    ) -> Result<SendWizardReadbackReport, InterspireError>;
    fn seed_readiness_gate(
        &self,
        request: &SeedReadinessGateRequest,
    ) -> Result<SeedReadinessGateReport, InterspireError>;
    fn seed_send_apply(
        &self,
        request: &SeedSendApplyRequest,
    ) -> Result<SeedSendApplyReport, InterspireError>;
    fn production_send_apply(
        &self,
        request: &ProductionSendApplyRequest,
    ) -> Result<ProductionSendApplyReport, InterspireError>;
    fn campaign_update_preview(
        &self,
        request: &CampaignUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError>;
    fn campaign_update_apply(
        &self,
        request: &CampaignUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError>;
    fn list_update_preview(
        &self,
        request: &ListUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError>;
    fn list_update_apply(
        &self,
        request: &ListUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError>;
    fn list_create_preview(
        &self,
        request: &ListCreatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError>;
    fn list_create_apply(
        &self,
        request: &ListCreateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError>;
    fn campaign_copy_preview(
        &self,
        request: &CampaignCopyPreviewRequest,
    ) -> Result<CampaignCopyPreviewReport, InterspireError>;
    fn campaign_copy_apply(
        &self,
        request: &CampaignCopyApplyRequest,
    ) -> Result<CampaignCopyApplyReport, InterspireError>;
    fn contact_import_preflight(
        &self,
        request: &ContactImportPreflightRequest,
    ) -> Result<ContactImportPreflightReport, InterspireError>;
    fn user_update_preview(
        &self,
        request: &UserUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError>;
    fn user_update_apply(
        &self,
        request: &UserUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError>;
    fn settings_update_preview(
        &self,
        request: &SettingsUpdatePreviewRequest,
    ) -> Result<GuardedWritePreviewReport, InterspireError>;
    fn settings_update_apply(
        &self,
        request: &SettingsUpdateApplyRequest,
    ) -> Result<GuardedWriteApplyReport, InterspireError>;
    fn sensitive_field_query(
        &self,
        request: &SensitiveFieldQueryRequest,
    ) -> Result<SensitiveFieldQueryReport, InterspireError>;
    fn warmup_audience_readiness(
        &self,
        request: &WarmupAudienceReadinessRequest,
    ) -> Result<WarmupAudienceReadinessReport, InterspireError>;
    fn audience_hygiene_export(
        &self,
        request: &AudienceHygieneExportRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError>;
    fn audience_hygiene_export_begin(
        &self,
        request: &AudienceHygieneExportBeginRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError>;
    fn audience_hygiene_export_resume(
        &self,
        request: &AudienceHygieneExportResumeRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError>;
    fn audience_hygiene_export_status(
        &self,
        request: &AudienceHygieneExportStatusRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError>;
}

#[derive(Clone)]
pub struct InterspireMcpServer {
    backend: Arc<dyn InterspireReadBackend>,
    tool_router: ToolRouter<Self>,
    inventory: ToolInventory,
}

impl InterspireMcpServer {
    pub fn new(config: InterspireServerConfig) -> Result<Self, ToolInventoryError> {
        Self::with_backend(Arc::new(live::LiveInterspireBackend::new(config)))
    }

    pub fn with_backend(
        backend: Arc<dyn InterspireReadBackend>,
    ) -> Result<Self, ToolInventoryError> {
        Ok(Self {
            backend,
            tool_router: Self::tool_router(),
            inventory: ToolInventory::from_capabilities([
                ToolCapability::new("interspire_status")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Report Interspire MCP configuration and safe read capability.",
                        ["interspire", "status", "read-only"],
                    )),
                ToolCapability::new("interspire_xml_auth_probe")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Probe Interspire XML API authentication with authentication/XmlApiTest.",
                        ["interspire", "xml", "auth", "probe"],
                    )),
                ToolCapability::new("interspire_list_summary")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Summarize Interspire contact lists and aggregate state counts.",
                        ["interspire", "lists", "summary"],
                    )),
                ToolCapability::new("interspire_contact_state")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Check one redacted contact's Interspire list presence with XML first and exact admin-HTML fallback.",
                        ["interspire", "contact", "presence"],
                    )),
                ToolCapability::new("interspire_list_owner_readback")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Read Interspire list owner, reply-to, and bounce metadata.",
                        ["interspire", "lists", "owners"],
                    )),
                ToolCapability::new("interspire_settings_audit")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Read redacted Interspire global settings for email, bounce, and cron.",
                        ["interspire", "settings", "audit"],
                    )),
                ToolCapability::new("interspire_settings_inventory")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Inventory redacted Interspire settings form fields across allowlisted tabs.",
                        ["interspire", "settings", "inventory", "audit"],
                    )),
                ToolCapability::new("interspire_admin_session_probe")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Probe authenticated admin HTML reachability through allowlisted read pages.",
                        ["interspire", "admin", "session", "probe"],
                    )),
                ToolCapability::new("interspire_user_smtp_readback")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Read redacted per-user SMTP override state.",
                        ["interspire", "users", "smtp"],
                    )),
                ToolCapability::new("interspire_queue_stats_readback")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Read scheduled queue and stats page summaries without triggering cron.",
                        ["interspire", "queue", "stats"],
                    )),
                ToolCapability::new("interspire_queue_control_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview cancel/delete plan ids for Interspire scheduled queue rows.",
                        ["interspire", "queue", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_queue_control_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a previously previewed Interspire scheduled queue cancel/delete plan.",
                        ["interspire", "queue", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_campaign_readback")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Read campaign manage rows or one campaign edit page summary.",
                        ["interspire", "campaign", "readback"],
                    )),
                ToolCapability::new("interspire_campaign_body_audit")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Audit redacted campaign body safety signals without returning raw HTML.",
                        ["interspire", "campaign", "body", "audit"],
                    )),
                ToolCapability::new("interspire_campaign_render_artifact")
                    .with_group("read")
                    .with_risk_posture(GuardedActionPosture::no_mutation_proof())
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Write private persisted-campaign render artifacts for native-browser screenshot inspection.",
                        [
                            "interspire",
                            "campaign",
                            "render",
                            "artifact",
                            "native-browser",
                        ],
                    )),
                ToolCapability::new("interspire_campaign_test_send_preview")
                    .with_group("guarded-send")
                    .with_risk_posture(GuardedActionPosture::no_mutation_proof())
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview a one-recipient Interspire campaign preview/test send without sending or mutating lists.",
                        ["interspire", "campaign", "test", "preview", "send"],
                    )),
                ToolCapability::new("interspire_campaign_test_send_apply")
                    .with_group("guarded-send")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply one explicitly acknowledged Interspire campaign preview/test send to a single recipient.",
                        [
                            "interspire",
                            "campaign",
                            "test",
                            "send",
                            "apply",
                            "guarded-send",
                        ],
                    )),
                ToolCapability::new("interspire_send_wizard_readback")
                    .with_group("read")
                    .with_risk_posture(GuardedActionPosture::no_mutation_proof())
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Render the send wizard through the no-send preview boundary and verify queue/stat invariants.",
                        ["interspire", "send", "wizard", "readback", "no-send"],
                    )),
                ToolCapability::new("interspire_seed_readiness_gate")
                    .with_group("read")
                    .with_risk_posture(GuardedActionPosture::no_mutation_proof())
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Combine campaign body audit and no-send wizard proof into seed-readiness gates.",
                        ["interspire", "seed", "readiness", "gate", "no-send"],
                    )),
                ToolCapability::new("interspire_seed_send_apply")
                    .with_group("guarded-send")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply one explicitly acknowledged seed send after immediate readiness proof and optional OCI ledger preflight.",
                        [
                            "interspire",
                            "seed",
                            "send",
                            "apply",
                            "guarded-send",
                            "oci-ledger",
                        ],
                    )),
                ToolCapability::new("interspire_production_send_apply")
                    .with_group("guarded-send")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply an explicitly acknowledged production send after strict immediate readiness proof and optional OCI ledger preflight.",
                        [
                            "interspire",
                            "production",
                            "send",
                            "apply",
                            "guarded-send",
                            "oci-ledger",
                        ],
                    )),
                ToolCapability::new("interspire_campaign_template_update_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview semantic EDM template edits such as subject, HTML body, text body, and tracking flags.",
                        ["interspire", "campaign", "template", "preview", "edm"],
                    )),
                ToolCapability::new("interspire_campaign_template_update_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a previously previewed semantic EDM template edit.",
                        ["interspire", "campaign", "template", "apply", "edm"],
                    )),
                ToolCapability::new("interspire_campaign_template_artifact_update_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview applying a private render artifact to a campaign template without returning raw HTML.",
                        ["interspire", "campaign", "template", "artifact", "preview"],
                    )),
                ToolCapability::new("interspire_campaign_template_artifact_update_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a previously previewed private render artifact to a campaign template and prove the persisted body hash.",
                        ["interspire", "campaign", "template", "artifact", "apply"],
                    )),
                ToolCapability::new("interspire_campaign_update_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview guarded campaign content or sender metadata edits.",
                        ["interspire", "campaign", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_campaign_update_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a guarded campaign content or sender metadata edit.",
                        ["interspire", "campaign", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_list_update_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview guarded list metadata edits.",
                        ["interspire", "list", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_list_update_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a guarded list metadata edit.",
                        ["interspire", "list", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_list_create_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview a guarded Interspire contact-list creation plan.",
                        ["interspire", "list", "create", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_list_create_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a previously previewed Interspire contact-list creation plan.",
                        ["interspire", "list", "create", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_campaign_copy_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview a guarded campaign-copy plan for creating a draft from a known campaign.",
                        ["interspire", "campaign", "copy", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_campaign_copy_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a previously previewed campaign-copy plan and return the new draft id.",
                        ["interspire", "campaign", "copy", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_contact_import_preflight")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preflight a local cleaned CSV import candidate with aggregate counts and hash only.",
                        ["interspire", "contact", "import", "preflight", "csv"],
                    )),
                ToolCapability::new("interspire_user_update_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview guarded user profile or footer edits.",
                        ["interspire", "user", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_user_update_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply a guarded user profile or footer edit.",
                        ["interspire", "user", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_settings_update_preview")
                    .with_group("guarded-write")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Preview guarded non-secret Interspire settings edits.",
                        ["interspire", "settings", "preview", "guarded-write"],
                    )),
                ToolCapability::new("interspire_settings_update_apply")
                    .with_group("guarded-write")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply guarded non-secret Interspire settings edits.",
                        ["interspire", "settings", "apply", "guarded-write"],
                    )),
                ToolCapability::new("interspire_sensitive_field_query")
                    .with_group("sensitive-read")
                    .with_risk_posture(GuardedActionPosture::sensitive_read())
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Query exact approved Interspire admin form fields with unredacted values after runtime and acknowledgement gates.",
                        [
                            "interspire",
                            "sensitive",
                            "unredacted",
                            "field",
                            "setup",
                        ],
                    )),
                ToolCapability::new("interspire_warmup_audience_readiness")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Assess a specified-list warm-up audience from Interspire list counts without exporting contacts.",
                        ["interspire", "audience", "warmup", "readiness"],
                    )),
                ToolCapability::new("interspire_audience_hygiene_export")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Export explicitly requested Interspire audience hygiene artifacts privately and return aggregate counts only.",
                        ["interspire", "audience", "hygiene", "mailgun", "sqlite"],
                    )),
                ToolCapability::new("interspire_audience_hygiene_export_begin")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Begin a checkpointed audience hygiene export job and advance a bounded number of XML subscriber queries.",
                        ["interspire", "audience", "hygiene", "checkpoint", "begin"],
                    )),
                ToolCapability::new("interspire_audience_hygiene_export_resume")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Resume a checkpointed audience hygiene export job for a bounded number of XML subscriber queries.",
                        ["interspire", "audience", "hygiene", "checkpoint", "resume"],
                    )),
                ToolCapability::new("interspire_audience_hygiene_export_status")
                    .with_group("read")
                    .with_read_only(true)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Read checkpointed audience hygiene export job status without advancing the export.",
                        ["interspire", "audience", "hygiene", "checkpoint", "status"],
                    )),
            ])?,
        })
    }

    pub fn tool_schema_snapshot(&self) -> Vec<Tool> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(with_interspire_tool_metadata)
            .collect()
    }

    pub fn inventory(&self) -> &ToolInventory {
        &self.inventory
    }

    fn campaign_template_artifact_update_preview(
        &self,
        request: &CampaignTemplateArtifactUpdatePreviewRequest,
    ) -> Result<CampaignTemplateArtifactUpdatePreviewReport, InterspireError> {
        let artifact_input = read_template_artifacts_for_preview(request)?;
        let mut guarded_preview =
            self.backend
                .campaign_update_preview(&CampaignUpdatePreviewRequest {
                    campaign_id: request.campaign_id,
                    updates: request.updates_with_bodies(
                        &artifact_input.html.contents,
                        artifact_input
                            .text
                            .as_ref()
                            .map(|artifact| artifact.contents.as_str()),
                    ),
                })?;
        scrub_template_body_preview_report(&mut guarded_preview);

        Ok(CampaignTemplateArtifactUpdatePreviewReport {
            ok: guarded_preview.ok,
            configured: guarded_preview.configured,
            campaign_id: request.campaign_id,
            artifacts: artifact_input.summaries,
            guarded_preview,
            production_send_authorized: false,
            warnings: vec![
                "preview only; raw artifact contents were read privately and are not returned"
                    .to_string(),
                "this tool does not send, schedule, import contacts, or authorize production mail"
                    .to_string(),
            ],
            evidence: response::Evidence {
                source: "private_render_artifact+interspire_admin_html".to_string(),
                notes: vec![
                    "fixed private render artifact read".to_string(),
                    "guarded campaign template update preview".to_string(),
                ],
            },
        })
    }

    fn campaign_template_artifact_update_apply(
        &self,
        request: &CampaignTemplateArtifactUpdateApplyRequest,
    ) -> Result<CampaignTemplateArtifactUpdateApplyReport, InterspireError> {
        let artifact_input = read_template_artifacts_for_apply(request)?;
        let mut guarded_apply =
            self.backend
                .campaign_update_apply(&CampaignUpdateApplyRequest {
                    campaign_id: request.campaign_id,
                    plan_id: request.plan_id.clone(),
                    updates: request.updates_with_bodies(
                        &artifact_input.html.contents,
                        artifact_input
                            .text
                            .as_ref()
                            .map(|artifact| artifact.contents.as_str()),
                    ),
                })?;
        scrub_template_body_apply_report(&mut guarded_apply);
        let campaign_body = self
            .backend
            .campaign_body_audit(&CampaignBodyAuditRequest {
                campaign_id: request.campaign_id,
            })?;
        if campaign_body.html_sha256.as_deref() != Some(artifact_input.html.sha256.as_str()) {
            return Err(InterspireError::Safety(
                "campaign template artifact apply did not persist the expected HTML SHA-256"
                    .to_string(),
            ));
        }
        if let Some(text_artifact) = artifact_input.text.as_ref() {
            if campaign_body.text_sha256.as_deref() != Some(text_artifact.sha256.as_str()) {
                return Err(InterspireError::Safety(
                    "campaign template artifact apply did not persist the expected text SHA-256"
                        .to_string(),
                ));
            }
        }

        Ok(CampaignTemplateArtifactUpdateApplyReport {
            ok: guarded_apply.ok && campaign_body.ok,
            configured: guarded_apply.configured,
            campaign_id: request.campaign_id,
            artifacts: artifact_input.summaries,
            guarded_apply,
            campaign_body,
            production_send_authorized: false,
            warnings: vec![
                "guarded artifact template apply completed; this did not send, schedule, import contacts, or authorize production mail".to_string(),
            ],
            evidence: response::Evidence {
                source: "private_render_artifact+interspire_admin_html".to_string(),
                notes: vec![
                    "fixed private render artifact read".to_string(),
                    "guarded campaign template update apply".to_string(),
                    "post-apply campaign body audit matched artifact hash".to_string(),
                ],
            },
        })
    }
}

struct TemplateArtifactInput {
    html: private_artifacts::PrivateTextArtifact,
    text: Option<private_artifacts::PrivateTextArtifact>,
    summaries: Vec<response::TemplateArtifactSummary>,
}

fn read_template_artifacts_for_preview(
    request: &CampaignTemplateArtifactUpdatePreviewRequest,
) -> Result<TemplateArtifactInput, InterspireError> {
    read_template_artifacts(
        &request.html_artifact_path,
        request.expected_html_sha256.as_deref(),
        request.expected_html_bytes,
        request.text_artifact_path.as_deref(),
        request.expected_text_sha256.as_deref(),
        request.expected_text_bytes,
    )
}

fn read_template_artifacts_for_apply(
    request: &CampaignTemplateArtifactUpdateApplyRequest,
) -> Result<TemplateArtifactInput, InterspireError> {
    read_template_artifacts(
        &request.html_artifact_path,
        request.expected_html_sha256.as_deref(),
        request.expected_html_bytes,
        request.text_artifact_path.as_deref(),
        request.expected_text_sha256.as_deref(),
        request.expected_text_bytes,
    )
}

fn read_template_artifacts(
    html_artifact_path: &str,
    expected_html_sha256: Option<&str>,
    expected_html_bytes: Option<u64>,
    text_artifact_path: Option<&str>,
    expected_text_sha256: Option<&str>,
    expected_text_bytes: Option<u64>,
) -> Result<TemplateArtifactInput, InterspireError> {
    let html = private_artifacts::read_private_render_text_artifact(
        html_artifact_path,
        "HTML template artifact",
        expected_html_sha256,
        expected_html_bytes,
    )?;
    if html.contents.trim().is_empty() {
        return Err(InterspireError::Safety(
            "HTML template artifact must not be empty".to_string(),
        ));
    }
    let text = text_artifact_path
        .filter(|value| !value.trim().is_empty())
        .map(|path| {
            private_artifacts::read_private_render_text_artifact(
                path,
                "text template artifact",
                expected_text_sha256,
                expected_text_bytes,
            )
        })
        .transpose()?;

    let mut summaries = vec![template_artifact_summary("html", &html)];
    if let Some(text_artifact) = text.as_ref() {
        summaries.push(template_artifact_summary("text", text_artifact));
    }

    Ok(TemplateArtifactInput {
        html,
        text,
        summaries,
    })
}

fn template_artifact_summary(
    kind: &str,
    artifact: &private_artifacts::PrivateTextArtifact,
) -> response::TemplateArtifactSummary {
    response::TemplateArtifactSummary {
        kind: kind.to_string(),
        file_name: artifact.file_name.clone(),
        bytes: artifact.bytes,
        sha256: artifact.sha256.clone(),
    }
}

fn scrub_template_body_preview_report(report: &mut GuardedWritePreviewReport) {
    for change in &mut report.changes {
        scrub_template_body_change(change);
    }
}

fn scrub_template_body_apply_report(report: &mut GuardedWriteApplyReport) {
    for change in &mut report.changes {
        scrub_template_body_change(change);
    }
    for field in &mut report.post_apply_fields {
        if is_template_body_field_name(&field.name) {
            field.value =
                Some("[private template body redacted; see artifact summary]".to_string());
        }
    }
}

fn scrub_template_body_change(change: &mut FormFieldChange) {
    if is_template_body_field_name(&change.name) {
        change.current_value =
            Some("[private template body redacted; see artifact summary]".to_string());
        change.requested_value =
            Some("[private template body redacted; see artifact summary]".to_string());
    }
}

fn is_template_body_field_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("html")
        || lower.contains("body")
        || lower.contains("content")
        || lower.contains("mydeveditcontrol")
        || lower == "text_body"
        || lower == "textbody"
        || lower == "textcontents"
}

#[tool_router]
impl InterspireMcpServer {
    #[tool(description = "Report Interspire MCP configuration and safe read capability.")]
    fn interspire_status(&self, Parameters(request): Parameters<StatusRequest>) -> String {
        response::tool_json(self.backend.status(&request))
    }

    #[tool(
        description = "Probe Interspire XML API authentication with authentication/XmlApiTest without reading lists or contacts."
    )]
    fn interspire_xml_auth_probe(
        &self,
        Parameters(request): Parameters<XmlAuthProbeRequest>,
    ) -> String {
        response::tool_json(self.backend.xml_auth_probe(&request))
    }

    #[tool(description = "Summarize Interspire contact lists and aggregate state counts.")]
    fn interspire_list_summary(
        &self,
        Parameters(request): Parameters<ListSummaryRequest>,
    ) -> String {
        response::tool_json(self.backend.list_summary(&request))
    }

    #[tool(
        description = "Check one redacted contact's Interspire list presence with XML first and exact admin-HTML fallback."
    )]
    fn interspire_contact_state(
        &self,
        Parameters(request): Parameters<ContactStateRequest>,
    ) -> String {
        response::tool_json(self.backend.contact_state(&request))
    }

    #[tool(description = "Read Interspire list owner, reply-to, and bounce metadata.")]
    fn interspire_list_owner_readback(
        &self,
        Parameters(request): Parameters<ListOwnerReadbackRequest>,
    ) -> String {
        response::tool_json(self.backend.list_owner_readback(&request))
    }

    #[tool(description = "Read redacted Interspire global settings for email, bounce, and cron.")]
    fn interspire_settings_audit(
        &self,
        Parameters(request): Parameters<SettingsAuditRequest>,
    ) -> String {
        response::tool_json(self.backend.settings_audit(&request))
    }

    #[tool(
        description = "Inventory redacted Interspire settings form fields across allowlisted tabs."
    )]
    fn interspire_settings_inventory(
        &self,
        Parameters(request): Parameters<SettingsInventoryRequest>,
    ) -> String {
        response::tool_json(self.backend.settings_inventory(&request))
    }

    #[tool(
        description = "Probe authenticated admin HTML reachability through allowlisted read pages."
    )]
    fn interspire_admin_session_probe(
        &self,
        Parameters(request): Parameters<AdminSessionProbeRequest>,
    ) -> String {
        response::tool_json(self.backend.admin_session_probe(&request))
    }

    #[tool(description = "Read redacted per-user SMTP override state.")]
    fn interspire_user_smtp_readback(
        &self,
        Parameters(request): Parameters<UserSmtpReadbackRequest>,
    ) -> String {
        response::tool_json(self.backend.user_smtp_readback(&request))
    }

    #[tool(description = "Read scheduled queue and stats page summaries without triggering cron.")]
    fn interspire_queue_stats_readback(
        &self,
        Parameters(request): Parameters<QueueStatsReadbackRequest>,
    ) -> String {
        response::tool_json(self.backend.queue_stats_readback(&request))
    }

    #[tool(
        description = "Preview cancel/delete plan ids for Interspire scheduled queue rows. Preview is read-only."
    )]
    fn interspire_queue_control_preview(
        &self,
        Parameters(request): Parameters<QueueControlPreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.queue_control_preview(&request))
    }

    #[tool(
        description = "Apply a previously previewed Interspire scheduled queue cancel/delete plan. Requires guarded write environment flags."
    )]
    fn interspire_queue_control_apply(
        &self,
        Parameters(request): Parameters<QueueControlApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.queue_control_apply(&request))
    }

    #[tool(description = "Read campaign manage rows or one campaign edit page summary.")]
    fn interspire_campaign_readback(
        &self,
        Parameters(request): Parameters<CampaignReadbackRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_readback(&request))
    }

    #[tool(description = "Audit redacted campaign body safety signals without returning raw HTML.")]
    fn interspire_campaign_body_audit(
        &self,
        Parameters(request): Parameters<CampaignBodyAuditRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_body_audit(&request))
    }

    #[tool(
        description = "Write private persisted-campaign render artifacts for native-browser screenshot inspection without returning raw HTML."
    )]
    fn interspire_campaign_render_artifact(
        &self,
        Parameters(request): Parameters<CampaignRenderArtifactRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_render_artifact(&request))
    }

    #[tool(
        description = "Preview a one-recipient Interspire campaign preview/test send without sending, scheduling, queueing, importing contacts, or mutating lists."
    )]
    fn interspire_campaign_test_send_preview(
        &self,
        Parameters(request): Parameters<CampaignTestSendPreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_test_send_preview(&request))
    }

    #[tool(
        description = "Apply one explicitly acknowledged Interspire campaign preview/test send to a single recipient. Requires guarded writes, send controls, acknowledge_test_send=true, and exact subject/HTML hash from preview; this does not prove list-specific unsubscribe or merge behavior."
    )]
    fn interspire_campaign_test_send_apply(
        &self,
        Parameters(request): Parameters<CampaignTestSendApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_test_send_apply(&request))
    }

    #[tool(
        description = "Render the send wizard through the no-send preview boundary and verify queue/stat invariants."
    )]
    fn interspire_send_wizard_readback(
        &self,
        Parameters(request): Parameters<SendWizardReadbackRequest>,
    ) -> String {
        response::tool_json(self.backend.send_wizard_readback(&request))
    }

    #[tool(
        description = "Combine campaign body audit and no-send wizard proof into seed-readiness gates."
    )]
    fn interspire_seed_readiness_gate(
        &self,
        Parameters(request): Parameters<SeedReadinessGateRequest>,
    ) -> String {
        response::tool_json(self.backend.seed_readiness_gate(&request))
    }

    #[tool(
        description = "Apply one explicitly acknowledged seed send after immediate readiness proof. Requires INTERSPIRE_GUARDED_WRITES=1, INTERSPIRE_SEND_CONTROLS=1, acknowledge_seed_send=true, and a bounded expected recipient count; when INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=1, also requires verified OCI ledger preflight."
    )]
    fn interspire_seed_send_apply(
        &self,
        Parameters(request): Parameters<SeedSendApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.seed_send_apply(&request))
    }

    #[tool(
        description = "Apply an explicitly acknowledged production send after strict immediate readiness proof. Requires guarded writes, send controls, production send controls, exact expected count, From, Reply-To, subject, HTML SHA-256, and the required confirmation phrase; when INTERSPIRE_REQUIRE_OCI_SEND_LEDGER=1, also requires verified OCI ledger preflight."
    )]
    fn interspire_production_send_apply(
        &self,
        Parameters(request): Parameters<ProductionSendApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.production_send_apply(&request))
    }

    #[tool(
        description = "Preview semantic EDM template edits such as subject, HTML body, text body, multipart, tracking, and embed-image flags."
    )]
    fn interspire_campaign_template_update_preview(
        &self,
        Parameters(request): Parameters<CampaignTemplateUpdatePreviewRequest>,
    ) -> String {
        response::tool_json(
            self.backend
                .campaign_update_preview(&CampaignUpdatePreviewRequest {
                    campaign_id: request.campaign_id,
                    updates: request.updates(),
                }),
        )
    }

    #[tool(description = "Apply a previously previewed semantic EDM template edit.")]
    fn interspire_campaign_template_update_apply(
        &self,
        Parameters(request): Parameters<CampaignTemplateUpdateApplyRequest>,
    ) -> String {
        let updates = request.updates();
        response::tool_json(
            self.backend
                .campaign_update_apply(&CampaignUpdateApplyRequest {
                    campaign_id: request.campaign_id,
                    plan_id: request.plan_id,
                    updates,
                }),
        )
    }

    #[tool(
        description = "Preview applying a fixed private render artifact to a campaign template without returning raw HTML."
    )]
    fn interspire_campaign_template_artifact_update_preview(
        &self,
        Parameters(request): Parameters<CampaignTemplateArtifactUpdatePreviewRequest>,
    ) -> String {
        response::tool_json(self.campaign_template_artifact_update_preview(&request))
    }

    #[tool(
        description = "Apply a fixed private render artifact to a campaign template and prove the persisted body hash."
    )]
    fn interspire_campaign_template_artifact_update_apply(
        &self,
        Parameters(request): Parameters<CampaignTemplateArtifactUpdateApplyRequest>,
    ) -> String {
        response::tool_json(self.campaign_template_artifact_update_apply(&request))
    }

    #[tool(description = "Preview guarded campaign content or sender metadata edits.")]
    fn interspire_campaign_update_preview(
        &self,
        Parameters(request): Parameters<CampaignUpdatePreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_update_preview(&request))
    }

    #[tool(description = "Apply a guarded campaign content or sender metadata edit.")]
    fn interspire_campaign_update_apply(
        &self,
        Parameters(request): Parameters<CampaignUpdateApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_update_apply(&request))
    }

    #[tool(description = "Preview guarded list metadata edits.")]
    fn interspire_list_update_preview(
        &self,
        Parameters(request): Parameters<ListUpdatePreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.list_update_preview(&request))
    }

    #[tool(description = "Apply a guarded list metadata edit.")]
    fn interspire_list_update_apply(
        &self,
        Parameters(request): Parameters<ListUpdateApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.list_update_apply(&request))
    }

    #[tool(description = "Preview a guarded Interspire contact-list creation plan.")]
    fn interspire_list_create_preview(
        &self,
        Parameters(request): Parameters<ListCreatePreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.list_create_preview(&request))
    }

    #[tool(description = "Apply a previously previewed Interspire contact-list creation plan.")]
    fn interspire_list_create_apply(
        &self,
        Parameters(request): Parameters<ListCreateApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.list_create_apply(&request))
    }

    #[tool(
        description = "Preview a guarded campaign-copy plan for creating a draft from a known campaign."
    )]
    fn interspire_campaign_copy_preview(
        &self,
        Parameters(request): Parameters<CampaignCopyPreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_copy_preview(&request))
    }

    #[tool(
        description = "Apply a previously previewed campaign-copy plan and return the new draft id."
    )]
    fn interspire_campaign_copy_apply(
        &self,
        Parameters(request): Parameters<CampaignCopyApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.campaign_copy_apply(&request))
    }

    #[tool(
        description = "Preflight a local cleaned CSV import candidate with aggregate counts and hash only."
    )]
    fn interspire_contact_import_preflight(
        &self,
        Parameters(request): Parameters<ContactImportPreflightRequest>,
    ) -> String {
        response::tool_json(self.backend.contact_import_preflight(&request))
    }

    #[tool(description = "Preview guarded user profile or footer edits.")]
    fn interspire_user_update_preview(
        &self,
        Parameters(request): Parameters<UserUpdatePreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.user_update_preview(&request))
    }

    #[tool(description = "Apply a guarded user profile or footer edit.")]
    fn interspire_user_update_apply(
        &self,
        Parameters(request): Parameters<UserUpdateApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.user_update_apply(&request))
    }

    #[tool(description = "Preview guarded non-secret Interspire settings edits.")]
    fn interspire_settings_update_preview(
        &self,
        Parameters(request): Parameters<SettingsUpdatePreviewRequest>,
    ) -> String {
        response::tool_json(self.backend.settings_update_preview(&request))
    }

    #[tool(description = "Apply guarded non-secret Interspire settings edits.")]
    fn interspire_settings_update_apply(
        &self,
        Parameters(request): Parameters<SettingsUpdateApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.settings_update_apply(&request))
    }

    #[tool(
        description = "Query exact approved Interspire admin form fields with unredacted values. Requires INTERSPIRE_SENSITIVE_READS=1 and acknowledge_sensitive_output=true."
    )]
    fn interspire_sensitive_field_query(
        &self,
        Parameters(request): Parameters<SensitiveFieldQueryRequest>,
    ) -> String {
        response::tool_json(self.backend.sensitive_field_query(&request))
    }

    #[tool(
        description = "Assess a specified-list warm-up audience from Interspire list counts without exporting contacts."
    )]
    fn interspire_warmup_audience_readiness(
        &self,
        Parameters(request): Parameters<WarmupAudienceReadinessRequest>,
    ) -> String {
        response::tool_json(self.backend.warmup_audience_readiness(&request))
    }

    #[tool(
        description = "Export explicitly requested Interspire audience hygiene artifacts privately and return aggregate counts only."
    )]
    fn interspire_audience_hygiene_export(
        &self,
        Parameters(request): Parameters<AudienceHygieneExportRequest>,
    ) -> String {
        response::tool_json(self.backend.audience_hygiene_export(&request))
    }

    #[tool(
        description = "Begin a checkpointed audience hygiene export job and advance a bounded number of XML subscriber queries."
    )]
    fn interspire_audience_hygiene_export_begin(
        &self,
        Parameters(request): Parameters<AudienceHygieneExportBeginRequest>,
    ) -> String {
        response::tool_json(self.backend.audience_hygiene_export_begin(&request))
    }

    #[tool(
        description = "Resume a checkpointed audience hygiene export job for a bounded number of XML subscriber queries."
    )]
    fn interspire_audience_hygiene_export_resume(
        &self,
        Parameters(request): Parameters<AudienceHygieneExportResumeRequest>,
    ) -> String {
        response::tool_json(self.backend.audience_hygiene_export_resume(&request))
    }

    #[tool(
        description = "Read checkpointed audience hygiene export job status without advancing the export."
    )]
    fn interspire_audience_hygiene_export_status(
        &self,
        Parameters(request): Parameters<AudienceHygieneExportStatusRequest>,
    ) -> String {
        response::tool_json(self.backend.audience_hygiene_export_status(&request))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for InterspireMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Safe Interspire Email Marketer evidence tools. Mutations are disabled by default and limited to guarded queue cancel/delete, campaign/list/user/settings/template apply plans, private render artifacts, and separately gated seed or production send apply tools.")
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            tools: self.tool_schema_snapshot(),
            next_cursor: None,
        }))
    }
}

fn with_interspire_tool_metadata(tool: Tool) -> Tool {
    match tool.name.as_ref() {
        "interspire_sensitive_field_query" => {
            let meta = with_mcp_apps_sensitive_output_metadata(
                Some(Meta::new()),
                "unredacted_admin_form_values",
            );
            tool.with_annotations(
                ToolAnnotations::with_title("Sensitive field query")
                    .read_only(true)
                    .destructive(false)
                    .idempotent(true)
                    .open_world(false),
            )
            .with_meta(meta)
        }
        "interspire_send_wizard_readback" => {
            let meta = with_mcp_apps_no_mutation_proof_metadata(
                Some(Meta::new()),
                "render Send wizard Step2/final editable page without submitting the final send boundary",
            );
            tool.with_annotations(
                ToolAnnotations::with_title("Send wizard readback")
                    .read_only(true)
                    .destructive(false)
                    .idempotent(true)
                    .open_world(false),
            )
            .with_meta(meta)
        }
        "interspire_seed_readiness_gate" => {
            let meta = with_mcp_apps_no_mutation_proof_metadata(
                Some(Meta::new()),
                "combine campaign audit and Send wizard readback without submitting a seed or production send",
            );
            tool.with_annotations(
                ToolAnnotations::with_title("Seed readiness gate")
                    .read_only(true)
                    .destructive(false)
                    .idempotent(true)
                    .open_world(false),
            )
            .with_meta(meta)
        }
        "interspire_campaign_render_artifact" => {
            let meta = with_mcp_apps_no_mutation_proof_metadata(
                Some(Meta::new()),
                "write private render artifacts for native-browser screenshot inspection without mutating Interspire",
            );
            tool.with_annotations(
                ToolAnnotations::with_title("Campaign render artifact")
                    .read_only(true)
                    .destructive(false)
                    .idempotent(false)
                    .open_world(false),
            )
            .with_meta(meta)
        }
        "interspire_campaign_test_send_preview" => {
            let meta = with_mcp_apps_no_mutation_proof_metadata(
                Some(Meta::new()),
                "read persisted campaign content and prepare one-recipient preview-send proof without posting the preview route",
            );
            tool.with_annotations(
                ToolAnnotations::with_title("Campaign test-send preview")
                    .read_only(true)
                    .destructive(false)
                    .idempotent(true)
                    .open_world(false),
            )
            .with_meta(meta)
        }
        "interspire_campaign_test_send_apply" => tool.with_annotations(
            ToolAnnotations::with_title("Campaign test-send apply")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        "interspire_seed_send_apply" => tool.with_annotations(
            ToolAnnotations::with_title("Seed send apply")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        "interspire_production_send_apply" => tool.with_annotations(
            ToolAnnotations::with_title("Production send apply")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        "interspire_campaign_template_update_preview" => tool.with_annotations(
            ToolAnnotations::with_title("Campaign template update preview")
                .read_only(true)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        "interspire_campaign_template_update_apply" => tool.with_annotations(
            ToolAnnotations::with_title("Campaign template update apply")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        "interspire_campaign_template_artifact_update_preview" => tool.with_annotations(
            ToolAnnotations::with_title("Campaign template artifact update preview")
                .read_only(true)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        "interspire_campaign_template_artifact_update_apply" => tool.with_annotations(
            ToolAnnotations::with_title("Campaign template artifact update apply")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        ),
        _ => tool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_toolkit_core::tool_inventory::{ToolInventoryPolicy, ToolOperation};
    use sha2::{Digest, Sha256};
    use std::{fs, process};

    #[derive(Debug, Default)]
    struct FixtureBackend {
        campaign_body_html_sha256: Option<String>,
        campaign_body_text_sha256: Option<String>,
    }

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
            request: &CampaignBodyAuditRequest,
        ) -> Result<CampaignBodyAuditReport, InterspireError> {
            let mut report = CampaignBodyAuditReport::fixture();
            report.campaign_id = request.campaign_id;
            if let Some(sha256) = &self.campaign_body_html_sha256 {
                report.html_sha256 = Some(sha256.clone());
            }
            if let Some(sha256) = &self.campaign_body_text_sha256 {
                report.text_sha256 = Some(sha256.clone());
            }
            Ok(report)
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
    fn inventory_matches_exported_tool_names() {
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend::default()))
            .unwrap_or_else(|err| panic!("server inventory must build: {err}"));
        let tools = server.tool_schema_snapshot();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "interspire_admin_session_probe",
                "interspire_audience_hygiene_export",
                "interspire_audience_hygiene_export_begin",
                "interspire_audience_hygiene_export_resume",
                "interspire_audience_hygiene_export_status",
                "interspire_campaign_body_audit",
                "interspire_campaign_copy_apply",
                "interspire_campaign_copy_preview",
                "interspire_campaign_readback",
                "interspire_campaign_render_artifact",
                "interspire_campaign_template_artifact_update_apply",
                "interspire_campaign_template_artifact_update_preview",
                "interspire_campaign_template_update_apply",
                "interspire_campaign_template_update_preview",
                "interspire_campaign_test_send_apply",
                "interspire_campaign_test_send_preview",
                "interspire_campaign_update_apply",
                "interspire_campaign_update_preview",
                "interspire_contact_import_preflight",
                "interspire_contact_state",
                "interspire_list_create_apply",
                "interspire_list_create_preview",
                "interspire_list_owner_readback",
                "interspire_list_summary",
                "interspire_list_update_apply",
                "interspire_list_update_preview",
                "interspire_production_send_apply",
                "interspire_queue_control_apply",
                "interspire_queue_control_preview",
                "interspire_queue_stats_readback",
                "interspire_seed_readiness_gate",
                "interspire_seed_send_apply",
                "interspire_send_wizard_readback",
                "interspire_sensitive_field_query",
                "interspire_settings_audit",
                "interspire_settings_inventory",
                "interspire_settings_update_apply",
                "interspire_settings_update_preview",
                "interspire_status",
                "interspire_user_smtp_readback",
                "interspire_user_update_apply",
                "interspire_user_update_preview",
                "interspire_warmup_audience_readiness",
                "interspire_xml_auth_probe",
            ]
        );

        let policy = ToolInventoryPolicy::default();
        for name in names {
            assert!(server
                .inventory()
                .is_allowed(name, ToolOperation::List, &policy));
            assert!(server
                .inventory()
                .is_allowed(name, ToolOperation::Call, &policy));
        }
    }

    #[test]
    fn sensitive_tool_descriptor_is_marked_approval_required() {
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend::default()))
            .unwrap_or_else(|err| panic!("server inventory must build: {err}"));
        let tool = server
            .tool_schema_snapshot()
            .into_iter()
            .find(|tool| tool.name.as_ref() == "interspire_sensitive_field_query")
            .unwrap_or_else(|| panic!("sensitive tool should be listed"));
        let meta = tool
            .meta
            .unwrap_or_else(|| panic!("sensitive tool should include Apps metadata"));

        assert_eq!(meta.0["approval_required"], serde_json::json!(true));
        assert_eq!(
            meta.0["sensitivity"],
            serde_json::json!("unredacted_admin_form_values")
        );
        assert_eq!(meta.0["openai/widgetAccessible"], serde_json::json!(false));
        assert_eq!(
            tool.annotations
                .and_then(|annotations| annotations.read_only_hint),
            Some(true)
        );
    }

    #[test]
    fn no_mutation_proof_descriptors_mark_the_proof_boundary() {
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend::default()))
            .unwrap_or_else(|err| panic!("server inventory must build: {err}"));
        let tools = server.tool_schema_snapshot();

        for name in [
            "interspire_send_wizard_readback",
            "interspire_seed_readiness_gate",
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool.name.as_ref() == name)
                .unwrap_or_else(|| panic!("{name} should be listed"));
            let meta = tool
                .meta
                .as_ref()
                .unwrap_or_else(|| panic!("{name} should include Apps metadata"));

            assert_eq!(
                meta.0["operation_class"],
                serde_json::json!("no_mutation_proof")
            );
            assert_eq!(meta.0["mutation_prohibited"], serde_json::json!(true));
            assert_eq!(
                meta.0["production_action_authorized"],
                serde_json::json!(false)
            );
            assert_eq!(meta.0["openai/widgetAccessible"], serde_json::json!(false));
            assert_eq!(
                tool.annotations
                    .as_ref()
                    .and_then(|annotations| annotations.read_only_hint),
                Some(true)
            );
        }
    }

    #[test]
    fn template_artifact_preview_does_not_return_raw_private_body() {
        let (path, sha256, bytes) = write_private_template_artifact(
            "preview-redaction",
            "<html><body>PRIVATE-NEWSLETTER-SENTINEL</body></html>",
        );
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend::default()))
            .unwrap_or_else(|err| panic!("server inventory must build: {err}"));

        let report = server
            .campaign_template_artifact_update_preview(
                &CampaignTemplateArtifactUpdatePreviewRequest {
                    campaign_id: 88,
                    html_artifact_path: path.to_string_lossy().to_string(),
                    expected_html_sha256: Some(sha256.clone()),
                    expected_html_bytes: Some(bytes),
                    text_artifact_path: None,
                    expected_text_sha256: None,
                    expected_text_bytes: None,
                    name: Some("Example Update draft".to_string()),
                    subject: Some("Example Update subject".to_string()),
                    send_multipart: Some(false),
                    track_opens: Some(true),
                    track_links: Some(true),
                    embed_images: Some(false),
                },
            )
            .unwrap_or_else(|err| panic!("{err}"));
        let serialized = serde_json::to_string(&report).unwrap_or_else(|err| panic!("json: {err}"));

        assert!(report.ok);
        assert_eq!(report.artifacts[0].sha256, sha256);
        assert_eq!(report.artifacts[0].bytes, bytes);
        assert!(!serialized.contains("PRIVATE-NEWSLETTER-SENTINEL"));
        assert!(!serialized.contains("<html>"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn template_artifact_apply_proves_hash_and_redacts_private_body() {
        let (path, sha256, bytes) = write_private_template_artifact(
            "apply-redaction",
            "<html><body>PRIVATE-NEWSLETTER-APPLY-SENTINEL</body></html>",
        );
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend {
            campaign_body_html_sha256: Some(sha256.clone()),
            campaign_body_text_sha256: None,
        }))
        .unwrap_or_else(|err| panic!("server inventory must build: {err}"));

        let report = server
            .campaign_template_artifact_update_apply(&CampaignTemplateArtifactUpdateApplyRequest {
                campaign_id: 88,
                plan_id: "ifw_000000000000000000000000".to_string(),
                html_artifact_path: path.to_string_lossy().to_string(),
                expected_html_sha256: Some(sha256.clone()),
                expected_html_bytes: Some(bytes),
                text_artifact_path: None,
                expected_text_sha256: None,
                expected_text_bytes: None,
                name: Some("Example Update draft".to_string()),
                subject: Some("Example Update subject".to_string()),
                send_multipart: Some(false),
                track_opens: Some(true),
                track_links: Some(true),
                embed_images: Some(false),
            })
            .unwrap_or_else(|err| panic!("{err}"));
        let serialized = serde_json::to_string(&report).unwrap_or_else(|err| panic!("json: {err}"));

        assert!(report.ok);
        assert_eq!(
            report.campaign_body.html_sha256.as_deref(),
            Some(sha256.as_str())
        );
        assert!(!serialized.contains("PRIVATE-NEWSLETTER-APPLY-SENTINEL"));
        assert!(!serialized.contains("<html>"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn template_artifact_apply_refuses_unproven_persisted_hash() {
        let (path, sha256, bytes) = write_private_template_artifact(
            "apply-hash-mismatch",
            "<html><body>PRIVATE-NEWSLETTER-MISMATCH-SENTINEL</body></html>",
        );
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend::default()))
            .unwrap_or_else(|err| panic!("server inventory must build: {err}"));

        let err = server
            .campaign_template_artifact_update_apply(&CampaignTemplateArtifactUpdateApplyRequest {
                campaign_id: 88,
                plan_id: "ifw_000000000000000000000000".to_string(),
                html_artifact_path: path.to_string_lossy().to_string(),
                expected_html_sha256: Some(sha256),
                expected_html_bytes: Some(bytes),
                text_artifact_path: None,
                expected_text_sha256: None,
                expected_text_bytes: None,
                name: None,
                subject: None,
                send_multipart: Some(false),
                track_opens: None,
                track_links: None,
                embed_images: None,
            })
            .err()
            .unwrap_or_else(|| panic!("hash mismatch must fail"));

        assert!(err
            .to_string()
            .contains("did not persist the expected HTML SHA-256"));

        let _ = fs::remove_file(path);
    }

    fn write_private_template_artifact(
        name: &str,
        contents: &str,
    ) -> (std::path::PathBuf, String, u64) {
        let dir = private_artifacts::prepare_private_render_output_dir(None)
            .unwrap_or_else(|err| panic!("{err}"));
        let path = dir.join(format!(
            "interspire-campaign-render-test-{}-{name}.html",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, contents).unwrap_or_else(|err| panic!("{err}"));
        let sha256 = hex::encode(Sha256::digest(contents.as_bytes()));
        (path, sha256, contents.len() as u64)
    }
}

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
    CampaignTemplateUpdateApplyRequest, CampaignTemplateUpdatePreviewRequest,
    CampaignUpdateApplyRequest, CampaignUpdatePreviewRequest, ContactImportPreflightReport,
    ContactImportPreflightRequest, ContactStateReport, ContactStateRequest, Evidence,
    FormFieldChange, FormFieldDescriptor, FormFieldUpdate, GuardedWriteApplyReport,
    GuardedWritePreviewReport, ListCreateApplyRequest, ListCreatePreviewRequest,
    ListOwnerReadbackReport, ListOwnerReadbackRequest, ListSummary, ListSummaryReport,
    ListSummaryRequest, ListUpdateApplyRequest, ListUpdatePreviewRequest,
    ProductionSendApplyReport, ProductionSendApplyRequest, QueueControlAction,
    QueueControlApplyReport, QueueControlApplyRequest, QueueControlCandidate,
    QueueControlPreviewReport, QueueControlPreviewRequest, QueueStatsReadbackReport,
    QueueStatsReadbackRequest, RenderArtifact, SeedReadinessGate, SeedReadinessGateReport,
    SeedReadinessGateRequest, SeedSendApplyReport, SeedSendApplyRequest, SendApplyStatus,
    SendReconciliationReport, SendWizardReadbackReport, SendWizardReadbackRequest,
    SensitiveFieldDenial, SensitiveFieldQueryReport, SensitiveFieldQueryRequest,
    SensitiveFieldTarget, SensitiveFieldValue, SensitiveToolMetadata, SettingsAuditReport,
    SettingsAuditRequest, SettingsSectionName, SettingsUpdateApplyRequest,
    SettingsUpdatePreviewRequest, StatusReport, StatusRequest, UserSmtpReadbackReport,
    UserSmtpReadbackRequest, UserUpdateApplyRequest, UserUpdatePreviewRequest,
    WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest, XmlAuthProbeReport,
    XmlAuthProbeRequest, DEFAULT_HYGIENE_QUERY_BUDGET, DEFAULT_LIST_READ_LIMIT,
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
                        "Apply one explicitly acknowledged seed send after immediate readiness proof.",
                        ["interspire", "seed", "send", "apply", "guarded-send"],
                    )),
                ToolCapability::new("interspire_production_send_apply")
                    .with_group("guarded-send")
                    .with_read_only(false)
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Apply an explicitly acknowledged production send after strict immediate readiness proof.",
                        [
                            "interspire",
                            "production",
                            "send",
                            "apply",
                            "guarded-send",
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
        description = "Apply one explicitly acknowledged seed send after immediate readiness proof. Requires INTERSPIRE_GUARDED_WRITES=1, INTERSPIRE_SEND_CONTROLS=1, acknowledge_seed_send=true, and a bounded expected recipient count."
    )]
    fn interspire_seed_send_apply(
        &self,
        Parameters(request): Parameters<SeedSendApplyRequest>,
    ) -> String {
        response::tool_json(self.backend.seed_send_apply(&request))
    }

    #[tool(
        description = "Apply an explicitly acknowledged production send after strict immediate readiness proof. Requires guarded writes, send controls, production send controls, exact expected count, From, Reply-To, subject, HTML SHA-256, and the required confirmation phrase."
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
        _ => tool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_toolkit_core::tool_inventory::{ToolInventoryPolicy, ToolOperation};

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

    #[test]
    fn inventory_matches_exported_tool_names() {
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend))
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
                "interspire_campaign_template_update_apply",
                "interspire_campaign_template_update_preview",
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
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend))
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
        let server = InterspireMcpServer::with_backend(Arc::new(FixtureBackend))
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
}

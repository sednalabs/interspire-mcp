//! # Interspire 6.2.3 MCP
//!
//! Curated stdio MCP server for safe Interspire Email Marketer 6.2.3
//! operational readback plus guarded no-send queue and form-write paths.
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
//! * Blocks send, schedule, cron, generic import/export, contact mutation,
//!   suppression mutation, provider mutation, and raw admin escape paths.
//! * Allows one narrow, explicit audience-hygiene artifact export that writes
//!   private local files and returns aggregate metadata only.
//! * Allows queue cancel/delete plus guarded campaign/list/user/settings edits
//!   only through deterministic preview/apply plan ids and explicit runtime
//!   write flags.
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
mod redact;
mod response;
mod safety;
mod xml_api;

use std::sync::Arc;

pub use config::{AdminHtmlConfig, InterspireServerConfig, XmlApiConfig};
pub use error::InterspireError;
use mcp_toolkit_core::tool_inventory::{
    ToolCapability, ToolDiscoveryMetadata, ToolInventory, ToolInventoryError,
};
pub use response::{
    AudienceHygieneArtifact, AudienceHygieneExportBeginRequest, AudienceHygieneExportReport,
    AudienceHygieneExportRequest, AudienceHygieneExportResumeRequest,
    AudienceHygieneExportStatusRequest, AudienceHygieneListSummary, CampaignReadbackReport,
    CampaignReadbackRequest, CampaignUpdateApplyRequest, CampaignUpdatePreviewRequest,
    ContactStateReport, ContactStateRequest, Evidence, FormFieldChange, FormFieldDescriptor,
    FormFieldUpdate, GuardedWriteApplyReport, GuardedWritePreviewReport, ListOwnerReadbackReport,
    ListOwnerReadbackRequest, ListSummary, ListSummaryReport, ListSummaryRequest,
    ListUpdateApplyRequest, ListUpdatePreviewRequest, QueueControlAction, QueueControlApplyReport,
    QueueControlApplyRequest, QueueControlCandidate, QueueControlPreviewReport,
    QueueControlPreviewRequest, QueueStatsReadbackReport, QueueStatsReadbackRequest,
    SettingsAuditReport, SettingsAuditRequest, SettingsSectionName, SettingsUpdateApplyRequest,
    SettingsUpdatePreviewRequest, StatusReport, StatusRequest, UserSmtpReadbackReport,
    UserSmtpReadbackRequest, UserUpdateApplyRequest, UserUpdatePreviewRequest,
    WarmupAudienceReadinessReport, WarmupAudienceReadinessRequest, DEFAULT_HYGIENE_QUERY_BUDGET,
    DEFAULT_LIST_READ_LIMIT, HARD_HYGIENE_QUERY_BUDGET, HARD_LIST_READ_LIMIT,
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo, Tool},
    tool, tool_handler, tool_router, ServerHandler,
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
                        "Check one redacted contact's Interspire XML list presence.",
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
        self.tool_router.list_all()
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

    #[tool(description = "Summarize Interspire contact lists and aggregate state counts.")]
    fn interspire_list_summary(
        &self,
        Parameters(request): Parameters<ListSummaryRequest>,
    ) -> String {
        response::tool_json(self.backend.list_summary(&request))
    }

    #[tool(description = "Check one redacted contact's Interspire XML list presence.")]
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
            .with_instructions("Safe Interspire Email Marketer 6.2.3 evidence tools. Mutations are disabled by default and limited to guarded queue cancel/delete plus explicitly gated campaign, list, user, and settings apply plans.")
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
                "interspire_audience_hygiene_export",
                "interspire_audience_hygiene_export_begin",
                "interspire_audience_hygiene_export_resume",
                "interspire_audience_hygiene_export_status",
                "interspire_campaign_readback",
                "interspire_campaign_update_apply",
                "interspire_campaign_update_preview",
                "interspire_contact_state",
                "interspire_list_owner_readback",
                "interspire_list_summary",
                "interspire_list_update_apply",
                "interspire_list_update_preview",
                "interspire_queue_control_apply",
                "interspire_queue_control_preview",
                "interspire_queue_stats_readback",
                "interspire_settings_audit",
                "interspire_settings_update_apply",
                "interspire_settings_update_preview",
                "interspire_status",
                "interspire_user_smtp_readback",
                "interspire_user_update_apply",
                "interspire_user_update_preview",
                "interspire_warmup_audience_readiness",
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
}

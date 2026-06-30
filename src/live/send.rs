use super::LiveInterspireBackend;
use crate::{
    error::InterspireError,
    guarded_write,
    response::{
        ProductionSendApplyReport, ProductionSendApplyRequest, SeedSendApplyReport,
        SeedSendApplyRequest,
    },
};

impl LiveInterspireBackend {
    pub(super) fn seed_send_apply_impl(
        &self,
        request: &SeedSendApplyRequest,
    ) -> Result<SeedSendApplyReport, InterspireError> {
        guarded_write::require_send_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        html.seed_send_apply(
            request,
            self.config.guarded_writes.enabled,
            self.config.guarded_writes.send_controls_enabled,
        )
    }

    pub(super) fn production_send_apply_impl(
        &self,
        request: &ProductionSendApplyRequest,
    ) -> Result<ProductionSendApplyReport, InterspireError> {
        guarded_write::require_production_send_controls_enabled(&self.config.guarded_writes)?;
        let html = self.html_client()?;
        html.production_send_apply(
            request,
            self.config.guarded_writes.enabled,
            self.config.guarded_writes.send_controls_enabled,
            self.config.guarded_writes.production_send_controls_enabled,
        )
    }
}

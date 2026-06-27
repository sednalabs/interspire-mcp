use super::LiveInterspireBackend;
use crate::{
    audience_hygiene_checkpoint,
    error::InterspireError,
    response::{
        AudienceHygieneExportBeginRequest, AudienceHygieneExportReport,
        AudienceHygieneExportResumeRequest, AudienceHygieneExportStatusRequest,
    },
};

impl LiveInterspireBackend {
    pub(super) fn audience_hygiene_export_begin_impl(
        &self,
        request: &AudienceHygieneExportBeginRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        let xml = self.xml_client()?;
        audience_hygiene_checkpoint::begin_export(&xml, request)
    }

    pub(super) fn audience_hygiene_export_resume_impl(
        &self,
        request: &AudienceHygieneExportResumeRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        let xml = self.xml_client()?;
        audience_hygiene_checkpoint::resume_export(&xml, request)
    }

    pub(super) fn audience_hygiene_export_status_impl(
        &self,
        request: &AudienceHygieneExportStatusRequest,
    ) -> Result<AudienceHygieneExportReport, InterspireError> {
        audience_hygiene_checkpoint::export_status(request)
    }
}

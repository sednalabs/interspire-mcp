use mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_interspire-6-mcp"),
        &[
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
        ],
    );
}

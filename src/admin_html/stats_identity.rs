use super::{compact_text, queue_control_page_is_complete, row_contains_nested_rows};
use crate::{
    error::InterspireError,
    redact,
    safety::{self, AdminReadPage},
};
use scraper::{Html, Selector};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatsRowIdentity {
    pub stat_id: u64,
    pub row_ordinal: usize,
    pub row_summary: String,
    pub recipients: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatsIdentityInventory {
    pub rows: Vec<StatsRowIdentity>,
}

impl StatsIdentityInventory {
    pub fn ids(&self) -> BTreeSet<u64> {
        self.rows.iter().map(|row| row.stat_id).collect()
    }
}

pub(super) fn unique_added_stats_identity<'a>(
    before: &StatsIdentityInventory,
    after: &'a StatsIdentityInventory,
) -> Result<Option<&'a StatsRowIdentity>, (usize, usize)> {
    let before_ids = before.ids();
    let after_ids = after.ids();
    let added = after
        .rows
        .iter()
        .filter(|row| !before_ids.contains(&row.stat_id))
        .collect::<Vec<_>>();
    let removed = before_ids.difference(&after_ids).count();
    match (added.as_slice(), removed) {
        ([], 0) => Ok(None),
        ([row], 0) => Ok(Some(*row)),
        _ => Err((added.len(), removed)),
    }
}

pub(super) fn parse_stats_identity_inventory(
    base_url: &str,
    html: &str,
    max_rows: usize,
) -> Result<StatsIdentityInventory, InterspireError> {
    if !queue_control_page_is_complete(html, max_rows)? {
        return Err(InterspireError::Safety(
            "Stats identity inventory reached the configured row cap or exposed pagination"
                .to_string(),
        ));
    }

    let document = Html::parse_document(html);
    let row_selector =
        Selector::parse("tr").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let link_selector =
        Selector::parse("a").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let header_cell_selector =
        Selector::parse("th").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let data_cell_selector =
        Selector::parse("td").map_err(|err| InterspireError::HtmlParse(err.to_string()))?;
    let mut rows = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut inspected_rows = 0usize;

    for row in document.select(&row_selector) {
        if row_contains_nested_rows(&row, &row_selector) {
            continue;
        }
        let row_text = compact_text(&row.text().collect::<Vec<_>>().join(" "));
        if row_text.len() < 3 {
            continue;
        }
        let header_cell_count = row.select(&header_cell_selector).count();
        let data_cell_count = row.select(&data_cell_selector).count();
        if header_cell_count > 0 && data_cell_count == 0 {
            continue;
        }
        inspected_rows += 1;
        if inspected_rows > max_rows {
            return Err(InterspireError::Safety(
                "Stats identity inventory exceeded the configured row cap".to_string(),
            ));
        }

        let mut stat_ids = Vec::new();
        for link in row.select(&link_selector) {
            let label = compact_text(&link.text().collect::<Vec<_>>().join(" "));
            if !label.eq_ignore_ascii_case("view") {
                continue;
            }
            let href = link.value().attr("href").ok_or_else(|| {
                InterspireError::Safety("Stats View action omitted its route".to_string())
            })?;
            let url = safety::ensure_allowed_admin_get(base_url, href)?;
            match safety::classify_allowed_admin_get(&url)? {
                AdminReadPage::StatsNewsletterSummary { stat_id } => stat_ids.push(stat_id),
                _ => {
                    return Err(InterspireError::Safety(
                        "Stats View action did not target an allowlisted newsletter summary"
                            .to_string(),
                    ))
                }
            }
        }
        if stat_ids.is_empty() {
            return Err(InterspireError::Safety(
                "non-header Stats row did not expose one allowlisted durable View identity"
                    .to_string(),
            ));
        }
        let stat_id = match stat_ids.as_slice() {
            [stat_id] => *stat_id,
            _ => {
                return Err(InterspireError::Safety(
                    "Stats row exposed multiple View identities".to_string(),
                ))
            }
        };
        if !seen_ids.insert(stat_id) {
            return Err(InterspireError::Safety(
                "Stats identity appeared on multiple rows".to_string(),
            ));
        }
        let counts = parse_stats_row_counts(&row_text).ok_or_else(|| {
            InterspireError::Safety(format!(
                "Stats row {stat_id} did not expose bounded aggregate counters"
            ))
        })?;
        rows.push(StatsRowIdentity {
            stat_id,
            row_ordinal: inspected_rows,
            row_summary: redact::redact_sensitive_text(&row_text),
            recipients: counts.0,
        });
    }

    Ok(StatsIdentityInventory { rows })
}

fn parse_stats_row_counts(row: &str) -> Option<(u64, u64, u64)> {
    let tokens = row
        .split_whitespace()
        .map(|token| token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != ','))
        .collect::<Vec<_>>();
    let action_index = tokens
        .iter()
        .rposition(|token| token.eq_ignore_ascii_case("view"))?;
    if action_index < 3 {
        return None;
    }
    Some((
        parse_count_token(tokens[action_index - 3])?,
        parse_count_token(tokens[action_index - 2])?,
        parse_count_token(tokens[action_index - 1])?,
    ))
}

fn parse_count_token(token: &str) -> Option<u64> {
    token.replace(',', "").parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_stats_identity_inventory;

    const BASE: &str = "https://example.test/admin/";

    #[test]
    fn parses_positive_stats_identities_and_aggregate_counts() {
        let html = r#"
            <table>
              <tr><th>Campaign</th><th>Recipients</th><th>Actions</th></tr>
              <tr>
                <td>Campaign Alpha</td><td>25</td><td>0</td><td>1</td>
                <td><a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71">View</a></td>
              </tr>
              <tr>
                <td>Campaign Beta</td><td>1,000</td><td>2</td><td>3</td>
                <td><a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;id=72">View</a></td>
              </tr>
            </table>
        "#;

        let inventory =
            parse_stats_identity_inventory(BASE, html, 25).unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(inventory.rows.len(), 2);
        assert_eq!(inventory.rows[0].stat_id, 71);
        assert_eq!(inventory.rows[0].recipients, 25);
        assert_eq!(inventory.rows[1].stat_id, 72);
        assert_eq!(inventory.rows[1].recipients, 1_000);
    }

    #[test]
    fn rejects_duplicate_malformed_and_smuggled_stats_identities() {
        for html in [
            r#"<table><tr><td>Campaign 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=0">View</a></td></tr></table>"#,
            r#"<table><tr><td>Campaign 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71&amp;id=72">View</a></td></tr></table>"#,
            r#"<table><tr><td>Campaign 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Delete&amp;statid=71">View</a></td></tr></table>"#,
            r#"<table><tr><td>Campaign 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71&amp;Next=Send">View</a></td></tr></table>"#,
        ] {
            assert!(parse_stats_identity_inventory(BASE, html, 25).is_err());
        }

        let duplicate = r#"
            <table>
              <tr><td>Campaign A 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71">View</a></td></tr>
              <tr><td>Campaign B 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71">View</a></td></tr>
            </table>
        "#;
        assert!(parse_stats_identity_inventory(BASE, duplicate, 25).is_err());
    }

    #[test]
    fn rejects_non_header_rows_without_a_durable_stats_identity() {
        for html in [
            r#"<table><tr><td>Campaign Alpha 25 0 0</td></tr></table>"#,
            r#"<table><tr><td>Campaign Alpha 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters">Export</a></td></tr></table>"#,
            r#"<table><tr><th>Campaign</th><td>Campaign Alpha 25 0 0</td></tr></table>"#,
        ] {
            let err = parse_stats_identity_inventory(BASE, html, 25)
                .expect_err("unidentified non-header Stats rows must fail closed");
            assert!(err.to_string().contains(
                "non-header Stats row did not expose one allowlisted durable View identity"
            ));
        }
    }

    #[test]
    fn rejects_capped_or_paginated_stats_inventory() {
        let capped = r#"
            <table>
              <tr><td>Campaign A 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71">View</a></td></tr>
            </table>
        "#;
        assert!(parse_stats_identity_inventory(BASE, capped, 1).is_err());

        let paginated = r#"
            <table>
              <tr><td>Campaign A 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71">View</a></td></tr>
            </table>
            <a class="pagination nextpage" href="index.php?Page=Stats&amp;DisplayPage=2">Next</a>
        "#;
        assert!(parse_stats_identity_inventory(BASE, paginated, 25).is_err());

        let blank_icon_pagination = r#"
            <table>
              <tr><td>Campaign A 25 0 0 <a href="index.php?Page=Stats&amp;Action=Newsletters&amp;SubAction=Step1&amp;statid=71">View</a></td></tr>
            </table>
            <a href="index.php?Page=Stats&amp;DisplayPage=2"><img src="next.svg" alt=""></a>
        "#;
        assert!(parse_stats_identity_inventory(BASE, blank_icon_pagination, 25).is_err());
    }
}

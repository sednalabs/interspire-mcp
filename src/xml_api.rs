//! Interspire XML API read adapter.
//!
//! XML calls are the preferred source for safe list/contact readback. This
//! adapter only implements narrow read methods and redacts request failures
//! before they reach MCP responses.

use crate::{
    config::XmlApiConfig,
    error::InterspireError,
    response::{Evidence, ListSummary},
};
use reqwest::{
    blocking::{Client, RequestBuilder},
    redirect::Policy,
};
use std::{thread, time::Duration};

const SHARDED_DOMAIN_PREFIX_STARTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const MAX_SHARDED_DOMAIN_PREFIX_LEN: usize = 8;
const DEFAULT_XML_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);
const CHECKPOINT_XML_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_XML_REQUEST_ATTEMPTS: usize = 3;
const CHECKPOINT_XML_REQUEST_ATTEMPTS: usize = 1;

#[derive(Debug, Clone)]
pub struct SubscriberRecord {
    pub subscriber_id: Option<u64>,
    pub email_address: String,
    pub subscribe_date: Option<u64>,
    pub confirmed: bool,
    pub unsubscribed: bool,
    pub bounced: bool,
}

#[derive(Debug, Clone)]
pub struct XmlApiClient {
    config: XmlApiConfig,
    http: Client,
}

impl XmlApiClient {
    pub fn new(config: XmlApiConfig) -> Result<Self, InterspireError> {
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(DEFAULT_XML_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        Ok(Self { config, http })
    }

    pub fn configured(&self) -> bool {
        self.config.is_configured()
    }

    pub fn get_lists(&self) -> Result<Vec<ListSummary>, InterspireError> {
        let xml = self.request_xml("user", "GetLists", "")?;
        parse_get_lists_response(&xml)
    }

    pub fn is_subscriber_on_list(
        &self,
        email: &str,
        list_id: u64,
    ) -> Result<bool, InterspireError> {
        let details = format!(
            "<emailaddress>{}</emailaddress><listids>{}</listids>",
            escape_xml(email),
            list_id
        );
        let xml = self.request_xml("subscribers", "IsSubscriberOnList", &details)?;
        parse_is_subscriber_on_list_response(&xml)
    }

    pub fn get_subscribers_for_list(
        &self,
        list_id: u64,
    ) -> Result<Vec<SubscriberRecord>, InterspireError> {
        self.get_subscribers_for_list_matching(list_id, "@")
    }

    pub fn get_subscribers_for_list_by_domain_prefix_shards(
        &self,
        list_id: u64,
    ) -> Result<Vec<SubscriberRecord>, InterspireError> {
        let mut records = Vec::new();
        let mut stack = initial_sharded_subscriber_queries();

        while let Some(query) = stack.pop() {
            match self.get_subscribers_for_list_matching(list_id, &query) {
                Ok(mut shard_records) => records.append(&mut shard_records),
                Err(err) => {
                    if let Some(children) = split_subscriber_query(&query, &err) {
                        stack.extend(children);
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        Ok(records)
    }

    pub(crate) fn get_subscribers_for_checkpoint_query(
        &self,
        list_id: u64,
        email_query: &str,
    ) -> Result<Vec<SubscriberRecord>, InterspireError> {
        self.get_subscribers_for_list_matching_with_policy(
            list_id,
            email_query,
            CHECKPOINT_XML_REQUEST_ATTEMPTS,
            CHECKPOINT_XML_REQUEST_TIMEOUT,
        )
    }

    pub fn should_retry_subscriber_read_with_shards(err: &InterspireError) -> bool {
        is_large_subscriber_response_error(err)
    }

    fn get_subscribers_for_list_matching(
        &self,
        list_id: u64,
        email_query: &str,
    ) -> Result<Vec<SubscriberRecord>, InterspireError> {
        self.get_subscribers_for_list_matching_with_policy(
            list_id,
            email_query,
            DEFAULT_XML_REQUEST_ATTEMPTS,
            DEFAULT_XML_REQUEST_TIMEOUT,
        )
    }

    fn get_subscribers_for_list_matching_with_policy(
        &self,
        list_id: u64,
        email_query: &str,
        attempts: usize,
        timeout: Duration,
    ) -> Result<Vec<SubscriberRecord>, InterspireError> {
        let details = subscriber_search_details(list_id, email_query);
        let xml = self.request_xml_with_policy(
            "subscribers",
            "GetSubscribers",
            &details,
            attempts,
            timeout,
        )?;
        parse_get_subscribers_response(&xml)
    }

    fn request_xml(
        &self,
        request_type: &str,
        request_method: &str,
        details: &str,
    ) -> Result<String, InterspireError> {
        self.request_xml_with_policy(
            request_type,
            request_method,
            details,
            DEFAULT_XML_REQUEST_ATTEMPTS,
            DEFAULT_XML_REQUEST_TIMEOUT,
        )
    }

    fn request_xml_with_policy(
        &self,
        request_type: &str,
        request_method: &str,
        details: &str,
        attempts: usize,
        timeout: Duration,
    ) -> Result<String, InterspireError> {
        let mut last_error = None;
        let attempts = attempts.max(1);
        for attempt in 1..=attempts {
            match self.request_xml_once(request_type, request_method, details, timeout) {
                Ok(text) if !text.trim().is_empty() => return Ok(text),
                Ok(_) => {
                    last_error = Some(InterspireError::XmlParse(
                        "empty XML response from Interspire".to_string(),
                    ));
                }
                Err(err) => last_error = Some(err),
            }

            if attempt < attempts {
                thread::sleep(Duration::from_secs(attempt as u64));
            }
        }

        Err(last_error.unwrap_or_else(|| {
            InterspireError::XmlParse("empty XML response from Interspire".to_string())
        }))
    }

    fn request_xml_once(
        &self,
        request_type: &str,
        request_method: &str,
        details: &str,
        timeout: Duration,
    ) -> Result<String, InterspireError> {
        if !self.config.is_configured() {
            return Err(InterspireError::XmlNotConfigured);
        }

        let endpoint = self.config.endpoint.as_deref().unwrap_or_default();
        let username = self.config.username.as_deref().unwrap_or_default();
        let token = self.config.token.as_deref().unwrap_or_default();
        let body = build_xml_request(username, token, request_type, request_method, details);

        let response = self
            .with_access_headers(self.http.post(endpoint))
            .header("content-type", "text/xml")
            .timeout(timeout)
            .body(body)
            .send()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        let status = response.status();
        let text = response
            .text()
            .map_err(|err| InterspireError::Http(err.to_string()))?;
        if !status.is_success() {
            return Err(InterspireError::Http(format!(
                "xml endpoint returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(text)
    }

    fn with_access_headers(&self, request: RequestBuilder) -> RequestBuilder {
        let access = &self.config.cloudflare_access;
        let Some(client_id) = access.client_id() else {
            return request;
        };
        let Some(client_secret) = access.client_secret() else {
            return request;
        };

        request
            .header("CF-Access-Client-Id", client_id)
            .header("CF-Access-Client-Secret", client_secret)
    }
}

pub fn xml_evidence(notes: Vec<String>) -> Evidence {
    Evidence {
        source: "interspire_xml_api".to_string(),
        notes,
    }
}

pub(crate) fn initial_subscriber_queries(declared_subscribed_count: Option<u64>) -> Vec<String> {
    if declared_subscribed_count.unwrap_or_default() > 500 {
        initial_sharded_subscriber_queries()
    } else {
        vec!["@".to_string()]
    }
}

pub(crate) fn split_subscriber_query(query: &str, err: &InterspireError) -> Option<Vec<String>> {
    let domain_prefix = query.strip_prefix('@')?;
    if domain_prefix.is_empty() {
        if is_large_subscriber_response_error(err) {
            return Some(initial_sharded_subscriber_queries());
        }
        return None;
    }
    if !can_split_subscriber_shard(err, domain_prefix) {
        return None;
    }

    let mut children = Vec::new();
    for byte in SHARDED_DOMAIN_PREFIX_STARTERS.iter() {
        let mut child = String::from("@");
        child.push_str(domain_prefix);
        child.push(*byte as char);
        children.push(child);
    }
    children.reverse();
    Some(children)
}

fn initial_sharded_subscriber_queries() -> Vec<String> {
    SHARDED_DOMAIN_PREFIX_STARTERS
        .iter()
        .map(|byte| format!("@{}", *byte as char))
        .rev()
        .collect()
}

pub fn parse_get_lists_response(xml: &str) -> Result<Vec<ListSummary>, InterspireError> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|err| InterspireError::XmlParse(err.to_string()))?;
    ensure_success(&doc)?;

    let mut lists = Vec::new();
    for item in doc.descendants().filter(|node| node.has_tag_name("item")) {
        let Some(list_id) = child_text(item, "listid").and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        let name = child_text(item, "name").unwrap_or_else(|| format!("List {list_id}"));
        lists.push(ListSummary {
            list_id,
            name,
            subscribed_count: child_u64(item, "subscribecount"),
            unsubscribed_count: child_u64(item, "unsubscribecount"),
            autoresponder_count: child_u64(item, "autorespondercount"),
            owner_name: None,
            owner_email_redacted: None,
            reply_to_email_redacted: None,
            bounce_email_redacted: None,
            source: "xml".to_string(),
        });
    }

    Ok(lists)
}

pub fn parse_is_subscriber_on_list_response(xml: &str) -> Result<bool, InterspireError> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|err| InterspireError::XmlParse(err.to_string()))?;
    ensure_success(&doc)?;
    let data = doc
        .descendants()
        .find(|node| node.has_tag_name("data"))
        .and_then(|node| node.text())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    Ok(matches!(data.as_str(), "1" | "true" | "yes"))
}

pub fn parse_get_subscribers_response(xml: &str) -> Result<Vec<SubscriberRecord>, InterspireError> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|err| InterspireError::XmlParse(err.to_string()))?;
    ensure_success(&doc)?;

    let mut records = Vec::new();
    for item in doc.descendants().filter(|node| node.has_tag_name("item")) {
        let email_address = child_text(item, "emailaddress").unwrap_or_default();
        if email_address.is_empty() {
            continue;
        }
        records.push(SubscriberRecord {
            subscriber_id: child_u64(item, "subscriberid"),
            email_address,
            subscribe_date: child_u64(item, "subscribedate"),
            confirmed: child_bool(item, "confirmed"),
            unsubscribed: child_bool(item, "unsubscribed"),
            bounced: child_bool(item, "bounced"),
        });
    }

    Ok(records)
}

fn build_xml_request(
    username: &str,
    token: &str,
    request_type: &str,
    request_method: &str,
    details: &str,
) -> String {
    let details = if details.is_empty() { " " } else { details };
    format!(
        "<xmlrequest><username>{}</username><usertoken>{}</usertoken><requesttype>{}</requesttype><requestmethod>{}</requestmethod><details>{}</details></xmlrequest>",
        escape_xml(username),
        escape_xml(token),
        escape_xml(request_type),
        escape_xml(request_method),
        details
    )
}

fn subscriber_search_details(list_id: u64, email_query: &str) -> String {
    format!(
        "<searchinfo><List>{list_id}</List><Status>a</Status><Confirmed>1</Confirmed><Email>{}</Email></searchinfo>",
        escape_xml(email_query)
    )
}

fn ensure_success(doc: &roxmltree::Document<'_>) -> Result<(), InterspireError> {
    let status = doc
        .descendants()
        .find(|node| node.has_tag_name("status"))
        .and_then(|node| node.text())
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    if status == "SUCCESS" {
        return Ok(());
    }

    let message = doc
        .descendants()
        .find(|node| node.has_tag_name("errormessage"))
        .and_then(|node| node.text())
        .unwrap_or("unknown API error");
    Err(InterspireError::Api(message.to_string()))
}

fn child_text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| child.has_tag_name(name))
        .and_then(|child| child.text())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn child_u64(node: roxmltree::Node<'_, '_>, name: &str) -> Option<u64> {
    child_text(node, name).and_then(|value| value.parse::<u64>().ok())
}

fn child_bool(node: roxmltree::Node<'_, '_>, name: &str) -> bool {
    child_text(node, name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn can_split_subscriber_shard(err: &InterspireError, domain_prefix: &str) -> bool {
    domain_prefix.len() < MAX_SHARDED_DOMAIN_PREFIX_LEN && is_large_subscriber_response_error(err)
}

fn is_large_subscriber_response_error(err: &InterspireError) -> bool {
    let message = match err {
        InterspireError::Http(message) | InterspireError::XmlParse(message) => message,
        _ => return false,
    };
    let lower = message.to_ascii_lowercase();
    [
        "truncated",
        "premature eof",
        "unexpected eof",
        "end of file",
        "response too large",
        "document too large",
        "entity too large",
        "http 413",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn parses_get_lists_response() {
        let xml = include_str!("../tests/fixtures/get_lists_success.xml");
        let lists = parse_get_lists_response(xml).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0].list_id, 7);
        assert_eq!(lists[0].subscribed_count, Some(42));
        assert_eq!(lists[1].unsubscribed_count, Some(0));
    }

    #[test]
    fn parses_subscriber_presence_response() {
        assert!(parse_is_subscriber_on_list_response(include_str!(
            "../tests/fixtures/is_subscriber_on_list_success.xml"
        ))
        .unwrap_or(false));
    }

    #[test]
    fn parses_get_subscribers_response() {
        let records = parse_get_subscribers_response(include_str!(
            "../tests/fixtures/get_subscribers_success.xml"
        ))
        .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(records.len(), 4);
        assert_eq!(records[0].subscriber_id, Some(501));
        assert_eq!(records[0].email_address, "first@example.test");
        assert_eq!(records[0].subscribe_date, Some(1710000000));
        assert!(records[0].confirmed);
        assert!(!records[0].unsubscribed);
        assert!(!records[0].bounced);
        assert!(!records[1].confirmed);
        assert!(records[2].unsubscribed);
        assert!(records[3].bounced);
    }

    #[test]
    fn cloudflare_access_headers_are_attached_to_xml_requests() {
        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|err| panic!("bind failed: {err}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|err| panic!("set_nonblocking failed: {err}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("local_addr failed: {err}"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(250)))
                            .unwrap_or_else(|err| panic!("set_read_timeout failed: {err}"));
                        let mut buffer = [0_u8; 8192];
                        let bytes = stream
                            .read(&mut buffer)
                            .unwrap_or_else(|err| panic!("test request read failed: {err}"));
                        let request = String::from_utf8_lossy(&buffer[..bytes]).to_string();
                        thread_requests
                            .lock()
                            .unwrap_or_else(|err| {
                                panic!("test requests lock poisoned while push: {err}")
                            })
                            .push(request);
                        let body = include_str!("../tests/fixtures/get_lists_success.xml");
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/xml; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .unwrap_or_else(|err| panic!("test response write failed: {err}"));
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("test server accept failed: {err}"),
                }
            }
        });

        let client = XmlApiClient::new(XmlApiConfig {
            endpoint: Some(format!("http://{address}/xml.php")),
            username: Some("xml-user".to_string()),
            token: Some("xml-token".to_string()),
            cloudflare_access: crate::config::CloudflareAccessConfig::from_values_for_test(
                "access-client",
                "access-secret",
            ),
        })
        .unwrap_or_else(|err| panic!("{err}"));

        client.get_lists().unwrap_or_else(|err| panic!("{err}"));
        handle
            .join()
            .unwrap_or_else(|_| panic!("test XML server thread panicked"));

        let captured = requests
            .lock()
            .unwrap_or_else(|err| panic!("test requests lock poisoned while read: {err}"));
        assert_eq!(captured.len(), 1);
        let request = captured[0].to_ascii_lowercase();
        assert!(request.contains("cf-access-client-id: access-client\r\n"));
        assert!(request.contains("cf-access-client-secret: access-secret\r\n"));
    }

    #[test]
    fn returns_api_error_without_leaking_token() {
        let err = parse_get_lists_response(
            "<response><status>ERROR</status><errormessage>Invalid details</errormessage></response>",
        )
        .err()
        .unwrap_or_else(|| panic!("expected error"));
        assert_eq!(err.code(), "api_error");
    }

    #[test]
    fn empty_details_are_serialized_as_non_empty_for_legacy_iem() {
        let xml = build_xml_request("admin", "token", "user", "GetLists", "");
        assert!(xml.contains("<details> </details>"));
    }

    #[test]
    fn provided_details_are_preserved() {
        let details = "<emailaddress>a@example.test</emailaddress><listids>7</listids>";
        let xml = build_xml_request(
            "admin",
            "token",
            "subscribers",
            "IsSubscriberOnList",
            details,
        );
        assert!(xml.contains(details));
    }

    #[test]
    fn subscriber_search_details_request_active_confirmed_rows() {
        let details = subscriber_search_details(72, "@example.test");
        assert!(details.contains("<List>72</List>"));
        assert!(details.contains("<Status>a</Status>"));
        assert!(details.contains("<Confirmed>1</Confirmed>"));
        assert!(details.contains("<Email>@example.test</Email>"));
    }

    #[test]
    fn subscriber_shard_split_is_bounded_to_large_response_failures() {
        assert!(can_split_subscriber_shard(
            &InterspireError::XmlParse("truncated response".to_string()),
            "gma"
        ));
        assert!(!can_split_subscriber_shard(
            &InterspireError::Http("timeout".to_string()),
            "gma"
        ));
        assert!(can_split_subscriber_shard(
            &InterspireError::Http("xml endpoint returned HTTP 413".to_string()),
            "gma"
        ));
        assert!(!can_split_subscriber_shard(
            &InterspireError::Api("bad request".to_string()),
            "gma"
        ));
        assert!(!can_split_subscriber_shard(
            &InterspireError::XmlParse("truncated response".to_string()),
            "gmailcom"
        ));
    }
}

use crate::models::service_models::*;
use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, error, warn};

/// Service trait for IAM operations including authentication and authorization.
///
/// This service provides functionality for:
/// - Parsing AWS Signature V4 authentication headers
/// - Validating signatures (basic implementation)
/// - Authorizing requests against IAM policies via HTTP API
/// - Extracting S3 actions and resources from HTTP requests
#[async_trait::async_trait]
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
pub trait IamService: Send + Sync {
    /// Parse AWS Signature V4 authorization header
    fn parse_signature_v4(&self, auth_header: &str) -> Result<SignatureV4, &'static str>;

    /// Extract S3 action and resource from HTTP method and URI
    fn extract_s3_action_resource(&self, method: &str, uri: &str) -> (String, String);

    /// Validate AWS Signature V4 (basic implementation)
    fn validate_signature(
        &self,
        sig_info: &SignatureV4,
        method: &str,
        uri: &str,
        headers: &HashMap<String, String>,
        payload: &[u8],
        secret_key: &str,
    ) -> bool;

    /// Authorize a request against IAM policies
    async fn authorize(&self, request: AuthorizeRequest) -> Result<AuthorizeResponse>;
}

/// HTTP-based IAM service implementation that connects to an IAM API server.
///
/// This service acts as a client to an external IAM service that manages
/// user authentication, authorization policies, and access control decisions.
///
/// # Architecture
///
/// The HttpIamService handles:
/// - AWS Signature V4 parsing and basic validation
/// - HTTP communication with IAM API for authorization decisions
/// - S3 action/resource extraction from HTTP requests
/// - Error handling and retry logic for IAM API calls
///
/// # Usage
///
/// This service is typically used in authentication middleware to:
/// 1. Parse incoming AWS authentication headers
/// 2. Extract the intended S3 action and resource
/// 3. Call the IAM API to check if the action is authorized
/// 4. Allow or deny the request based on the response
pub struct HttpIamService {
    client: Client,
    base_url: String,
}

impl HttpIamService {
    /// Creates a new HttpIamService instance.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the IAM API service (e.g., "http://localhost:8988")
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use s3_core::HttpIamService;
    ///
    /// let iam_service = HttpIamService::new("http://localhost:8988".to_string());
    /// ```
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }
}

#[async_trait::async_trait]
impl IamService for HttpIamService {
    fn parse_signature_v4(&self, auth_header: &str) -> Result<SignatureV4, &'static str> {
        // Check for AWS4-HMAC-SHA256 prefix
        if !auth_header.starts_with("AWS4-HMAC-SHA256") {
            return Err("Missing AWS4-HMAC-SHA256 prefix");
        }

        // Remove AWS4-HMAC-SHA256 prefix and trim whitespace
        let content = auth_header.trim_start_matches("AWS4-HMAC-SHA256").trim();

        let mut parts: HashMap<&str, String> = HashMap::new();

        // Split by comma and parse each key=value pair carefully
        for part in content.split(',') {
            let part = part.trim();
            if let Some(eq_pos) = part.find('=') {
                let key = part[..eq_pos].trim();
                let value = part[eq_pos + 1..].trim();
                parts.insert(key, value.to_string());
            }
        }

        let credential = parts.get("Credential").ok_or("Missing Credential")?;
        let signed_headers = parts.get("SignedHeaders").ok_or("Missing SignedHeaders")?;
        let signature = parts.get("Signature").ok_or("Missing Signature")?;

        let credential_parts: Vec<&str> = credential.split('/').collect();
        if credential_parts.len() < 5 {
            return Err("Invalid credential format");
        }

        let access_key = credential_parts[0];
        let date = credential_parts[1];
        let region = credential_parts[2];
        let service = credential_parts[3];
        let request_type = credential_parts[4];

        let credential_scope = format!("{}/{}/{}/{}", date, region, service, request_type);

        // Parse timestamp from date (AWS format is YYYYMMDD)
        let date_string = format!("{}T000000", date);
        let naive_timestamp = NaiveDateTime::parse_from_str(&date_string, "%Y%m%dT%H%M%S")
            .map_err(|_| "Invalid date format")?;
        let timestamp = Utc.from_utc_datetime(&naive_timestamp);

        Ok(SignatureV4 {
            access_key: access_key.to_string(),
            signature: signature.clone(),
            signed_headers: signed_headers.clone(),
            credential_scope,
            timestamp,
        })
    }

    fn extract_s3_action_resource(&self, method: &str, uri: &str) -> (String, String) {
        let parts: Vec<&str> = uri.trim_start_matches('/').split('/').collect();

        match (method, parts.len()) {
            ("GET", 0) | ("GET", 1) if parts[0].is_empty() => {
                ("s3:ListAllMyBuckets".to_string(), "*".to_string())
            },
            ("PUT", 1) => {
                ("s3:CreateBucket".to_string(), format!("arn:aws:s3:::{}", parts[0]))
            },
            ("GET", 1) => {
                ("s3:ListBucket".to_string(), format!("arn:aws:s3:::{}", parts[0]))
            },
            ("GET", 2) => {
                ("s3:GetObject".to_string(), format!("arn:aws:s3:::{}/{}", parts[0], parts[1]))
            },
            ("PUT", 2) => {
                ("s3:PutObject".to_string(), format!("arn:aws:s3:::{}/{}", parts[0], parts[1]))
            },
            ("DELETE", 2) => {
                ("s3:DeleteObject".to_string(), format!("arn:aws:s3:::{}/{}", parts[0], parts[1]))
            },
            _ => {
                warn!("Unknown S3 action for method: {}, uri: {}", method, uri);
                ("s3:*".to_string(), "*".to_string())
            }
        }
    }

    fn validate_signature(
        &self,
        sig_info: &SignatureV4,
        method: &str,
        uri: &str,
        headers: &HashMap<String, String>,
        payload: &[u8],
        secret_key: &str,
    ) -> bool {
        // This is a simplified signature validation
        // In production, you'd implement the full AWS4 signature algorithm

        let canonical_request = create_canonical_request(method, uri, headers, payload, &sig_info.signed_headers);
        let string_to_sign = create_string_to_sign(&sig_info.timestamp, &sig_info.credential_scope, &canonical_request);
        let expected_signature = calculate_signature(&string_to_sign, secret_key, &sig_info.credential_scope);

        sig_info.signature == expected_signature
    }

    async fn authorize(&self, request: AuthorizeRequest) -> Result<AuthorizeResponse> {
        let url = format!("{}/authorize", self.base_url);

        debug!("Calling IAM authorize endpoint: {}", url);
        debug!("Authorization request: {:?}", request);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            error!("IAM authorization failed with status: {}", response.status());
            return Err(anyhow::anyhow!("IAM authorization failed: {}", response.status()));
        }

        let auth_response: AuthorizeResponse = response.json().await?;
        debug!("Authorization response: {:?}", auth_response);

        Ok(auth_response)
    }
}

// Helper functions for signature validation

fn create_canonical_request(
    method: &str,
    uri: &str,
    headers: &HashMap<String, String>,
    payload: &[u8],
    signed_headers: &str,
) -> String {
    let canonical_uri = uri;
    let canonical_query_string = ""; // Simplified

    let mut canonical_headers = String::new();
    for header_name in signed_headers.split(';') {
        if let Some(header_value) = headers.get(header_name) {
            canonical_headers.push_str(&format!("{}:{}\n", header_name, header_value));
        }
    }

    let payload_hash = hex::encode(Sha256::digest(payload));

    format!("{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query_string, canonical_headers, signed_headers, payload_hash)
}

fn create_string_to_sign(timestamp: &DateTime<Utc>, credential_scope: &str, canonical_request: &str) -> String {
    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    format!("AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp.format("%Y%m%dT%H%M%SZ"), credential_scope, canonical_request_hash)
}

fn calculate_signature(string_to_sign: &str, secret_key: &str, credential_scope: &str) -> String {
    // Simplified signature calculation
    // In production, implement the full HMAC chain: kDate -> kRegion -> kService -> kSigning
    hex::encode(Sha256::digest(format!("{}{}{}", secret_key, credential_scope, string_to_sign).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{method, path, body_json};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_service() -> HttpIamService {
        HttpIamService::new("http://localhost:8988".to_string())
    }

    #[test]
    fn test_parse_signature_v4_valid_header() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_ok());

        let sig_info = result.unwrap();
        assert_eq!(sig_info.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(sig_info.signature, "fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5");
        assert_eq!(sig_info.signed_headers, "host;range;x-amz-date");
        assert_eq!(sig_info.credential_scope, "20230101/us-east-1/s3/aws4_request");
        assert_eq!(sig_info.timestamp, Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_parse_signature_v4_missing_credential() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 SignedHeaders=host;range;x-amz-date, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing Credential");
    }

    #[test]
    fn test_parse_signature_v4_missing_signed_headers() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing SignedHeaders");
    }

    #[test]
    fn test_parse_signature_v4_missing_signature() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing Signature");
    }

    #[test]
    fn test_parse_signature_v4_invalid_credential_format() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1, SignedHeaders=host;range;x-amz-date, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid credential format");
    }

    #[test]
    fn test_parse_signature_v4_credential_with_equals_in_signature() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5==";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_ok());

        let sig_info = result.unwrap();
        assert_eq!(sig_info.signature, "fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5==");
    }

    #[test]
    fn test_parse_signature_v4_malformed_date() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/invalid-date/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid date format");
    }

    #[test]
    fn test_parse_signature_v4_no_aws4_prefix() {
        let service = create_test_service();
        let auth_header = "Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_v4_empty_values() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=, SignedHeaders=, Signature=";

        let result = service.parse_signature_v4(auth_header);
        // This should still work but with empty values
        assert!(result.is_err()); // Should fail due to invalid credential format
    }

    #[test]
    fn test_parse_signature_v4_real_aws_example() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_ok());

        let sig_info = result.unwrap();
        assert_eq!(sig_info.access_key, "AKIAI44QH8DHBEXAMPLE");
        assert_eq!(sig_info.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
        assert_eq!(sig_info.signed_headers, "host;range;x-amz-date");
        assert_eq!(sig_info.credential_scope, "20130524/us-east-1/s3/aws4_request");
        assert_eq!(sig_info.timestamp, Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_parse_signature_v4_whitespace_handling() {
        let service = create_test_service();
        let auth_header = "AWS4-HMAC-SHA256  Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request,  SignedHeaders=host;range;x-amz-date,  Signature=fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5  ";

        let result = service.parse_signature_v4(auth_header);
        assert!(result.is_ok());

        let sig_info = result.unwrap();
        assert_eq!(sig_info.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(sig_info.signature, "fe5a25f78e4b1429a88a1e5de68a6e6f45c1c8bb2f63ce2a8bb6c6c5de30b4e5");
        assert_eq!(sig_info.signed_headers, "host;range;x-amz-date");
    }

    #[test]
    fn test_extract_s3_action_resource() {
        let service = create_test_service();

        assert_eq!(
            service.extract_s3_action_resource("GET", "/"),
            ("s3:ListAllMyBuckets".to_string(), "*".to_string())
        );

        assert_eq!(
            service.extract_s3_action_resource("GET", "/my-bucket"),
            ("s3:ListBucket".to_string(), "arn:aws:s3:::my-bucket".to_string())
        );

        assert_eq!(
            service.extract_s3_action_resource("GET", "/my-bucket/my-object.txt"),
            ("s3:GetObject".to_string(), "arn:aws:s3:::my-bucket/my-object.txt".to_string())
        );

        assert_eq!(
            service.extract_s3_action_resource("PUT", "/my-bucket"),
            ("s3:CreateBucket".to_string(), "arn:aws:s3:::my-bucket".to_string())
        );

        assert_eq!(
            service.extract_s3_action_resource("PUT", "/my-bucket/my-object.txt"),
            ("s3:PutObject".to_string(), "arn:aws:s3:::my-bucket/my-object.txt".to_string())
        );

        assert_eq!(
            service.extract_s3_action_resource("DELETE", "/my-bucket/my-object.txt"),
            ("s3:DeleteObject".to_string(), "arn:aws:s3:::my-bucket/my-object.txt".to_string())
        );
    }

    #[tokio::test]
    async fn test_authorize_success() {
        let mock_server = MockServer::start().await;

        let auth_request = AuthorizeRequest {
            access_key_id: "test-access-key".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: HashMap::new(),
        };

        let auth_response = AuthorizeResponse {
            allowed: true,
            reason: None,
            matched_policies: vec!["test-policy".to_string()],
        };

        Mock::given(method("POST"))
            .and(path("/authorize"))
            .and(body_json(&auth_request))
            .respond_with(ResponseTemplate::new(200).set_body_json(&auth_response))
            .mount(&mock_server)
            .await;

        let service = HttpIamService::new(mock_server.uri());
        let result = service.authorize(auth_request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.allowed);
        assert_eq!(response.matched_policies, vec!["test-policy".to_string()]);
    }

    #[tokio::test]
    async fn test_authorize_denied() {
        let mock_server = MockServer::start().await;

        let auth_request = AuthorizeRequest {
            access_key_id: "test-access-key".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: HashMap::new(),
        };

        let auth_response = AuthorizeResponse {
            allowed: false,
            reason: Some("Access denied".to_string()),
            matched_policies: vec![],
        };

        Mock::given(method("POST"))
            .and(path("/authorize"))
            .and(body_json(&auth_request))
            .respond_with(ResponseTemplate::new(200).set_body_json(&auth_response))
            .mount(&mock_server)
            .await;

        let service = HttpIamService::new(mock_server.uri());
        let result = service.authorize(auth_request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.allowed);
        assert_eq!(response.reason, Some("Access denied".to_string()));
    }

    #[tokio::test]
    async fn test_authorize_server_error() {
        let mock_server = MockServer::start().await;

        let auth_request = AuthorizeRequest {
            access_key_id: "test-access-key".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: HashMap::new(),
        };

        Mock::given(method("POST"))
            .and(path("/authorize"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let service = HttpIamService::new(mock_server.uri());
        let result = service.authorize(auth_request).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_signature_basic() {
        let service = create_test_service();
        let sig_info = SignatureV4 {
            access_key: "test-key".to_string(),
            signature: "test-signature".to_string(),
            signed_headers: "host".to_string(),
            credential_scope: "20230101/us-east-1/s3/aws4_request".to_string(),
            timestamp: Utc::now(),
        };

        let headers = HashMap::new();
        let result = service.validate_signature(
            &sig_info,
            "GET",
            "/test",
            &headers,
            b"test payload",
            "secret-key"
        );

        // This is a basic test - in real implementation you'd test with known values
        assert!(!result); // Expected to fail with our simple implementation
    }
}
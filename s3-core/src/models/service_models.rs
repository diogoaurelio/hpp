use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseFormat {
    Xml,
    Json,
}

#[derive(Debug, Clone)]
pub struct ServiceResponse {
    pub content: String,
    pub content_type: String,
    pub status_code: u16,
}

#[derive(Debug, Clone)]
pub struct GetObjectServiceResponse {
    pub body: Bytes,
    pub content_type: Option<String>,
    pub content_length: u64,
    pub etag: String,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ListObjectsQuery {
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<i32>,
    pub continuation_token: Option<String>,
}

// IAM Service Models

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub access_key_id: String,
    pub action: String,
    pub resource: String,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub matched_policies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SignatureV4 {
    pub access_key: String,
    pub signature: String,
    pub signed_headers: String,
    pub credential_scope: String,
    pub timestamp: DateTime<Utc>,
}
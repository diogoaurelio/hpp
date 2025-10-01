use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub user_name: String,
    pub path: String,
    pub create_date: DateTime<Utc>,
    pub arn: String,
    pub max_session_duration: Option<i32>,
    pub permissions_boundary: Option<String>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKey {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub status: KeyStatus,
    pub create_date: DateTime<Utc>,
    pub user_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub role_id: String,
    pub role_name: String,
    pub path: String,
    pub arn: String,
    pub create_date: DateTime<Utc>,
    pub assume_role_policy_document: String,
    pub description: Option<String>,
    pub max_session_duration: Option<i32>,
    pub permissions_boundary: Option<String>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub policy_name: String,
    pub path: String,
    pub arn: String,
    pub policy_version_id: String,
    pub default_version_id: String,
    pub attachment_count: i32,
    pub permissions_boundary_usage_count: i32,
    pub is_attachable: bool,
    pub description: Option<String>,
    pub create_date: DateTime<Utc>,
    pub update_date: DateTime<Utc>,
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Statement")]
    pub statement: Vec<Statement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "Effect")]
    pub effect: Effect,
    #[serde(rename = "Action")]
    pub action: ActionValue,
    #[serde(rename = "Resource")]
    pub resource: ResourceValue,
    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<HashMap<String, HashMap<String, serde_json::Value>>>,
    #[serde(rename = "Principal", skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ActionValue {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ResourceValue {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrincipalValue {
    Single(String),
    Multiple(Vec<String>),
    Map(HashMap<String, serde_json::Value>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub user_name: String,
    pub path: Option<String>,
    pub permissions_boundary: Option<String>,
    pub tags: Option<Vec<Tag>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccessKeyRequest {
    pub user_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachPolicyRequest {
    pub user_name: Option<String>,
    pub role_name: Option<String>,
    pub policy_arn: String,
}
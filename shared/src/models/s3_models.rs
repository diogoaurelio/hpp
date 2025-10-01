use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Object {
    pub key: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    pub etag: String,
    pub storage_class: StorageClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub name: String,
    pub creation_date: DateTime<Utc>,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageClass {
    Standard,
    ReducedRedundancy,
    Glacier,
    StandardIA,
}

#[derive(Debug, Clone)]
pub struct PutObjectRequest {
    pub bucket: String,
    pub key: String,
    pub body: bytes::Bytes,
    pub content_type: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct GetObjectRequest {
    pub bucket: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct DeleteObjectRequest {
    pub bucket: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct ListObjectsRequest {
    pub bucket: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<i32>,
    pub continuation_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListObjectsResponse {
    pub objects: Vec<S3Object>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GetObjectResponse {
    pub body: bytes::Bytes,
    pub content_type: Option<String>,
    pub content_length: u64,
    pub last_modified: DateTime<Utc>,
    pub etag: String,
    pub metadata: HashMap<String, String>,
}

/// Trait defining the interface for S3-compatible object storage operations
#[async_trait::async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait S3ObjectStorageRepository: Send + Sync {
    /// Put an object into storage
    async fn put_object(&self, request: PutObjectRequest) -> Result<String>;

    /// Get an object from storage
    async fn get_object(&self, request: GetObjectRequest) -> Result<GetObjectResponse>;

    /// Delete an object from storage
    async fn delete_object(&self, request: DeleteObjectRequest) -> Result<()>;

    /// List objects in a bucket
    async fn list_objects(&self, request: ListObjectsRequest) -> Result<ListObjectsResponse>;

    /// List all buckets
    async fn list_buckets(&self) -> Result<Vec<Bucket>>;

    /// Create a new bucket
    async fn create_bucket(&self, bucket_name: &str) -> Result<()>;
}
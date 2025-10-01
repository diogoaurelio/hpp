use crate::models::s3_models::*;
use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{Client, Config};
use aws_config::Region;

/// S3-compatible object storage repository implementation
/// Can work with AWS S3, Hetzner Object Storage, MinIO, or any S3-compatible service
pub struct AwsS3Repository {
    client: Client,
    region: String,
}

impl AwsS3Repository {
    /// Create a new S3ObjectStorageRepository instance
    pub async fn new(
        access_key: String,
        secret_key: String,
        endpoint: String,
        region: String,
    ) -> Result<Self> {
        let creds = aws_sdk_s3::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "hpp-s3-proxy",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .credentials_provider(creds)
            .endpoint_url(&endpoint)
            .load()
            .await;

        let s3_config = Config::from(&config);
        let client = Client::from_conf(s3_config);

        Ok(Self { client, region })
    }
}

#[async_trait::async_trait]
impl S3ObjectStorageRepository for AwsS3Repository {
    async fn put_object(&self, request: PutObjectRequest) -> Result<String> {
        let mut put_request = self
            .client
            .put_object()
            .bucket(&request.bucket)
            .key(&request.key)
            .body(request.body.into());

        if let Some(content_type) = request.content_type {
            put_request = put_request.content_type(content_type);
        }

        for (key, value) in request.metadata {
            put_request = put_request.metadata(key, value);
        }

        let response = put_request.send().await?;

        Ok(response.e_tag().unwrap_or_default().to_string())
    }

    async fn get_object(&self, request: GetObjectRequest) -> Result<GetObjectResponse> {
        let response = self
            .client
            .get_object()
            .bucket(&request.bucket)
            .key(&request.key)
            .send()
            .await?;

        let content_type = response.content_type().map(|s| s.to_string());
        let content_length = response.content_length().unwrap_or(0) as u64;
        let last_modified = response
            .last_modified()
            .and_then(|dt| chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos()))
            .unwrap_or_else(chrono::Utc::now);
        let etag = response.e_tag().unwrap_or_default().to_string();

        let metadata = response
            .metadata()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let body = response.body.collect().await?.into_bytes();

        Ok(GetObjectResponse {
            body,
            content_type,
            content_length,
            last_modified,
            etag,
            metadata,
        })
    }

    async fn delete_object(&self, request: DeleteObjectRequest) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&request.bucket)
            .key(&request.key)
            .send()
            .await?;

        Ok(())
    }

    async fn list_objects(&self, request: ListObjectsRequest) -> Result<ListObjectsResponse> {
        let mut list_request = self
            .client
            .list_objects_v2()
            .bucket(&request.bucket);

        if let Some(prefix) = request.prefix {
            list_request = list_request.prefix(prefix);
        }

        if let Some(delimiter) = request.delimiter {
            list_request = list_request.delimiter(delimiter);
        }

        if let Some(max_keys) = request.max_keys {
            list_request = list_request.max_keys(max_keys);
        }

        if let Some(token) = request.continuation_token {
            list_request = list_request.continuation_token(token);
        }

        let response = list_request.send().await?;

        let objects = response
            .contents()
            .iter()
            .map(|obj| S3Object {
                key: obj.key().unwrap_or_default().to_string(),
                size: obj.size().unwrap_or(0) as u64,
                last_modified: obj
                    .last_modified()
                    .and_then(|dt| chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos()))
                    .unwrap_or_else(chrono::Utc::now),
                etag: obj.e_tag().unwrap_or_default().to_string(),
                storage_class: StorageClass::Standard,
            })
            .collect();

        let common_prefixes = response
            .common_prefixes()
            .iter()
            .filter_map(|cp| cp.prefix().map(|p| p.to_string()))
            .collect();

        Ok(ListObjectsResponse {
            objects,
            common_prefixes,
            is_truncated: response.is_truncated().unwrap_or(false),
            next_continuation_token: response.next_continuation_token().map(|s| s.to_string()),
        })
    }

    async fn list_buckets(&self) -> Result<Vec<Bucket>> {
        let response = self.client.list_buckets().send().await?;

        let buckets = response
            .buckets()
            .iter()
            .map(|bucket| Bucket {
                name: bucket.name().unwrap_or_default().to_string(),
                creation_date: bucket
                    .creation_date()
                    .and_then(|dt| chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos()))
                    .unwrap_or_else(chrono::Utc::now),
                region: self.region.to_string(),
            })
            .collect();

        Ok(buckets)
    }

    async fn create_bucket(&self, bucket_name: &str) -> Result<()> {
        self.client
            .create_bucket()
            .bucket(bucket_name)
            .send()
            .await?;

        Ok(())
    }
}
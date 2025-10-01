use crate::models::service_models::*;
use shared::*;
use anyhow::Result;
use serde_json;
use std::sync::Arc;

#[async_trait::async_trait]
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
pub trait S3Service: Send + Sync {
    async fn list_buckets(&self, format: ResponseFormat) -> Result<ServiceResponse>;
    async fn list_objects(&self, bucket: &str, query_params: ListObjectsQuery, format: ResponseFormat) -> Result<ServiceResponse>;
    async fn create_bucket(&self, bucket: &str, format: ResponseFormat) -> Result<ServiceResponse>;
    async fn get_object(&self, bucket: &str, key: &str) -> Result<GetObjectServiceResponse>;
    async fn put_object(&self, request: PutObjectRequest, format: ResponseFormat) -> Result<ServiceResponse>;
    async fn delete_object(&self, bucket: &str, key: &str, format: ResponseFormat) -> Result<ServiceResponse>;
}

/// A proxy S3 service that acts as an intermediary between the API layer and various
/// S3-compatible storage backends (AWS S3, Hetzner Object Storage, MinIO, etc.).
///
/// This service provides a unified interface for S3 operations while supporting
/// multiple response formats (XML/JSON) and delegating actual storage operations
/// to the configured backend repository.
///
/// # Architecture
///
/// The ProxyS3Service follows the proxy pattern:
/// - Receives S3 API requests from the HTTP handlers
/// - Transforms requests into repository calls
/// - Handles response formatting (XML/JSON conversion)
/// - Returns formatted responses back to the API layer
///
/// # Supported Backends
///
/// Any storage backend that implements `S3ObjectStorageRepository` can be used:
/// - AWS S3
/// - Hetzner Object Storage
/// - MinIO
/// - Other S3-compatible services
pub struct ProxyS3Service {
    repository: Arc<dyn S3ObjectStorageRepository>,
}

impl ProxyS3Service {
    /// Creates a new ProxyS3Service instance that will proxy requests to the given repository.
    ///
    /// # Arguments
    ///
    /// * `repository` - The S3-compatible storage backend to proxy requests to.
    ///                  This can be any implementation of `S3ObjectStorageRepository`
    ///                  (AWS S3, Hetzner Object Storage, MinIO, etc.)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use s3_core::ProxyS3Service;
    /// use shared::AwsS3Repository;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let access_key = "your-access-key".to_string();
    /// let secret_key = "your-secret-key".to_string();
    /// let endpoint = "https://s3.amazonaws.com".to_string();
    /// let region = "us-east-1".to_string();
    ///
    /// let storage_client = Arc::new(
    ///     AwsS3Repository::new(access_key, secret_key, endpoint, region).await?
    /// );
    /// let s3_service = ProxyS3Service::new(storage_client);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(repository: Arc<dyn S3ObjectStorageRepository>) -> Self {
        Self { repository }
    }

    fn format_list_buckets_response(&self, buckets: &[Bucket], format: ResponseFormat) -> ServiceResponse {
        match format {
            ResponseFormat::Xml => {
                let xml = self.list_buckets_xml(buckets);
                ServiceResponse {
                    content: xml,
                    content_type: "application/xml".to_string(),
                    status_code: 200,
                }
            }
            ResponseFormat::Json => {
                let json = serde_json::to_string_pretty(buckets).unwrap_or_default();
                ServiceResponse {
                    content: json,
                    content_type: "application/json".to_string(),
                    status_code: 200,
                }
            }
        }
    }

    fn format_list_objects_response(&self, response: &ListObjectsResponse, format: ResponseFormat) -> ServiceResponse {
        match format {
            ResponseFormat::Xml => {
                let xml = self.list_objects_xml(response);
                ServiceResponse {
                    content: xml,
                    content_type: "application/xml".to_string(),
                    status_code: 200,
                }
            }
            ResponseFormat::Json => {
                let json = serde_json::to_string_pretty(response).unwrap_or_default();
                ServiceResponse {
                    content: json,
                    content_type: "application/json".to_string(),
                    status_code: 200,
                }
            }
        }
    }

    fn format_simple_response(&self, message: &str, format: ResponseFormat) -> ServiceResponse {
        match format {
            ResponseFormat::Xml => {
                let xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Message>{}</Message>", escape_xml(message));
                ServiceResponse {
                    content: xml,
                    content_type: "application/xml".to_string(),
                    status_code: 200,
                }
            }
            ResponseFormat::Json => {
                let json = serde_json::json!({ "message": message }).to_string();
                ServiceResponse {
                    content: json,
                    content_type: "application/json".to_string(),
                    status_code: 200,
                }
            }
        }
    }

    fn list_buckets_xml(&self, buckets: &[Bucket]) -> String {
        let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>hpp-cloud</ID>
        <DisplayName>HPP Cloud</DisplayName>
    </Owner>
    <Buckets>"#);

        for bucket in buckets {
            xml.push_str(&format!(
                r#"
        <Bucket>
            <Name>{}</Name>
            <CreationDate>{}</CreationDate>
        </Bucket>"#,
                escape_xml(&bucket.name),
                bucket.creation_date.format("%Y-%m-%dT%H:%M:%S.%3fZ")
            ));
        }

        xml.push_str(
            r#"
    </Buckets>
</ListAllMyBucketsResult>"#,
        );

        xml
    }

    fn list_objects_xml(&self, response: &ListObjectsResponse) -> String {
        let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <IsTruncated>"#);

        xml.push_str(&response.is_truncated.to_string());
        xml.push_str("</IsTruncated>");

        if let Some(token) = &response.next_continuation_token {
            xml.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", escape_xml(token)));
        }

        for obj in &response.objects {
            xml.push_str(&format!(
                r#"
    <Contents>
        <Key>{}</Key>
        <LastModified>{}</LastModified>
        <ETag>"{}"</ETag>
        <Size>{}</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>"#,
                escape_xml(&obj.key),
                obj.last_modified.format("%Y-%m-%dT%H:%M:%S.%3fZ"),
                escape_xml(&obj.etag),
                obj.size
            ));
        }

        for prefix in &response.common_prefixes {
            xml.push_str(&format!(
                r#"
    <CommonPrefixes>
        <Prefix>{}</Prefix>
    </CommonPrefixes>"#,
                escape_xml(prefix)
            ));
        }

        xml.push_str("</ListBucketResult>");
        xml
    }

    fn error_response(&self, code: &str, message: &str, resource: &str, format: ResponseFormat) -> ServiceResponse {
        match format {
            ResponseFormat::Xml => {
                let xml = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>{}</Code>
    <Message>{}</Message>
    <Resource>{}</Resource>
    <RequestId>{}</RequestId>
</Error>"#,
                    escape_xml(code),
                    escape_xml(message),
                    escape_xml(resource),
                    uuid::Uuid::new_v4()
                );
                ServiceResponse {
                    content: xml,
                    content_type: "application/xml".to_string(),
                    status_code: 400,
                }
            }
            ResponseFormat::Json => {
                let json = serde_json::json!({
                    "error": {
                        "code": code,
                        "message": message,
                        "resource": resource,
                        "request_id": uuid::Uuid::new_v4().to_string()
                    }
                }).to_string();
                ServiceResponse {
                    content: json,
                    content_type: "application/json".to_string(),
                    status_code: 400,
                }
            }
        }
    }
}

/// Implementation of S3Service trait for ProxyS3Service.
///
/// This implementation proxies all S3 operations to the underlying storage repository
/// while handling response formatting and error conversion. Each method:
/// 1. Delegates the actual storage operation to the repository
/// 2. Formats the response according to the requested format (XML/JSON)
/// 3. Converts repository errors into appropriate S3 error responses
#[async_trait::async_trait]
impl S3Service for ProxyS3Service {
    async fn list_buckets(&self, format: ResponseFormat) -> Result<ServiceResponse> {
        match self.repository.list_buckets().await {
            Ok(buckets) => Ok(self.format_list_buckets_response(&buckets, format)),
            Err(err) => Ok(self.error_response("InternalError", &err.to_string(), "/", format)),
        }
    }

    async fn list_objects(&self, bucket: &str, query_params: ListObjectsQuery, format: ResponseFormat) -> Result<ServiceResponse> {
        let request = ListObjectsRequest {
            bucket: bucket.to_string(),
            prefix: query_params.prefix,
            delimiter: query_params.delimiter,
            max_keys: query_params.max_keys,
            continuation_token: query_params.continuation_token,
        };

        match self.repository.list_objects(request).await {
            Ok(response) => Ok(self.format_list_objects_response(&response, format)),
            Err(err) => Ok(self.error_response("InternalError", &err.to_string(), &format!("/{}", bucket), format)),
        }
    }

    async fn create_bucket(&self, bucket: &str, format: ResponseFormat) -> Result<ServiceResponse> {
        match self.repository.create_bucket(bucket).await {
            Ok(_) => Ok(self.format_simple_response("Bucket created successfully", format)),
            Err(err) => Ok(self.error_response("BucketAlreadyExists", &err.to_string(), &format!("/{}", bucket), format)),
        }
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<GetObjectServiceResponse> {
        let request = GetObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
        };

        match self.repository.get_object(request).await {
            Ok(response) => Ok(GetObjectServiceResponse {
                body: response.body,
                content_type: response.content_type,
                content_length: response.content_length,
                etag: response.etag,
                last_modified: response.last_modified,
            }),
            Err(err) => Err(err),
        }
    }

    async fn put_object(&self, request: PutObjectRequest, format: ResponseFormat) -> Result<ServiceResponse> {
        let bucket = request.bucket.clone();
        let key = request.key.clone();

        match self.repository.put_object(request).await {
            Ok(etag) => Ok(ServiceResponse {
                content: match format {
                    ResponseFormat::Xml => format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ETag>{}</ETag>", escape_xml(&etag)),
                    ResponseFormat::Json => serde_json::json!({"etag": etag}).to_string(),
                },
                content_type: match format {
                    ResponseFormat::Xml => "application/xml".to_string(),
                    ResponseFormat::Json => "application/json".to_string(),
                },
                status_code: 200,
            }),
            Err(err) => Ok(self.error_response("InternalError", &err.to_string(), &format!("/{}/{}", bucket, key), format)),
        }
    }

    async fn delete_object(&self, bucket: &str, key: &str, format: ResponseFormat) -> Result<ServiceResponse> {
        let request = DeleteObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
        };

        match self.repository.delete_object(request).await {
            Ok(_) => Ok(self.format_simple_response("Object deleted successfully", format)),
            Err(err) => Ok(self.error_response("InternalError", &err.to_string(), &format!("/{}/{}", bucket, key), format)),
        }
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;
    use mockall::{mock, predicate::*};
    use std::collections::HashMap;

    mock! {
        Repository {}

        #[async_trait::async_trait]
        impl S3ObjectStorageRepository for Repository {
            async fn put_object(&self, request: PutObjectRequest) -> Result<String>;
            async fn get_object(&self, request: GetObjectRequest) -> Result<GetObjectResponse>;
            async fn delete_object(&self, request: DeleteObjectRequest) -> Result<()>;
            async fn list_objects(&self, request: ListObjectsRequest) -> Result<ListObjectsResponse>;
            async fn list_buckets(&self) -> Result<Vec<Bucket>>;
            async fn create_bucket(&self, bucket_name: &str) -> Result<()>;
        }
    }


    fn create_test_bucket() -> Bucket {
        Bucket {
            name: "test-bucket".to_string(),
            creation_date: Utc::now(),
            region: "us-east-1".to_string(),
        }
    }

    fn create_test_object() -> S3Object {
        S3Object {
            key: "test-file.txt".to_string(),
            size: 1024,
            last_modified: Utc::now(),
            etag: "abc123".to_string(),
            storage_class: StorageClass::Standard,
        }
    }

    #[tokio::test]
    async fn test_list_buckets_xml_format() {
        let test_bucket = create_test_bucket();
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_list_buckets()
            .times(1)
            .returning(move || Ok(vec![test_bucket.clone()]));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.list_buckets(ResponseFormat::Xml).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/xml");
        assert!(result.content.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(result.content.contains("<ListAllMyBucketsResult"));
        assert!(result.content.contains("<Name>test-bucket</Name>"));
        assert!(result.content.contains("HPP Cloud"));
    }

    #[tokio::test]
    async fn test_list_buckets_json_format() {
        let test_bucket = create_test_bucket();
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_list_buckets()
            .times(1)
            .returning(move || Ok(vec![test_bucket.clone()]));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.list_buckets(ResponseFormat::Json).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/json");
        assert!(result.content.contains("test-bucket"));
        assert!(result.content.contains("us-east-1"));

        // Verify it's valid JSON
        let _: serde_json::Value = serde_json::from_str(&result.content).unwrap();
    }

    #[tokio::test]
    async fn test_list_buckets_error_handling() {
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_list_buckets()
            .times(1)
            .returning(|| Err(anyhow::anyhow!("Repository error")));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.list_buckets(ResponseFormat::Xml).await.unwrap();

        assert_eq!(result.status_code, 400);
        assert_eq!(result.content_type, "application/xml");
        assert!(result.content.contains("<Code>InternalError</Code>"));
        assert!(result.content.contains("<Message>Repository error</Message>"));
        assert!(result.content.contains("<Resource>/</Resource>"));
    }

    #[tokio::test]
    async fn test_list_objects_xml_format() {
        let test_object = create_test_object();
        let list_response = ListObjectsResponse {
            objects: vec![test_object],
            common_prefixes: vec!["folder/".to_string()],
            is_truncated: false,
            next_continuation_token: Some("token123".to_string()),
        };

        let mut mock_repo = MockRepository::new();
        mock_repo
            .expect_list_objects()
            .times(1)
            .returning(move |_| Ok(list_response.clone()));

        let service = ProxyS3Service::new(Arc::new(mock_repo));

        let query_params = ListObjectsQuery {
            prefix: Some("prefix/".to_string()),
            delimiter: Some("/".to_string()),
            max_keys: Some(10),
            continuation_token: None,
        };

        let result = service.list_objects("test-bucket", query_params, ResponseFormat::Xml).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/xml");
        assert!(result.content.contains("<ListBucketResult"));
        assert!(result.content.contains("<Key>test-file.txt</Key>"));
        assert!(result.content.contains("<Size>1024</Size>"));
        assert!(result.content.contains("<ETag>\"abc123\"</ETag>"));
        assert!(result.content.contains("<Prefix>folder/</Prefix>"));
        assert!(result.content.contains("<NextContinuationToken>token123</NextContinuationToken>"));
        assert!(result.content.contains("<IsTruncated>false</IsTruncated>"));
    }

    #[tokio::test]
    async fn test_create_bucket_success() {
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_create_bucket()
            .with(eq("new-bucket"))
            .times(1)
            .returning(|_| Ok(()));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.create_bucket("new-bucket", ResponseFormat::Json).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/json");
        assert!(result.content.contains("Bucket created successfully"));
    }

    #[tokio::test]
    async fn test_create_bucket_error() {
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_create_bucket()
            .times(1)
            .returning(|_| Err(anyhow::anyhow!("Bucket already exists")));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.create_bucket("existing-bucket", ResponseFormat::Xml).await.unwrap();

        assert_eq!(result.status_code, 400);
        assert_eq!(result.content_type, "application/xml");
        assert!(result.content.contains("<Code>BucketAlreadyExists</Code>"));
        assert!(result.content.contains("<Message>Bucket already exists</Message>"));
    }

    #[tokio::test]
    async fn test_get_object_success() {
        let test_body = Bytes::from("test content");
        let test_time = Utc::now();

        let get_response = GetObjectResponse {
            body: test_body.clone(),
            content_type: Some("text/plain".to_string()),
            content_length: 12,
            last_modified: test_time,
            etag: "etag123".to_string(),
            metadata: HashMap::new(),
        };

        let mut mock_repo = MockRepository::new();
        mock_repo
            .expect_get_object()
            .times(1)
            .returning(move |_| Ok(get_response.clone()));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.get_object("test-bucket", "test-file.txt").await.unwrap();

        assert_eq!(result.body, test_body);
        assert_eq!(result.content_type, Some("text/plain".to_string()));
        assert_eq!(result.content_length, 12);
        assert_eq!(result.etag, "etag123");
        assert_eq!(result.last_modified, test_time);
    }

    #[tokio::test]
    async fn test_put_object_xml_format() {
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_put_object()
            .times(1)
            .returning(|_| Ok("new-etag123".to_string()));

        let service = ProxyS3Service::new(Arc::new(mock_repo));

        let put_request = PutObjectRequest {
            bucket: "test-bucket".to_string(),
            key: "new-file.txt".to_string(),
            body: Bytes::from("new content"),
            content_type: Some("text/plain".to_string()),
            metadata: HashMap::new(),
        };

        let result = service.put_object(put_request, ResponseFormat::Xml).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/xml");
        assert!(result.content.contains("<ETag>new-etag123</ETag>"));
    }

    #[tokio::test]
    async fn test_delete_object_success() {
        let mut mock_repo = MockRepository::new();

        mock_repo
            .expect_delete_object()
            .times(1)
            .returning(|_| Ok(()));

        let service = ProxyS3Service::new(Arc::new(mock_repo));
        let result = service.delete_object("test-bucket", "file-to-delete.txt", ResponseFormat::Json).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/json");
        assert!(result.content.contains("Object deleted successfully"));
    }

    #[tokio::test]
    async fn test_xml_escaping() {
        let test_str = "test & <script>alert('xss')</script> \"quoted\" 'single'";
        let escaped = escape_xml(test_str);

        assert_eq!(escaped, "test &amp; &lt;script&gt;alert(&apos;xss&apos;)&lt;/script&gt; &quot;quoted&quot; &apos;single&apos;");
    }

    #[tokio::test]
    async fn test_error_response_json_format() {
        let mock_repo = MockRepository::new();
        let service = ProxyS3Service::new(Arc::new(mock_repo));

        let response = service.error_response("TestError", "Test error message", "/test-resource", ResponseFormat::Json);

        assert_eq!(response.status_code, 400);
        assert_eq!(response.content_type, "application/json");
        assert!(response.content.contains("TestError"));
        assert!(response.content.contains("Test error message"));
        assert!(response.content.contains("/test-resource"));

        // Verify it's valid JSON
        let json: serde_json::Value = serde_json::from_str(&response.content).unwrap();
        assert_eq!(json["error"]["code"], "TestError");
        assert_eq!(json["error"]["message"], "Test error message");
        assert_eq!(json["error"]["resource"], "/test-resource");
        assert!(json["error"]["request_id"].is_string());
    }

    #[tokio::test]
    async fn test_list_objects_json_format() {
        let test_object = create_test_object();
        let list_response = ListObjectsResponse {
            objects: vec![test_object],
            common_prefixes: vec![],
            is_truncated: false,
            next_continuation_token: None,
        };

        let mut mock_repo = MockRepository::new();
        mock_repo
            .expect_list_objects()
            .times(1)
            .returning(move |_| Ok(list_response.clone()));

        let service = ProxyS3Service::new(Arc::new(mock_repo));

        let query_params = ListObjectsQuery {
            prefix: None,
            delimiter: None,
            max_keys: None,
            continuation_token: None,
        };

        let result = service.list_objects("test-bucket", query_params, ResponseFormat::Json).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.content_type, "application/json");
        assert!(result.content.contains("test-file.txt"));
        assert!(result.content.contains("1024"));
        assert!(result.content.contains("abc123"));
    }
}
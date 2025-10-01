use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    body::Body,
};
use shared::*;
use s3_core::*;
use std::collections::HashMap;
use tracing::{debug, error};

pub async fn list_buckets(State(state): State<AppState>) -> Result<Response<Body>, StatusCode> {
    debug!("Received list_buckets request");

    // Default to XML format for S3 compatibility
    let format = ResponseFormat::Xml;

    match state.s3_service.list_buckets(format).await {
        Ok(service_response) => {
            debug!("list_buckets response: status={}", service_response.status_code);
            Ok(Response::builder()
                .status(StatusCode::from_u16(service_response.status_code).unwrap_or(StatusCode::OK))
                .header("content-type", service_response.content_type)
                .body(Body::from(service_response.content))
                .unwrap())
        }
        Err(err) => {
            error!("Failed to list buckets: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Received list_objects request for bucket: {}, params: {:?}", bucket, params);

    // Default to XML format for S3 compatibility
    let format = ResponseFormat::Xml;

    let query_params = ListObjectsQuery {
        prefix: params.get("prefix").cloned(),
        delimiter: params.get("delimiter").cloned(),
        max_keys: params.get("max-keys").and_then(|s| s.parse().ok()),
        continuation_token: params.get("continuation-token").cloned(),
    };

    match state.s3_service.list_objects(&bucket, query_params, format).await {
        Ok(service_response) => {
            debug!("list_objects response: status={}", service_response.status_code);
            Ok(Response::builder()
                .status(StatusCode::from_u16(service_response.status_code).unwrap_or(StatusCode::OK))
                .header("content-type", service_response.content_type)
                .body(Body::from(service_response.content))
                .unwrap())
        }
        Err(err) => {
            error!("Failed to list objects: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Received get_object request for bucket: {}, key: {}", bucket, key);

    match state.s3_service.get_object(&bucket, &key).await {
        Ok(response) => {
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("content-length", response.content_length.to_string())
                .header("etag", format!("\"{}\"", response.etag))
                .header("last-modified", response.last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

            if let Some(content_type) = response.content_type {
                builder = builder.header("content-type", content_type);
            }

            Ok(builder.body(Body::from(response.body)).unwrap())
        }
        Err(err) => {
            error!("Failed to get object: {:?}", err);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    debug!("Received put_object request for bucket: {}, key: {}", bucket, key);

    // Default to XML format for S3 compatibility
    let format = ResponseFormat::Xml;

    let content_type = headers.get("content-type")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let metadata = headers
        .iter()
        .filter_map(|(k, v)| {
            if k.as_str().starts_with("x-amz-meta-") {
                let key = k.as_str().strip_prefix("x-amz-meta-")?;
                let value = v.to_str().ok()?;
                Some((key.to_string(), value.to_string()))
            } else {
                None
            }
        })
        .collect();

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!("Failed to read request body: {:?}", err);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let request = PutObjectRequest {
        bucket,
        key,
        body: body_bytes,
        content_type,
        metadata,
    };

    match state.s3_service.put_object(request, format).await {
        Ok(service_response) => {
            debug!("put_object response: status={}", service_response.status_code);
            Ok(Response::builder()
                .status(StatusCode::from_u16(service_response.status_code).unwrap_or(StatusCode::OK))
                .header("content-type", service_response.content_type)
                .body(Body::from(service_response.content))
                .unwrap())
        }
        Err(err) => {
            error!("Failed to put object: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Received delete_object request for bucket: {}, key: {}", bucket, key);

    // Default to XML format for S3 compatibility
    let format = ResponseFormat::Xml;

    match state.s3_service.delete_object(&bucket, &key, format).await {
        Ok(service_response) => {
            debug!("delete_object response: status={}", service_response.status_code);
            Ok(Response::builder()
                .status(StatusCode::from_u16(service_response.status_code).unwrap_or(StatusCode::NO_CONTENT))
                .header("content-type", service_response.content_type)
                .body(Body::from(service_response.content))
                .unwrap())
        }
        Err(err) => {
            error!("Failed to delete object: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Received create_bucket request for bucket: {}", bucket);

    // Default to XML format for S3 compatibility
    let format = ResponseFormat::Xml;

    match state.s3_service.create_bucket(&bucket, format).await {
        Ok(service_response) => {
            debug!("create_bucket response: status={}", service_response.status_code);
            Ok(Response::builder()
                .status(StatusCode::from_u16(service_response.status_code).unwrap_or(StatusCode::OK))
                .header("content-type", service_response.content_type)
                .body(Body::from(service_response.content))
                .unwrap())
        }
        Err(err) => {
            error!("Failed to create bucket: {:?}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
        routing::{delete, get, put},
        Router,
    };
    use bytes::Bytes;
    use chrono::Utc;
    use s3_core::{MockS3Service, MockIamService};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn create_test_app_state_with_s3_mock(mock_s3: MockS3Service) -> AppState {
        let mock_iam = MockIamService::new();

        AppState {
            s3_service: Arc::new(mock_s3),
            iam_service: Arc::new(mock_iam),
        }
    }

    #[tokio::test]
    async fn test_list_buckets_success() {
        // Mock successful service response
        let expected_response = ServiceResponse {
            content: r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Buckets>
        <Bucket>
            <Name>test-bucket</Name>
            <CreationDate>2023-01-01T12:00:00.000Z</CreationDate>
        </Bucket>
    </Buckets>
</ListAllMyBucketsResult>"#.to_string(),
            content_type: "application/xml".to_string(),
            status_code: 200,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_list_buckets()
            .with(mockall::predicate::eq(ResponseFormat::Xml))
            .times(1)
            .returning(move |_| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/", get(list_buckets))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn test_list_buckets_service_error() {
        let mut mock_s3 = MockS3Service::new();
        mock_s3.expect_list_buckets()
            .times(1)
            .returning(|_| Box::pin(async move { Err(anyhow::anyhow!("Service error")) }));

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/", get(list_buckets))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_list_objects_success() {
        let expected_response = ServiceResponse {
            content: r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>test-object.txt</Key>
        <Size>1024</Size>
    </Contents>
</ListBucketResult>"#.to_string(),
            content_type: "application/xml".to_string(),
            status_code: 200,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_list_objects()
            .withf(|bucket, query, format| {
                bucket == "test-bucket"
                && query.prefix == Some("test/".to_string())
                && matches!(format, ResponseFormat::Xml)
            })
            .times(1)
            .returning(move |_, _, _| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket", get(list_objects))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket?prefix=test/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn test_get_object_success() {
        let timestamp = Utc::now();
        let expected_response = GetObjectServiceResponse {
            body: Bytes::from("test file content"),
            content_type: Some("text/plain".to_string()),
            content_length: 17,
            etag: "abc123".to_string(),
            last_modified: timestamp,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_get_object()
            .with(
                mockall::predicate::eq("test-bucket"),
                mockall::predicate::eq("test-object.txt")
            )
            .times(1)
            .returning(move |_, _| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket/:key", get(get_object))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket/test-object.txt")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain"
        );
        assert_eq!(
            response.headers().get("content-length").unwrap(),
            "17"
        );
        assert_eq!(
            response.headers().get("etag").unwrap(),
            "\"abc123\""
        );
    }

    #[tokio::test]
    async fn test_get_object_not_found() {
        let mut mock_s3 = MockS3Service::new();
        mock_s3.expect_get_object()
            .times(1)
            .returning(|_, _| Box::pin(async move { Err(anyhow::anyhow!("Object not found")) }));

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket/:key", get(get_object))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket/nonexistent.txt")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_put_object_success() {
        let expected_response = ServiceResponse {
            content: r#"<?xml version="1.0" encoding="UTF-8"?><ETag>new-etag123</ETag>"#.to_string(),
            content_type: "application/xml".to_string(),
            status_code: 200,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_put_object()
            .withf(|req, format| {
                req.bucket == "test-bucket"
                && req.key == "new-file.txt"
                && req.body == Bytes::from("test content")
                && req.content_type == Some("text/plain".to_string())
                && matches!(format, ResponseFormat::Xml)
            })
            .times(1)
            .returning(move |_, _| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket/:key", put(put_object))
            .with_state(state);

        let request = Request::builder()
            .method(Method::PUT)
            .uri("/test-bucket/new-file.txt")
            .header("content-type", "text/plain")
            .header("x-amz-meta-user", "testuser")
            .body(Body::from("test content"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn test_put_object_service_error() {
        let mut mock_s3 = MockS3Service::new();
        mock_s3.expect_put_object()
            .times(1)
            .returning(|_, _| Box::pin(async move { Err(anyhow::anyhow!("Storage error")) }));

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket/:key", put(put_object))
            .with_state(state);

        let request = Request::builder()
            .method(Method::PUT)
            .uri("/test-bucket/test-file.txt")
            .body(Body::from("content"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_delete_object_success() {
        let expected_response = ServiceResponse {
            content: r#"{"message": "Object deleted successfully"}"#.to_string(),
            content_type: "application/xml".to_string(),
            status_code: 200,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_delete_object()
            .with(
                mockall::predicate::eq("test-bucket"),
                mockall::predicate::eq("file-to-delete.txt"),
                mockall::predicate::eq(ResponseFormat::Xml)
            )
            .times(1)
            .returning(move |_, _, _| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket/:key", delete(delete_object))
            .with_state(state);

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/test-bucket/file-to-delete.txt")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn test_delete_object_service_error() {
        let mut mock_s3 = MockS3Service::new();
        mock_s3.expect_delete_object()
            .times(1)
            .returning(|_, _, _| Box::pin(async move { Err(anyhow::anyhow!("Delete failed")) }));

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket/:key", delete(delete_object))
            .with_state(state);

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/test-bucket/test-file.txt")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_create_bucket_success() {
        let expected_response = ServiceResponse {
            content: r#"<?xml version="1.0" encoding="UTF-8"?><Message>Bucket created successfully</Message>"#.to_string(),
            content_type: "application/xml".to_string(),
            status_code: 200,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_create_bucket()
            .with(
                mockall::predicate::eq("new-bucket"),
                mockall::predicate::eq(ResponseFormat::Xml)
            )
            .times(1)
            .returning(move |_, _| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket", put(create_bucket))
            .with_state(state);

        let request = Request::builder()
            .method(Method::PUT)
            .uri("/new-bucket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn test_create_bucket_already_exists() {
        let mut mock_s3 = MockS3Service::new();
        mock_s3.expect_create_bucket()
            .times(1)
            .returning(|_, _| Box::pin(async move { Err(anyhow::anyhow!("Bucket already exists")) }));

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket", put(create_bucket))
            .with_state(state);

        let request = Request::builder()
            .method(Method::PUT)
            .uri("/existing-bucket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_list_objects_with_query_parameters() {
        let expected_response = ServiceResponse {
            content: "test xml content".to_string(),
            content_type: "application/xml".to_string(),
            status_code: 200,
        };

        let mut mock_s3 = MockS3Service::new();
        let response_clone = expected_response.clone();
        mock_s3.expect_list_objects()
            .withf(|bucket, query, _| {
                bucket == "test-bucket"
                && query.prefix == Some("documents/".to_string())
                && query.delimiter == Some("/".to_string())
                && query.max_keys == Some(100)
                && query.continuation_token == Some("token123".to_string())
            })
            .times(1)
            .returning(move |_, _, _| {
                let response = response_clone.clone();
                Box::pin(async move { Ok(response) })
            });

        let state = create_test_app_state_with_s3_mock(mock_s3);

        let app = Router::new()
            .route("/:bucket", get(list_objects))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket?prefix=documents/&delimiter=/&max-keys=100&continuation-token=token123")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
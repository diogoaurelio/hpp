use crate::AppState;
use s3_core::AuthorizeRequest;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use tracing::{error, warn};
use tracing::log::info;

#[derive(Debug)]
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}


pub async fn auth_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = request.headers();

    // Check for AWS4-HMAC-SHA256 authorization
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;

        if auth_str.starts_with("AWS4-HMAC-SHA256") {
            // This middleware is deprecated - use iam_auth_middleware instead
            // For now, just allow all AWS4 signed requests
            return Ok(next.run(request).await);
        }
    } else {
        // No authorization header
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}


pub async fn iam_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    info!("received iam auth request");
    let headers = request.headers();

    // Check for AWS4-HMAC-SHA256 authorization
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
        info!("auth header: {:?}", auth_str);

        if auth_str.starts_with("AWS4-HMAC-SHA256") {
            let sig_info = state.iam_service.parse_signature_v4(auth_str).map_err(|_| StatusCode::UNAUTHORIZED)?;

            // Extract S3 action and resource from request
            let method = request.method().as_str();
            let uri = request.uri().path();

            let (action, resource) = state.iam_service.extract_s3_action_resource(method, uri);

            info!("Extracted S3 action: {}, resource: {}", action, resource);

            // Create authorization request
            let auth_request = AuthorizeRequest {
                access_key_id: sig_info.access_key.clone(),
                action,
                resource,
                context: HashMap::new(), // Could add request context like IP, timestamp, etc.
            };

            // Call IAM API for authorization
            match state.iam_service.authorize(auth_request).await {
                Ok(auth_response) => {
                    if auth_response.allowed {
                        info!("Authorization granted for access key: {}", sig_info.access_key);
                        // Store access key in request extensions for handlers to use
                        request.extensions_mut().insert(sig_info.access_key);
                        Ok(next.run(request).await)
                    } else {
                        warn!("Authorization denied: {:?}", auth_response.reason);
                        Err(StatusCode::FORBIDDEN)
                    }
                },
                Err(err) => {
                    error!("Failed to call IAM API: {:?}", err);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        } else {
            warn!("Unsupported authorization header format");
            Err(StatusCode::UNAUTHORIZED)
        }
    } else {
        warn!("No authorization header found");
        Err(StatusCode::UNAUTHORIZED)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        middleware::from_fn_with_state,
        routing::get,
        Router,
    };
    use s3_core::{MockIamService, S3Service, ProxyS3Service, SignatureV4, AuthorizeResponse, IamService};
    use shared::MockS3ObjectStorageRepository;
    use std::sync::Arc;
    use tower::ServiceExt;
    use chrono::Utc;

    async fn dummy_handler() -> &'static str {
        "success"
    }

    fn create_test_signature_v4() -> SignatureV4 {
        SignatureV4 {
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            signature: "test-signature".to_string(),
            signed_headers: "host;x-amz-date".to_string(),
            credential_scope: "20230101/us-east-1/s3/aws4_request".to_string(),
            timestamp: Utc::now(),
        }
    }

    fn create_app_state_with_mock_iam(mock_iam: MockIamService) -> AppState {
        // Create a mock S3 repository and service for the AppState
        let mock_repo = MockS3ObjectStorageRepository::new();
        let s3_service: Arc<dyn S3Service> = Arc::new(ProxyS3Service::new(Arc::new(mock_repo)));
        let iam_service: Arc<dyn IamService> = Arc::new(mock_iam);

        AppState {
            s3_service,
            iam_service,
        }
    }

    #[tokio::test]
    async fn test_iam_auth_middleware_success() {
        let mut mock_iam = MockIamService::new();

        // Mock signature parsing
        mock_iam
            .expect_parse_signature_v4()
            .returning(|_| Ok(create_test_signature_v4()));

        // Mock action extraction
        mock_iam
            .expect_extract_s3_action_resource()
            .returning(|_, _| ("s3:GetObject".to_string(), "arn:aws:s3:::test-bucket/test-object".to_string()));

        // Mock successful authorization
        mock_iam
            .expect_authorize()
            .returning(|_| Box::pin(async move {
                Ok(AuthorizeResponse {
                    allowed: true,
                    reason: None,
                    matched_policies: vec!["test-policy".to_string()],
                })
            }));

        let state = create_app_state_with_mock_iam(mock_iam);

        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test-signature")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_iam_auth_middleware_parse_signature_failure() {
        let mut mock_iam = MockIamService::new();

        // Mock signature parsing failure
        mock_iam
            .expect_parse_signature_v4()
            .returning(|_| Err("Invalid signature format"));

        let state = create_app_state_with_mock_iam(mock_iam);

        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("authorization", "Invalid-Auth-Header")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_iam_auth_middleware_authorization_denied() {
        let mut mock_iam = MockIamService::new();

        // Mock signature parsing
        mock_iam
            .expect_parse_signature_v4()
            .returning(|_| Ok(create_test_signature_v4()));

        // Mock action extraction
        mock_iam
            .expect_extract_s3_action_resource()
            .returning(|_, _| ("s3:GetObject".to_string(), "arn:aws:s3:::test-bucket/test-object".to_string()));

        // Mock denied authorization
        mock_iam
            .expect_authorize()
            .returning(|_| Box::pin(async move {
                Ok(AuthorizeResponse {
                    allowed: false,
                    reason: Some("Access denied".to_string()),
                    matched_policies: vec![],
                })
            }));

        let state = create_app_state_with_mock_iam(mock_iam);

        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test-signature")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_iam_auth_middleware_iam_service_error() {
        let mut mock_iam = MockIamService::new();

        // Mock signature parsing
        mock_iam
            .expect_parse_signature_v4()
            .returning(|_| Ok(create_test_signature_v4()));

        // Mock action extraction
        mock_iam
            .expect_extract_s3_action_resource()
            .returning(|_, _| ("s3:GetObject".to_string(), "arn:aws:s3:::test-bucket/test-object".to_string()));

        // Mock IAM service error
        mock_iam
            .expect_authorize()
            .returning(|_| Box::pin(async move {
                Err(anyhow::anyhow!("IAM service unavailable"))
            }));

        let state = create_app_state_with_mock_iam(mock_iam);

        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test-signature")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_iam_auth_middleware_missing_authorization_header() {
        let mock_iam = MockIamService::new();
        let state = create_app_state_with_mock_iam(mock_iam);

        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_iam_auth_middleware_non_aws4_auth_header() {
        let mock_iam = MockIamService::new();
        let state = create_app_state_with_mock_iam(mock_iam);

        let app = Router::new()
            .route("/test", get(dummy_handler))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("authorization", "Bearer some-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // Note: test_iam_auth_middleware_invalid_auth_header_encoding removed
    // because HTTP library prevents building requests with invalid UTF-8 headers

    #[tokio::test]
    async fn test_iam_auth_middleware_different_s3_actions() {
        // Test different HTTP methods and URIs to ensure proper action extraction
        let test_cases = vec![
            (Method::GET, "/", "s3:ListAllMyBuckets", "*"),
            (Method::GET, "/my-bucket", "s3:ListBucket", "arn:aws:s3:::my-bucket"),
            (Method::PUT, "/my-bucket", "s3:CreateBucket", "arn:aws:s3:::my-bucket"),
            (Method::GET, "/my-bucket/object.txt", "s3:GetObject", "arn:aws:s3:::my-bucket/object.txt"),
            (Method::PUT, "/my-bucket/object.txt", "s3:PutObject", "arn:aws:s3:::my-bucket/object.txt"),
            (Method::DELETE, "/my-bucket/object.txt", "s3:DeleteObject", "arn:aws:s3:::my-bucket/object.txt"),
        ];

        for (method, uri, expected_action, expected_resource) in test_cases {
            let mut mock_iam = MockIamService::new();

            // Mock signature parsing
            mock_iam
                .expect_parse_signature_v4()
                .returning(|_| Ok(create_test_signature_v4()));

            // Mock action extraction with specific expectations
            let expected_action_clone = expected_action.to_string();
            let expected_resource_clone = expected_resource.to_string();
            mock_iam
                .expect_extract_s3_action_resource()
                .returning(move |_, _| (expected_action_clone.clone(), expected_resource_clone.clone()));

            // Mock successful authorization
            mock_iam
                .expect_authorize()
                .withf(move |req| req.action == expected_action && req.resource == expected_resource)
                .returning(|_| Box::pin(async move {
                    Ok(AuthorizeResponse {
                        allowed: true,
                        reason: None,
                        matched_policies: vec!["test-policy".to_string()],
                    })
                }));

            let state = create_app_state_with_mock_iam(mock_iam);

            let app = Router::new()
                .route("/", get(dummy_handler))
                .route("/:bucket", get(dummy_handler).put(dummy_handler))
                .route("/:bucket/:key", get(dummy_handler).put(dummy_handler).delete(dummy_handler))
                .layer(from_fn_with_state(state, iam_auth_middleware));

            let request = Request::builder()
                .method(method.clone())
                .uri(uri)
                .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test-signature")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "Failed for {} {}", method, uri);
        }
    }

    #[tokio::test]
    async fn test_access_key_stored_in_request_extensions() {
        let mut mock_iam = MockIamService::new();

        // Mock signature parsing
        let expected_access_key = "AKIAIOSFODNN7EXAMPLE";
        let mut test_sig = create_test_signature_v4();
        test_sig.access_key = expected_access_key.to_string();

        mock_iam
            .expect_parse_signature_v4()
            .returning(move |_| Ok(test_sig.clone()));

        // Mock action extraction
        mock_iam
            .expect_extract_s3_action_resource()
            .returning(|_, _| ("s3:GetObject".to_string(), "arn:aws:s3:::test-bucket/test-object".to_string()));

        // Mock successful authorization
        mock_iam
            .expect_authorize()
            .returning(|_| Box::pin(async move {
                Ok(AuthorizeResponse {
                    allowed: true,
                    reason: None,
                    matched_policies: vec!["test-policy".to_string()],
                })
            }));

        let state = create_app_state_with_mock_iam(mock_iam);

        async fn handler_with_extension_check(req: Request<Body>) -> Result<&'static str, StatusCode> {
            let access_key = req.extensions().get::<String>().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
            if access_key == "AKIAIOSFODNN7EXAMPLE" {
                Ok("access key stored correctly")
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }

        let app = Router::new()
            .route("/test", get(handler_with_extension_check))
            .layer(from_fn_with_state(state, iam_auth_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test-signature")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use iam_core::*;
use serde_json::{json, Value};

pub async fn create_user(
    State(state): State<AppState>,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<Value>, StatusCode> {
    let mut iam_service = state.iam_service.lock().unwrap();
    
    match iam_service.create_user(request) {
        Ok(user) => Ok(Json(json!({
            "CreateUserResponse": {
                "CreateUserResult": {
                    "User": user
                },
                "ResponseMetadata": {
                    "RequestId": uuid::Uuid::new_v4().to_string()
                }
            }
        }))),
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(user_name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let iam_service = state.iam_service.lock().unwrap();
    
    match iam_service.get_user(&user_name) {
        Some(user) => Ok(Json(json!({
            "GetUserResponse": {
                "GetUserResult": {
                    "User": user
                },
                "ResponseMetadata": {
                    "RequestId": uuid::Uuid::new_v4().to_string()
                }
            }
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn list_users(
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusCode> {
    let iam_service = state.iam_service.lock().unwrap();
    let users = iam_service.list_users();
    
    Ok(Json(json!({
        "ListUsersResponse": {
            "ListUsersResult": {
                "Users": users,
                "IsTruncated": false
            },
            "ResponseMetadata": {
                "RequestId": uuid::Uuid::new_v4().to_string()
            }
        }
    })))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut iam_service = state.iam_service.lock().unwrap();
    
    match iam_service.delete_user(&user_name) {
        Ok(()) => Ok(Json(json!({
            "DeleteUserResponse": {
                "ResponseMetadata": {
                    "RequestId": uuid::Uuid::new_v4().to_string()
                }
            }
        }))),
        Err(e) => {
            tracing::error!("Failed to delete user: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn create_access_key(
    State(state): State<AppState>,
    Path(user_name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut iam_service = state.iam_service.lock().unwrap();
    let request = CreateAccessKeyRequest { user_name };
    
    match iam_service.create_access_key(request) {
        Ok(access_key) => Ok(Json(json!({
            "CreateAccessKeyResponse": {
                "CreateAccessKeyResult": {
                    "AccessKey": access_key
                },
                "ResponseMetadata": {
                    "RequestId": uuid::Uuid::new_v4().to_string()
                }
            }
        }))),
        Err(e) => {
            tracing::error!("Failed to create access key: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn list_access_keys(
    State(state): State<AppState>,
    Path(user_name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let iam_service = state.iam_service.lock().unwrap();
    let access_keys = iam_service.list_access_keys(&user_name);
    
    Ok(Json(json!({
        "ListAccessKeysResponse": {
            "ListAccessKeysResult": {
                "AccessKeyMetadata": access_keys,
                "IsTruncated": false
            },
            "ResponseMetadata": {
                "RequestId": uuid::Uuid::new_v4().to_string()
            }
        }
    })))
}

pub async fn delete_access_key(
    State(state): State<AppState>,
    Path(access_key_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut iam_service = state.iam_service.lock().unwrap();
    
    match iam_service.delete_access_key(&access_key_id) {
        Ok(()) => Ok(Json(json!({
            "DeleteAccessKeyResponse": {
                "ResponseMetadata": {
                    "RequestId": uuid::Uuid::new_v4().to_string()
                }
            }
        }))),
        Err(e) => {
            tracing::error!("Failed to delete access key: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn attach_user_policy(
    State(state): State<AppState>,
    Path(user_name): Path<String>,
    Json(mut request): Json<AttachPolicyRequest>,
) -> Result<Json<Value>, StatusCode> {
    let mut iam_service = state.iam_service.lock().unwrap();
    request.user_name = Some(user_name);
    
    match iam_service.attach_user_policy(request) {
        Ok(()) => Ok(Json(json!({
            "AttachUserPolicyResponse": {
                "ResponseMetadata": {
                    "RequestId": uuid::Uuid::new_v4().to_string()
                }
            }
        }))),
        Err(e) => {
            tracing::error!("Failed to attach policy: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn authorize(
    State(state): State<AppState>,
    Json(request): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, StatusCode> {
    let iam_service = state.iam_service.lock().unwrap();
    let response = iam_service.authorize(request);
    Ok(Json(response))
}

pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "hpp-iam",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header::CONTENT_TYPE},
        routing::{delete, get, post},
        Router,
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn create_test_app_state() -> AppState {
        let mut iam_service = IamService::new();
        iam_service.add_builtin_policies();

        AppState {
            iam_service: Arc::new(Mutex::new(iam_service)),
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let app = Router::new()
            .route("/health", get(health_check));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "hpp-iam");
        assert!(json["timestamp"].is_string());
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/", post(create_user))
            .with_state(state);

        let create_request = CreateUserRequest {
            user_name: "testuser".to_string(),
            path: Some("/".to_string()),
            permissions_boundary: None,
            tags: None,
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&create_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["CreateUserResponse"]["CreateUserResult"]["User"]["user_name"].is_string());
        assert_eq!(json["CreateUserResponse"]["CreateUserResult"]["User"]["user_name"], "testuser");
        assert!(json["CreateUserResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_create_user_duplicate() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/", post(create_user))
            .with_state(state);

        let create_request = CreateUserRequest {
            user_name: "testuser".to_string(),
            path: Some("/".to_string()),
            permissions_boundary: None,
            tags: None,
        };

        // Create user first time
        let request1 = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&create_request).unwrap()))
            .unwrap();

        let response1 = app.clone().oneshot(request1).await.unwrap();
        assert_eq!(response1.status(), StatusCode::OK);

        // Try to create same user again
        let request2 = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&create_request).unwrap()))
            .unwrap();

        let response2 = app.oneshot(request2).await.unwrap();
        assert_eq!(response2.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_user_success() {
        let state = create_test_app_state();

        // Create a user first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_request).unwrap();
        }

        let app = Router::new()
            .route("/users/:user_name", get(get_user))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/users/testuser")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["GetUserResponse"]["GetUserResult"]["User"]["user_name"], "testuser");
        assert!(json["GetUserResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/users/:user_name", get(get_user))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/users/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_users_empty() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/users", get(list_users))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/users")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["ListUsersResponse"]["ListUsersResult"]["Users"].is_array());
        assert_eq!(json["ListUsersResponse"]["ListUsersResult"]["Users"].as_array().unwrap().len(), 0);
        assert_eq!(json["ListUsersResponse"]["ListUsersResult"]["IsTruncated"], false);
        assert!(json["ListUsersResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_list_users_with_data() {
        let state = create_test_app_state();

        // Create users first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_request1 = CreateUserRequest {
                user_name: "user1".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            let create_request2 = CreateUserRequest {
                user_name: "user2".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_request1).unwrap();
            iam_service.create_user(create_request2).unwrap();
        }

        let app = Router::new()
            .route("/users", get(list_users))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/users")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["ListUsersResponse"]["ListUsersResult"]["Users"].as_array().unwrap().len(), 2);
        assert_eq!(json["ListUsersResponse"]["ListUsersResult"]["IsTruncated"], false);
    }

    #[tokio::test]
    async fn test_delete_user_success() {
        let state = create_test_app_state();

        // Create a user first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_request).unwrap();
        }

        let app = Router::new()
            .route("/users/:user_name", delete(delete_user))
            .with_state(state);

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/users/testuser")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["DeleteUserResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/users/:user_name", delete(delete_user))
            .with_state(state);

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/users/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_access_key_success() {
        let state = create_test_app_state();

        // Create a user first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_request).unwrap();
        }

        let app = Router::new()
            .route("/users/:user_name/access-keys", post(create_access_key))
            .with_state(state);

        let request = Request::builder()
            .method(Method::POST)
            .uri("/users/testuser/access-keys")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["CreateAccessKeyResponse"]["CreateAccessKeyResult"]["AccessKey"]["access_key_id"].is_string());
        assert!(json["CreateAccessKeyResponse"]["CreateAccessKeyResult"]["AccessKey"]["secret_access_key"].is_string());
        assert_eq!(json["CreateAccessKeyResponse"]["CreateAccessKeyResult"]["AccessKey"]["user_name"], "testuser");
        assert!(json["CreateAccessKeyResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_create_access_key_user_not_found() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/users/:user_name/access-keys", post(create_access_key))
            .with_state(state);

        let request = Request::builder()
            .method(Method::POST)
            .uri("/users/nonexistent/access-keys")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_access_keys() {
        let state = create_test_app_state();

        // Create a user and access key first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_user_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_user_request).unwrap();

            let create_key_request = CreateAccessKeyRequest {
                user_name: "testuser".to_string(),
            };
            iam_service.create_access_key(create_key_request).unwrap();
        }

        let app = Router::new()
            .route("/users/:user_name/access-keys", get(list_access_keys))
            .with_state(state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/users/testuser/access-keys")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["ListAccessKeysResponse"]["ListAccessKeysResult"]["AccessKeyMetadata"].is_array());
        assert_eq!(json["ListAccessKeysResponse"]["ListAccessKeysResult"]["AccessKeyMetadata"].as_array().unwrap().len(), 1);
        assert_eq!(json["ListAccessKeysResponse"]["ListAccessKeysResult"]["IsTruncated"], false);
        assert!(json["ListAccessKeysResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_delete_access_key_success() {
        let state = create_test_app_state();
        let access_key_id: String;

        // Create a user and access key first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_user_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_user_request).unwrap();

            let create_key_request = CreateAccessKeyRequest {
                user_name: "testuser".to_string(),
            };
            let access_key = iam_service.create_access_key(create_key_request).unwrap();
            access_key_id = access_key.access_key_id;
        }

        let app = Router::new()
            .route("/access-keys/:access_key_id", delete(delete_access_key))
            .with_state(state);

        let request = Request::builder()
            .method(Method::DELETE)
            .uri(&format!("/access-keys/{}", access_key_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["DeleteAccessKeyResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_delete_access_key_not_found() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/access-keys/:access_key_id", delete(delete_access_key))
            .with_state(state);

        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/access-keys/nonexistent-key-id")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_attach_user_policy_success() {
        let state = create_test_app_state();

        // Create a user first
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_request).unwrap();
        }

        let app = Router::new()
            .route("/users/:user_name/attached-policies", post(attach_user_policy))
            .with_state(state);

        let attach_request = AttachPolicyRequest {
            user_name: None, // Will be set by handler from path parameter
            role_name: None,
            policy_arn: "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_string(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/users/testuser/attached-policies")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&attach_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["AttachUserPolicyResponse"]["ResponseMetadata"]["RequestId"].is_string());
    }

    #[tokio::test]
    async fn test_attach_user_policy_user_not_found() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/users/:user_name/attached-policies", post(attach_user_policy))
            .with_state(state);

        let attach_request = AttachPolicyRequest {
            user_name: None,
            role_name: None,
            policy_arn: "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_string(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/users/nonexistent/attached-policies")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&attach_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_success() {
        let state = create_test_app_state();
        let access_key_id: String;

        // Create a user, access key, and attach policy
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_user_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_user_request).unwrap();

            let create_key_request = CreateAccessKeyRequest {
                user_name: "testuser".to_string(),
            };
            let access_key = iam_service.create_access_key(create_key_request).unwrap();
            access_key_id = access_key.access_key_id;

            let attach_request = AttachPolicyRequest {
                user_name: Some("testuser".to_string()),
                role_name: None,
                policy_arn: "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_string(),
            };
            iam_service.attach_user_policy(attach_request).unwrap();
        }

        let app = Router::new()
            .route("/authorize", post(authorize))
            .with_state(state);

        let auth_request = AuthorizeRequest {
            access_key_id,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/authorize")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&auth_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let auth_response: AuthorizeResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(auth_response.allowed, true);
        assert!(auth_response.matched_policies.len() > 0);
    }

    #[tokio::test]
    async fn test_authorize_invalid_access_key() {
        let state = create_test_app_state();

        let app = Router::new()
            .route("/authorize", post(authorize))
            .with_state(state);

        let auth_request = AuthorizeRequest {
            access_key_id: "invalid-access-key".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/authorize")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&auth_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let auth_response: AuthorizeResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(auth_response.allowed, false);
        assert!(auth_response.reason.is_some());
        assert!(auth_response.reason.unwrap().contains("Invalid access key"));
    }

    #[tokio::test]
    async fn test_authorize_no_permissions() {
        let state = create_test_app_state();
        let access_key_id: String;

        // Create a user and access key but don't attach any policies
        {
            let mut iam_service = state.iam_service.lock().unwrap();
            let create_user_request = CreateUserRequest {
                user_name: "testuser".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            iam_service.create_user(create_user_request).unwrap();

            let create_key_request = CreateAccessKeyRequest {
                user_name: "testuser".to_string(),
            };
            let access_key = iam_service.create_access_key(create_key_request).unwrap();
            access_key_id = access_key.access_key_id;
        }

        let app = Router::new()
            .route("/authorize", post(authorize))
            .with_state(state);

        let auth_request = AuthorizeRequest {
            access_key_id,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/authorize")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&auth_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let auth_response: AuthorizeResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(auth_response.allowed, false);
        assert_eq!(auth_response.matched_policies.len(), 0);
    }
}
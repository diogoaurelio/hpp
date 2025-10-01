use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use iam_api::{handlers, AppState};
use iam_core::{IamService, IamServiceTrait};
use std::sync::{Arc, Mutex};
use tracing::{info, Level};
use tracing_subscriber;
use shared::AwsS3Repository;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // Create S3-backed IAM service or fallback to in-memory
    let mut iam_service = if let (Ok(endpoint), Ok(region), Ok(access_key), Ok(secret_key), Ok(bucket)) = (
        std::env::var("S3_ENDPOINT"),
        std::env::var("S3_REGION"),
        std::env::var("S3_ACCESS_KEY"),
        std::env::var("S3_SECRET_KEY"),
        std::env::var("IAM_S3_BUCKET")
    ) {
        info!("Initializing S3-backed IAM service with bucket: {}", bucket);

        let s3_client = AwsS3Repository::new(access_key, secret_key, endpoint, region).await?;
        let user_s3_client = Box::new(s3_client) as Box<dyn shared::S3ObjectStorageRepository>;

        // Create second client for policy engine (since we can't clone)
        let s3_client2 = AwsS3Repository::new(
            std::env::var("S3_ACCESS_KEY")?,
            std::env::var("S3_SECRET_KEY")?,
            std::env::var("S3_ENDPOINT")?,
            std::env::var("S3_REGION")?
        ).await?;
        let policy_s3_client = Box::new(s3_client2) as Box<dyn shared::S3ObjectStorageRepository>;

        IamService::with_s3_storage(user_s3_client, policy_s3_client, bucket)
    } else {
        info!("S3 environment variables not found, using in-memory IAM service");
        IamService::new()
    };

    iam_service.add_builtin_policies();

    let state = AppState {
        iam_service: Arc::new(Mutex::new(iam_service)) as Arc<Mutex<dyn IamServiceTrait + Send>>,
    };

    let app = Router::new()
        // User management
        .route("/", post(handlers::create_user))
        .route("/users/:user_name", get(handlers::get_user))
        .route("/users", get(handlers::list_users))
        .route("/users/:user_name", axum::routing::delete(handlers::delete_user))

        // Access key management
        .route("/users/:user_name/access-keys", post(handlers::create_access_key))
        .route("/users/:user_name/access-keys", get(handlers::list_access_keys))
        .route("/access-keys/:access_key_id", axum::routing::delete(handlers::delete_access_key))

        // Policy management
        .route("/users/:user_name/attached-policies", post(handlers::attach_user_policy))

        // Authorization endpoint for S3 API
        .route("/authorize", post(handlers::authorize))

        // Health check
        .route("/health", get(handlers::health_check))
        .with_state(state);

    let hostname = std::env::var("INTERFACE").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8988".to_string());
    let endpoint = format!("{hostname}:{port}");
    let listener = tokio::net::TcpListener::bind(&endpoint).await?;
    info!("IAM Facade API server listening on {endpoint}");

    axum::serve(listener, app).await?;

    Ok(())
}
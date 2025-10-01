mod auth;
mod handlers;

use anyhow::Result;
use axum::{
    extract::{DefaultBodyLimit, Request},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, put},
    Router,
};
use shared::AwsS3Repository;
use s3_core::{S3Service, ProxyS3Service, IamService, HttpIamService};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber;

#[derive(Clone)]
pub struct AppState {
    pub s3_service: Arc<dyn S3Service>,
    pub iam_service: Arc<dyn IamService>,
}

async fn log_request_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    info!("Incoming request: {} {}", method, uri);
    info!("Request headers:");
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            info!("  {}: {}", name, value_str);
        } else {
            info!("  {}: <non-utf8 value>", name);
        }
    }

    next.run(request).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let log_level = std::env::var("LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .to_lowercase();

    let level = match log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    let access_key = std::env::var("AWS_ACCESS_KEY_ID")
        .unwrap_or_else(|_| "secret".to_string());
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .unwrap_or_else(|_| "supersecret".to_string());
    let endpoint = std::env::var("AWS_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:4567".to_string());
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "eu-central-1".to_string());

    let iam_url = std::env::var("IAM_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8988".to_string());

    // Create storage client using concrete implementation
    let storage_client: Arc<dyn shared::S3ObjectStorageRepository> = Arc::new(
        AwsS3Repository::new(access_key, secret_key, endpoint, region).await?,
    );

    // Create S3 service layer
    let s3_service: Arc<dyn S3Service> = Arc::new(ProxyS3Service::new(storage_client));
    let iam_service: Arc<dyn IamService> = Arc::new(HttpIamService::new(iam_url));

    let state = AppState {
        s3_service,
        iam_service,
    };

    let app = Router::new()
        .route("/", get(handlers::list_buckets))
        .route("/:bucket", get(handlers::list_objects))
        .route("/:bucket", put(handlers::create_bucket))
        .route("/:bucket/:key", get(handlers::get_object))
        .route("/:bucket/:key", put(handlers::put_object))
        .route("/:bucket/:key", delete(handlers::delete_object))
        .layer(middleware::from_fn_with_state(state.clone(), auth::iam_auth_middleware))
        .layer(middleware::from_fn(log_request_middleware))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024)) // 100MB max
        .with_state(state);

    let hostname = std::env::var("INTERFACE").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8989".to_string());
    let endpoint = format!("{hostname}:{port}");
    let listener = tokio::net::TcpListener::bind(&endpoint).await?;
    info!("S3 Facade API server listening on {endpoint}");

    axum::serve(listener, app).await?;

    Ok(())
}
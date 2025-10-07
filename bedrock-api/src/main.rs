use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use bedrock_api::{handlers, AppState};
use bedrock_core::{BedrockService, BedrockServiceTrait, InMemoryEmbeddingEngine};
use std::sync::Arc;
use tracing::{info, Level};
use shared::AwsS3Repository;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // Determine which embedding engine to use
    let use_huggingface = std::env::var("USE_HUGGINGFACE_EMBEDDINGS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    let bedrock_service = if use_huggingface {
        info!("Initializing Bedrock service with HuggingFace embeddings");

        let hf_engine = {
            let cache_dir = std::env::var("HF_CACHE_DIR")
                .ok()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("hf_models"));

            // Use runtime environment variable instead of compile-time feature
            let enable_real_hf = std::env::var("ENABLE_REAL_HUGGINGFACE")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false);

            if enable_real_hf {
                InMemoryEmbeddingEngine::with_cache_dir(cache_dir)
            } else {
                InMemoryEmbeddingEngine::new()
            }
        };

        // Check if we should use S3 for vector storage
        if let (Ok(endpoint), Ok(region), Ok(access_key), Ok(secret_key), Ok(bucket)) = (
            std::env::var("S3_ENDPOINT"),
            std::env::var("S3_REGION"),
            std::env::var("S3_ACCESS_KEY"),
            std::env::var("S3_SECRET_KEY"),
            std::env::var("BEDROCK_S3_BUCKET")
        ) {
            info!("Using S3 storage for state persistency in bucket: {}", bucket);
            let s3_storage_client = AwsS3Repository::new(access_key, secret_key, endpoint, region).await?;
            let vector_client = Box::new(s3_storage_client) as Box<dyn shared::S3ObjectStorageRepository>;
            BedrockService::with_huggingface_and_s3_storage(Arc::new(hf_engine), vector_client, bucket)
        } else {
            info!("Using in-memory storage for vectors");
            BedrockService::with_huggingface_embeddings(Arc::new(hf_engine))
        }
    } else if let (Ok(endpoint), Ok(region), Ok(access_key), Ok(secret_key), Ok(bucket)) = (
        std::env::var("S3_ENDPOINT"),
        std::env::var("S3_REGION"),
        std::env::var("S3_ACCESS_KEY"),
        std::env::var("S3_SECRET_KEY"),
        std::env::var("BEDROCK_S3_BUCKET")
    ) {
        info!("Initializing S3-backed Bedrock service with simulated embeddings, bucket: {}", bucket);

        let embedding_s3_client = AwsS3Repository::new(access_key.clone(), secret_key.clone(), endpoint.clone(), region.clone()).await?;
        let vector_s3_client = AwsS3Repository::new(access_key, secret_key, endpoint, region).await?;

        let _embedding_client = Box::new(embedding_s3_client) as Box<dyn shared::S3ObjectStorageRepository>;
        let vector_client = Box::new(vector_s3_client) as Box<dyn shared::S3ObjectStorageRepository>;

        let s3_embedding_engine = Arc::new(InMemoryEmbeddingEngine::new());
        BedrockService::with_s3_storage(s3_embedding_engine, vector_client, bucket)
    } else {
        info!("S3 environment variables not found, using in-memory Bedrock service with simulated embeddings");
        BedrockService::new()
    };

    let state = AppState {
        bedrock_service: Arc::new(bedrock_service) as Arc<dyn BedrockServiceTrait + Send + Sync>,
    };

    let app = Router::new()
        // AWS Bedrock compatible endpoints
        .route("/model/:model_id/invoke", post(handlers::invoke_model))

        // Custom vector database endpoints
        .route("/embeddings", post(handlers::create_embedding))
        .route("/documents", get(handlers::list_documents))
        .route("/documents", post(handlers::create_document))
        .route("/documents/search", post(handlers::search_documents))
        .route("/documents/:document_id", get(handlers::get_document))
        .route("/documents/:document_id", axum::routing::delete(handlers::delete_document))

        // Health check
        .route("/health", get(handlers::health_check))
        .with_state(state);

    let hostname = std::env::var("INTERFACE").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("BEDROCK_PORT").unwrap_or_else(|_| "8990".to_string());
    let endpoint = format!("{hostname}:{port}");
    let listener = tokio::net::TcpListener::bind(&endpoint).await?;
    info!("Bedrock API server listening on {endpoint}");

    axum::serve(listener, app).await?;

    Ok(())
}
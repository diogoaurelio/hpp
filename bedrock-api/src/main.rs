use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use bedrock_api::{handlers, AppState};
use bedrock_core::{BedrockService, BedrockServiceTrait, create_huggingface_engine};
use std::sync::{Arc, Mutex};
use tracing::{info, Level};
use tracing_subscriber;
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

        // Load specified models or defaults
        let models_to_load = std::env::var("HF_MODELS_TO_LOAD")
            .unwrap_or_else(|_| "sentence-transformers/all-MiniLM-L6-v2".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let cache_dir = std::env::var("HF_CACHE_DIR")
            .ok()
            .map(std::path::PathBuf::from);

        let hf_engine = create_huggingface_engine(models_to_load, cache_dir).await?;

        // Check if we should use S3 for vector storage
        if let (Ok(endpoint), Ok(region), Ok(access_key), Ok(secret_key), Ok(bucket)) = (
            std::env::var("S3_ENDPOINT"),
            std::env::var("S3_REGION"),
            std::env::var("S3_ACCESS_KEY"),
            std::env::var("S3_SECRET_KEY"),
            std::env::var("BEDROCK_S3_BUCKET")
        ) {
            info!("Using S3 storage for vectors with bucket: {}", bucket);
            let vector_s3_client = AwsS3Repository::new(access_key, secret_key, endpoint, region).await?;
            let vector_client = Box::new(vector_s3_client) as Box<dyn shared::S3ObjectStorageRepository>;
            BedrockService::with_huggingface_and_s3_storage(hf_engine, vector_client, bucket)
        } else {
            info!("Using in-memory storage for vectors");
            BedrockService::with_huggingface_embeddings(hf_engine)
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

        let embedding_client = Box::new(embedding_s3_client) as Box<dyn shared::S3ObjectStorageRepository>;
        let vector_client = Box::new(vector_s3_client) as Box<dyn shared::S3ObjectStorageRepository>;

        BedrockService::with_s3_storage(embedding_client, vector_client, bucket)
    } else {
        info!("S3 environment variables not found, using in-memory Bedrock service with simulated embeddings");
        BedrockService::new()
    };

    let state = AppState {
        bedrock_service: Arc::new(Mutex::new(bedrock_service)) as Arc<Mutex<dyn BedrockServiceTrait + Send>>,
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
    let port = std::env::var("PORT").unwrap_or_else(|_| "8990".to_string());
    let endpoint = format!("{hostname}:{port}");
    let listener = tokio::net::TcpListener::bind(&endpoint).await?;
    info!("Bedrock API server listening on {endpoint}");

    axum::serve(listener, app).await?;

    Ok(())
}
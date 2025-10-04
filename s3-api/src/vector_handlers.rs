use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
    body::Body,
    Json,
};
use s3_core::{InMemoryVectorStore, S3VectorStore, CreateDocumentRequest, SearchRequest, VectorDocument, SearchResponse, CreateVectorBucketRequest};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use chrono::Utc;

// Use Mutex instead of RwLock for mutable operations
type VectorStoreType = Arc<Mutex<dyn s3_core::VectorStoreTrait + Send + Sync>>;

// Global in-memory registry of vector stores per bucket
lazy_static::lazy_static! {
    static ref VECTOR_STORES: tokio::sync::RwLock<HashMap<String, VectorStoreType>> = tokio::sync::RwLock::new(HashMap::new());
}

pub async fn create_vector_bucket(
    State(_state): State<AppState>,
    Path(bucket): Path<String>,
    Json(request): Json<CreateVectorBucketRequest>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Creating vector bucket: {}", bucket);

    // Create new vector store instance for this bucket
    let mut vector_store: VectorStoreType = if bucket.starts_with("s3-") {
        // For buckets starting with "s3-", use S3-backed storage
        let storage_client = shared::AwsS3Repository::new(
            std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_else(|_| "admin".to_string()),
            std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_else(|_| "admin123".to_string()),
            std::env::var("AWS_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string()),
            std::env::var("AWS_REGION").unwrap_or_else(|_| "eu-central-1".to_string()),
        ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Arc::new(Mutex::new(S3VectorStore::new(
            Box::new(storage_client),
            bucket.clone(),
        )))
    } else {
        // Default to in-memory storage
        Arc::new(Mutex::new(InMemoryVectorStore::new()))
    };

    // Create index for the vector store
    {
        let mut store = vector_store.lock().await;
        store.create_index(
            format!("{}-index", bucket),
            request.dimensions,
            request.similarity_metric.unwrap_or_default(),
        ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Register the vector store
    {
        let mut stores = VECTOR_STORES.write().await;
        stores.insert(bucket.clone(), vector_store);
    }

    info!("Vector bucket '{}' created successfully", bucket);

    let response = json!({
        "message": "Vector bucket created successfully",
        "bucket_name": bucket,
        "dimensions": request.dimensions,
        "similarity_metric": request.similarity_metric.unwrap_or_default()
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response.to_string()))
        .unwrap())
}

pub async fn put_vector_document(
    State(_state): State<AppState>,
    Path((bucket, document_id)): Path<(String, String)>,
    Json(request): Json<CreateDocumentRequest>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Storing vector document in bucket: {}, id: {}", bucket, document_id);

    // Get the vector store for this bucket
    let vector_store = {
        let stores = VECTOR_STORES.read().await;
        stores.get(&bucket).cloned()
    };

    let Some(vector_store) = vector_store else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Generate embedding for the content (mock implementation)
    let embedding = generate_mock_embedding(&request.content);

    let document = VectorDocument {
        id: request.id.unwrap_or(document_id),
        content: request.content,
        embedding,
        metadata: request.metadata.unwrap_or_default(),
        created_at: Utc::now(),
    };

    // Lock the store and perform the mutable operation
    {
        let mut store = vector_store.lock().await;
        store.store_document(document.clone()).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let response = json!({
        "message": "Document stored successfully",
        "document_id": document.id
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response.to_string()))
        .unwrap())
}

pub async fn get_vector_document(
    State(_state): State<AppState>,
    Path((bucket, document_id)): Path<(String, String)>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Getting vector document from bucket: {}, id: {}", bucket, document_id);

    let vector_store = {
        let stores = VECTOR_STORES.read().await;
        stores.get(&bucket).cloned()
    };

    let Some(vector_store) = vector_store else {
        return Err(StatusCode::NOT_FOUND);
    };

    let document = {
        let store = vector_store.lock().await;
        store.get_document(&document_id).await
    };

    match document {
        Some(document) => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&document).unwrap()))
                .unwrap())
        }
        None => Err(StatusCode::NOT_FOUND)
    }
}

pub async fn delete_vector_document(
    State(_state): State<AppState>,
    Path((bucket, document_id)): Path<(String, String)>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Deleting vector document from bucket: {}, id: {}", bucket, document_id);

    let vector_store = {
        let stores = VECTOR_STORES.read().await;
        stores.get(&bucket).cloned()
    };

    let Some(vector_store) = vector_store else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Lock the store and perform the mutable operation
    let deleted = {
        let mut store = vector_store.lock().await;
        store.delete_document(&document_id).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    if deleted {
        let response = json!({
            "message": "Document deleted successfully",
            "document_id": document_id
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(response.to_string()))
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn search_vectors(
    State(_state): State<AppState>,
    Path(bucket): Path<String>,
    Json(request): Json<SearchRequest>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Searching vectors in bucket: {}, query: {}", bucket, request.query);

    let vector_store = {
        let stores = VECTOR_STORES.read().await;
        stores.get(&bucket).cloned()
    };

    let Some(vector_store) = vector_store else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Generate embedding for the query
    let query_embedding = generate_mock_embedding(&request.query);

    let limit = request.limit.unwrap_or(10);
    let threshold = request.similarity_threshold;

    let (results, total_count) = {
        let store = vector_store.lock().await;
        let search_results = store.search_similar(query_embedding, limit, threshold).await
            .map_err(|err| {
                error!("Search failed: {:?}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let count = store.count_documents().await.unwrap_or(0);
        (search_results, count)
    };

    let response = SearchResponse {
        results,
        total_count,
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

pub async fn list_vector_documents(
    State(_state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, StatusCode> {
    debug!("Listing vector documents in bucket: {}", bucket);

    let vector_store = {
        let stores = VECTOR_STORES.read().await;
        stores.get(&bucket).cloned()
    };

    let Some(vector_store) = vector_store else {
        return Err(StatusCode::NOT_FOUND);
    };

    let limit = params.get("limit").and_then(|s| s.parse().ok());
    let offset = params.get("offset").and_then(|s| s.parse().ok());

    let (documents, total_count) = {
        let store = vector_store.lock().await;
        let docs = store.list_documents(limit, offset).await
            .map_err(|err| {
                error!("List documents failed: {:?}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let count = store.count_documents().await.unwrap_or(0);
        (docs, count)
    };

    let response = json!({
        "documents": documents,
        "total_count": total_count,
        "limit": limit,
        "offset": offset
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(response.to_string()))
        .unwrap())
}

// Mock embedding generation - in a real implementation, this would call Bedrock
fn generate_mock_embedding(text: &str) -> Vec<f32> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    let hash = hasher.finish();

    // Generate a deterministic 1536-dimensional embedding based on the text hash
    let mut embedding = Vec::with_capacity(1536);
    for i in 0..1536 {
        let value = ((hash.wrapping_add(i as u64) as f64).sin() * 1000.0) as f32 / 1000.0;
        embedding.push(value);
    }

    // Normalize the embedding
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        embedding.iter_mut().for_each(|x| *x /= magnitude);
    }

    embedding
}
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use bedrock_core::{
    BedrockServiceTrait, EmbeddingRequest, CreateDocumentRequest, SearchRequest, SearchResponse,
    InvokeModelRequest, VectorDocument, TextEmbeddingRequest, TextEmbeddingResponse
};
use serde::Deserialize;

use crate::AppState;

/// Health check endpoint
pub async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "service": "bedrock-api",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// AWS Bedrock InvokeModel endpoint
pub async fn invoke_model(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request = InvokeModelRequest {
        model_id,
        content_type: Some("application/json".to_string()),
        accept: Some("application/json".to_string()),
        body: body.to_string(),
    };

    let service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.invoke_model(request).await {
        Ok(response) => {
            // Parse the response body back to JSON
            let response_json: serde_json::Value = serde_json::from_slice(&response.body)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(response_json))
        }
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateEmbeddingQuery {
    pub model_id: Option<String>,
}

/// Create embedding endpoint (custom extension)
pub async fn create_embedding(
    State(state): State<AppState>,
    Query(params): Query<CreateEmbeddingQuery>,
    Json(request): Json<TextEmbeddingRequest>,
) -> Result<Json<TextEmbeddingResponse>, StatusCode> {
    let model_id = params.model_id.unwrap_or_else(|| "amazon.titan-embed-text-v1".to_string());

    let embedding_request = EmbeddingRequest {
        model_id,
        input_text: request.input_text,
    };

    let service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.create_embedding(embedding_request).await {
        Ok(response) => Ok(Json(TextEmbeddingResponse {
            embedding: response.embedding,
            input_text_token_count: response.input_token_count,
        })),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(Debug, Deserialize)]
pub struct ListDocumentsQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// List documents endpoint
pub async fn list_documents(
    State(state): State<AppState>,
    Query(params): Query<ListDocumentsQuery>,
) -> Result<Json<Vec<VectorDocument>>, StatusCode> {
    let service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.list_documents(params.limit, params.offset).await {
        Ok(documents) => Ok(Json(documents)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Create document endpoint
pub async fn create_document(
    State(state): State<AppState>,
    Json(request): Json<CreateDocumentRequest>,
) -> Result<Json<VectorDocument>, StatusCode> {
    let mut service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.create_document(request).await {
        Ok(document) => Ok(Json(document)),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

/// Get document by ID endpoint
pub async fn get_document(
    State(state): State<AppState>,
    Path(document_id): Path<String>,
) -> Result<Json<VectorDocument>, StatusCode> {
    let service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.get_document(&document_id).await {
        Some(document) => Ok(Json(document)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Delete document endpoint
pub async fn delete_document(
    State(state): State<AppState>,
    Path(document_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.delete_document(&document_id).await {
        Ok(existed) => {
            if existed {
                Ok(Json(serde_json::json!({
                    "deleted": true,
                    "document_id": document_id
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Search documents endpoint
pub async fn search_documents(
    State(state): State<AppState>,
    Json(request): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, StatusCode> {
    let service = state.bedrock_service.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match service.search_documents(request).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use bedrock_core::BedrockService;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn create_test_app() -> Router {
        let bedrock_service = BedrockService::new();
        let state = AppState {
            bedrock_service: Arc::new(Mutex::new(bedrock_service)) as Arc<Mutex<dyn BedrockServiceTrait + Send>>,
        };

        Router::new()
            .route("/health", axum::routing::get(health_check))
            .route("/model/:model_id/invoke", axum::routing::post(invoke_model))
            .route("/embeddings", axum::routing::post(create_embedding))
            .route("/documents", axum::routing::get(list_documents))
            .route("/documents", axum::routing::post(create_document))
            .route("/documents/:document_id", axum::routing::get(get_document))
            .route("/documents/:document_id", axum::routing::delete(delete_document))
            .route("/documents/search", axum::routing::post(search_documents))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_health_check() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invoke_model_embedding() {
        let app = create_test_app();

        let request_body = serde_json::json!({
            "inputText": "Hello, world!"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/model/amazon.titan-embed-text-v1/invoke")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_embedding() {
        let app = create_test_app();

        let request_body = serde_json::json!({
            "inputText": "Test text for embedding"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/embeddings")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_and_get_document() {
        let app = create_test_app();

        // Create document
        let create_request = serde_json::json!({
            "id": "test-doc",
            "content": "This is test content",
            "metadata": {
                "category": "test"
            }
        });

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/documents")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(create_response.status(), StatusCode::OK);

        // Get document
        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/documents/test-doc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_search_documents() {
        let app = create_test_app();

        // First create a document
        let create_request = serde_json::json!({
            "content": "Machine learning and artificial intelligence"
        });

        let _create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/documents")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Search for documents
        let search_request = serde_json::json!({
            "query": "machine learning",
            "limit": 5
        });

        let search_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/documents/search")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&search_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(search_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_documents() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/documents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
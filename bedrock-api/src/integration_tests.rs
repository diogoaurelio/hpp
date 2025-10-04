use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bedrock_core::{BedrockService, ModelRegistry, CreateDocumentRequest, SearchRequest, EmbeddingRequest};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// Create a test app with in-memory storage
fn create_test_app() -> axum::Router {
    let bedrock_service = BedrockService::new();
    let state = AppState {
        bedrock_service: Arc::new(Mutex::new(bedrock_service)) as Arc<Mutex<dyn bedrock_core::BedrockServiceTrait + Send>>,
    };

    axum::Router::new()
        .route("/health", axum::routing::get(handlers::health_check))
        .route("/model/:model_id/invoke", axum::routing::post(handlers::invoke_model))
        .route("/embeddings", axum::routing::post(handlers::create_embedding))
        .route("/documents", axum::routing::get(handlers::list_documents))
        .route("/documents", axum::routing::post(handlers::create_document))
        .route("/documents/:document_id", axum::routing::get(handlers::get_document))
        .route("/documents/:document_id", axum::routing::delete(handlers::delete_document))
        .route("/documents/search", axum::routing::post(handlers::search_documents))
        .with_state(state)
}

async fn send_request(app: axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
        json!({"error": "Failed to parse response as JSON", "body": String::from_utf8_lossy(&body)})
    });
    (status, json)
}

#[tokio::test]
async fn test_health_check_endpoint() {
    let app = create_test_app();

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app, request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "bedrock-api");
    assert!(body["timestamp"].is_string());
}

#[tokio::test]
async fn test_invoke_model_embedding() {
    let app = create_test_app();

    let request_body = json!({
        "inputText": "The quick brown fox jumps over the lazy dog"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/model/amazon.titan-embed-text-v1/invoke")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let (status, body) = send_request(app, request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["embedding"].is_array());
    assert!(body["inputTextTokenCount"].is_number());

    let embedding = body["embedding"].as_array().unwrap();
    assert!(embedding.len() > 0);
}

#[tokio::test]
async fn test_invoke_model_non_embedding() {
    let app = create_test_app();

    let request_body = json!({
        "prompt": "What is machine learning?"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/model/anthropic.claude-v2/invoke")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let (status, body) = send_request(app, request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["completion"].is_string());
    assert_eq!(body["stop_reason"], "end_turn");
}

#[tokio::test]
async fn test_create_embedding_endpoint() {
    let app = create_test_app();

    let request_body = json!({
        "inputText": "Machine learning is a subset of artificial intelligence"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/embeddings?model_id=amazon.titan-embed-text-v1")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let (status, body) = send_request(app, request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["embedding"].is_array());
    assert!(body["inputTextTokenCount"].is_number());

    let embedding = body["embedding"].as_array().unwrap();
    assert!(embedding.len() > 0);

    // Check that embedding values are reasonable
    for value in embedding {
        let val = value.as_f64().unwrap();
        assert!(val.abs() <= 1.0); // Normalized embeddings should be <= 1
    }
}

#[tokio::test]
async fn test_create_embedding_default_model() {
    let app = create_test_app();

    let request_body = json!({
        "inputText": "Test with default model"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/embeddings") // No model_id specified
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let (status, body) = send_request(app, request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["embedding"].is_array());
}

#[tokio::test]
async fn test_document_lifecycle() {
    let app = create_test_app();

    // 1. Create a document
    let create_request = json!({
        "id": "test-doc-1",
        "content": "Artificial intelligence and machine learning are transforming technology",
        "metadata": {
            "category": "AI",
            "source": "test"
        }
    });

    let request = Request::builder()
        .method("POST")
        .uri("/documents")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_request).unwrap()))
        .unwrap();

    let (status, body) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "test-doc-1");
    assert_eq!(body["content"], "Artificial intelligence and machine learning are transforming technology");
    assert!(body["embedding"].is_array());
    assert!(body["createdAt"].is_string());

    // 2. Get the document
    let request = Request::builder()
        .method("GET")
        .uri("/documents/test-doc-1")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "test-doc-1");
    assert_eq!(body["content"], "Artificial intelligence and machine learning are transforming technology");

    // 3. List documents
    let request = Request::builder()
        .method("GET")
        .uri("/documents")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_array());
    let documents = body.as_array().unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["id"], "test-doc-1");

    // 4. Delete the document
    let request = Request::builder()
        .method("DELETE")
        .uri("/documents/test-doc-1")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);
    assert_eq!(body["document_id"], "test-doc-1");

    // 5. Verify document is deleted
    let request = Request::builder()
        .method("GET")
        .uri("/documents/test-doc-1")
        .body(Body::empty())
        .unwrap();

    let (status, _) = send_request(app, request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_document_search() {
    let app = create_test_app();

    // Create multiple documents
    let documents = vec![
        ("doc1", "Machine learning algorithms process data to find patterns", "AI"),
        ("doc2", "Rust programming language focuses on memory safety", "Programming"),
        ("doc3", "Deep neural networks are inspired by biological neurons", "AI"),
        ("doc4", "HTTP protocol enables communication between web servers and clients", "Web"),
        ("doc5", "Vector databases store high-dimensional data for similarity search", "Database"),
    ];

    for (id, content, category) in documents {
        let create_request = json!({
            "id": id,
            "content": content,
            "metadata": {
                "category": category
            }
        });

        let request = Request::builder()
            .method("POST")
            .uri("/documents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_request).unwrap()))
            .unwrap();

        let (status, _) = send_request(app.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Search for AI-related content
    let search_request = json!({
        "query": "artificial intelligence and neural networks",
        "limit": 3,
        "similarity_threshold": 0.1
    });

    let request = Request::builder()
        .method("POST")
        .uri("/documents/search")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&search_request).unwrap()))
        .unwrap();

    let (status, body) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["results"].is_array());
    assert!(body["totalCount"].is_number());

    let results = body["results"].as_array().unwrap();
    assert!(results.len() <= 3);

    // Check that results are properly formatted
    for result in results {
        assert!(result["document"].is_object());
        assert!(result["similarityScore"].is_number());
        assert!(result["document"]["id"].is_string());
        assert!(result["document"]["content"].is_string());

        let score = result["similarityScore"].as_f64().unwrap();
        assert!(score >= 0.0 && score <= 1.0);
    }

    // Test search with metadata filter
    let filtered_search = json!({
        "query": "programming and development",
        "limit": 5,
        "metadataFilter": {
            "category": "Programming"
        }
    });

    let request = Request::builder()
        .method("POST")
        .uri("/documents/search")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&filtered_search).unwrap()))
        .unwrap();

    let (status, body) = send_request(app, request).await;
    assert_eq!(status, StatusCode::OK);

    let results = body["results"].as_array().unwrap();
    // Should only return programming-related documents
    for result in results {
        let metadata = &result["document"]["metadata"];
        assert_eq!(metadata["category"], "Programming");
    }
}

#[tokio::test]
async fn test_list_documents_pagination() {
    let app = create_test_app();

    // Create several documents
    for i in 1..=10 {
        let create_request = json!({
            "id": format!("doc-{}", i),
            "content": format!("This is document number {}", i)
        });

        let request = Request::builder()
            .method("POST")
            .uri("/documents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_request).unwrap()))
            .unwrap();

        let (status, _) = send_request(app.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Test pagination with limit
    let request = Request::builder()
        .method("GET")
        .uri("/documents?limit=5")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::OK);

    let documents = body.as_array().unwrap();
    assert_eq!(documents.len(), 5);

    // Test pagination with offset
    let request = Request::builder()
        .method("GET")
        .uri("/documents?limit=3&offset=5")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app, request).await;
    assert_eq!(status, StatusCode::OK);

    let documents = body.as_array().unwrap();
    assert_eq!(documents.len(), 3);
}

#[tokio::test]
async fn test_error_cases() {
    let app = create_test_app();

    // Test getting non-existent document
    let request = Request::builder()
        .method("GET")
        .uri("/documents/non-existent")
        .body(Body::empty())
        .unwrap();

    let (status, _) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Test deleting non-existent document
    let request = Request::builder()
        .method("DELETE")
        .uri("/documents/non-existent")
        .body(Body::empty())
        .unwrap();

    let (status, _) = send_request(app.clone(), request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Test invalid JSON in request body
    let request = Request::builder()
        .method("POST")
        .uri("/documents")
        .header("content-type", "application/json")
        .body(Body::from("invalid json"))
        .unwrap();

    let (status, _) = send_request(app, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_aws_model_compatibility() {
    let registry = ModelRegistry::new();

    // Test that all AWS models are supported
    let aws_models = vec![
        "amazon.titan-embed-text-v1",
        "amazon.titan-embed-text-v2:0",
        "cohere.embed-english-v3",
        "cohere.embed-multilingual-v3",
    ];

    for model_id in aws_models {
        assert!(registry.get_mapping(model_id).is_ok(), "Model {} should be supported", model_id);

        let hf_id = registry.get_hf_model_id(model_id).unwrap();
        assert!(!hf_id.is_empty(), "HF model ID should not be empty for {}", model_id);

        let dimensions = registry.get_expected_dimensions(model_id).unwrap();
        assert!(dimensions > 0, "Dimensions should be > 0 for {}", model_id);

        let is_high_quality = registry.is_high_quality_mapping(model_id).unwrap();
        assert!(is_high_quality, "Should have high quality mapping for {}", model_id);
    }
}

#[tokio::test]
async fn test_embedding_consistency() {
    let app = create_test_app();

    let test_text = "The quick brown fox jumps over the lazy dog";

    // Create embedding multiple times
    let mut embeddings = Vec::new();

    for _ in 0..3 {
        let request_body = json!({
            "inputText": test_text
        });

        let request = Request::builder()
            .method("POST")
            .uri("/embeddings")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .unwrap();

        let (status, body) = send_request(app.clone(), request).await;
        assert_eq!(status, StatusCode::OK);

        let embedding = body["embedding"].as_array().unwrap();
        embeddings.push(embedding.clone());
    }

    // All embeddings should be identical (deterministic)
    for i in 1..embeddings.len() {
        assert_eq!(embeddings[0], embeddings[i], "Embeddings should be deterministic");
    }
}

#[tokio::test]
async fn test_concurrent_requests() {
    let app = create_test_app();

    // Create multiple concurrent requests
    let tasks: Vec<_> = (0..10).map(|i| {
        let app = app.clone();
        tokio::spawn(async move {
            let create_request = json!({
                "id": format!("concurrent-doc-{}", i),
                "content": format!("Concurrent document {}", i)
            });

            let request = Request::builder()
                .method("POST")
                .uri("/documents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_request).unwrap()))
                .unwrap();

            send_request(app, request).await
        })
    }).collect();

    // Wait for all tasks to complete
    let results = futures::future::join_all(tasks).await;

    // All requests should succeed
    for result in results {
        let (status, _) = result.unwrap();
        assert_eq!(status, StatusCode::OK);
    }

    // Verify all documents were created
    let request = Request::builder()
        .method("GET")
        .uri("/documents")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request(app, request).await;
    assert_eq!(status, StatusCode::OK);

    let documents = body.as_array().unwrap();
    assert_eq!(documents.len(), 10);
}
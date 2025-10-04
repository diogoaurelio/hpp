use crate::types::*;
use crate::embedding::{EmbeddingEngineTrait, InMemoryEmbeddingEngine, S3EmbeddingEngine};
use crate::vector_store::{VectorStoreTrait, InMemoryVectorStore, S3VectorStore};
use crate::huggingface_embedding::HuggingFaceEmbeddingEngine;
use anyhow::Result;
use std::collections::HashMap;

/// Trait defining the Bedrock service interface
#[async_trait::async_trait]
pub trait BedrockServiceTrait: Send + Sync {
    async fn invoke_model(&self, request: InvokeModelRequest) -> Result<InvokeModelResponse>;
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse>;
    async fn create_document(&mut self, request: CreateDocumentRequest) -> Result<VectorDocument>;
    async fn get_document(&self, id: &str) -> Option<VectorDocument>;
    async fn delete_document(&mut self, id: &str) -> Result<bool>;
    async fn search_documents(&self, request: SearchRequest) -> Result<SearchResponse>;
    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>>;
}

/// Main Bedrock service implementation
pub struct BedrockService {
    embedding_engine: Box<dyn EmbeddingEngineTrait>,
    vector_store: Box<dyn VectorStoreTrait>,
}

impl BedrockService {
    /// Create a new Bedrock service with in-memory storage
    pub fn new() -> Self {
        Self {
            embedding_engine: Box::new(InMemoryEmbeddingEngine::new()),
            vector_store: Box::new(InMemoryVectorStore::new()),
        }
    }

    /// Create a new Bedrock service with S3-backed storage
    pub fn with_s3_storage(
        embedding_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        vector_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String,
    ) -> Self {
        Self {
            embedding_engine: Box::new(S3EmbeddingEngine::new(embedding_s3_client, bucket.clone())),
            vector_store: Box::new(S3VectorStore::new(vector_s3_client, bucket)),
        }
    }

    /// Create a new Bedrock service with custom similarity metric
    pub fn with_similarity_metric(similarity_metric: SimilarityMetric) -> Self {
        Self {
            embedding_engine: Box::new(InMemoryEmbeddingEngine::new()),
            vector_store: Box::new(InMemoryVectorStore::with_similarity_metric(similarity_metric)),
        }
    }

    /// Create a new Bedrock service with S3 storage and custom similarity metric
    pub fn with_s3_storage_and_similarity_metric(
        embedding_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        vector_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String,
        similarity_metric: SimilarityMetric,
    ) -> Self {
        Self {
            embedding_engine: Box::new(S3EmbeddingEngine::new(embedding_s3_client, bucket.clone())),
            vector_store: Box::new(S3VectorStore::with_similarity_metric(vector_s3_client, bucket, similarity_metric)),
        }
    }

    /// Create a new Bedrock service with HuggingFace embeddings (in-memory storage)
    pub fn with_huggingface_embeddings(embedding_engine: HuggingFaceEmbeddingEngine) -> Self {
        Self {
            embedding_engine: Box::new(embedding_engine),
            vector_store: Box::new(InMemoryVectorStore::new()),
        }
    }

    /// Create a new Bedrock service with HuggingFace embeddings and S3 vector storage
    pub fn with_huggingface_and_s3_storage(
        embedding_engine: HuggingFaceEmbeddingEngine,
        vector_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String,
    ) -> Self {
        Self {
            embedding_engine: Box::new(embedding_engine),
            vector_store: Box::new(S3VectorStore::new(vector_s3_client, bucket)),
        }
    }

    async fn create_embedding_for_text(&self, text: &str, model_id: &str) -> Result<Vec<f32>> {
        let request = EmbeddingRequest {
            model_id: model_id.to_string(),
            input_text: text.to_string(),
        };

        let response = self.embedding_engine.create_embedding(request).await?;
        Ok(response.embedding)
    }
}

#[async_trait::async_trait]
impl BedrockServiceTrait for BedrockService {
    async fn invoke_model(&self, request: InvokeModelRequest) -> Result<InvokeModelResponse> {
        // For text embedding models, parse the body and create embeddings
        if request.model_id.contains("embed") {
            let embedding_request: TextEmbeddingRequest = serde_json::from_str(&request.body)?;

            let bedrock_request = EmbeddingRequest {
                model_id: request.model_id,
                input_text: embedding_request.input_text,
            };

            let embedding_response = self.embedding_engine.create_embedding(bedrock_request).await?;

            let text_response = TextEmbeddingResponse {
                embedding: embedding_response.embedding,
                input_text_token_count: embedding_response.input_token_count,
            };

            let response_body = serde_json::to_vec(&text_response)?;

            Ok(InvokeModelResponse {
                content_type: "application/json".to_string(),
                body: response_body,
            })
        } else {
            // For other models, return a simple mock response
            let mock_response = serde_json::json!({
                "completion": "This is a mock response from the Bedrock API",
                "stop_reason": "end_turn"
            });

            Ok(InvokeModelResponse {
                content_type: "application/json".to_string(),
                body: serde_json::to_vec(&mock_response)?,
            })
        }
    }

    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        self.embedding_engine.create_embedding(request).await
    }

    async fn create_document(&mut self, request: CreateDocumentRequest) -> Result<VectorDocument> {
        let id = request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Create embedding for the document content
        // Use a default model if not specified
        let embedding = self.create_embedding_for_text(&request.content, "amazon.titan-embed-text-v1").await?;

        let document = VectorDocument {
            id: id.clone(),
            content: request.content,
            embedding,
            metadata: request.metadata.unwrap_or_default(),
            created_at: chrono::Utc::now(),
        };

        self.vector_store.store_document(document.clone()).await?;
        Ok(document)
    }

    async fn get_document(&self, id: &str) -> Option<VectorDocument> {
        self.vector_store.get_document(id).await
    }

    async fn delete_document(&mut self, id: &str) -> Result<bool> {
        self.vector_store.delete_document(id).await
    }

    async fn search_documents(&self, request: SearchRequest) -> Result<SearchResponse> {
        // Create embedding for the query
        let query_embedding = self.create_embedding_for_text(&request.query, "amazon.titan-embed-text-v1").await?;

        let limit = request.limit.unwrap_or(10);
        let results = self.vector_store.search_similar(
            query_embedding,
            limit,
            request.similarity_threshold,
        ).await?;

        // Filter by metadata if provided
        let filtered_results: Vec<SearchResult> = if let Some(metadata_filter) = request.metadata_filter {
            results.into_iter().filter(|result| {
                metadata_filter.iter().all(|(key, value)| {
                    result.document.metadata.get(key).map_or(false, |v| v == value)
                })
            }).collect()
        } else {
            results
        };

        Ok(SearchResponse {
            total_count: filtered_results.len(),
            results: filtered_results,
        })
    }

    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>> {
        self.vector_store.list_documents(limit, offset).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use shared::MockS3ObjectStorageRepository;

    #[tokio::test]
    async fn test_bedrock_service_create_embedding() {
        let service = BedrockService::new();
        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Hello, world!".to_string(),
        };

        let result = service.create_embedding(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.embedding.len(), 1536);
        assert!(response.input_token_count > 0);
    }

    #[tokio::test]
    async fn test_bedrock_service_invoke_model_embedding() {
        let service = BedrockService::new();

        let text_request = TextEmbeddingRequest {
            input_text: "Test text for embedding".to_string(),
        };

        let request = InvokeModelRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            content_type: Some("application/json".to_string()),
            accept: Some("application/json".to_string()),
            body: serde_json::to_string(&text_request).unwrap(),
        };

        let result = service.invoke_model(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.content_type, "application/json");

        let text_response: TextEmbeddingResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(text_response.embedding.len(), 1536);
        assert!(text_response.input_text_token_count > 0);
    }

    #[tokio::test]
    async fn test_bedrock_service_invoke_model_non_embedding() {
        let service = BedrockService::new();

        let request = InvokeModelRequest {
            model_id: "anthropic.claude-v2".to_string(),
            content_type: Some("application/json".to_string()),
            accept: Some("application/json".to_string()),
            body: r#"{"prompt": "Hello, how are you?"}"#.to_string(),
        };

        let result = service.invoke_model(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.content_type, "application/json");

        let mock_response: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(mock_response.get("completion").is_some());
    }

    #[tokio::test]
    async fn test_bedrock_service_create_document() {
        let mut service = BedrockService::new();

        let request = CreateDocumentRequest {
            id: Some("doc1".to_string()),
            content: "This is test content".to_string(),
            metadata: Some(HashMap::from([
                ("category".to_string(), "test".to_string()),
            ])),
        };

        let result = service.create_document(request).await;
        assert!(result.is_ok());

        let document = result.unwrap();
        assert_eq!(document.id, "doc1");
        assert_eq!(document.content, "This is test content");
        assert_eq!(document.embedding.len(), 1536);
        assert_eq!(document.metadata.get("category").unwrap(), "test");
    }

    #[tokio::test]
    async fn test_bedrock_service_document_operations() {
        let mut service = BedrockService::new();

        // Create a document
        let request = CreateDocumentRequest {
            id: Some("doc1".to_string()),
            content: "Test document content".to_string(),
            metadata: None,
        };
        let document = service.create_document(request).await.unwrap();
        assert_eq!(document.id, "doc1");

        // Get the document
        let retrieved = service.get_document("doc1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, "Test document content");

        // Delete the document
        let deleted = service.delete_document("doc1").await.unwrap();
        assert!(deleted);

        // Verify it's gone
        let retrieved = service.get_document("doc1").await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_bedrock_service_search_documents() {
        let mut service = BedrockService::new();

        // Create some test documents
        let docs = vec![
            ("doc1", "The quick brown fox jumps over the lazy dog"),
            ("doc2", "Machine learning is a subset of artificial intelligence"),
            ("doc3", "Vector databases store and query high-dimensional data"),
        ];

        for (id, content) in docs {
            let request = CreateDocumentRequest {
                id: Some(id.to_string()),
                content: content.to_string(),
                metadata: None,
            };
            service.create_document(request).await.unwrap();
        }

        // Search for documents
        let search_request = SearchRequest {
            query: "artificial intelligence machine learning".to_string(),
            limit: Some(2),
            similarity_threshold: None,
            metadata_filter: None,
        };

        let result = service.search_documents(search_request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.results.len() <= 2);
        assert_eq!(response.total_count, response.results.len());

        // Check that results are sorted by similarity
        if response.results.len() > 1 {
            assert!(response.results[0].similarity_score >= response.results[1].similarity_score);
        }
    }

    #[tokio::test]
    async fn test_bedrock_service_list_documents() {
        let mut service = BedrockService::new();

        // Create multiple documents
        for i in 0..5 {
            let request = CreateDocumentRequest {
                id: Some(format!("doc{}", i)),
                content: format!("Content for document {}", i),
                metadata: None,
            };
            service.create_document(request).await.unwrap();
        }

        // List all documents
        let all_docs = service.list_documents(None, None).await.unwrap();
        assert_eq!(all_docs.len(), 5);

        // List with limit
        let limited_docs = service.list_documents(Some(3), None).await.unwrap();
        assert_eq!(limited_docs.len(), 3);

        // List with offset
        let offset_docs = service.list_documents(Some(2), Some(2)).await.unwrap();
        assert_eq!(offset_docs.len(), 2);
    }

    #[tokio::test]
    async fn test_bedrock_service_with_similarity_metric() {
        let service = BedrockService::with_similarity_metric(SimilarityMetric::DotProduct);

        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Test with dot product similarity".to_string(),
        };

        let result = service.create_embedding(request).await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_bedrock_service_with_s3_storage() {
        let mut embedding_mock = MockS3ObjectStorageRepository::new();
        let mut vector_mock = MockS3ObjectStorageRepository::new();

        // Mock S3 operations for embedding engine
        embedding_mock
            .expect_get_object()
            .returning(|_| Box::pin(async { Err(anyhow::anyhow!("Not found")) }));
        embedding_mock
            .expect_put_object()
            .returning(|_| Box::pin(async { Ok("etag".to_string()) }));

        // Mock S3 operations for vector store
        vector_mock
            .expect_get_object()
            .returning(|_| Box::pin(async { Err(anyhow::anyhow!("Not found")) }));
        vector_mock
            .expect_put_object()
            .returning(|_| Box::pin(async { Ok("etag".to_string()) }));

        let mut service = BedrockService::with_s3_storage(
            Box::new(embedding_mock),
            Box::new(vector_mock),
            "test-bucket".to_string(),
        );

        let request = CreateDocumentRequest {
            id: Some("doc1".to_string()),
            content: "Test content with S3 storage".to_string(),
            metadata: None,
        };

        let result = service.create_document(request).await;
        assert!(result.is_ok());
    }
}
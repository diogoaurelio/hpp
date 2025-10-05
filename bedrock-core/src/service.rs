use crate::types::*;
use crate::embedding::{EmbeddingEngineTrait, InMemoryEmbeddingEngine};
use crate::text_generation::{TextGenerationEngineTrait, InMemoryTextGenerationEngine, TextGenerationRequest};
use crate::model_mappings::ModelRegistry;
use anyhow::Result;
use std::sync::Arc;
use s3_core::{VectorStoreTrait, InMemoryVectorStore};

/// Trait defining the Bedrock service interface (embeddings, model invocation, and vector store)
#[async_trait::async_trait]
pub trait BedrockServiceTrait: Send + Sync {
    /// Generate embeddings using specified model
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse>;

    /// Invoke a foundation model directly
    async fn invoke_model(&self, request: InvokeModelRequest) -> Result<InvokeModelResponse>;

    /// List available foundation models
    async fn list_foundation_models(&self) -> Result<ListFoundationModelsResponse>;

    /// Get information about a specific model
    async fn get_foundation_model(&self, model_id: &str) -> Result<Option<FoundationModel>>;

    /// Vector store operations
    async fn create_document(&self, request: CreateDocumentRequest) -> Result<VectorDocument>;
    async fn get_document(&self, id: &str) -> Option<VectorDocument>;
    async fn delete_document(&self, id: &str) -> Result<bool>;
    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>>;
    async fn search_documents(&self, request: SearchRequest) -> Result<SearchResponse>;

    /// Vector index operations
    async fn create_vector_index(&self, index_name: String, dimensions: usize, similarity_metric: SimilarityMetric) -> Result<()>;
    async fn get_vector_index_metadata(&self) -> Result<Option<VectorIndexMetadata>>;
    async fn delete_vector_index(&self) -> Result<bool>;
    async fn validate_vector_index(&self) -> Result<bool>;
}

/// AWS Bedrock service implementation
pub struct BedrockService {
    embedding_engine: Arc<dyn EmbeddingEngineTrait>,
    text_generation_engine: Arc<dyn TextGenerationEngineTrait>,
    model_registry: ModelRegistry,
    vector_store: Arc<tokio::sync::Mutex<dyn VectorStoreTrait + Send>>,
}

impl BedrockService {
    /// Create a new Bedrock service with in-memory embedding engine and vector store
    pub fn new() -> Self {
        Self {
            embedding_engine: Arc::new(InMemoryEmbeddingEngine::new()),
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(InMemoryVectorStore::new())),
        }
    }

    /// Create a new Bedrock service with custom embedding engine
    pub fn with_embedding_engine(embedding_engine: Arc<dyn EmbeddingEngineTrait>) -> Self {
        Self {
            embedding_engine,
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(InMemoryVectorStore::new())),
        }
    }

    /// Create a new Bedrock service with custom embedding engine and vector store
    pub fn with_components(
        embedding_engine: Arc<dyn EmbeddingEngineTrait>,
        vector_store: Arc<tokio::sync::Mutex<dyn VectorStoreTrait + Send>>,
    ) -> Self {
        Self {
            embedding_engine,
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store,
        }
    }

    /// Create service with HuggingFace embeddings and S3 vector storage
    pub fn with_huggingface_and_s3_storage(
        embedding_engine: Arc<dyn EmbeddingEngineTrait>,
        s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String,
    ) -> Self {
        use s3_core::S3VectorStore;
        let vector_store = S3VectorStore::new(s3_client, bucket);
        Self {
            embedding_engine,
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(vector_store)),
        }
    }

    /// Create service with HuggingFace embeddings and in-memory vector storage
    #[cfg(feature = "huggingface")]
    pub fn with_huggingface_local(
        model_cache_dir: std::path::PathBuf,
    ) -> Self {
        let embedding_engine = Arc::new(InMemoryEmbeddingEngine::with_cache_dir(model_cache_dir));
        Self {
            embedding_engine,
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(InMemoryVectorStore::new())),
        }
    }

    /// Create service with HuggingFace embeddings and in-memory vector storage
    pub fn with_huggingface_embeddings(embedding_engine: Arc<dyn EmbeddingEngineTrait>) -> Self {
        Self {
            embedding_engine,
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(InMemoryVectorStore::new())),
        }
    }

    /// Create service with S3 storage for vectors
    pub fn with_s3_storage(
        embedding_engine: Arc<dyn EmbeddingEngineTrait>,
        s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String,
    ) -> Self {
        use s3_core::S3VectorStore;
        let vector_store = S3VectorStore::new(s3_client, bucket);
        Self {
            embedding_engine,
            text_generation_engine: Arc::new(InMemoryTextGenerationEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(vector_store)),
        }
    }
}

impl Default for BedrockService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl BedrockServiceTrait for BedrockService {
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        self.embedding_engine.create_embedding(request).await
    }

    async fn invoke_model(&self, request: InvokeModelRequest) -> Result<InvokeModelResponse> {
        // Handle different model types
        if self.is_embedding_model(&request.model_id) {
            // For embedding models, parse the request body and generate embeddings
            let body: serde_json::Value = serde_json::from_str(&request.body)?;

            if let Some(input_text) = body.get("inputText").and_then(|v| v.as_str()) {
                let embedding_request = EmbeddingRequest {
                    model_id: request.model_id.clone(),
                    input_text: input_text.to_string(),
                };

                let embedding_response = self.embedding_engine.create_embedding(embedding_request).await?;

                let response_body = serde_json::json!({
                    "embedding": embedding_response.embedding,
                    "inputTextTokenCount": embedding_response.input_token_count
                });

                return Ok(InvokeModelResponse {
                    content_type: "application/json".to_string(),
                    body: response_body.to_string().into_bytes(),
                });
            }
        }

        // For text generation models, use the real text generation engine
        if self.is_text_generation_model(&request.model_id) {
            let body: serde_json::Value = serde_json::from_str(&request.body)?;

            // Extract prompt and parameters from request body
            let prompt = body.get("prompt")
                .or_else(|| body.get("inputText"))  // Alternative field name
                .or_else(|| body.get("messages").and_then(|m| m.as_array().and_then(|arr| arr.last()).and_then(|last| last.get("content"))))
                .and_then(|v| v.as_str())
                .unwrap_or("") // Default to empty string if no prompt found
                .to_string();

            let max_tokens = body.get("maxTokens").or_else(|| body.get("max_tokens")).and_then(|v| v.as_u64()).map(|v| v as u32);
            let temperature = body.get("temperature").and_then(|v| v.as_f64()).map(|v| v as f32);
            let top_p = body.get("topP").or_else(|| body.get("top_p")).and_then(|v| v.as_f64()).map(|v| v as f32);
            let stop_sequences = body.get("stopSequences")
                .or_else(|| body.get("stop_sequences"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect());

            let text_request = TextGenerationRequest {
                model_id: request.model_id.clone(),
                prompt,
                max_tokens,
                temperature,
                top_p,
                stop_sequences,
            };

            let text_response = self.text_generation_engine.generate_text(text_request).await?;

            let response_body = serde_json::json!({
                "completion": text_response.completion,
                "stop_reason": text_response.stop_reason,
                "inputTextTokenCount": text_response.input_token_count,
                "outputTextTokenCount": text_response.output_token_count
            });

            return Ok(InvokeModelResponse {
                content_type: "application/json".to_string(),
                body: response_body.to_string().into_bytes(),
            });
        }

        Err(anyhow::anyhow!("Unsupported model: {}", request.model_id))
    }

    async fn list_foundation_models(&self) -> Result<ListFoundationModelsResponse> {
        let embedding_models = self.embedding_engine.get_supported_models().await;
        let text_generation_models = self.text_generation_engine.get_supported_models().await;
        let mut model_summaries = Vec::new();

        // Add embedding models
        for model_id in embedding_models {
            if let Ok(mapping) = self.model_registry.get_mapping(&model_id) {
                model_summaries.push(FoundationModel {
                    model_id: model_id.clone(),
                    provider_name: mapping.aws_model.provider.clone(),
                    model_name: mapping.aws_model.name.clone(),
                    input_modalities: vec!["TEXT".to_string()],
                    output_modalities: vec!["EMBEDDING".to_string()],
                    supported_customizations: vec![],
                    supported_inference_types: vec!["ON_DEMAND".to_string()],
                });
            }
        }

        // Add text generation models
        for model_id in text_generation_models {
            let (provider_name, model_name) = match model_id.as_str() {
                "anthropic.claude-v2" => ("Anthropic".to_string(), "Claude v2".to_string()),
                "anthropic.claude-v2:1" => ("Anthropic".to_string(), "Claude v2.1".to_string()),
                "anthropic.claude-instant-v1" => ("Anthropic".to_string(), "Claude Instant v1".to_string()),
                "amazon.titan-text-lite-v1" => ("Amazon".to_string(), "Titan Text Lite v1".to_string()),
                "amazon.titan-text-express-v1" => ("Amazon".to_string(), "Titan Text Express v1".to_string()),
                "ai21.j2-mid-v1" => ("AI21 Labs".to_string(), "Jurassic-2 Mid".to_string()),
                "ai21.j2-ultra-v1" => ("AI21 Labs".to_string(), "Jurassic-2 Ultra".to_string()),
                "meta.llama2-13b-chat-v1" => ("Meta".to_string(), "Llama 2 13B Chat".to_string()),
                "meta.llama2-70b-chat-v1" => ("Meta".to_string(), "Llama 2 70B Chat".to_string()),
                _ => ("Unknown".to_string(), model_id.clone()),
            };

            model_summaries.push(FoundationModel {
                model_id,
                provider_name,
                model_name,
                input_modalities: vec!["TEXT".to_string()],
                output_modalities: vec!["TEXT".to_string()],
                supported_customizations: vec!["FINE_TUNING".to_string()],
                supported_inference_types: vec!["ON_DEMAND".to_string()],
            });
        }

        Ok(ListFoundationModelsResponse { model_summaries })
    }

    async fn get_foundation_model(&self, model_id: &str) -> Result<Option<FoundationModel>> {
        let models = self.list_foundation_models().await?;
        Ok(models.model_summaries.into_iter()
            .find(|m| m.model_id == model_id))
    }

    async fn create_document(&self, request: CreateDocumentRequest) -> Result<VectorDocument> {
        use chrono::Utc;
        use std::collections::HashMap;

        let id = request.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Generate embedding for the document content
        let embedding_request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(), // Default embedding model
            input_text: request.content.clone(),
        };

        let embedding_response = self.create_embedding(embedding_request).await?;

        let document = VectorDocument {
            id: id.clone(),
            content: request.content,
            embedding: embedding_response.embedding,
            metadata: request.metadata.unwrap_or_else(HashMap::new),
            created_at: Utc::now(),
        };

        let mut vector_store = self.vector_store.lock().await;
        vector_store.store_document(document.clone()).await?;

        Ok(document)
    }

    async fn get_document(&self, id: &str) -> Option<VectorDocument> {
        let vector_store = self.vector_store.lock().await;
        vector_store.get_document(id).await
    }

    async fn delete_document(&self, id: &str) -> Result<bool> {
        let mut vector_store = self.vector_store.lock().await;
        vector_store.delete_document(id).await
    }

    async fn list_documents(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<VectorDocument>> {
        let vector_store = self.vector_store.lock().await;
        vector_store.list_documents(limit, offset).await
    }

    async fn search_documents(&self, request: SearchRequest) -> Result<SearchResponse> {
        // Generate embedding for the search query
        let embedding_request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(), // Default embedding model
            input_text: request.query,
        };

        let embedding_response = self.create_embedding(embedding_request).await?;

        let vector_store = self.vector_store.lock().await;
        let search_results = vector_store.search_similar(
            embedding_response.embedding,
            request.limit.unwrap_or(10),
            request.similarity_threshold,
        ).await?;

        // Apply metadata filtering if provided
        let filtered_results = if let Some(metadata_filter) = &request.metadata_filter {
            search_results.into_iter()
                .filter(|result| {
                    metadata_filter.iter().all(|(key, value)| {
                        result.document.metadata.get(key).map_or(false, |v| v == value)
                    })
                })
                .collect()
        } else {
            search_results
        };

        Ok(SearchResponse {
            total_count: filtered_results.len(),
            results: filtered_results,
        })
    }

    async fn create_vector_index(&self, index_name: String, dimensions: usize, similarity_metric: SimilarityMetric) -> Result<()> {
        let mut vector_store = self.vector_store.lock().await;
        vector_store.create_index(index_name, dimensions, similarity_metric).await
    }

    async fn get_vector_index_metadata(&self) -> Result<Option<VectorIndexMetadata>> {
        let vector_store = self.vector_store.lock().await;
        vector_store.get_index_metadata().await
    }

    async fn delete_vector_index(&self) -> Result<bool> {
        let mut vector_store = self.vector_store.lock().await;
        vector_store.delete_index().await
    }

    async fn validate_vector_index(&self) -> Result<bool> {
        let vector_store = self.vector_store.lock().await;
        vector_store.validate_index().await
    }
}

impl BedrockService {
    fn is_embedding_model(&self, model_id: &str) -> bool {
        model_id.contains("embed") ||
        model_id.starts_with("amazon.titan-embed") ||
        model_id.starts_with("cohere.embed")
    }

    fn is_text_generation_model(&self, model_id: &str) -> bool {
        model_id.starts_with("anthropic.claude") ||
        model_id.starts_with("amazon.titan-text") ||
        model_id.starts_with("ai21.j2") ||
        model_id.contains("llama")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bedrock_service_create_embedding() {
        let service = BedrockService::new();

        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Test text for embedding".to_string(),
        };

        let result = service.create_embedding(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        #[cfg(feature = "huggingface")]
        assert!(response.embedding.len() > 0); // Real HF model dimensions
        #[cfg(not(feature = "huggingface"))]
        assert_eq!(response.embedding.len(), 1536); // Simulated Titan v1 dimensions
        assert!(response.input_token_count > 0);
    }

    #[tokio::test]
    async fn test_bedrock_service_invoke_embedding_model() {
        let service = BedrockService::new();

        let request = InvokeModelRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            content_type: Some("application/json".to_string()),
            accept: Some("application/json".to_string()),
            body: serde_json::json!({
                "inputText": "Test embedding generation"
            }).to_string(),
        };

        let result = service.invoke_model(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.content_type, "application/json");

        let parsed_response: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(parsed_response["embedding"].is_array());
        assert!(parsed_response["inputTextTokenCount"].is_number());
    }

    #[tokio::test]
    async fn test_bedrock_service_invoke_text_model() {
        let service = BedrockService::new();

        let request = InvokeModelRequest {
            model_id: "anthropic.claude-v2".to_string(),
            content_type: Some("application/json".to_string()),
            accept: Some("application/json".to_string()),
            body: serde_json::json!({
                "prompt": "What is machine learning?"
            }).to_string(),
        };

        let result = service.invoke_model(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let parsed_response: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(parsed_response["completion"].is_string());
        assert_eq!(parsed_response["stop_reason"], "end_turn");
    }

    #[tokio::test]
    async fn test_list_foundation_models() {
        let service = BedrockService::new();
        let result = service.list_foundation_models().await;
        assert!(result.is_ok());

        let models = result.unwrap();
        assert!(!models.model_summaries.is_empty());

        // Should include both embedding and text generation models
        let has_embedding_model = models.model_summaries.iter()
            .any(|m| m.output_modalities.contains(&"EMBEDDING".to_string()));
        let has_text_model = models.model_summaries.iter()
            .any(|m| m.output_modalities.contains(&"TEXT".to_string()));

        assert!(has_embedding_model);
        assert!(has_text_model);
    }

    /// Test the complete BedrockService integration workflow
    #[tokio::test]
    async fn test_bedrock_service_full_workflow() {
        let service = BedrockService::new();

        // 1. Test embedding creation
        let embedding_request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Machine learning is revolutionizing technology".to_string(),
        };

        let embedding_response = service.create_embedding(embedding_request).await.unwrap();
        #[cfg(feature = "huggingface")]
        let expected_dims = embedding_response.embedding.len(); // Use actual dimensions
        #[cfg(not(feature = "huggingface"))]
        let expected_dims = 1536; // Simulated Titan v1 dimensions
        assert_eq!(embedding_response.embedding.len(), expected_dims);
        assert!(embedding_response.input_token_count > 0);

        // 2. Test document creation and storage
        let doc_request = CreateDocumentRequest {
            id: Some("tech-doc-1".to_string()),
            content: "Artificial intelligence and machine learning are transforming industries".to_string(),
            metadata: Some(std::collections::HashMap::from([
                ("category".to_string(), "technology".to_string()),
                ("topic".to_string(), "AI".to_string()),
            ])),
        };

        let document = service.create_document(doc_request).await.unwrap();
        assert_eq!(document.id, "tech-doc-1");
        assert_eq!(document.embedding.len(), expected_dims);
        assert_eq!(document.metadata.get("category").unwrap(), "technology");

        // 3. Test document retrieval
        let retrieved = service.get_document("tech-doc-1").await;
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, "tech-doc-1");
        assert_eq!(retrieved.content, "Artificial intelligence and machine learning are transforming industries");

        // 4. Test document listing
        let documents = service.list_documents(None, None).await.unwrap();
        assert_eq!(documents.len(), 1);
        assert_eq!(documents[0].id, "tech-doc-1");

        // 5. Test search functionality
        let search_request = SearchRequest {
            query: "artificial intelligence".to_string(),
            limit: Some(5),
            similarity_threshold: None,
            metadata_filter: None,
        };

        let search_response = service.search_documents(search_request).await.unwrap();
        assert_eq!(search_response.results.len(), 1);
        assert_eq!(search_response.results[0].document.id, "tech-doc-1");
        assert!(search_response.results[0].similarity_score >= -1.0 && search_response.results[0].similarity_score <= 1.0);

        // 6. Test document deletion
        let deleted = service.delete_document("tech-doc-1").await.unwrap();
        assert!(deleted);

        let retrieved_after_delete = service.get_document("tech-doc-1").await;
        assert!(retrieved_after_delete.is_none());
    }

    #[tokio::test]
    async fn test_bedrock_service_different_similarity_metrics() {
        // Test with Cosine similarity (default)
        let service_cosine = BedrockService::new();
        test_similarity_metric(service_cosine, SimilarityMetric::Cosine, "Cosine").await;

        // Test with Euclidean distance
        let service_euclidean = BedrockService::new();
        test_similarity_metric(service_euclidean, SimilarityMetric::Euclidean, "Euclidean").await;

        // Test with Dot Product
        let service_dot = BedrockService::new();
        test_similarity_metric(service_dot, SimilarityMetric::DotProduct, "DotProduct").await;
    }

    async fn test_similarity_metric(service: BedrockService, similarity_metric: SimilarityMetric, metric_name: &str) {
        // Get the embedding dimensions for the current configuration
        let test_request = CreateDocumentRequest {
            id: Some("dim-test".to_string()),
            content: "Test content".to_string(),
            metadata: None,
        };
        let test_doc = service.create_document(test_request).await.unwrap();
        let embedding_dims = test_doc.embedding.len();
        service.delete_document("dim-test").await.unwrap();

        // Create an index with the correct embedding dimensions
        service.create_vector_index(
            format!("test-index-{}", metric_name.to_lowercase()),
            embedding_dims,
            similarity_metric,
        ).await.expect("Failed to create index");

        // Create test documents
        let doc1 = CreateDocumentRequest {
            id: Some("similar1".to_string()),
            content: "Machine learning and artificial intelligence".to_string(),
            metadata: None,
        };

        let doc2 = CreateDocumentRequest {
            id: Some("similar2".to_string()),
            content: "Deep learning and neural networks".to_string(),
            metadata: None,
        };

        let doc3 = CreateDocumentRequest {
            id: Some("different".to_string()),
            content: "Cooking recipes and food preparation".to_string(),
            metadata: None,
        };

        // Store documents
        service.create_document(doc1).await.unwrap();
        service.create_document(doc2).await.unwrap();
        service.create_document(doc3).await.unwrap();

        // Search for AI-related content
        let search_request = SearchRequest {
            query: "artificial intelligence machine learning".to_string(),
            limit: Some(3),
            similarity_threshold: None,
            metadata_filter: None,
        };

        let search_response = service.search_documents(search_request).await.unwrap();
        assert_eq!(search_response.results.len(), 3);

        // Results should be ordered by similarity (descending)
        assert!(search_response.results[0].similarity_score >= search_response.results[1].similarity_score);
        assert!(search_response.results[1].similarity_score >= search_response.results[2].similarity_score);

        // All documents should be present
        let document_ids: std::collections::HashSet<_> = search_response.results
            .iter()
            .map(|r| r.document.id.as_str())
            .collect();
        assert!(document_ids.contains("similar1"));
        assert!(document_ids.contains("similar2"));
        assert!(document_ids.contains("different"));

        // All similarity scores should be within expected ranges
        for result in &search_response.results {
            match similarity_metric {
                SimilarityMetric::Cosine => {
                    assert!(result.similarity_score >= -1.0 && result.similarity_score <= 1.0);
                }
                SimilarityMetric::DotProduct => {
                    // Dot product can be any value, just ensure it's finite
                    assert!(result.similarity_score.is_finite());
                }
                SimilarityMetric::Euclidean => {
                    // Euclidean converted to similarity should be positive
                    assert!(result.similarity_score > 0.0);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_bedrock_service_vector_index_operations() {
        let service = BedrockService::new();

        // Initially no index should exist
        let metadata = service.get_vector_index_metadata().await.unwrap();
        assert!(metadata.is_none());

        // Create an index
        service.create_vector_index(
            "test-index".to_string(),
            1536,
            SimilarityMetric::Cosine,
        ).await.unwrap();

        // Now index should exist
        let metadata = service.get_vector_index_metadata().await.unwrap();
        assert!(metadata.is_some());
        let metadata = metadata.unwrap();
        assert_eq!(metadata.index_name, "test-index");
        assert_eq!(metadata.dimensions, 1536);
        assert_eq!(metadata.similarity_metric, SimilarityMetric::Cosine);

        // Validate index
        let is_valid = service.validate_vector_index().await.unwrap();
        assert!(is_valid);

        // Delete index
        let deleted = service.delete_vector_index().await.unwrap();
        assert!(deleted);

        // Index should no longer exist
        let metadata = service.get_vector_index_metadata().await.unwrap();
        assert!(metadata.is_none());
    }
}
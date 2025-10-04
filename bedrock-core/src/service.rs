use crate::types::*;
use crate::embedding::{EmbeddingEngineTrait, InMemoryEmbeddingEngine};
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
    model_registry: ModelRegistry,
    vector_store: Arc<tokio::sync::Mutex<dyn VectorStoreTrait + Send>>,
}

impl BedrockService {
    /// Create a new Bedrock service with in-memory embedding engine and vector store
    pub fn new() -> Self {
        Self {
            embedding_engine: Arc::new(InMemoryEmbeddingEngine::new()),
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(InMemoryVectorStore::new())),
        }
    }

    /// Create a new Bedrock service with custom embedding engine
    pub fn with_embedding_engine(embedding_engine: Arc<dyn EmbeddingEngineTrait>) -> Self {
        Self {
            embedding_engine,
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
            model_registry: ModelRegistry::new(),
            vector_store: Arc::new(tokio::sync::Mutex::new(vector_store)),
        }
    }

    /// Create service with HuggingFace embeddings and in-memory vector storage
    pub fn with_huggingface_embeddings(embedding_engine: Arc<dyn EmbeddingEngineTrait>) -> Self {
        Self {
            embedding_engine,
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

        // For text generation models, return a mock response
        if self.is_text_generation_model(&request.model_id) {
            let response_body = serde_json::json!({
                "completion": "This is a mock response from the Bedrock service. In a real implementation, this would call the actual foundation model.",
                "stop_reason": "end_turn"
            });

            return Ok(InvokeModelResponse {
                content_type: "application/json".to_string(),
                body: response_body.to_string().into_bytes(),
            });
        }

        Err(anyhow::anyhow!("Unsupported model: {}", request.model_id))
    }

    async fn list_foundation_models(&self) -> Result<ListFoundationModelsResponse> {
        let supported_models = self.embedding_engine.get_supported_models().await;
        let mut model_summaries = Vec::new();

        // Add embedding models
        for model_id in supported_models {
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

        // Add text generation models (mock)
        model_summaries.push(FoundationModel {
            model_id: "anthropic.claude-v2".to_string(),
            provider_name: "Anthropic".to_string(),
            model_name: "Claude v2".to_string(),
            input_modalities: vec!["TEXT".to_string()],
            output_modalities: vec!["TEXT".to_string()],
            supported_customizations: vec!["FINE_TUNING".to_string()],
            supported_inference_types: vec!["ON_DEMAND".to_string()],
        });

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
        assert_eq!(response.embedding.len(), 1536); // Titan v1 dimensions
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
}
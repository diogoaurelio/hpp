use serde::{Deserialize, Serialize};

/// AWS Bedrock model invocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeModelRequest {
    pub model_id: String,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    pub body: String,
}

/// AWS Bedrock model invocation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeModelResponse {
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Request to create embeddings using Bedrock models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    pub model_id: String,
    pub input_text: String,
}

/// Response from Bedrock embedding generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    pub embedding: Vec<f32>,
    pub input_token_count: u32,
}

/// AWS Bedrock text embedding request format (direct API compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbeddingRequest {
    #[serde(rename = "inputText")]
    pub input_text: String,
}

/// AWS Bedrock text embedding response format (direct API compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbeddingResponse {
    pub embedding: Vec<f32>,
    #[serde(rename = "inputTextTokenCount")]
    pub input_text_token_count: u32,
}

/// Bedrock foundation model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationModel {
    pub model_id: String,
    pub provider_name: String,
    pub model_name: String,
    pub input_modalities: Vec<String>,
    pub output_modalities: Vec<String>,
    pub supported_customizations: Vec<String>,
    pub supported_inference_types: Vec<String>,
}

/// List foundation models response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFoundationModelsResponse {
    pub model_summaries: Vec<FoundationModel>,
}

// Re-export vector store types from s3-core
pub use s3_core::{
    VectorDocument, CreateDocumentRequest, SearchRequest, SearchResponse, SearchResult,
    SimilarityMetric, CreateVectorBucketRequest, VectorIndexConfiguration, VectorBucketInfo,
    VectorIndexMetadata
};
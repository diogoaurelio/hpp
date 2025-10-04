use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeModelRequest {
    pub model_id: String,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeModelResponse {
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    pub model_id: String,
    pub input_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    pub embedding: Vec<f32>,
    pub input_token_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbeddingRequest {
    #[serde(rename = "inputText")]
    pub input_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbeddingResponse {
    pub embedding: Vec<f32>,
    #[serde(rename = "inputTextTokenCount")]
    pub input_text_token_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorDocument {
    pub id: String,
    pub content: String,
    pub embedding: Vec<f32>,
    pub metadata: HashMap<String, String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDocumentRequest {
    pub id: Option<String>,
    pub content: String,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub limit: Option<usize>,
    pub similarity_threshold: Option<f32>,
    pub metadata_filter: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub document: VectorDocument,
    pub similarity_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub total_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityMetric {
    Cosine,
    Euclidean,
    DotProduct,
}

impl Default for SimilarityMetric {
    fn default() -> Self {
        SimilarityMetric::Cosine
    }
}
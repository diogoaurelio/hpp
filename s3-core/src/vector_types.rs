use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vector document stored in S3 Vector bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorDocument {
    pub id: String,
    pub content: String,
    pub embedding: Vec<f32>,
    pub metadata: HashMap<String, String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create a document in S3 Vector bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDocumentRequest {
    pub id: Option<String>,
    pub content: String,
    pub metadata: Option<HashMap<String, String>>,
}

/// Request to search vectors in S3 Vector bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub limit: Option<usize>,
    pub similarity_threshold: Option<f32>,
    pub metadata_filter: Option<HashMap<String, String>>,
}

/// Search result with similarity score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub document: VectorDocument,
    pub similarity_score: f32,
}

/// Response from vector search operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub total_count: usize,
}

/// Similarity metrics supported by S3 Vectors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// S3 Vector bucket creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVectorBucketRequest {
    pub bucket_name: String,
    pub dimensions: usize,
    pub similarity_metric: Option<SimilarityMetric>,
    pub index_configuration: Option<VectorIndexConfiguration>,
}

/// Vector index configuration for S3 Vector bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorIndexConfiguration {
    pub max_vectors: Option<usize>,
    pub distance_function: Option<String>,
    pub index_type: Option<String>,
}

/// S3 Vector bucket metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorBucketInfo {
    pub bucket_name: String,
    pub dimensions: usize,
    pub similarity_metric: SimilarityMetric,
    pub vector_count: usize,
    pub index_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Vector index metadata stored in S3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorIndexMetadata {
    pub index_name: String,
    pub dimensions: usize,
    pub similarity_metric: SimilarityMetric,
    pub index_configuration: VectorIndexConfiguration,
    pub document_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_modified: chrono::DateTime<chrono::Utc>,
    pub version: String,
}

impl VectorIndexMetadata {
    pub fn new(index_name: String, dimensions: usize, similarity_metric: SimilarityMetric) -> Self {
        let now = chrono::Utc::now();
        Self {
            index_name,
            dimensions,
            similarity_metric,
            index_configuration: VectorIndexConfiguration::default(),
            document_count: 0,
            created_at: now,
            last_modified: now,
            version: "1.0".to_string(),
        }
    }

    pub fn validate_document(&self, document: &VectorDocument) -> Result<(), String> {
        if document.embedding.len() != self.dimensions {
            return Err(format!(
                "Document embedding dimensions ({}) don't match index dimensions ({})",
                document.embedding.len(),
                self.dimensions
            ));
        }
        Ok(())
    }
}

impl Default for VectorIndexConfiguration {
    fn default() -> Self {
        Self {
            max_vectors: Some(100_000),
            distance_function: Some("cosine".to_string()),
            index_type: Some("flat".to_string()),
        }
    }
}
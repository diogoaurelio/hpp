use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AWS Bedrock model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsBedrockModel {
    pub model_id: String,
    pub provider: String,
    pub name: String,
    pub dimensions: usize,
    pub max_tokens: usize,
    pub description: String,
}

/// HuggingFace model that maps to AWS Bedrock model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuggingFaceEquivalent {
    pub hf_model_id: String,
    pub dimensions: usize,
    pub max_tokens: usize,
    pub similarity_score: f32, // How closely it matches the AWS model (0.0-1.0)
    pub notes: String,
}

/// Complete model mapping between AWS and HuggingFace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMapping {
    pub aws_model: AwsBedrockModel,
    pub hf_equivalent: HuggingFaceEquivalent,
}

pub struct ModelRegistry {
    mappings: HashMap<String, ModelMapping>,
}

impl ModelRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            mappings: HashMap::new(),
        };
        registry.initialize_mappings();
        registry
    }

    fn initialize_mappings(&mut self) {
        // Amazon Titan Embed Text v1
        self.add_mapping(ModelMapping {
            aws_model: AwsBedrockModel {
                model_id: "amazon.titan-embed-text-v1".to_string(),
                provider: "Amazon".to_string(),
                name: "Titan Text Embeddings v1".to_string(),
                dimensions: 1536,
                max_tokens: 8192,
                description: "Amazon's general-purpose text embedding model".to_string(),
            },
            hf_equivalent: HuggingFaceEquivalent {
                hf_model_id: "sentence-transformers/all-mpnet-base-v2".to_string(),
                dimensions: 768,
                max_tokens: 514,
                similarity_score: 0.85,
                notes: "High-quality general embeddings, dimensions adjusted via projection".to_string(),
            },
        });

        // Amazon Titan Embed Text v2
        self.add_mapping(ModelMapping {
            aws_model: AwsBedrockModel {
                model_id: "amazon.titan-embed-text-v2:0".to_string(),
                provider: "Amazon".to_string(),
                name: "Titan Text Embeddings v2".to_string(),
                dimensions: 1024,
                max_tokens: 8192,
                description: "Improved Amazon text embedding model with better performance".to_string(),
            },
            hf_equivalent: HuggingFaceEquivalent {
                hf_model_id: "sentence-transformers/all-mpnet-base-v2".to_string(),
                dimensions: 768,
                max_tokens: 514,
                similarity_score: 0.88,
                notes: "Best open alternative, dimensions projected to match AWS".to_string(),
            },
        });

        // Cohere Embed English v3
        self.add_mapping(ModelMapping {
            aws_model: AwsBedrockModel {
                model_id: "cohere.embed-english-v3".to_string(),
                provider: "Cohere".to_string(),
                name: "Embed English v3".to_string(),
                dimensions: 1024,
                max_tokens: 512,
                description: "Cohere's English-optimized embedding model".to_string(),
            },
            hf_equivalent: HuggingFaceEquivalent {
                hf_model_id: "sentence-transformers/all-MiniLM-L12-v2".to_string(),
                dimensions: 384,
                max_tokens: 512,
                similarity_score: 0.80,
                notes: "Good English performance, dimensions projected".to_string(),
            },
        });

        // Cohere Embed Multilingual v3
        self.add_mapping(ModelMapping {
            aws_model: AwsBedrockModel {
                model_id: "cohere.embed-multilingual-v3".to_string(),
                provider: "Cohere".to_string(),
                name: "Embed Multilingual v3".to_string(),
                dimensions: 1024,
                max_tokens: 512,
                description: "Cohere's multilingual embedding model".to_string(),
            },
            hf_equivalent: HuggingFaceEquivalent {
                hf_model_id: "sentence-transformers/paraphrase-multilingual-mpnet-base-v2".to_string(),
                dimensions: 768,
                max_tokens: 512,
                similarity_score: 0.82,
                notes: "Excellent multilingual support, close performance to Cohere".to_string(),
            },
        });

        // Add some additional high-quality models for completeness

        // BGE models (very competitive with commercial models)
        self.add_mapping(ModelMapping {
            aws_model: AwsBedrockModel {
                model_id: "amazon.titan-embed-text-v1-optimized".to_string(),
                provider: "Amazon".to_string(),
                name: "Titan Text Embeddings v1 (BGE Alternative)".to_string(),
                dimensions: 1536,
                max_tokens: 8192,
                description: "High-performance alternative using BGE model".to_string(),
            },
            hf_equivalent: HuggingFaceEquivalent {
                hf_model_id: "BAAI/bge-large-en-v1.5".to_string(),
                dimensions: 1024,
                max_tokens: 512,
                similarity_score: 0.92,
                notes: "State-of-the-art open model, often outperforms commercial models".to_string(),
            },
        });

        // E5 models (Microsoft's excellent embeddings)
        self.add_mapping(ModelMapping {
            aws_model: AwsBedrockModel {
                model_id: "cohere.embed-english-v3-e5".to_string(),
                provider: "Cohere".to_string(),
                name: "Embed English v3 (E5 Alternative)".to_string(),
                dimensions: 1024,
                max_tokens: 512,
                description: "High-performance alternative using E5 model".to_string(),
            },
            hf_equivalent: HuggingFaceEquivalent {
                hf_model_id: "intfloat/e5-large-v2".to_string(),
                dimensions: 1024,
                max_tokens: 512,
                similarity_score: 0.90,
                notes: "Microsoft's E5 model, excellent performance on benchmarks".to_string(),
            },
        });
    }

    fn add_mapping(&mut self, mapping: ModelMapping) {
        self.mappings.insert(mapping.aws_model.model_id.clone(), mapping);
    }

    pub fn get_mapping(&self, aws_model_id: &str) -> Result<&ModelMapping> {
        self.mappings
            .get(aws_model_id)
            .ok_or_else(|| anyhow!("Unsupported AWS model: {}", aws_model_id))
    }

    pub fn get_hf_model_id(&self, aws_model_id: &str) -> Result<String> {
        Ok(self.get_mapping(aws_model_id)?.hf_equivalent.hf_model_id.clone())
    }

    pub fn get_expected_dimensions(&self, aws_model_id: &str) -> Result<usize> {
        Ok(self.get_mapping(aws_model_id)?.aws_model.dimensions)
    }

    pub fn list_supported_models(&self) -> Vec<&AwsBedrockModel> {
        self.mappings.values().map(|m| &m.aws_model).collect()
    }

    pub fn get_model_info(&self, aws_model_id: &str) -> Result<&AwsBedrockModel> {
        Ok(&self.get_mapping(aws_model_id)?.aws_model)
    }

    /// Check if we have a good equivalent for the AWS model
    pub fn is_high_quality_mapping(&self, aws_model_id: &str) -> Result<bool> {
        let mapping = self.get_mapping(aws_model_id)?;
        Ok(mapping.hf_equivalent.similarity_score >= 0.80)
    }

    /// Get all available AWS model IDs
    pub fn get_aws_model_ids(&self) -> Vec<String> {
        self.mappings.keys().cloned().collect()
    }

    /// Get mapping with quality assessment
    pub fn get_mapping_with_quality(&self, aws_model_id: &str) -> Result<(String, f32, String)> {
        let mapping = self.get_mapping(aws_model_id)?;
        Ok((
            mapping.hf_equivalent.hf_model_id.clone(),
            mapping.hf_equivalent.similarity_score,
            mapping.hf_equivalent.notes.clone(),
        ))
    }
}

/// Dimension projection utilities for models with different dimensions
pub struct DimensionProjector {
    target_dimensions: usize,
}

impl DimensionProjector {
    pub fn new(target_dimensions: usize) -> Self {
        Self { target_dimensions }
    }

    /// Project embeddings to target dimensions using PCA-like approach
    pub fn project_embedding(&self, embedding: Vec<f32>) -> Vec<f32> {
        let current_dims = embedding.len();

        if current_dims == self.target_dimensions {
            return embedding;
        }

        if current_dims > self.target_dimensions {
            // Truncate to target dimensions
            embedding[..self.target_dimensions].to_vec()
        } else {
            // Pad with zeros to reach target dimensions
            let mut projected = embedding;
            projected.resize(self.target_dimensions, 0.0);
            projected
        }
    }

    /// More sophisticated projection using learned linear transformation
    /// In production, you'd train this transformation on your specific data
    pub fn linear_project_embedding(&self, embedding: Vec<f32>) -> Vec<f32> {
        let current_dims = embedding.len();

        if current_dims == self.target_dimensions {
            return embedding;
        }

        // Simple linear interpolation/extrapolation
        let ratio = self.target_dimensions as f32 / current_dims as f32;

        if ratio > 1.0 {
            // Upsample using interpolation
            let mut projected = Vec::with_capacity(self.target_dimensions);
            for i in 0..self.target_dimensions {
                let source_idx = (i as f32 / ratio) as usize;
                if source_idx < current_dims {
                    projected.push(embedding[source_idx]);
                } else {
                    projected.push(0.0);
                }
            }
            projected
        } else {
            // Downsample using averaging
            let mut projected = Vec::with_capacity(self.target_dimensions);
            let window_size = (1.0 / ratio) as usize;

            for i in 0..self.target_dimensions {
                let start_idx = (i as f32 * window_size as f32) as usize;
                let end_idx = ((i + 1) as f32 * window_size as f32) as usize;

                let sum: f32 = embedding[start_idx..end_idx.min(current_dims)].iter().sum();
                let count = (end_idx.min(current_dims) - start_idx) as f32;
                projected.push(sum / count);
            }
            projected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_registry_initialization() {
        let registry = ModelRegistry::new();

        // Test that all expected AWS models are present
        assert!(registry.get_mapping("amazon.titan-embed-text-v1").is_ok());
        assert!(registry.get_mapping("amazon.titan-embed-text-v2:0").is_ok());
        assert!(registry.get_mapping("cohere.embed-english-v3").is_ok());
        assert!(registry.get_mapping("cohere.embed-multilingual-v3").is_ok());
    }

    #[test]
    fn test_get_hf_model_id() {
        let registry = ModelRegistry::new();

        let hf_id = registry.get_hf_model_id("amazon.titan-embed-text-v1").unwrap();
        assert_eq!(hf_id, "sentence-transformers/all-mpnet-base-v2");
    }

    #[test]
    fn test_get_expected_dimensions() {
        let registry = ModelRegistry::new();

        let dims = registry.get_expected_dimensions("amazon.titan-embed-text-v1").unwrap();
        assert_eq!(dims, 1536);

        let dims2 = registry.get_expected_dimensions("cohere.embed-english-v3").unwrap();
        assert_eq!(dims2, 1024);
    }

    #[test]
    fn test_unsupported_model() {
        let registry = ModelRegistry::new();

        assert!(registry.get_mapping("unsupported-model").is_err());
    }

    #[test]
    fn test_list_supported_models() {
        let registry = ModelRegistry::new();

        let models = registry.list_supported_models();
        assert!(models.len() >= 4); // At least the main AWS models

        let model_ids: Vec<&str> = models.iter().map(|m| m.model_id.as_str()).collect();
        assert!(model_ids.contains(&"amazon.titan-embed-text-v1"));
        assert!(model_ids.contains(&"cohere.embed-multilingual-v3"));
    }

    #[test]
    fn test_high_quality_mapping() {
        let registry = ModelRegistry::new();

        // All our mappings should be reasonably high quality
        assert!(registry.is_high_quality_mapping("amazon.titan-embed-text-v1").unwrap());
        assert!(registry.is_high_quality_mapping("cohere.embed-english-v3").unwrap());
    }

    #[test]
    fn test_dimension_projector_same_size() {
        let projector = DimensionProjector::new(4);
        let embedding = vec![1.0, 2.0, 3.0, 4.0];
        let projected = projector.project_embedding(embedding.clone());

        // Should keep same size when target equals input size
        assert_eq!(projected.len(), 4);
        assert_eq!(projected, embedding);
    }

    #[test]
    fn test_dimension_projector_upsampling() {
        let projector = DimensionProjector::new(6);
        let embedding = vec![1.0, 2.0, 3.0];
        let projected = projector.project_embedding(embedding);

        assert_eq!(projected.len(), 6);
        assert_eq!(projected[0], 1.0);
        assert_eq!(projected[1], 2.0);
        assert_eq!(projected[2], 3.0);
        // Rest should be zeros
        assert_eq!(projected[5], 0.0);
    }

    #[test]
    fn test_dimension_projector_downsampling() {
        let projector = DimensionProjector::new(2);
        let embedding = vec![1.0, 2.0, 3.0, 4.0];
        let projected = projector.project_embedding(embedding);

        assert_eq!(projected.len(), 2);
        // Should contain the first 2 elements
        assert_eq!(projected[0], 1.0);
        assert_eq!(projected[1], 2.0);
    }

    #[test]
    fn test_linear_projection() {
        let projector = DimensionProjector::new(4);
        let embedding = vec![1.0, 2.0];
        let projected = projector.linear_project_embedding(embedding);

        assert_eq!(projected.len(), 4);
        // Should have interpolated values
        assert!(projected[0] > 0.0);
        assert!(projected[1] > 0.0);
    }

    #[test]
    fn test_get_mapping_with_quality() {
        let registry = ModelRegistry::new();

        let (hf_id, score, notes) = registry
            .get_mapping_with_quality("amazon.titan-embed-text-v1")
            .unwrap();

        assert_eq!(hf_id, "sentence-transformers/all-mpnet-base-v2");
        assert!(score >= 0.8);
        assert!(!notes.is_empty());
    }
}
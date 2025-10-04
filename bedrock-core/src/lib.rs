pub mod types;
pub mod embedding;
pub mod vector_store;
pub mod service;
pub mod huggingface_embedding;
pub mod model_mappings;

#[cfg(test)]
pub mod huggingface_tests;

#[cfg(test)]
pub mod integration_tests;

pub use service::{BedrockService, BedrockServiceTrait};
pub use types::*;
pub use embedding::{EmbeddingEngineTrait, InMemoryEmbeddingEngine, S3EmbeddingEngine};
pub use vector_store::{VectorStoreTrait, InMemoryVectorStore, S3VectorStore};
pub use huggingface_embedding::{HuggingFaceEmbeddingEngine, ModelConfig, create_huggingface_engine};
pub use model_mappings::{ModelRegistry, AwsBedrockModel, HuggingFaceEquivalent, ModelMapping, DimensionProjector};
pub mod types;
pub mod embedding;
pub mod service;
pub mod text_generation;
pub mod model_mappings;

pub use service::{BedrockService, BedrockServiceTrait};
pub use types::*;
pub use embedding::{EmbeddingEngineTrait, InMemoryEmbeddingEngine, S3EmbeddingEngine};
pub use text_generation::{TextGenerationEngineTrait, InMemoryTextGenerationEngine, TextGenerationRequest, TextGenerationResponse};
pub use model_mappings::{ModelRegistry, AwsBedrockModel, HuggingFaceEquivalent, ModelMapping, DimensionProjector};
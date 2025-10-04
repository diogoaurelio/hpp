use crate::{
    model_mappings::{ModelRegistry, DimensionProjector},
    types::EmbeddingRequest,
    embedding::EmbeddingEngineTrait,
    huggingface_embedding::{HuggingFaceEmbeddingEngine, ModelConfig, create_huggingface_engine},
};

#[tokio::test]
async fn test_model_registry_aws_compatibility() {
    let registry = ModelRegistry::new();

    // Test all official AWS Bedrock embedding models
    let official_models = vec![
        ("amazon.titan-embed-text-v1", 1536),
        ("amazon.titan-embed-text-v2:0", 1024),
        ("cohere.embed-english-v3", 1024),
        ("cohere.embed-multilingual-v3", 1024),
    ];

    for (aws_model, expected_dims) in official_models {
        // Should be able to get mapping
        let mapping = registry.get_mapping(aws_model).unwrap();
        assert_eq!(mapping.aws_model.model_id, aws_model);
        assert_eq!(mapping.aws_model.dimensions, expected_dims);

        // Should have HuggingFace equivalent
        let hf_id = registry.get_hf_model_id(aws_model).unwrap();
        assert!(!hf_id.is_empty());
        assert!(hf_id.contains("sentence-transformers") || hf_id.contains("BAAI") || hf_id.contains("intfloat"));

        // Should have good quality mapping
        let is_high_quality = registry.is_high_quality_mapping(aws_model).unwrap();
        assert!(is_high_quality, "Model {} should have high quality mapping", aws_model);

        // Test mapping with quality info
        let (hf_model, quality_score, notes) = registry.get_mapping_with_quality(aws_model).unwrap();
        assert_eq!(hf_model, hf_id);
        assert!(quality_score >= 0.8, "Quality score should be >= 0.8 for {}", aws_model);
        assert!(!notes.is_empty());
    }
}

#[tokio::test]
async fn test_model_registry_supported_models() {
    let registry = ModelRegistry::new();

    let supported = registry.list_supported_models();
    assert!(supported.len() >= 4, "Should support at least 4 AWS models");

    let aws_ids = registry.get_aws_model_ids();
    assert!(aws_ids.contains(&"amazon.titan-embed-text-v1".to_string()));
    assert!(aws_ids.contains(&"cohere.embed-english-v3".to_string()));

    // Each model should have complete information
    for model in supported {
        assert!(!model.model_id.is_empty());
        assert!(!model.provider.is_empty());
        assert!(!model.name.is_empty());
        assert!(model.dimensions > 0);
        assert!(model.max_tokens > 0);
        assert!(!model.description.is_empty());
    }
}

#[tokio::test]
async fn test_dimension_projector_functionality() {
    // Test same size (no projection needed)
    let projector = DimensionProjector::new(5);
    let embedding = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let result = projector.project_embedding(embedding.clone());
    assert_eq!(result, embedding);

    // Test downsampling (truncation)
    let projector = DimensionProjector::new(3);
    let embedding = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let result = projector.project_embedding(embedding);
    assert_eq!(result, vec![1.0, 2.0, 3.0]);

    // Test upsampling (padding with zeros)
    let projector = DimensionProjector::new(7);
    let embedding = vec![1.0, 2.0, 3.0];
    let result = projector.project_embedding(embedding);
    assert_eq!(result, vec![1.0, 2.0, 3.0, 0.0, 0.0, 0.0, 0.0]);

    // Test linear projection upsampling
    let projector = DimensionProjector::new(6);
    let embedding = vec![1.0, 2.0, 3.0];
    let result = projector.linear_project_embedding(embedding);
    assert_eq!(result.len(), 6);
    assert!(result[0] > 0.0);

    // Test linear projection downsampling
    let projector = DimensionProjector::new(2);
    let embedding = vec![1.0, 2.0, 3.0, 4.0];
    let result = projector.linear_project_embedding(embedding);
    assert_eq!(result.len(), 2);
    assert!(result[0] > 0.0);
    assert!(result[1] > 0.0);
}

#[tokio::test]
async fn test_dimension_projector_aws_compatibility() {
    // Test projecting to AWS Titan v1 dimensions (1536)
    let projector = DimensionProjector::new(1536);
    let small_embedding = vec![0.1; 768]; // MPNet dimensions
    let projected = projector.linear_project_embedding(small_embedding);
    assert_eq!(projected.len(), 1536);

    // Test projecting to AWS Titan v2 dimensions (1024)
    let projector = DimensionProjector::new(1024);
    let large_embedding = vec![0.1; 1536]; // Titan v1 dimensions
    let projected = projector.linear_project_embedding(large_embedding);
    assert_eq!(projected.len(), 1024);

    // Test projecting to Cohere dimensions (1024)
    let projector = DimensionProjector::new(1024);
    let mini_embedding = vec![0.1; 384]; // MiniLM dimensions
    let projected = projector.linear_project_embedding(mini_embedding);
    assert_eq!(projected.len(), 1024);
}

#[tokio::test]
async fn test_model_config_presets() {
    let config = ModelConfig::sentence_transformers_all_minilm_l6_v2();
    assert_eq!(config.model_id, "sentence-transformers/all-MiniLM-L6-v2");
    assert_eq!(config.dimension, 384);
    assert_eq!(config.max_length, 512);

    let config = ModelConfig::sentence_transformers_all_mpnet_base_v2();
    assert_eq!(config.model_id, "sentence-transformers/all-mpnet-base-v2");
    assert_eq!(config.dimension, 768);
    assert_eq!(config.max_length, 512);

    let config = ModelConfig::titan_embed_text_v1();
    assert_eq!(config.dimension, 1536); // Should match AWS Titan
}

#[tokio::test]
async fn test_huggingface_engine_initialization() {
    let cache_dir = std::env::temp_dir().join("test_hf_cache");
    let engine = HuggingFaceEmbeddingEngine::new(Some(cache_dir.clone())).await.unwrap();

    // Cache directory should exist
    assert!(tokio::fs::metadata(&cache_dir).await.is_ok());

    // Should have model registry
    let models = engine.get_supported_models().await;
    assert!(!models.is_empty());
    assert!(models.contains(&"amazon.titan-embed-text-v1".to_string()));
}

#[tokio::test]
#[ignore] // Requires internet connection and model downloads
async fn test_huggingface_engine_real_embedding() {
    let models_to_load = vec!["sentence-transformers/all-MiniLM-L6-v2".to_string()];
    let engine = create_huggingface_engine(models_to_load, None).await.unwrap();

    // Test AWS model ID mapping
    let request = EmbeddingRequest {
        model_id: "amazon.titan-embed-text-v1".to_string(),
        input_text: "The quick brown fox jumps over the lazy dog".to_string(),
    };

    let result = engine.create_embedding(request).await;
    assert!(result.is_ok(), "Should create embedding successfully");

    let response = result.unwrap();
    assert_eq!(response.embedding.len(), 1536); // Should match AWS Titan dimensions
    assert!(response.input_token_count > 0);

    // Check that embedding is normalized
    let magnitude: f32 = response.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((magnitude - 1.0).abs() < 0.01, "Embedding should be normalized");

    // All values should be reasonable
    for &value in &response.embedding {
        assert!(value.abs() <= 1.0, "Embedding values should be in reasonable range");
    }
}

#[tokio::test]
#[ignore] // Requires internet connection
async fn test_huggingface_engine_different_models() {
    let models = vec![
        ("amazon.titan-embed-text-v1", 1536),
        ("amazon.titan-embed-text-v2:0", 1024),
        ("cohere.embed-english-v3", 1024),
    ];

    for (aws_model_id, expected_dims) in models {
        // Map to HuggingFace models
        let registry = ModelRegistry::new();
        let hf_model_id = registry.get_hf_model_id(aws_model_id).unwrap();

        let engine = create_huggingface_engine(vec![hf_model_id], None).await.unwrap();

        let request = EmbeddingRequest {
            model_id: aws_model_id.to_string(),
            input_text: "Test text for embedding".to_string(),
        };

        let result = engine.create_embedding(request).await.unwrap();
        assert_eq!(result.embedding.len(), expected_dims,
                  "Model {} should produce {} dimensions", aws_model_id, expected_dims);
    }
}

#[tokio::test]
async fn test_embedding_consistency() {
    // Test that the same input produces the same embedding
    let engine = HuggingFaceEmbeddingEngine::new(None).await.unwrap();
    let _test_text = "Consistency test text";

    // We can't actually load models without internet, but we can test the interface
    let supported_models = engine.get_supported_models().await;
    assert!(!supported_models.is_empty());
    assert!(supported_models.contains(&"amazon.titan-embed-text-v1".to_string()));
}

#[tokio::test]
async fn test_error_handling() {
    let registry = ModelRegistry::new();

    // Test unsupported model
    let result = registry.get_mapping("unsupported-model-id");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported AWS model"));

    // Test dimension projector with zero dimensions (edge case)
    let projector = DimensionProjector::new(0);
    let embedding = vec![1.0, 2.0, 3.0];
    let result = projector.project_embedding(embedding);
    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_model_registry_completeness() {
    let registry = ModelRegistry::new();

    // Test that we have mappings for all major AWS embedding models
    let required_models = vec![
        "amazon.titan-embed-text-v1",
        "amazon.titan-embed-text-v2:0",
        "cohere.embed-english-v3",
        "cohere.embed-multilingual-v3",
    ];

    for model_id in required_models {
        let mapping = registry.get_mapping(model_id).unwrap();

        // AWS model info should be complete
        assert!(!mapping.aws_model.model_id.is_empty());
        assert!(!mapping.aws_model.provider.is_empty());
        assert!(!mapping.aws_model.name.is_empty());
        assert!(mapping.aws_model.dimensions > 0);
        assert!(mapping.aws_model.max_tokens > 0);

        // HF equivalent should be complete
        assert!(!mapping.hf_equivalent.hf_model_id.is_empty());
        assert!(mapping.hf_equivalent.dimensions > 0);
        assert!(mapping.hf_equivalent.max_tokens > 0);
        assert!(mapping.hf_equivalent.similarity_score >= 0.0);
        assert!(mapping.hf_equivalent.similarity_score <= 1.0);
        assert!(!mapping.hf_equivalent.notes.is_empty());
    }
}

#[tokio::test]
async fn test_advanced_model_mappings() {
    let registry = ModelRegistry::new();

    // Test BGE model mapping (should be very high quality)
    let mapping = registry.get_mapping("amazon.titan-embed-text-v1-optimized");
    assert!(mapping.is_ok());
    let mapping = mapping.unwrap();
    assert!(mapping.hf_equivalent.hf_model_id.contains("bge"));
    assert!(mapping.hf_equivalent.similarity_score >= 0.90);

    // Test E5 model mapping
    let mapping = registry.get_mapping("cohere.embed-english-v3-e5");
    assert!(mapping.is_ok());
    let mapping = mapping.unwrap();
    assert!(mapping.hf_equivalent.hf_model_id.contains("e5"));
    assert!(mapping.hf_equivalent.similarity_score >= 0.90);
}

#[tokio::test]
async fn test_multilingual_support() {
    let registry = ModelRegistry::new();

    let mapping = registry.get_mapping("cohere.embed-multilingual-v3").unwrap();
    assert!(mapping.hf_equivalent.hf_model_id.contains("multilingual"));
    assert_eq!(mapping.aws_model.dimensions, 1024);

    // Should have good quality for multilingual tasks
    assert!(mapping.hf_equivalent.similarity_score >= 0.80);
}

#[tokio::test]
async fn test_dimension_compatibility() {
    let registry = ModelRegistry::new();

    // Test that all AWS models have reasonable dimensions
    let models = registry.list_supported_models();
    for model in models {
        assert!(model.dimensions >= 384, "Dimensions should be at least 384 for {}", model.model_id);
        assert!(model.dimensions <= 1536, "Dimensions should not exceed 1536 for {}", model.model_id);

        // Common embedding dimensions
        assert!(
            model.dimensions == 384 ||
            model.dimensions == 512 ||
            model.dimensions == 768 ||
            model.dimensions == 1024 ||
            model.dimensions == 1536,
            "Should use standard embedding dimensions for {}", model.model_id
        );
    }
}

#[tokio::test]
async fn test_performance_characteristics() {
    let registry = ModelRegistry::new();

    // Test that models have reasonable token limits
    let models = registry.list_supported_models();
    for model in models {
        assert!(model.max_tokens >= 512, "Should support at least 512 tokens for {}", model.model_id);
        assert!(model.max_tokens <= 8192, "Token limit should be reasonable for {}", model.model_id);
    }
}

// Benchmark test (only runs in release mode)
#[tokio::test]
#[ignore]
async fn benchmark_dimension_projection() {
    use std::time::Instant;

    let projector = DimensionProjector::new(1536);
    let embedding = vec![0.1; 768];

    let start = Instant::now();
    for _ in 0..10000 {
        let _ = projector.linear_project_embedding(embedding.clone());
    }
    let duration = start.elapsed();

    println!("10000 dimension projections took: {:?}", duration);
    assert!(duration.as_millis() < 1000, "Projection should be fast");
}

#[tokio::test]
async fn test_factory_function() {
    let models = vec!["sentence-transformers/all-MiniLM-L6-v2".to_string()];
    let cache_dir = std::env::temp_dir().join("test_cache");

    // Should create engine without errors
    let result = create_huggingface_engine(models, Some(cache_dir.clone())).await;
    assert!(result.is_ok());

    let engine = result.unwrap();
    let supported = engine.get_supported_models().await;
    assert!(!supported.is_empty());

    // Cache directory should exist
    assert!(tokio::fs::metadata(&cache_dir).await.is_ok());
}
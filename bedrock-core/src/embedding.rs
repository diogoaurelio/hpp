use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Trait defining the embedding engine interface
#[async_trait::async_trait]
pub trait EmbeddingEngineTrait: Send + Sync {
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse>;
    async fn get_supported_models(&self) -> Vec<String>;
}

/// In-memory embedding engine that simulates AWS Titan embeddings
pub struct InMemoryEmbeddingEngine {
    supported_models: Vec<String>,
}

impl InMemoryEmbeddingEngine {
    pub fn new() -> Self {
        Self {
            supported_models: vec![
                "amazon.titan-embed-text-v1".to_string(),
                "amazon.titan-embed-text-v2:0".to_string(),
                "cohere.embed-english-v3".to_string(),
                "cohere.embed-multilingual-v3".to_string(),
            ],
        }
    }

    fn simulate_embedding(&self, text: &str, model_id: &str) -> Vec<f32> {
        // Simulate different embedding dimensions based on model
        let dimension = match model_id {
            "amazon.titan-embed-text-v1" => 1536,
            "amazon.titan-embed-text-v2:0" => 1024,
            "cohere.embed-english-v3" => 1024,
            "cohere.embed-multilingual-v3" => 1024,
            _ => 1536, // default
        };

        // Simple deterministic "embedding" based on text hash
        let mut embedding = Vec::with_capacity(dimension);
        let text_bytes = text.as_bytes();

        for i in 0..dimension {
            let mut hash: u32 = 2166136261; // FNV offset basis
            for &byte in text_bytes {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(16777619); // FNV prime
                hash ^= i as u32; // Add position to make each dimension different
            }

            // Normalize to [-1, 1] range
            let normalized = (hash as f32) / (u32::MAX as f32) * 2.0 - 1.0;
            embedding.push(normalized);
        }

        // L2 normalize the embedding vector
        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if magnitude > 0.0 {
            for value in &mut embedding {
                *value /= magnitude;
            }
        }

        embedding
    }

    fn count_tokens(&self, text: &str) -> u32 {
        // Simple token counting approximation (words + punctuation)
        text.split_whitespace().count() as u32 + text.chars().filter(|c| c.is_ascii_punctuation()).count() as u32
    }
}

#[async_trait::async_trait]
impl EmbeddingEngineTrait for InMemoryEmbeddingEngine {
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        if !self.supported_models.contains(&request.model_id) {
            return Err(anyhow::anyhow!("Model '{}' is not supported", request.model_id));
        }

        let embedding = self.simulate_embedding(&request.input_text, &request.model_id);
        let token_count = self.count_tokens(&request.input_text);

        Ok(EmbeddingResponse {
            embedding,
            input_token_count: token_count,
        })
    }

    async fn get_supported_models(&self) -> Vec<String> {
        self.supported_models.clone()
    }
}

/// S3-backed embedding engine that can cache embeddings
pub struct S3EmbeddingEngine {
    inner_engine: InMemoryEmbeddingEngine,
    s3_client: Box<dyn shared::S3ObjectStorageRepository>,
    bucket: String,
    cache: tokio::sync::RwLock<HashMap<String, EmbeddingResponse>>,
}

impl S3EmbeddingEngine {
    pub fn new(s3_client: Box<dyn shared::S3ObjectStorageRepository>, bucket: String) -> Self {
        Self {
            inner_engine: InMemoryEmbeddingEngine::new(),
            s3_client,
            bucket,
            cache: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    async fn load_cached_embedding(&self, cache_key: &str) -> Option<EmbeddingResponse> {
        let request = shared::GetObjectRequest {
            bucket: self.bucket.clone(),
            key: format!("embeddings/{}.json", cache_key),
        };

        match self.s3_client.get_object(request).await {
            Ok(response) => {
                let data = String::from_utf8(response.body.to_vec()).ok()?;
                serde_json::from_str(&data).ok()
            }
            Err(_) => None,
        }
    }

    async fn save_cached_embedding(&self, cache_key: &str, embedding: &EmbeddingResponse) -> Result<()> {
        let data = serde_json::to_string_pretty(embedding)?;
        let request = shared::PutObjectRequest {
            bucket: self.bucket.clone(),
            key: format!("embeddings/{}.json", cache_key),
            body: bytes::Bytes::from(data),
            content_type: Some("application/json".to_string()),
            metadata: HashMap::new(),
        };

        self.s3_client.put_object(request).await?;
        Ok(())
    }

    fn generate_cache_key(&self, request: &EmbeddingRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        request.model_id.hash(&mut hasher);
        request.input_text.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[async_trait::async_trait]
impl EmbeddingEngineTrait for S3EmbeddingEngine {
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        let cache_key = self.generate_cache_key(&request);

        // Check memory cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // Check S3 cache
        if let Some(cached) = self.load_cached_embedding(&cache_key).await {
            // Update memory cache
            {
                let mut cache = self.cache.write().await;
                cache.insert(cache_key, cached.clone());
            }
            return Ok(cached);
        }

        // Generate new embedding
        let embedding = self.inner_engine.create_embedding(request).await?;

        // Cache the result
        let _ = self.save_cached_embedding(&cache_key, &embedding).await;
        {
            let mut cache = self.cache.write().await;
            cache.insert(cache_key, embedding.clone());
        }

        Ok(embedding)
    }

    async fn get_supported_models(&self) -> Vec<String> {
        self.inner_engine.get_supported_models().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use shared::MockS3ObjectStorageRepository;

    #[tokio::test]
    async fn test_in_memory_embedding_engine_create_embedding() {
        let engine = InMemoryEmbeddingEngine::new();
        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Hello, world!".to_string(),
        };

        let result = engine.create_embedding(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.embedding.len(), 1536); // Titan v1 dimension
        assert!(response.input_token_count > 0);

        // Verify embedding is normalized
        let magnitude: f32 = response.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((magnitude - 1.0).abs() < 0.001); // Should be unit vector
    }

    #[tokio::test]
    async fn test_in_memory_embedding_engine_unsupported_model() {
        let engine = InMemoryEmbeddingEngine::new();
        let request = EmbeddingRequest {
            model_id: "unsupported-model".to_string(),
            input_text: "Hello, world!".to_string(),
        };

        let result = engine.create_embedding(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn test_embedding_deterministic() {
        let engine = InMemoryEmbeddingEngine::new();
        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "test text".to_string(),
        };

        let result1 = engine.create_embedding(request.clone()).await.unwrap();
        let result2 = engine.create_embedding(request).await.unwrap();

        assert_eq!(result1.embedding, result2.embedding);
        assert_eq!(result1.input_token_count, result2.input_token_count);
    }

    #[tokio::test]
    async fn test_different_models_different_dimensions() {
        let engine = InMemoryEmbeddingEngine::new();

        let request_v1 = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "test".to_string(),
        };

        let request_v2 = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v2:0".to_string(),
            input_text: "test".to_string(),
        };

        let result_v1 = engine.create_embedding(request_v1).await.unwrap();
        let result_v2 = engine.create_embedding(request_v2).await.unwrap();

        assert_eq!(result_v1.embedding.len(), 1536);
        assert_eq!(result_v2.embedding.len(), 1024);
    }

    #[tokio::test]
    async fn test_get_supported_models() {
        let engine = InMemoryEmbeddingEngine::new();
        let models = engine.get_supported_models().await;

        assert!(models.contains(&"amazon.titan-embed-text-v1".to_string()));
        assert!(models.contains(&"amazon.titan-embed-text-v2:0".to_string()));
        assert!(models.contains(&"cohere.embed-english-v3".to_string()));
        assert!(models.contains(&"cohere.embed-multilingual-v3".to_string()));
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_s3_embedding_engine_cache_miss() {
        let mut mock_s3 = MockS3ObjectStorageRepository::new();

        // Mock get_object to return not found (cache miss)
        mock_s3
            .expect_get_object()
            .returning(|_| Box::pin(async { Err(anyhow::anyhow!("Not found")) }));

        // Mock put_object for caching
        mock_s3
            .expect_put_object()
            .returning(|_| Box::pin(async { Ok("etag".to_string()) }));

        let engine = S3EmbeddingEngine::new(Box::new(mock_s3), "test-bucket".to_string());
        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Hello, world!".to_string(),
        };

        let result = engine.create_embedding(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.embedding.len(), 1536);
        assert!(response.input_token_count > 0);
    }

    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_s3_embedding_engine_cache_hit() {
        let mut mock_s3 = MockS3ObjectStorageRepository::new();

        let cached_response = EmbeddingResponse {
            embedding: vec![0.1, 0.2, 0.3],
            input_token_count: 5,
        };
        let cached_json = serde_json::to_string(&cached_response).unwrap();

        // Mock get_object to return cached embedding
        mock_s3
            .expect_get_object()
            .returning(move |_| {
                let cached_json = cached_json.clone();
                Box::pin(async move {
                    Ok(shared::GetObjectResponse {
                        body: bytes::Bytes::from(cached_json),
                        content_type: Some("application/json".to_string()),
                        content_length: 0,
                        etag: "etag".to_string(),
                        last_modified: chrono::Utc::now(),
                        metadata: HashMap::new(),
                    })
                })
            });

        let engine = S3EmbeddingEngine::new(Box::new(mock_s3), "test-bucket".to_string());
        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Hello, world!".to_string(),
        };

        let result = engine.create_embedding(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.embedding, vec![0.1, 0.2, 0.3]);
        assert_eq!(response.input_token_count, 5);
    }
}
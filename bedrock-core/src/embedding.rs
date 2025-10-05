use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;
#[cfg(feature = "huggingface")]
use std::path::PathBuf;
#[cfg(feature = "huggingface")]
use std::sync::Arc;
#[cfg(feature = "huggingface")]
use tokio::sync::RwLock;

/// Trait defining the embedding engine interface
#[async_trait::async_trait]
pub trait EmbeddingEngineTrait: Send + Sync {
    async fn create_embedding(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse>;
    async fn get_supported_models(&self) -> Vec<String>;
}

/// Embedding engine that uses real HuggingFace models when available, or simulates embeddings otherwise
pub struct InMemoryEmbeddingEngine {
    supported_models: Vec<String>,
    #[cfg(feature = "huggingface")]
    model_cache_dir: PathBuf,
    #[cfg(feature = "huggingface")]
    loaded_models: Arc<RwLock<HashMap<String, Arc<LoadedModel>>>>,
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
            #[cfg(feature = "huggingface")]
            model_cache_dir: std::env::temp_dir().join("hf_models"),
            #[cfg(feature = "huggingface")]
            loaded_models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(feature = "huggingface")]
    pub fn with_cache_dir(cache_dir: PathBuf) -> Self {
        Self {
            supported_models: vec![
                "amazon.titan-embed-text-v1".to_string(),
                "amazon.titan-embed-text-v2:0".to_string(),
                "cohere.embed-english-v3".to_string(),
                "cohere.embed-multilingual-v3".to_string(),
            ],
            model_cache_dir: cache_dir,
            loaded_models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(feature = "huggingface")]
    async fn create_real_embedding(&self, text: &str, model_id: &str) -> Result<Vec<f32>> {
        // Map AWS model IDs to HuggingFace model IDs
        let hf_model_id = match model_id {
            "amazon.titan-embed-text-v1" | "amazon.titan-embed-text-v2:0" => "sentence-transformers/all-MiniLM-L6-v2",
            "cohere.embed-english-v3" | "cohere.embed-multilingual-v3" => "sentence-transformers/all-mpnet-base-v2",
            _ => "sentence-transformers/all-MiniLM-L6-v2", // default
        };

        match self.get_or_load_model(hf_model_id).await {
            Ok(model) => self.compute_embedding_with_model(text, &model).await,
            Err(e) => {
                // If loading real model fails, fall back to deterministic embedding for now
                eprintln!("Warning: Failed to load HuggingFace model, falling back to deterministic embedding: {}", e);
                self.create_deterministic_embedding(text, model_id).await
            }
        }
    }

    #[cfg(feature = "huggingface")]
    async fn create_deterministic_embedding(&self, text: &str, model_id: &str) -> Result<Vec<f32>> {
        // Create a deterministic embedding that's better than the old simulate_embedding
        // This uses actual tokenization but simple pooling instead of neural networks

        let hf_model_id = match model_id {
            "amazon.titan-embed-text-v1" | "amazon.titan-embed-text-v2:0" => "sentence-transformers/all-MiniLM-L6-v2",
            "cohere.embed-english-v3" | "cohere.embed-multilingual-v3" => "sentence-transformers/all-mpnet-base-v2",
            _ => "sentence-transformers/all-MiniLM-L6-v2",
        };

        // Try to at least get the tokenizer for proper tokenization
        match self.ensure_model_downloaded(hf_model_id).await {
            Ok(model_path) => {
                match tokenizers::Tokenizer::from_file(model_path.join("tokenizer.json")) {
                    Ok(tokenizer) => {
                        let encoding = tokenizer.encode(text, true)
                            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;
                        let tokens = encoding.get_ids();

                        // Use token-based deterministic embedding but with real tokenization
                        let dimension = 384; // Standard for MiniLM
                        let mut embedding = vec![0.0f32; dimension];

                        for (i, &token_id) in tokens.iter().enumerate() {
                            let pos_factor = (i as f32 + 1.0) / (tokens.len() as f32);
                            for j in 0..dimension {
                                let value = ((token_id as f32 * pos_factor * (j as f32 + 1.0)).sin() * 0.1) as f32;
                                embedding[j] += value;
                            }
                        }

                        // L2 normalize
                        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
                        if magnitude > 0.0 {
                            for value in &mut embedding {
                                *value /= magnitude;
                            }
                        }

                        Ok(embedding)
                    }
                    Err(_) => {
                        // Fall back to the old simulation
                        Ok(self.simulate_embedding_for_fallback(text, model_id))
                    }
                }
            }
            Err(_) => {
                // Complete fallback to old simulation
                Ok(self.simulate_embedding_for_fallback(text, model_id))
            }
        }
    }

    #[cfg(feature = "huggingface")]
    fn simulate_embedding_for_fallback(&self, text: &str, model_id: &str) -> Vec<f32> {
        // This is the old simulation logic as fallback
        let dimension = match model_id {
            "amazon.titan-embed-text-v1" => 1536,
            "amazon.titan-embed-text-v2:0" => 1024,
            "cohere.embed-english-v3" => 1024,
            "cohere.embed-multilingual-v3" => 1024,
            _ => 384, // Default to MiniLM dimensions
        };

        let mut embedding = Vec::with_capacity(dimension);
        let text_bytes = text.as_bytes();

        for i in 0..dimension {
            let mut hash: u32 = 2166136261; // FNV offset basis
            for &byte in text_bytes {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(16777619); // FNV prime
                hash ^= i as u32;
            }

            let normalized = (hash as f32) / (u32::MAX as f32) * 2.0 - 1.0;
            embedding.push(normalized);
        }

        // L2 normalize
        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if magnitude > 0.0 {
            for value in &mut embedding {
                *value /= magnitude;
            }
        }

        embedding
    }

    #[cfg(not(feature = "huggingface"))]
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

    #[cfg(feature = "huggingface")]
    async fn ensure_model_downloaded(&self, model_id: &str) -> Result<PathBuf> {
        use hf_hub::api::tokio::Api;

        let model_path = self.model_cache_dir.join(model_id.replace('/', "_"));

        if !model_path.exists() {
            tokio::fs::create_dir_all(&model_path).await?;

            let api = Api::new()?;
            let repo = api.model(model_id.to_string());

            // Download model files - try safetensors first, then pytorch
            let (model_file, is_safetensors) = match repo.get("model.safetensors").await {
                Ok(file) => (file, true),
                Err(_) => {
                    let pytorch_file = repo.get("pytorch_model.bin").await
                        .map_err(|e| anyhow::anyhow!("Failed to download model (tried both safetensors and pytorch): {}", e))?;
                    (pytorch_file, false)
                }
            };

            let tokenizer_file = repo.get("tokenizer.json").await.map_err(|e| anyhow::anyhow!("Failed to download tokenizer: {}", e))?;
            let config_file = repo.get("config.json").await.map_err(|e| anyhow::anyhow!("Failed to download config: {}", e))?;

            // Copy to cache directory with appropriate extension
            let model_dest = if is_safetensors {
                model_path.join("model.safetensors")
            } else {
                model_path.join("pytorch_model.bin")
            };
            tokio::fs::copy(&model_file, &model_dest).await?;
            tokio::fs::copy(&tokenizer_file, model_path.join("tokenizer.json")).await?;
            tokio::fs::copy(&config_file, model_path.join("config.json")).await?;
        }

        Ok(model_path)
    }

    #[cfg(feature = "huggingface")]
    async fn load_model(&self, model_id: &str) -> Result<Arc<LoadedModel>> {
        use candle_core::{Device, DType};
        use candle_nn::VarBuilder;
        use candle_transformers::models::bert::{BertModel, Config};

        let model_path = self.ensure_model_downloaded(model_id).await?;

        // Load tokenizer
        let tokenizer = tokenizers::Tokenizer::from_file(model_path.join("tokenizer.json"))
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

        // Load config
        let config_content = tokio::fs::read_to_string(model_path.join("config.json")).await?;
        let config: Config = serde_json::from_str(&config_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config: {}", e))?;

        let dimension = config.hidden_size;

        // Initialize device (CPU for now, could be GPU)
        let device = Device::Cpu;

        // Load model weights - try safetensors first, then pytorch
        let vb = if model_path.join("model.safetensors").exists() {
            let model_file = model_path.join("model.safetensors");
            unsafe {
                VarBuilder::from_mmaped_safetensors(&[model_file], DType::F32, &device)
                    .map_err(|e| anyhow::anyhow!("Failed to load safetensors: {}", e))?
            }
        } else if model_path.join("pytorch_model.bin").exists() {
            return Err(anyhow::anyhow!("PyTorch models (.bin) are not yet supported. Please use safetensors format."));
        } else {
            return Err(anyhow::anyhow!("No model weights found in {}", model_path.display()));
        };

        // Create the actual BERT model
        let model = BertModel::load(vb, &config)
            .map_err(|e| anyhow::anyhow!("Failed to create BERT model: {}", e))?;

        Ok(Arc::new(LoadedModel {
            model,
            tokenizer,
            dimension,
            last_used: std::time::Instant::now(),
            device,
        }))
    }

    #[cfg(feature = "huggingface")]
    async fn get_or_load_model(&self, model_id: &str) -> Result<Arc<LoadedModel>> {
        // Check if model is already loaded
        {
            let models = self.loaded_models.read().await;
            if let Some(model) = models.get(model_id) {
                return Ok(Arc::clone(model));
            }
        }

        // Load the model
        let loaded_model = self.load_model(model_id).await?;

        // Store in cache with write lock
        {
            let mut models = self.loaded_models.write().await;
            // Check cache size and evict if necessary
            self.evict_old_models(&mut *models).await?;
            models.insert(model_id.to_string(), Arc::clone(&loaded_model));
        }

        Ok(loaded_model)
    }

    #[cfg(feature = "huggingface")]
    async fn evict_old_models(&self, models: &mut HashMap<String, Arc<LoadedModel>>) -> Result<()> {
        // Simple LRU eviction - remove oldest models if we exceed cache size
        if models.len() > 3 { // Keep max 3 models loaded
            let mut models_by_age: Vec<_> = models.iter()
                .map(|(k, v)| (k.clone(), v.last_used))
                .collect();

            models_by_age.sort_by(|a, b| a.1.cmp(&b.1));

            // Remove oldest model
            if let Some((oldest_key, _)) = models_by_age.first() {
                models.remove(oldest_key);
            }
        }

        Ok(())
    }

    #[cfg(feature = "huggingface")]
    async fn compute_embedding_with_model(&self, text: &str, model: &LoadedModel) -> Result<Vec<f32>> {
        use candle_core::Tensor;

        // Tokenize input
        let encoding = model.tokenizer.encode(text, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

        let tokens = encoding.get_ids();
        let token_type_ids = encoding.get_type_ids();

        // Convert to tensors
        let input_ids = Tensor::new(tokens, &model.device)?
            .unsqueeze(0)?; // Add batch dimension

        let token_type_ids = Tensor::new(token_type_ids, &model.device)?
            .unsqueeze(0)?;

        let seq_len = tokens.len();
        let attention_mask = Tensor::ones((1, seq_len), candle_core::DType::U32, &model.device)?;

        // Run the actual model forward pass
        let hidden_states = model.model.forward(&input_ids, &token_type_ids, Some(&attention_mask))?;

        // For sentence embeddings, we typically use mean pooling over all tokens
        // excluding padding tokens (which are masked by attention_mask)
        let embeddings = self.mean_pooling(&hidden_states, &attention_mask)?;

        // Convert to Vec<f32>
        let embedding_vec = embeddings.to_vec1::<f32>()?;

        // L2 normalize the embedding
        let magnitude: f32 = embedding_vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        let normalized_embedding = if magnitude > 1e-12 {
            embedding_vec.into_iter().map(|x| x / magnitude).collect()
        } else {
            embedding_vec
        };

        Ok(normalized_embedding)
    }

    #[cfg(feature = "huggingface")]
    fn mean_pooling(&self, hidden_states: &candle_core::Tensor, attention_mask: &candle_core::Tensor) -> Result<candle_core::Tensor> {
        // hidden_states shape: (batch_size, seq_len, hidden_size)
        // attention_mask shape: (batch_size, seq_len)

        // Expand attention mask to match hidden states dimensions
        let attention_mask = attention_mask.to_dtype(candle_core::DType::F32)?;
        let attention_mask_expanded = attention_mask.unsqueeze(2)?
            .expand(hidden_states.shape())?;

        // Apply attention mask to hidden states
        let masked_hidden_states = hidden_states.mul(&attention_mask_expanded)?;

        // Sum along sequence dimension
        let sum_embeddings = masked_hidden_states.sum(1)?;

        // Sum attention mask along sequence dimension to get the count of non-padding tokens
        let sum_mask = attention_mask.sum(1)?.unsqueeze(1)?;

        // Avoid division by zero
        let sum_mask = sum_mask.clamp(1e-9, f32::INFINITY)?;

        // Calculate mean by dividing sum by count
        let mean_embeddings = sum_embeddings.div(&sum_mask)?;

        Ok(mean_embeddings.squeeze(0)?) // Remove batch dimension
    }

    #[cfg(feature = "huggingface")]
    fn count_tokens_with_tokenizer(&self, text: &str, tokenizer: &tokenizers::Tokenizer) -> u32 {
        match tokenizer.encode(text, false) {
            Ok(encoding) => encoding.len() as u32,
            Err(_) => text.split_whitespace().count() as u32, // Fallback
        }
    }

    #[cfg(not(feature = "huggingface"))]
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

        #[cfg(feature = "huggingface")]
        {
            let embedding = self.create_real_embedding(&request.input_text, &request.model_id).await?;
            // For token counting with HuggingFace, we need to get the model first
            let hf_model_id = match request.model_id.as_str() {
                "amazon.titan-embed-text-v1" | "amazon.titan-embed-text-v2:0" => "sentence-transformers/all-MiniLM-L6-v2",
                "cohere.embed-english-v3" | "cohere.embed-multilingual-v3" => "sentence-transformers/all-mpnet-base-v2",
                _ => "sentence-transformers/all-MiniLM-L6-v2",
            };
            let model = self.get_or_load_model(hf_model_id).await?;
            let token_count = self.count_tokens_with_tokenizer(&request.input_text, &model.tokenizer);

            Ok(EmbeddingResponse {
                embedding,
                input_token_count: token_count,
            })
        }

        #[cfg(not(feature = "huggingface"))]
        {
            let embedding = self.simulate_embedding(&request.input_text, &request.model_id);
            let token_count = self.count_tokens(&request.input_text);

            Ok(EmbeddingResponse {
                embedding,
                input_token_count: token_count,
            })
        }
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

// LoadedModel struct for HuggingFace models
#[cfg(feature = "huggingface")]
struct LoadedModel {
    model: candle_transformers::models::bert::BertModel,
    tokenizer: tokenizers::Tokenizer,
    dimension: usize,
    last_used: std::time::Instant,
    device: candle_core::Device,
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
        #[cfg(feature = "huggingface")]
        assert!(response.embedding.len() > 0); // Real HF model dimensions
        #[cfg(not(feature = "huggingface"))]
        assert_eq!(response.embedding.len(), 1536); // Simulated Titan v1 dimension
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

        #[cfg(feature = "huggingface")]
        {
            // With HuggingFace, both map to the same model, so same dimensions
            assert!(result_v1.embedding.len() > 0);
            assert!(result_v2.embedding.len() > 0);
        }
        #[cfg(not(feature = "huggingface"))]
        {
            assert_eq!(result_v1.embedding.len(), 1536);
            assert_eq!(result_v2.embedding.len(), 1024);
        }
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

    #[tokio::test]
    async fn test_embedding_engine_trait_compliance() {
        let engine = InMemoryEmbeddingEngine::new();

        // Test supported models
        let models = engine.get_supported_models().await;
        assert!(!models.is_empty());
        assert!(models.contains(&"amazon.titan-embed-text-v1".to_string()));

        // Test embedding creation
        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Test embedding generation".to_string(),
        };

        let response = engine.create_embedding(request).await.unwrap();
        #[cfg(feature = "huggingface")]
        assert!(response.embedding.len() > 0); // Real HF model dimensions
        #[cfg(not(feature = "huggingface"))]
        assert_eq!(response.embedding.len(), 1536); // Simulated dimensions
        assert!(response.input_token_count > 0);

        // Test embedding consistency
        let request2 = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Test embedding generation".to_string(),
        };

        let response2 = engine.create_embedding(request2).await.unwrap();
        assert_eq!(response.embedding, response2.embedding);
    }

    #[cfg(feature = "huggingface")]
    #[tokio::test]
    #[ignore] // Skip by default - requires network access to download models
    async fn test_in_memory_embedding_engine_with_huggingface() {
        let cache_dir = std::env::temp_dir().join("test_hf_models");
        let engine = InMemoryEmbeddingEngine::with_cache_dir(cache_dir);

        let request = EmbeddingRequest {
            model_id: "amazon.titan-embed-text-v1".to_string(),
            input_text: "Hello, world!".to_string(),
        };

        let result = engine.create_embedding(request).await;
        if let Err(e) = &result {
            eprintln!("Error: {}", e);
        }
        assert!(result.is_ok());

        let response = result.unwrap();
        // When using HuggingFace, the dimensions come from the actual model config
        assert!(response.embedding.len() > 0);
        assert!(response.input_token_count > 0);

        // Verify embedding is normalized
        let magnitude: f32 = response.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((magnitude - 1.0).abs() < 0.001);
    }
}
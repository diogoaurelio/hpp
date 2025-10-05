use anyhow::Result;
#[cfg(feature = "huggingface")]
use std::collections::HashMap;
#[cfg(feature = "huggingface")]
use std::path::PathBuf;
#[cfg(feature = "huggingface")]
use std::sync::Arc;
#[cfg(feature = "huggingface")]
use tokio::sync::RwLock;

/// Trait defining the text generation engine interface
#[async_trait::async_trait]
pub trait TextGenerationEngineTrait: Send + Sync {
    async fn generate_text(&self, request: TextGenerationRequest) -> Result<TextGenerationResponse>;
    async fn get_supported_models(&self) -> Vec<String>;
}

/// Text generation request for internal use
#[derive(Debug, Clone)]
pub struct TextGenerationRequest {
    pub model_id: String,
    pub prompt: String,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub stop_sequences: Option<Vec<String>>,
}

/// Text generation response for internal use
#[derive(Debug, Clone)]
pub struct TextGenerationResponse {
    pub completion: String,
    pub stop_reason: String,
    pub input_token_count: u32,
    pub output_token_count: u32,
}

/// Text generation engine that uses real HuggingFace models when available, or simulates text generation otherwise
pub struct InMemoryTextGenerationEngine {
    supported_models: Vec<String>,
    #[cfg(feature = "huggingface")]
    model_cache_dir: PathBuf,
    #[cfg(feature = "huggingface")]
    loaded_models: Arc<RwLock<HashMap<String, Arc<LoadedTextModel>>>>,
}

impl InMemoryTextGenerationEngine {
    pub fn new() -> Self {
        Self {
            supported_models: vec![
                "anthropic.claude-v2".to_string(),
                "anthropic.claude-v2:1".to_string(),
                "anthropic.claude-instant-v1".to_string(),
                "amazon.titan-text-lite-v1".to_string(),
                "amazon.titan-text-express-v1".to_string(),
                "ai21.j2-mid-v1".to_string(),
                "ai21.j2-ultra-v1".to_string(),
                "meta.llama2-13b-chat-v1".to_string(),
                "meta.llama2-70b-chat-v1".to_string(),
            ],
            #[cfg(feature = "huggingface")]
            model_cache_dir: std::env::temp_dir().join("hf_text_models"),
            #[cfg(feature = "huggingface")]
            loaded_models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(feature = "huggingface")]
    pub fn with_cache_dir(cache_dir: PathBuf) -> Self {
        Self {
            supported_models: vec![
                "anthropic.claude-v2".to_string(),
                "anthropic.claude-v2:1".to_string(),
                "anthropic.claude-instant-v1".to_string(),
                "amazon.titan-text-lite-v1".to_string(),
                "amazon.titan-text-express-v1".to_string(),
                "ai21.j2-mid-v1".to_string(),
                "ai21.j2-ultra-v1".to_string(),
                "meta.llama2-13b-chat-v1".to_string(),
                "meta.llama2-70b-chat-v1".to_string(),
            ],
            model_cache_dir: cache_dir,
            loaded_models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(feature = "huggingface")]
    async fn generate_real_text(&self, request: &TextGenerationRequest) -> Result<TextGenerationResponse> {
        // Map AWS model IDs to HuggingFace model IDs
        let hf_model_id = match request.model_id.as_str() {
            "anthropic.claude-v2" | "anthropic.claude-v2:1" | "anthropic.claude-instant-v1" => "microsoft/DialoGPT-medium",
            "amazon.titan-text-lite-v1" | "amazon.titan-text-express-v1" => "gpt2",
            "ai21.j2-mid-v1" | "ai21.j2-ultra-v1" => "gpt2", // Use GPT-2 as fallback since J2 requires auth
            "meta.llama2-13b-chat-v1" | "meta.llama2-70b-chat-v1" => "gpt2", // Use GPT-2 as fallback since Llama2 requires auth
            _ => "gpt2", // default
        };

        match self.get_or_load_text_model(hf_model_id).await {
            Ok(_model) => {
                // For now, since we don't have the actual generation method, fall back to deterministic
                eprintln!("Warning: HuggingFace text generation models not yet fully implemented, falling back to deterministic generation");
                self.generate_deterministic_text(request).await
            },
            Err(e) => {
                // If loading real model fails, fall back to deterministic generation
                eprintln!("Warning: Failed to load HuggingFace text generation model, falling back to deterministic generation: {}", e);
                self.generate_deterministic_text(request).await
            }
        }
    }

    #[cfg(feature = "huggingface")]
    async fn generate_deterministic_text(&self, request: &TextGenerationRequest) -> Result<TextGenerationResponse> {
        // Generate a deterministic but more realistic response
        let base_responses = match request.model_id.as_str() {
            "anthropic.claude-v2" | "anthropic.claude-v2:1" => vec![
                "I understand your question. Based on the context, I would suggest that",
                "Thank you for asking. In my analysis, the key point is that",
                "This is an interesting question. From my perspective,",
            ],
            "amazon.titan-text-lite-v1" | "amazon.titan-text-express-v1" => vec![
                "Based on the information provided, it appears that",
                "The answer to your question involves several factors:",
                "To address your inquiry, let me explain that",
            ],
            "ai21.j2-mid-v1" | "ai21.j2-ultra-v1" => vec![
                "Considering the prompt, I would respond by saying that",
                "The context suggests that the appropriate response is:",
                "Given the information, my analysis indicates that",
            ],
            _ => vec![
                "This is a response to your prompt. The key points are:",
                "Based on your input, I can provide the following information:",
                "To answer your question, I would like to explain that",
            ],
        };

        // Use prompt hash to select response deterministically
        let prompt_hash = self.hash_string(&request.prompt);
        let base_response = &base_responses[prompt_hash % base_responses.len()];

        // Generate continuation based on prompt content
        let completion = format!("{} {}", base_response, self.generate_continuation(&request.prompt));

        // Apply max_tokens if specified
        let final_completion = if let Some(max_tokens) = request.max_tokens {
            let words: Vec<&str> = completion.split_whitespace().collect();
            let token_limit = (max_tokens as usize).min(words.len());
            words[..token_limit].join(" ")
        } else {
            completion
        };

        let input_tokens = self.count_tokens(&request.prompt);
        let output_tokens = self.count_tokens(&final_completion);

        Ok(TextGenerationResponse {
            completion: final_completion,
            stop_reason: if request.max_tokens.is_some() { "length" } else { "end_turn" }.to_string(),
            input_token_count: input_tokens,
            output_token_count: output_tokens,
        })
    }

    #[cfg(feature = "huggingface")]
    fn hash_string(&self, s: &str) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish() as usize
    }

    #[cfg(feature = "huggingface")]
    fn generate_continuation(&self, prompt: &str) -> String {
        // Simple continuation generation based on prompt keywords
        let prompt_lower = prompt.to_lowercase();

        if prompt_lower.contains("what") || prompt_lower.contains("how") || prompt_lower.contains("why") {
            "the answer involves understanding the underlying principles and applying them appropriately in this context."
        } else if prompt_lower.contains("explain") || prompt_lower.contains("describe") {
            "there are several important aspects to consider, including the technical implementation and practical implications."
        } else if prompt_lower.contains("code") || prompt_lower.contains("program") || prompt_lower.contains("implement") {
            "the solution requires careful consideration of the requirements and proper implementation of the necessary functionality."
        } else {
            "this topic has multiple dimensions that need to be addressed systematically for a comprehensive understanding."
        }.to_string()
    }

    #[cfg(not(feature = "huggingface"))]
    fn simulate_text_generation(&self, request: &TextGenerationRequest) -> TextGenerationResponse {
        // Simple deterministic text generation for testing
        let completion = match request.model_id.as_str() {
            "anthropic.claude-v2" | "anthropic.claude-v2:1" => {
                format!("I understand your request: '{}'. Based on my analysis, I would suggest considering the key factors involved.", request.prompt)
            }
            "amazon.titan-text-lite-v1" | "amazon.titan-text-express-v1" => {
                format!("In response to '{}', I can provide relevant information that addresses your specific needs.", request.prompt)
            }
            "ai21.j2-mid-v1" | "ai21.j2-ultra-v1" => {
                format!("Regarding your prompt '{}', the appropriate response involves several considerations.", request.prompt)
            }
            _ => {
                format!("This is a response to your input: '{}'. The generated text provides relevant information.", request.prompt)
            }
        };

        // Apply max_tokens if specified
        let final_completion = if let Some(max_tokens) = request.max_tokens {
            let words: Vec<&str> = completion.split_whitespace().collect();
            let token_limit = (max_tokens as usize).min(words.len());
            words[..token_limit].join(" ")
        } else {
            completion
        };

        let input_tokens = self.count_tokens(&request.prompt);
        let output_tokens = self.count_tokens(&final_completion);

        TextGenerationResponse {
            completion: final_completion,
            stop_reason: if request.max_tokens.is_some() { "length" } else { "end_turn" }.to_string(),
            input_token_count: input_tokens,
            output_token_count: output_tokens,
        }
    }

    #[cfg(feature = "huggingface")]
    async fn ensure_text_model_downloaded(&self, model_id: &str) -> Result<PathBuf> {
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
                        .map_err(|e| anyhow::anyhow!("Failed to download text model (tried both safetensors and pytorch): {}", e))?;
                    (pytorch_file, false)
                }
            };

            let tokenizer_file = repo.get("tokenizer.json").await
                .map_err(|e| anyhow::anyhow!("Failed to download tokenizer: {}", e))?;
            let config_file = repo.get("config.json").await
                .map_err(|e| anyhow::anyhow!("Failed to download config: {}", e))?;

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
    async fn load_text_model(&self, _model_id: &str) -> Result<Arc<LoadedTextModel>> {
        // For now, just return an error since we don't have proper GPT models in candle-transformers
        // This will fall back to the deterministic text generation
        Err(anyhow::anyhow!("Text generation models not yet implemented with HuggingFace. Using deterministic fallback."))
    }

    #[cfg(feature = "huggingface")]
    async fn get_or_load_text_model(&self, model_id: &str) -> Result<Arc<LoadedTextModel>> {
        // Since we're not implementing actual models yet, just return an error
        // This will cause the system to fall back to deterministic generation
        self.load_text_model(model_id).await
    }

    fn count_tokens(&self, text: &str) -> u32 {
        // Simple token counting approximation (words + punctuation)
        text.split_whitespace().count() as u32 + text.chars().filter(|c| c.is_ascii_punctuation()).count() as u32
    }
}

#[async_trait::async_trait]
impl TextGenerationEngineTrait for InMemoryTextGenerationEngine {
    async fn generate_text(&self, request: TextGenerationRequest) -> Result<TextGenerationResponse> {
        if !self.supported_models.contains(&request.model_id) {
            return Err(anyhow::anyhow!("Model '{}' is not supported", request.model_id));
        }

        #[cfg(feature = "huggingface")]
        {
            self.generate_real_text(&request).await
        }

        #[cfg(not(feature = "huggingface"))]
        {
            Ok(self.simulate_text_generation(&request))
        }
    }

    async fn get_supported_models(&self) -> Vec<String> {
        self.supported_models.clone()
    }
}

// LoadedTextModel struct for HuggingFace models (placeholder for future implementation)
#[cfg(feature = "huggingface")]
struct LoadedTextModel {
    // Placeholder - actual implementation would contain the model, tokenizer, config, etc.
    last_used: std::time::Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_text_generation_engine_create_text() {
        let engine = InMemoryTextGenerationEngine::new();
        let request = TextGenerationRequest {
            model_id: "anthropic.claude-v2".to_string(),
            prompt: "What is machine learning?".to_string(),
            max_tokens: Some(50),
            temperature: Some(0.7),
            top_p: None,
            stop_sequences: None,
        };

        let result = engine.generate_text(request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.completion.is_empty());
        assert!(response.input_token_count > 0);
        assert!(response.output_token_count > 0);
        assert!(response.stop_reason == "length" || response.stop_reason == "end_turn");
    }

    #[tokio::test]
    async fn test_in_memory_text_generation_engine_unsupported_model() {
        let engine = InMemoryTextGenerationEngine::new();
        let request = TextGenerationRequest {
            model_id: "unsupported-model".to_string(),
            prompt: "Test prompt".to_string(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop_sequences: None,
        };

        let result = engine.generate_text(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn test_text_generation_deterministic() {
        let engine = InMemoryTextGenerationEngine::new();
        let request = TextGenerationRequest {
            model_id: "anthropic.claude-v2".to_string(),
            prompt: "test prompt".to_string(),
            max_tokens: Some(20),
            temperature: Some(0.0), // Should be deterministic
            top_p: None,
            stop_sequences: None,
        };

        let result1 = engine.generate_text(request.clone()).await.unwrap();
        let result2 = engine.generate_text(request).await.unwrap();

        #[cfg(not(feature = "huggingface"))]
        {
            // Without HuggingFace, should be exactly the same
            assert_eq!(result1.completion, result2.completion);
        }

        // Both should have reasonable output
        assert!(!result1.completion.is_empty());
        assert!(!result2.completion.is_empty());
        assert!(result1.input_token_count > 0);
        assert!(result2.input_token_count > 0);
    }

    #[tokio::test]
    async fn test_get_supported_models() {
        let engine = InMemoryTextGenerationEngine::new();
        let models = engine.get_supported_models().await;

        assert!(models.contains(&"anthropic.claude-v2".to_string()));
        assert!(models.contains(&"amazon.titan-text-lite-v1".to_string()));
        assert!(models.contains(&"meta.llama2-13b-chat-v1".to_string()));
    }

    #[tokio::test]
    async fn test_text_generation_different_models() {
        let engine = InMemoryTextGenerationEngine::new();

        let claude_request = TextGenerationRequest {
            model_id: "anthropic.claude-v2".to_string(),
            prompt: "Explain AI".to_string(),
            max_tokens: Some(30),
            temperature: None,
            top_p: None,
            stop_sequences: None,
        };

        let titan_request = TextGenerationRequest {
            model_id: "amazon.titan-text-lite-v1".to_string(),
            prompt: "Explain AI".to_string(),
            max_tokens: Some(30),
            temperature: None,
            top_p: None,
            stop_sequences: None,
        };

        let claude_result = engine.generate_text(claude_request).await.unwrap();
        let titan_result = engine.generate_text(titan_request).await.unwrap();

        // Both should generate text but potentially different
        assert!(!claude_result.completion.is_empty());
        assert!(!titan_result.completion.is_empty());
        assert!(claude_result.input_token_count > 0);
        assert!(titan_result.input_token_count > 0);
    }

    #[tokio::test]
    async fn test_max_tokens_limit() {
        let engine = InMemoryTextGenerationEngine::new();
        let request = TextGenerationRequest {
            model_id: "anthropic.claude-v2".to_string(),
            prompt: "Write a long explanation about artificial intelligence and machine learning".to_string(),
            max_tokens: Some(10), // Very short limit
            temperature: None,
            top_p: None,
            stop_sequences: None,
        };

        let result = engine.generate_text(request).await.unwrap();

        // Should respect max_tokens
        let word_count = result.completion.split_whitespace().count();
        assert!(word_count <= 10);
        assert_eq!(result.stop_reason, "length");
    }
}
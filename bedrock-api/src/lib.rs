pub mod handlers;

use bedrock_core::BedrockServiceTrait;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub bedrock_service: Arc<dyn BedrockServiceTrait + Send + Sync>,
}
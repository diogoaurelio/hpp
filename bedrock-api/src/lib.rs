pub mod handlers;
#[cfg(test)]
pub mod integration_tests;

use bedrock_core::BedrockServiceTrait;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub bedrock_service: Arc<Mutex<dyn BedrockServiceTrait + Send>>,
}
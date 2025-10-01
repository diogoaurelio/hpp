pub mod handlers;
pub mod middleware;

use iam_core::IamServiceTrait;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub iam_service: Arc<Mutex<dyn IamServiceTrait + Send>>,
}

pub use handlers::*;
pub mod models;
pub mod services;
pub mod vector_store;
pub mod vector_types;

// Re-export from shared for backward compatibility
pub use shared::{S3ObjectStorageRepository, AwsS3Repository as HetznerStorageClient};
pub use shared::*;
pub use models::service_models::*;
pub use services::s3_service::{S3Service, ProxyS3Service};
pub use services::iam_service::{IamService, HttpIamService};

// S3 Vectors functionality
pub use vector_types::*;
pub use vector_store::{VectorStoreTrait, InMemoryVectorStore, S3VectorStore};

#[cfg(any(test, feature = "testing"))]
pub use services::s3_service::MockS3Service;
#[cfg(any(test, feature = "testing"))]
pub use services::iam_service::MockIamService;
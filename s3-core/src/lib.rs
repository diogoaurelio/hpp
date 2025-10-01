pub mod models;
pub mod services;

// Re-export from shared for backward compatibility
pub use shared::{S3ObjectStorageRepository, AwsS3Repository as HetznerStorageClient};
pub use shared::*;
pub use models::service_models::*;
pub use services::s3_service::{S3Service, ProxyS3Service};
pub use services::iam_service::{IamService, HttpIamService};
#[cfg(any(test, feature = "testing"))]
pub use services::s3_service::MockS3Service;
#[cfg(any(test, feature = "testing"))]
pub use services::iam_service::MockIamService;
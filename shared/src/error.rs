use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum S3Error {
    NoSuchBucket,
    NoSuchKey,
    AccessDenied,
    InvalidAccessKeyId,
    SignatureDoesNotMatch,
    InternalError,
    InvalidRequest(String),
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S3Error::NoSuchBucket => write!(f, "NoSuchBucket"),
            S3Error::NoSuchKey => write!(f, "NoSuchKey"),
            S3Error::AccessDenied => write!(f, "AccessDenied"),
            S3Error::InvalidAccessKeyId => write!(f, "InvalidAccessKeyId"),
            S3Error::SignatureDoesNotMatch => write!(f, "SignatureDoesNotMatch"),
            S3Error::InternalError => write!(f, "InternalError"),
            S3Error::InvalidRequest(msg) => write!(f, "InvalidRequest: {}", msg),
        }
    }
}

impl std::error::Error for S3Error {}
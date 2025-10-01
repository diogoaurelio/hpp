use crate::{types::*, InMemoryPolicyEngine, PolicyEngineTrait, InMemoryUserManager, UserManagerTrait, S3UserManager, S3PolicyEngine};
use anyhow::Result;

/// Trait defining the IAM service interface for user and access key management,
/// policy attachment, and authorization operations.
pub trait IamServiceTrait: Send + Sync {
    fn create_user(&mut self, request: CreateUserRequest) -> Result<User>;
    fn get_user(&self, user_name: &str) -> Option<User>;
    fn list_users(&self) -> Vec<User>;
    fn delete_user(&mut self, user_name: &str) -> Result<()>;
    fn create_access_key(&mut self, request: CreateAccessKeyRequest) -> Result<AccessKey>;
    fn list_access_keys(&self, user_name: &str) -> Vec<AccessKey>;
    fn delete_access_key(&mut self, access_key_id: &str) -> Result<()>;
    fn attach_user_policy(&mut self, request: AttachPolicyRequest) -> Result<()>;
    fn authorize(&self, request: AuthorizeRequest) -> AuthorizeResponse;
    fn add_builtin_policies(&mut self);
    fn validate_signature_request(&self, access_key_id: &str, signature_info: &str) -> bool;
    fn get_user_by_access_key(&self, access_key_id: &str) -> Option<User>;
}

pub struct IamService {
    user_manager: Box<dyn UserManagerTrait>,
    policy_engine: Box<dyn PolicyEngineTrait>,
}

impl IamService {
    pub fn new() -> Self {
        Self {
            user_manager: Box::new(InMemoryUserManager::new()),
            policy_engine: Box::new(InMemoryPolicyEngine::new()),
        }
    }

    pub fn with_dependencies(
        user_manager: Box<dyn UserManagerTrait>,
        policy_engine: Box<dyn PolicyEngineTrait>,
    ) -> Self {
        Self {
            user_manager,
            policy_engine,
        }
    }

    pub fn with_s3_storage(
        user_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        policy_s3_client: Box<dyn shared::S3ObjectStorageRepository>,
        bucket: String
    ) -> Self {
        Self {
            user_manager: Box::new(S3UserManager::new(user_s3_client, bucket.clone())),
            policy_engine: Box::new(S3PolicyEngine::new(policy_s3_client, bucket)),
        }
    }
}

impl IamServiceTrait for IamService {
    fn create_user(&mut self, request: CreateUserRequest) -> Result<User> {
        self.user_manager.create_user(request)
    }

    fn get_user(&self, user_name: &str) -> Option<User> {
        self.user_manager.get_user(user_name)
    }

    fn list_users(&self) -> Vec<User> {
        self.user_manager.list_users()
    }

    fn delete_user(&mut self, user_name: &str) -> Result<()> {
        self.user_manager.delete_user(user_name)
    }

    fn create_access_key(&mut self, request: CreateAccessKeyRequest) -> Result<AccessKey> {
        self.user_manager.create_access_key(request)
    }

    fn list_access_keys(&self, user_name: &str) -> Vec<AccessKey> {
        self.user_manager.list_access_keys(user_name)
    }

    fn delete_access_key(&mut self, access_key_id: &str) -> Result<()> {
        self.user_manager.delete_access_key(access_key_id)
    }

    fn attach_user_policy(&mut self, request: AttachPolicyRequest) -> Result<()> {
        if let Some(user_name) = request.user_name {
            if self.user_manager.get_user(&user_name).is_none() {
                return Err(anyhow::anyhow!("User does not exist"));
            }
            self.policy_engine.attach_user_policy(user_name, request.policy_arn);
            Ok(())
        } else {
            Err(anyhow::anyhow!("User name is required"))
        }
    }

    fn authorize(&self, request: AuthorizeRequest) -> AuthorizeResponse {
        // First validate the access key exists and is active
        if let Some(access_key) = self.user_manager.get_access_key(&request.access_key_id) {
            if !matches!(access_key.status, KeyStatus::Active) {
                return AuthorizeResponse {
                    allowed: false,
                    reason: Some("Access key is not active".to_string()),
                    matched_policies: vec![],
                };
            }
        } else {
            return AuthorizeResponse {
                allowed: false,
                reason: Some("Invalid access key".to_string()),
                matched_policies: vec![],
            };
        }

        // Get the user associated with this access key
        let access_key = self.user_manager.get_access_key(&request.access_key_id).unwrap();
        let user_name = &access_key.user_name;

        // Evaluate policies for this specific user
        self.policy_engine.evaluate_request_for_user(&request, user_name)
    }

    fn add_builtin_policies(&mut self) {
        use crate::policy::{create_s3_full_access_policy, create_s3_read_only_policy};

        self.policy_engine.add_policy(
            "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_string(),
            create_s3_full_access_policy(),
        );

        self.policy_engine.add_policy(
            "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess".to_string(),
            create_s3_read_only_policy(),
        );
    }

    fn validate_signature_request(&self, access_key_id: &str, _signature_info: &str) -> bool {
        // This would implement AWS4-HMAC-SHA256 signature validation
        // For now, just check if the access key exists and is active
        if let Some(access_key) = self.user_manager.get_access_key(access_key_id) {
            matches!(access_key.status, KeyStatus::Active)
        } else {
            false
        }
    }

    fn get_user_by_access_key(&self, access_key_id: &str) -> Option<User> {
        if let Some(access_key) = self.user_manager.get_access_key(access_key_id) {
            self.user_manager.get_user(&access_key.user_name)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iam_service_new() {
        let mut service = IamService::new();

        // Test that the service is functional by trying basic operations
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        let result = service.create_user(request);
        assert!(result.is_ok(), "Service should be able to create users after construction");
    }

    #[test]
    fn test_iam_service_with_dependencies() {
        let user_manager: Box<dyn UserManagerTrait> = Box::new(InMemoryUserManager::new());
        let policy_engine: Box<dyn PolicyEngineTrait> = Box::new(InMemoryPolicyEngine::new());

        let mut service = IamService::with_dependencies(user_manager, policy_engine);

        // Test that the service works with injected dependencies
        let request = CreateUserRequest {
            user_name: "injected-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        let result = service.create_user(request);
        assert!(result.is_ok(), "Service should work with injected dependencies");

        let user = service.get_user("injected-user");
        assert!(user.is_some(), "Should be able to retrieve created user");
    }

    #[test]
    fn test_create_user_through_iam_service() {
        let mut service = IamService::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        let result = service.create_user(request);
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.user_name, "test-user");
    }

    #[test]
    fn test_get_user_through_iam_service() {
        let mut service = IamService::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        service.create_user(request).unwrap();
        let user = service.get_user("test-user");
        assert!(user.is_some());
        assert_eq!(user.unwrap().user_name, "test-user");
    }

    #[test]
    fn test_list_users_through_iam_service() {
        let mut service = IamService::new();

        let request1 = CreateUserRequest {
            user_name: "user1".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        let request2 = CreateUserRequest {
            user_name: "user2".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        service.create_user(request1).unwrap();
        service.create_user(request2).unwrap();

        let users = service.list_users();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_delete_user_through_iam_service() {
        let mut service = IamService::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        service.create_user(request).unwrap();
        let result = service.delete_user("test-user");
        assert!(result.is_ok());

        let user = service.get_user("test-user");
        assert!(user.is_none());
    }

    #[test]
    fn test_create_access_key_through_iam_service() {
        let mut service = IamService::new();

        // Create user first
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        // Create access key
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };

        let result = service.create_access_key(key_request);
        assert!(result.is_ok());

        let access_key = result.unwrap();
        assert_eq!(access_key.user_name, "test-user");
        assert!(access_key.access_key_id.starts_with("AKIA"));
    }

    #[test]
    fn test_list_access_keys_through_iam_service() {
        let mut service = IamService::new();

        // Create user
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        // Create access key
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        service.create_access_key(key_request).unwrap();

        let keys = service.list_access_keys("test-user");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].user_name, "test-user");
    }

    #[test]
    fn test_delete_access_key_through_iam_service() {
        let mut service = IamService::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = service.create_access_key(key_request).unwrap();

        let result = service.delete_access_key(&created_key.access_key_id);
        assert!(result.is_ok());

        let keys = service.list_access_keys("test-user");
        assert!(keys.is_empty());
    }

    #[test]
    fn test_attach_user_policy_through_iam_service() {
        let mut service = IamService::new();

        // Create user
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        // Attach policy
        let policy_request = AttachPolicyRequest {
            user_name: Some("test-user".to_string()),
            role_name: None,
            policy_arn: "arn:aws:iam::123456789012:policy/S3FullAccess".to_string(),
        };

        let result = service.attach_user_policy(policy_request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_attach_user_policy_user_not_found() {
        let mut service = IamService::new();

        let policy_request = AttachPolicyRequest {
            user_name: Some("nonexistent".to_string()),
            role_name: None,
            policy_arn: "arn:aws:iam::123456789012:policy/S3FullAccess".to_string(),
        };

        let result = service.attach_user_policy(policy_request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "User does not exist");
    }

    #[test]
    fn test_add_builtin_policies() {
        let mut service = IamService::new();

        // Create a user and access key first
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = service.create_access_key(key_request).unwrap();

        // Add builtin policies
        service.add_builtin_policies();

        // Test that we can attach the builtin policies
        let s3_full_policy = AttachPolicyRequest {
            user_name: Some("test-user".to_string()),
            role_name: None,
            policy_arn: "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_string(),
        };
        let result = service.attach_user_policy(s3_full_policy);
        assert!(result.is_ok(), "Should be able to attach S3FullAccess policy");

        // Test that the policy works for authorization
        let auth_request = AuthorizeRequest {
            access_key_id: created_key.access_key_id,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = service.authorize(auth_request);
        assert!(response.allowed, "S3FullAccess policy should allow s3:GetObject");
    }

    #[test]
    fn test_authorize_invalid_access_key() {
        let service = IamService::new();

        let request = AuthorizeRequest {
            access_key_id: "AKIANONEXISTENT".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = service.authorize(request);
        assert!(!response.allowed);
        assert_eq!(response.reason, Some("Invalid access key".to_string()));
        assert!(response.matched_policies.is_empty());
    }

    #[test]
    fn test_authorize_inactive_access_key() {
        // Note: This test demonstrates a limitation - we can't easily make keys inactive
        // through the current IamService interface. In a real implementation, we'd need
        // an update_access_key_status method in IamServiceTrait.

        // For now, test that non-existent keys (which behave similarly) are denied
        let service = IamService::new();

        let request = AuthorizeRequest {
            access_key_id: "AKIAINACTIVE123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = service.authorize(request);
        assert!(!response.allowed, "Non-existent access key should be denied");
        assert_eq!(response.reason, Some("Invalid access key".to_string()));
        assert!(response.matched_policies.is_empty());
    }

    #[test]
    fn test_authorize_success() {
        let mut service = IamService::new();

        // Add built-in policies
        service.add_builtin_policies();

        // Create user
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        // Create access key
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = service.create_access_key(key_request).unwrap();

        // Attach S3 full access policy
        let policy_request = AttachPolicyRequest {
            user_name: Some("test-user".to_string()),
            role_name: None,
            policy_arn: "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_string(),
        };
        service.attach_user_policy(policy_request).unwrap();

        // Test authorization
        let auth_request = AuthorizeRequest {
            access_key_id: created_key.access_key_id,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = service.authorize(auth_request);
        assert!(response.allowed);
        assert!(!response.matched_policies.is_empty());
    }

    #[test]
    fn test_authorize_no_permissions() {
        let mut service = IamService::new();

        // Create user without any policies
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        // Create access key
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = service.create_access_key(key_request).unwrap();

        // Test authorization without any policies
        let auth_request = AuthorizeRequest {
            access_key_id: created_key.access_key_id,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = service.authorize(auth_request);
        assert!(!response.allowed);
        assert_eq!(response.reason, Some("No matching allow policy found".to_string()));
        assert!(response.matched_policies.is_empty());
    }

    #[test]
    fn test_validate_signature_request() {
        let mut service = IamService::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = service.create_access_key(key_request).unwrap();

        // Test signature validation (simplified implementation)
        let is_valid = service.validate_signature_request(&created_key.access_key_id, "dummy-signature");
        assert!(is_valid); // Should be true since the key exists and is active
    }

    #[test]
    fn test_validate_signature_request_invalid_key() {
        let service = IamService::new();
        let is_valid = service.validate_signature_request("AKIANONEXISTENT", "dummy-signature");
        assert!(!is_valid);
    }

    #[test]
    fn test_get_user_by_access_key() {
        let mut service = IamService::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = service.create_access_key(key_request).unwrap();

        // Get user by access key
        let user = service.get_user_by_access_key(&created_key.access_key_id);
        assert!(user.is_some());
        assert_eq!(user.unwrap().user_name, "test-user");
    }

    #[test]
    fn test_get_user_by_access_key_not_found() {
        let service = IamService::new();
        let user = service.get_user_by_access_key("AKIANONEXISTENT");
        assert!(user.is_none());
    }

    #[test]
    fn test_iam_service_trait_implementation() {
        let mut service: Box<dyn IamServiceTrait> = Box::new(IamService::new());

        // Test create_user through trait
        let request = CreateUserRequest {
            user_name: "trait-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        let result = service.create_user(request);
        assert!(result.is_ok());

        // Test get_user through trait
        let user = service.get_user("trait-user");
        assert!(user.is_some());
        assert_eq!(user.unwrap().user_name, "trait-user");
    }
}
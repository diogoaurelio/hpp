use crate::types::*;
use crate::authorization::AuthorizationManagerTrait;
use crate::user::UserManagerTrait;
use std::collections::HashMap;
use std::sync::Arc;

/// Trait defining the policy engine interface for IAM operations
pub trait PolicyEngineTrait: Send + Sync {
    fn set_authorization_manager(&mut self, auth_manager: Arc<dyn AuthorizationManagerTrait>);
    fn set_user_manager(&mut self, user_manager: Arc<dyn UserManagerTrait>);

    fn add_policy(&mut self, arn: String, document: PolicyDocument);
    fn attach_user_policy(&mut self, user_name: String, policy_arn: String);
    fn attach_role_policy(&mut self, role_name: String, policy_arn: String);

    fn evaluate_request(&self, request: &AuthorizeRequest) -> AuthorizeResponse;
    fn evaluate_request_for_user(&self, request: &AuthorizeRequest, user_name: &str) -> AuthorizeResponse;
}

pub struct InMemoryPolicyEngine {
    policies: HashMap<String, PolicyDocument>,
    user_policies: HashMap<String, Vec<String>>, // user_name -> policy_arns
    role_policies: HashMap<String, Vec<String>>, // role_name -> policy_arns
    auth_manager: Option<Arc<dyn AuthorizationManagerTrait>>,
    user_manager: Option<Arc<dyn UserManagerTrait>>,
}

impl InMemoryPolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            user_policies: HashMap::new(),
            role_policies: HashMap::new(),
            auth_manager: None,
            user_manager: None,
        }
    }


    fn get_user_from_access_key(&self, access_key_id: &str) -> Option<String> {
        if let Some(user_manager) = &self.user_manager {
            // Look up the user by access key
            user_manager.get_access_key(access_key_id)
                .map(|access_key| access_key.user_name)
        } else {
            // Fallback for testing - return a dummy user
            Some("test-user".to_string())
        }
    }
}

pub fn create_s3_full_access_policy() -> PolicyDocument {
    PolicyDocument {
        version: "2012-10-17".to_string(),
        statement: vec![Statement {
            sid: Some("S3FullAccess".to_string()),
            effect: Effect::Allow,
            action: ActionValue::Single("s3:*".to_string()),
            resource: ResourceValue::Single("*".to_string()),
            condition: None,
            principal: None,
        }],
    }
}

pub fn create_s3_read_only_policy() -> PolicyDocument {
    PolicyDocument {
        version: "2012-10-17".to_string(),
        statement: vec![Statement {
            sid: Some("S3ReadOnly".to_string()),
            effect: Effect::Allow,
            action: ActionValue::Multiple(vec![
                "s3:GetObject".to_string(),
                "s3:ListBucket".to_string(),
            ]),
            resource: ResourceValue::Single("*".to_string()),
            condition: None,
            principal: None,
        }],
    }
}

impl PolicyEngineTrait for InMemoryPolicyEngine {
    fn set_authorization_manager(&mut self, auth_manager: Arc<dyn AuthorizationManagerTrait>) {
        self.auth_manager = Some(auth_manager);
    }

    fn set_user_manager(&mut self, user_manager: Arc<dyn UserManagerTrait>) {
        self.user_manager = Some(user_manager);
    }

    fn add_policy(&mut self, arn: String, document: PolicyDocument) {
        self.policies.insert(arn, document);
    }

    fn attach_user_policy(&mut self, user_name: String, policy_arn: String) {
        self.user_policies
            .entry(user_name)
            .or_insert_with(Vec::new)
            .push(policy_arn);
    }

    fn attach_role_policy(&mut self, role_name: String, policy_arn: String) {
        self.role_policies
            .entry(role_name)
            .or_insert_with(Vec::new)
            .push(policy_arn);
    }

    fn evaluate_request(&self, request: &AuthorizeRequest) -> AuthorizeResponse {
        let user_name = self.get_user_from_access_key(&request.access_key_id);

        if let Some(user) = user_name {
            return self.evaluate_request_for_user(request, &user);
        }

        AuthorizeResponse {
            allowed: false,
            reason: Some("No user found for access key".to_string()),
            matched_policies: vec![],
        }
    }

    fn evaluate_request_for_user(&self, request: &AuthorizeRequest, user_name: &str) -> AuthorizeResponse {
        if let Some(policy_arns) = self.user_policies.get(user_name) {
            let policies_with_arns: Vec<(String, PolicyDocument)> = policy_arns
                .iter()
                .filter_map(|arn| self.policies.get(arn).map(|policy| (arn.clone(), policy.clone())))
                .collect();

            if !policies_with_arns.is_empty() {
                if let Some(auth_manager) = &self.auth_manager {
                    let policies_refs: Vec<(String, &PolicyDocument)> = policies_with_arns
                        .iter()
                        .map(|(arn, policy)| (arn.clone(), policy))
                        .collect();
                    return auth_manager.authorize_for_user_with_arns(request, user_name, &policies_refs);
                } else {
                    // Fallback: Use Cedar authorization manager as default
                    use crate::cedar_authorization::CedarAuthorizationManager;
                    if let Ok(cedar_auth) = CedarAuthorizationManager::new() {
                        let policies_refs: Vec<(String, &PolicyDocument)> = policies_with_arns
                            .iter()
                            .map(|(arn, policy)| (arn.clone(), policy))
                            .collect();
                        return cedar_auth.authorize_for_user_with_arns(request, user_name, &policies_refs);
                    } else {
                        // Last resort: deny all requests if Cedar can't be initialized
                        return AuthorizeResponse {
                            allowed: false,
                            reason: Some("No authorization manager available".to_string()),
                            matched_policies: vec![],
                        };
                    }
                }
            }
        }

        AuthorizeResponse {
            allowed: false,
            reason: Some("No matching allow policy found".to_string()),
            matched_policies: vec![],
        }
    }
}

pub struct S3PolicyEngine {
    s3_client: Box<dyn shared::S3ObjectStorageRepository>,
    bucket: String,
    auth_manager: Option<Arc<dyn AuthorizationManagerTrait>>,
    user_manager: Option<Arc<dyn UserManagerTrait>>,
    // Cache for better performance - invalidated on writes
    policies_cache: tokio::sync::RwLock<Option<HashMap<String, PolicyDocument>>>,
    user_policies_cache: tokio::sync::RwLock<Option<HashMap<String, Vec<String>>>>,
    role_policies_cache: tokio::sync::RwLock<Option<HashMap<String, Vec<String>>>>,
}

impl S3PolicyEngine {
    pub fn new(s3_client: Box<dyn shared::S3ObjectStorageRepository>, bucket: String) -> Self {
        Self {
            s3_client,
            bucket,
            auth_manager: None,
            user_manager: None,
            policies_cache: tokio::sync::RwLock::new(None),
            user_policies_cache: tokio::sync::RwLock::new(None),
            role_policies_cache: tokio::sync::RwLock::new(None),
        }
    }

    async fn load_policies(&self) -> anyhow::Result<HashMap<String, PolicyDocument>> {
        let request = shared::GetObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/policies.json".to_string(),
        };

        match self.s3_client.get_object(request).await {
            Ok(response) => {
                let policies_data = String::from_utf8(response.body.to_vec())?;
                let policies: HashMap<String, PolicyDocument> = serde_json::from_str(&policies_data)?;
                Ok(policies)
            }
            Err(_) => {
                // File doesn't exist yet, return empty map
                Ok(HashMap::new())
            }
        }
    }

    async fn save_policies(&self, policies: &HashMap<String, PolicyDocument>) -> anyhow::Result<()> {
        let policies_json = serde_json::to_string_pretty(policies)?;
        let request = shared::PutObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/policies.json".to_string(),
            body: bytes::Bytes::from(policies_json),
            content_type: Some("application/json".to_string()),
            metadata: HashMap::new(),
        };

        self.s3_client.put_object(request).await?;

        // Invalidate cache
        *self.policies_cache.write().await = None;
        Ok(())
    }

    async fn load_policy_attachments(&self) -> anyhow::Result<(HashMap<String, Vec<String>>, HashMap<String, Vec<String>>)> {
        let request = shared::GetObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/policy_attachments.json".to_string(),
        };

        let (user_policies, role_policies) = match self.s3_client.get_object(request).await {
            Ok(response) => {
                let data = String::from_utf8(response.body.to_vec())?;
                let stored_data: StoredPolicyAttachmentsData = serde_json::from_str(&data)?;
                (stored_data.user_policies, stored_data.role_policies)
            }
            Err(_) => {
                // File doesn't exist yet, return empty maps
                (HashMap::new(), HashMap::new())
            }
        };

        Ok((user_policies, role_policies))
    }

    async fn save_policy_attachments(&self, user_policies: &HashMap<String, Vec<String>>, role_policies: &HashMap<String, Vec<String>>) -> anyhow::Result<()> {
        let data = StoredPolicyAttachmentsData {
            user_policies: user_policies.clone(),
            role_policies: role_policies.clone(),
        };

        let attachments_json = serde_json::to_string_pretty(&data)?;
        let request = shared::PutObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/policy_attachments.json".to_string(),
            body: bytes::Bytes::from(attachments_json),
            content_type: Some("application/json".to_string()),
            metadata: HashMap::new(),
        };

        self.s3_client.put_object(request).await?;

        // Invalidate caches
        *self.user_policies_cache.write().await = None;
        *self.role_policies_cache.write().await = None;
        Ok(())
    }

    async fn get_policies_cached(&self) -> anyhow::Result<HashMap<String, PolicyDocument>> {
        let cache_read = self.policies_cache.read().await;
        if let Some(ref cached_policies) = *cache_read {
            return Ok(cached_policies.clone());
        }
        drop(cache_read);

        let policies = self.load_policies().await?;
        *self.policies_cache.write().await = Some(policies.clone());
        Ok(policies)
    }

    async fn get_policy_attachments_cached(&self) -> anyhow::Result<(HashMap<String, Vec<String>>, HashMap<String, Vec<String>>)> {
        let user_policies_cache_read = self.user_policies_cache.read().await;
        let role_policies_cache_read = self.role_policies_cache.read().await;

        if let (Some(ref cached_user_policies), Some(ref cached_role_policies)) = (&*user_policies_cache_read, &*role_policies_cache_read) {
            return Ok((cached_user_policies.clone(), cached_role_policies.clone()));
        }
        drop(user_policies_cache_read);
        drop(role_policies_cache_read);

        let (user_policies, role_policies) = self.load_policy_attachments().await?;
        *self.user_policies_cache.write().await = Some(user_policies.clone());
        *self.role_policies_cache.write().await = Some(role_policies.clone());
        Ok((user_policies, role_policies))
    }


    fn get_user_from_access_key(&self, access_key_id: &str) -> Option<String> {
        if let Some(user_manager) = &self.user_manager {
            // Look up the user by access key
            user_manager.get_access_key(access_key_id)
                .map(|access_key| access_key.user_name)
        } else {
            // Fallback for testing - return a dummy user
            Some("test-user".to_string())
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredPolicyAttachmentsData {
    user_policies: HashMap<String, Vec<String>>,
    role_policies: HashMap<String, Vec<String>>,
}

#[async_trait::async_trait]
impl PolicyEngineTrait for S3PolicyEngine {
    fn set_authorization_manager(&mut self, auth_manager: Arc<dyn AuthorizationManagerTrait>) {
        self.auth_manager = Some(auth_manager);
    }

    fn set_user_manager(&mut self, user_manager: Arc<dyn UserManagerTrait>) {
        self.user_manager = Some(user_manager);
    }

    fn add_policy(&mut self, arn: String, document: PolicyDocument) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut policies = self.get_policies_cached().await.unwrap_or_default();
                policies.insert(arn, document);
                let _ = self.save_policies(&policies).await;
            })
        })
    }

    fn attach_user_policy(&mut self, user_name: String, policy_arn: String) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (mut user_policies, role_policies) = self.get_policy_attachments_cached().await.unwrap_or_default();
                user_policies
                    .entry(user_name)
                    .or_insert_with(Vec::new)
                    .push(policy_arn);
                let _ = self.save_policy_attachments(&user_policies, &role_policies).await;
            })
        })
    }

    fn attach_role_policy(&mut self, role_name: String, policy_arn: String) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (user_policies, mut role_policies) = self.get_policy_attachments_cached().await.unwrap_or_default();
                role_policies
                    .entry(role_name)
                    .or_insert_with(Vec::new)
                    .push(policy_arn);
                let _ = self.save_policy_attachments(&user_policies, &role_policies).await;
            })
        })
    }

    fn evaluate_request(&self, request: &AuthorizeRequest) -> AuthorizeResponse {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let user_name = self.get_user_from_access_key(&request.access_key_id);

                if let Some(user) = user_name {
                    return self.evaluate_request_for_user(request, &user);
                }

                AuthorizeResponse {
                    allowed: false,
                    reason: Some("No user found for access key".to_string()),
                    matched_policies: vec![],
                }
            })
        })
    }

    fn evaluate_request_for_user(&self, request: &AuthorizeRequest, user_name: &str) -> AuthorizeResponse {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (user_policies, _) = self.get_policy_attachments_cached().await.unwrap_or_default();
                let policies = self.get_policies_cached().await.unwrap_or_default();

                if let Some(policy_arns) = user_policies.get(user_name) {
                    let policies_with_arns: Vec<(String, &PolicyDocument)> = policy_arns
                        .iter()
                        .filter_map(|arn| policies.get(arn).map(|policy| (arn.clone(), policy)))
                        .collect();

                    if !policies_with_arns.is_empty() {
                        if let Some(auth_manager) = &self.auth_manager {
                            return auth_manager.authorize_for_user_with_arns(request, user_name, &policies_with_arns);
                        } else {
                            // Fallback: Use Cedar authorization manager as default
                            use crate::cedar_authorization::CedarAuthorizationManager;
                            if let Ok(cedar_auth) = CedarAuthorizationManager::new() {
                                return cedar_auth.authorize_for_user_with_arns(request, user_name, &policies_with_arns);
                            } else {
                                // Last resort: deny all requests if Cedar can't be initialized
                                return AuthorizeResponse {
                                    allowed: false,
                                    reason: Some("No authorization manager available".to_string()),
                                    matched_policies: vec![],
                                };
                            }
                        }
                    }
                }

                AuthorizeResponse {
                    allowed: false,
                    reason: Some("No matching allow policy found".to_string()),
                    matched_policies: vec![],
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use shared::MockS3ObjectStorageRepository;

    #[test]
    fn test_add_policy() {
        let mut policy_engine = InMemoryPolicyEngine::new();
        let policy_doc = create_s3_full_access_policy();
        let arn = "arn:aws:iam::123456789012:policy/S3FullAccess".to_string();

        policy_engine.add_policy(arn.clone(), policy_doc.clone());

        // Verify policy was added (internal state check)
        assert!(policy_engine.policies.contains_key(&arn));
    }

    #[test]
    fn test_attach_user_policy() {
        let mut policy_engine = InMemoryPolicyEngine::new();
        let policy_arn = "arn:aws:iam::123456789012:policy/S3FullAccess".to_string();
        let user_name = "test-user".to_string();

        policy_engine.attach_user_policy(user_name.clone(), policy_arn.clone());

        // Verify policy was attached to user
        assert!(policy_engine.user_policies.contains_key(&user_name));
        let user_policies = &policy_engine.user_policies[&user_name];
        assert!(user_policies.contains(&policy_arn));
    }

    #[test]
    fn test_attach_role_policy() {
        let mut policy_engine = InMemoryPolicyEngine::new();
        let policy_arn = "arn:aws:iam::123456789012:policy/S3FullAccess".to_string();
        let role_name = "test-role".to_string();

        policy_engine.attach_role_policy(role_name.clone(), policy_arn.clone());

        // Verify policy was attached to role
        assert!(policy_engine.role_policies.contains_key(&role_name));
        let role_policies = &policy_engine.role_policies[&role_name];
        assert!(role_policies.contains(&policy_arn));
    }

    #[test]
    fn test_evaluate_request_for_user_allow() {
        let mut policy_engine = InMemoryPolicyEngine::new();

        // Add S3 full access policy
        let policy_arn = "arn:aws:iam::123456789012:policy/S3FullAccess".to_string();
        let policy_doc = create_s3_full_access_policy();
        policy_engine.add_policy(policy_arn.clone(), policy_doc);

        // Attach policy to user
        let user_name = "test-user";
        policy_engine.attach_user_policy(user_name.to_string(), policy_arn.clone());

        // Create authorize request
        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = policy_engine.evaluate_request_for_user(&request, user_name);
        assert!(response.allowed);
        assert_eq!(response.matched_policies, vec![policy_arn]);
    }

    #[test]
    fn test_evaluate_request_for_user_deny_no_policy() {
        let policy_engine = InMemoryPolicyEngine::new();

        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = policy_engine.evaluate_request_for_user(&request, "test-user");
        assert!(!response.allowed);
        assert_eq!(response.reason, Some("No matching allow policy found".to_string()));
        assert!(response.matched_policies.is_empty());
    }



    #[test]
    fn test_create_s3_full_access_policy() {
        let policy = create_s3_full_access_policy();
        assert_eq!(policy.version, "2012-10-17");
        assert_eq!(policy.statement.len(), 1);

        let statement = &policy.statement[0];
        assert_eq!(statement.effect, Effect::Allow);
        assert_eq!(statement.action, ActionValue::Single("s3:*".to_string()));
        assert_eq!(statement.resource, ResourceValue::Single("*".to_string()));
    }

    #[test]
    fn test_create_s3_read_only_policy() {
        let policy = create_s3_read_only_policy();
        assert_eq!(policy.version, "2012-10-17");
        assert_eq!(policy.statement.len(), 1);

        let statement = &policy.statement[0];
        assert_eq!(statement.effect, Effect::Allow);

        if let ActionValue::Multiple(actions) = &statement.action {
            assert!(actions.contains(&"s3:GetObject".to_string()));
            assert!(actions.contains(&"s3:ListBucket".to_string()));
            assert_eq!(actions.len(), 2);
        } else {
            panic!("Expected multiple actions for read-only policy");
        }
    }

    #[test]
    fn test_policy_engine_trait_implementation() {
        let mut policy_engine: Box<dyn PolicyEngineTrait> = Box::new(InMemoryPolicyEngine::new());

        // Test add_policy through trait
        let policy_doc = create_s3_full_access_policy();
        let arn = "arn:aws:iam::123456789012:policy/S3FullAccess".to_string();
        policy_engine.add_policy(arn.clone(), policy_doc);

        // Test attach_user_policy through trait
        let user_name = "trait-user".to_string();
        policy_engine.attach_user_policy(user_name.clone(), arn.clone());

        // Test evaluate_request_for_user through trait
        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = policy_engine.evaluate_request_for_user(&request, &user_name);
        assert!(response.allowed);
    }

    // TODO: Add S3PolicyEngine integration tests (requires async mock setup)
}
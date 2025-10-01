use crate::types::*;
use std::collections::HashMap;

/// Trait defining the policy engine interface for IAM operations
pub trait PolicyEngineTrait: Send + Sync {
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
}

impl InMemoryPolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            user_policies: HashMap::new(),
            role_policies: HashMap::new(),
        }
    }

    fn evaluate_policy(&self, policy: &PolicyDocument, request: &AuthorizeRequest) -> bool {
        for statement in &policy.statement {
            if self.evaluate_statement(statement, request) {
                match statement.effect {
                    Effect::Allow => return true,
                    Effect::Deny => return false,
                }
            }
        }
        false
    }

    fn evaluate_statement(&self, statement: &Statement, request: &AuthorizeRequest) -> bool {
        // Check if action matches
        if !self.matches_action(&statement.action, &request.action) {
            return false;
        }

        // Check if resource matches
        if !self.matches_resource(&statement.resource, &request.resource) {
            return false;
        }

        // Check conditions (simplified)
        if let Some(_conditions) = &statement.condition {
            // TODO: Implement condition evaluation
            // For now, assume conditions pass
        }

        true
    }

    fn matches_action(&self, action_value: &ActionValue, request_action: &str) -> bool {
        match action_value {
            ActionValue::Single(action) => self.wildcard_match(action, request_action),
            ActionValue::Multiple(actions) => {
                actions.iter().any(|action| self.wildcard_match(action, request_action))
            }
        }
    }

    fn matches_resource(&self, resource_value: &ResourceValue, request_resource: &str) -> bool {
        match resource_value {
            ResourceValue::Single(resource) => self.wildcard_match(resource, request_resource),
            ResourceValue::Multiple(resources) => {
                resources.iter().any(|resource| self.wildcard_match(resource, request_resource))
            }
        }
    }

    fn wildcard_match(&self, pattern: &str, text: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            // Simple wildcard matching - replace with proper glob matching in production
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let prefix = parts[0];
                let suffix = parts[1];
                return text.starts_with(prefix) && text.ends_with(suffix);
            }
        }

        pattern == text
    }

    fn get_user_from_access_key(&self, _access_key_id: &str) -> Option<String> {
        // TODO: Implement access key to user mapping
        // For now, return a dummy user
        Some("test-user".to_string())
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
            if let Some(policy_arns) = self.user_policies.get(&user) {
                for policy_arn in policy_arns {
                    if let Some(policy_doc) = self.policies.get(policy_arn) {
                        if self.evaluate_policy(policy_doc, request) {
                            return AuthorizeResponse {
                                allowed: true,
                                reason: Some("Policy allows action".to_string()),
                                matched_policies: vec![policy_arn.clone()],
                            };
                        }
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

    fn evaluate_request_for_user(&self, request: &AuthorizeRequest, user_name: &str) -> AuthorizeResponse {
        if let Some(policy_arns) = self.user_policies.get(user_name) {
            for policy_arn in policy_arns {
                if let Some(policy_doc) = self.policies.get(policy_arn) {
                    if self.evaluate_policy(policy_doc, request) {
                        return AuthorizeResponse {
                            allowed: true,
                            reason: Some("Policy allows action".to_string()),
                            matched_policies: vec![policy_arn.clone()],
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

    fn evaluate_policy(&self, policy: &PolicyDocument, request: &AuthorizeRequest) -> bool {
        for statement in &policy.statement {
            if self.evaluate_statement(statement, request) {
                match statement.effect {
                    Effect::Allow => return true,
                    Effect::Deny => return false,
                }
            }
        }
        false
    }

    fn evaluate_statement(&self, statement: &Statement, request: &AuthorizeRequest) -> bool {
        // Check if action matches
        if !self.matches_action(&statement.action, &request.action) {
            return false;
        }

        // Check if resource matches
        if !self.matches_resource(&statement.resource, &request.resource) {
            return false;
        }

        // Check conditions (simplified)
        if let Some(_conditions) = &statement.condition {
            // TODO: Implement condition evaluation
            // For now, assume conditions pass
        }

        true
    }

    fn matches_action(&self, action_value: &ActionValue, request_action: &str) -> bool {
        match action_value {
            ActionValue::Single(action) => self.wildcard_match(action, request_action),
            ActionValue::Multiple(actions) => {
                actions.iter().any(|action| self.wildcard_match(action, request_action))
            }
        }
    }

    fn matches_resource(&self, resource_value: &ResourceValue, request_resource: &str) -> bool {
        match resource_value {
            ResourceValue::Single(resource) => self.wildcard_match(resource, request_resource),
            ResourceValue::Multiple(resources) => {
                resources.iter().any(|resource| self.wildcard_match(resource, request_resource))
            }
        }
    }

    fn wildcard_match(&self, pattern: &str, text: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            // Simple wildcard matching - replace with proper glob matching in production
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let prefix = parts[0];
                let suffix = parts[1];
                return text.starts_with(prefix) && text.ends_with(suffix);
            }
        }

        pattern == text
    }

    fn get_user_from_access_key(&self, _access_key_id: &str) -> Option<String> {
        // TODO: Implement access key to user mapping
        // For now, return a dummy user
        Some("test-user".to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredPolicyAttachmentsData {
    user_policies: HashMap<String, Vec<String>>,
    role_policies: HashMap<String, Vec<String>>,
}

#[async_trait::async_trait]
impl PolicyEngineTrait for S3PolicyEngine {
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
                    let (user_policies, _) = self.get_policy_attachments_cached().await.unwrap_or_default();
                    let policies = self.get_policies_cached().await.unwrap_or_default();

                    if let Some(policy_arns) = user_policies.get(&user) {
                        for policy_arn in policy_arns {
                            if let Some(policy_doc) = policies.get(policy_arn) {
                                if self.evaluate_policy(policy_doc, request) {
                                    return AuthorizeResponse {
                                        allowed: true,
                                        reason: Some("Policy allows action".to_string()),
                                        matched_policies: vec![policy_arn.clone()],
                                    };
                                }
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

    fn evaluate_request_for_user(&self, request: &AuthorizeRequest, user_name: &str) -> AuthorizeResponse {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (user_policies, _) = self.get_policy_attachments_cached().await.unwrap_or_default();
                let policies = self.get_policies_cached().await.unwrap_or_default();

                if let Some(policy_arns) = user_policies.get(user_name) {
                    for policy_arn in policy_arns {
                        if let Some(policy_doc) = policies.get(policy_arn) {
                            if self.evaluate_policy(policy_doc, request) {
                                return AuthorizeResponse {
                                    allowed: true,
                                    reason: Some("Policy allows action".to_string()),
                                    matched_policies: vec![policy_arn.clone()],
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
    fn test_evaluate_request_for_user_deny_no_matching_action() {
        let mut policy_engine = InMemoryPolicyEngine::new();

        // Add S3 read-only policy (only allows GetObject and ListBucket)
        let policy_arn = "arn:aws:iam::123456789012:policy/S3ReadOnly".to_string();
        let policy_doc = create_s3_read_only_policy();
        policy_engine.add_policy(policy_arn.clone(), policy_doc);

        // Attach policy to user
        let user_name = "test-user";
        policy_engine.attach_user_policy(user_name.to_string(), policy_arn);

        // Try to perform PutObject (not allowed by read-only policy)
        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:PutObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = policy_engine.evaluate_request_for_user(&request, user_name);
        assert!(!response.allowed);
        assert_eq!(response.reason, Some("No matching allow policy found".to_string()));
        assert!(response.matched_policies.is_empty());
    }

    #[test]
    fn test_evaluate_request_for_user_multiple_policies() {
        let mut policy_engine = InMemoryPolicyEngine::new();

        // Add both read-only and full access policies
        let readonly_arn = "arn:aws:iam::123456789012:policy/S3ReadOnly".to_string();
        let fullaccess_arn = "arn:aws:iam::123456789012:policy/S3FullAccess".to_string();

        policy_engine.add_policy(readonly_arn.clone(), create_s3_read_only_policy());
        policy_engine.add_policy(fullaccess_arn.clone(), create_s3_full_access_policy());

        // Attach both policies to user
        let user_name = "test-user";
        policy_engine.attach_user_policy(user_name.to_string(), readonly_arn);
        policy_engine.attach_user_policy(user_name.to_string(), fullaccess_arn.clone());

        // Test GetObject (allowed by both policies, should match first one found)
        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/test-object".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = policy_engine.evaluate_request_for_user(&request, user_name);
        assert!(response.allowed);
        assert!(!response.matched_policies.is_empty());
    }

    #[test]
    fn test_wildcard_match_star() {
        let policy_engine = InMemoryPolicyEngine::new();
        assert!(policy_engine.wildcard_match("*", "anything"));
        assert!(policy_engine.wildcard_match("*", "s3:GetObject"));
        assert!(policy_engine.wildcard_match("*", ""));
    }

    #[test]
    fn test_wildcard_match_exact() {
        let policy_engine = InMemoryPolicyEngine::new();
        assert!(policy_engine.wildcard_match("s3:GetObject", "s3:GetObject"));
        assert!(!policy_engine.wildcard_match("s3:GetObject", "s3:PutObject"));
    }

    #[test]
    fn test_wildcard_match_prefix_suffix() {
        let policy_engine = InMemoryPolicyEngine::new();
        assert!(policy_engine.wildcard_match("s3:*", "s3:GetObject"));
        assert!(policy_engine.wildcard_match("s3:*", "s3:PutObject"));
        assert!(!policy_engine.wildcard_match("s3:*", "ec2:DescribeInstances"));

        assert!(policy_engine.wildcard_match("*:GetObject", "s3:GetObject"));
        assert!(policy_engine.wildcard_match("*:GetObject", "dynamodb:GetObject"));
        assert!(!policy_engine.wildcard_match("*:GetObject", "s3:PutObject"));
    }

    #[test]
    fn test_matches_action_single() {
        let policy_engine = InMemoryPolicyEngine::new();
        let action_value = ActionValue::Single("s3:GetObject".to_string());

        assert!(policy_engine.matches_action(&action_value, "s3:GetObject"));
        assert!(!policy_engine.matches_action(&action_value, "s3:PutObject"));
    }

    #[test]
    fn test_matches_action_multiple() {
        let policy_engine = InMemoryPolicyEngine::new();
        let action_value = ActionValue::Multiple(vec![
            "s3:GetObject".to_string(),
            "s3:ListBucket".to_string(),
        ]);

        assert!(policy_engine.matches_action(&action_value, "s3:GetObject"));
        assert!(policy_engine.matches_action(&action_value, "s3:ListBucket"));
        assert!(!policy_engine.matches_action(&action_value, "s3:PutObject"));
    }

    #[test]
    fn test_matches_resource_single() {
        let policy_engine = InMemoryPolicyEngine::new();
        let resource_value = ResourceValue::Single("arn:aws:s3:::test-bucket/*".to_string());

        assert!(policy_engine.matches_resource(&resource_value, "arn:aws:s3:::test-bucket/file.txt"));
        assert!(!policy_engine.matches_resource(&resource_value, "arn:aws:s3:::other-bucket/file.txt"));
    }

    #[test]
    fn test_matches_resource_multiple() {
        let policy_engine = InMemoryPolicyEngine::new();
        let resource_value = ResourceValue::Multiple(vec![
            "arn:aws:s3:::bucket1/*".to_string(),
            "arn:aws:s3:::bucket2/*".to_string(),
        ]);

        assert!(policy_engine.matches_resource(&resource_value, "arn:aws:s3:::bucket1/file.txt"));
        assert!(policy_engine.matches_resource(&resource_value, "arn:aws:s3:::bucket2/file.txt"));
        assert!(!policy_engine.matches_resource(&resource_value, "arn:aws:s3:::bucket3/file.txt"));
    }

    #[test]
    fn test_evaluate_statement_success() {
        let policy_engine = InMemoryPolicyEngine::new();

        let statement = Statement {
            sid: Some("AllowS3GetObject".to_string()),
            effect: Effect::Allow,
            action: ActionValue::Single("s3:GetObject".to_string()),
            resource: ResourceValue::Single("arn:aws:s3:::test-bucket/*".to_string()),
            condition: None,
            principal: None,
        };

        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        assert!(policy_engine.evaluate_statement(&statement, &request));
    }

    #[test]
    fn test_evaluate_statement_action_mismatch() {
        let policy_engine = InMemoryPolicyEngine::new();

        let statement = Statement {
            sid: Some("AllowS3GetObject".to_string()),
            effect: Effect::Allow,
            action: ActionValue::Single("s3:GetObject".to_string()),
            resource: ResourceValue::Single("*".to_string()),
            condition: None,
            principal: None,
        };

        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:PutObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        assert!(!policy_engine.evaluate_statement(&statement, &request));
    }

    #[test]
    fn test_evaluate_statement_resource_mismatch() {
        let policy_engine = InMemoryPolicyEngine::new();

        let statement = Statement {
            sid: Some("AllowS3GetObject".to_string()),
            effect: Effect::Allow,
            action: ActionValue::Single("s3:GetObject".to_string()),
            resource: ResourceValue::Single("arn:aws:s3:::specific-bucket/*".to_string()),
            condition: None,
            principal: None,
        };

        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::other-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        assert!(!policy_engine.evaluate_statement(&statement, &request));
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
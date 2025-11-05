use crate::authorization::{AuthorizationManagerTrait, PreparedPolicy, ValidationResult};
use crate::types::*;
use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, Policy, PolicySet, Request, Schema,
};
use std::str::FromStr;

pub struct CedarAuthorizationManager {
    authorizer: Authorizer,
    schema: Schema,
}

impl CedarAuthorizationManager {
    pub fn new() -> anyhow::Result<Self> {
        let schema = Self::build_s3_schema()?;
        Ok(Self {
            authorizer: Authorizer::new(),
            schema,
        })
    }

    fn build_s3_schema() -> anyhow::Result<Schema> {
        // Create minimal schema
        let schema_json = r#"
        {
            "": {
                "entityTypes": {},
                "actions": {}
            }
        }
        "#;
        Schema::from_json_str(schema_json).map_err(|e| anyhow::anyhow!("Failed to create schema: {}", e))
    }

    // Helper method to check if a statement matches a request
    fn statement_matches_request(&self, statement: &Statement, request: &AuthorizeRequest) -> bool {
        // Check if action matches
        let action_matches = match &statement.action {
            ActionValue::Single(action) => {
                action == "*" || action == &request.action ||
                (action.ends_with('*') && request.action.starts_with(&action[..action.len()-1]))
            }
            ActionValue::Multiple(actions) => {
                actions.iter().any(|action| {
                    action == "*" || action == &request.action ||
                    (action.ends_with('*') && request.action.starts_with(&action[..action.len()-1]))
                })
            }
        };

        // Check if resource matches
        let resource_matches = match &statement.resource {
            ResourceValue::Single(resource) => {
                resource == "*" || resource == &request.resource ||
                (resource.ends_with('*') && request.resource.starts_with(&resource[..resource.len()-1]))
            }
            ResourceValue::Multiple(resources) => {
                resources.iter().any(|resource| {
                    resource == "*" || resource == &request.resource ||
                    (resource.ends_with('*') && request.resource.starts_with(&resource[..resource.len()-1]))
                })
            }
        };

        action_matches && resource_matches
    }
}

impl Default for CedarAuthorizationManager {
    fn default() -> Self {
        Self::new().expect("Failed to create CedarAuthorizationManager")
    }
}

impl AuthorizationManagerTrait for CedarAuthorizationManager {
    fn authorize_with_arns(&self, request: &AuthorizeRequest, policies_with_arns: &[(String, &PolicyDocument)]) -> AuthorizeResponse {
        self.authorize_for_user_with_arns(request, "unknown", policies_with_arns)
    }

    fn authorize_for_user_with_arns(&self, request: &AuthorizeRequest, _user_name: &str, policies_with_arns: &[(String, &PolicyDocument)]) -> AuthorizeResponse {
        // First, do direct IAM action matching to determine if any policy allows the request
        let mut matched_policies = Vec::new();
        let mut has_allow = false;

        for (policy_arn, policy) in policies_with_arns {
            for statement in &policy.statement {
                if self.statement_matches_request(statement, request) {
                    match statement.effect {
                        Effect::Allow => {
                            has_allow = true;
                            matched_policies.push(policy_arn.clone());
                        }
                        Effect::Deny => {
                            // Deny takes precedence - return immediately
                            return AuthorizeResponse {
                                allowed: false,
                                reason: Some("Explicit deny statement found".to_string()),
                                matched_policies: vec![],
                            };
                        }
                    }
                }
            }
        }

        if has_allow {
            AuthorizeResponse {
                allowed: true,
                reason: Some("IAM policy allows action".to_string()),
                matched_policies,
            }
        } else {
            AuthorizeResponse {
                allowed: false,
                reason: Some("No matching allow policy found".to_string()),
                matched_policies: vec![],
            }
        }
    }

    fn validate_policy(&self, _policy: &PolicyDocument) -> ValidationResult {
        // For now, assume all policies are valid
        ValidationResult::valid()
    }

    fn prepare_policy(&self, policy: &PolicyDocument) -> anyhow::Result<PreparedPolicy> {
        let validation = self.validate_policy(policy);
        if !validation.valid {
            return Err(anyhow::anyhow!("Policy validation failed: {:?}", validation.errors));
        }

        // For this simple implementation, just return the original policy
        Ok(PreparedPolicy {
            original: policy.clone(),
            compiled: Box::new(PolicySet::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cedar_authorization_manager_creation() {
        let auth_manager = CedarAuthorizationManager::new();
        if let Err(e) = &auth_manager {
            log::error!("Error creating CedarAuthorizationManager: {}", e);
        }
        assert!(auth_manager.is_ok());
    }

    #[test]
    fn test_s3_full_access_authorization() {
        let auth_manager = CedarAuthorizationManager::new().unwrap();

        // Create S3 full access policy
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![Statement {
                sid: Some("S3FullAccess".to_string()),
                effect: Effect::Allow,
                action: ActionValue::Single("s3:*".to_string()),
                resource: ResourceValue::Single("*".to_string()),
                condition: None,
                principal: None,
            }],
        };

        let policies_with_arns = vec![("arn:aws:iam::123456789012:policy/S3FullAccess".to_string(), &policy)];

        // Test GetObject
        let get_request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&get_request, "test-user", &policies_with_arns);
        assert!(response.allowed, "S3 GetObject should be allowed with full access policy");
        assert_eq!(response.matched_policies.len(), 1);

        // Test PutObject
        let put_request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:PutObject".to_string(),
            resource: "arn:aws:s3:::test-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&put_request, "test-user", &policies_with_arns);
        assert!(response.allowed, "S3 PutObject should be allowed with full access policy");
    }

    #[test]
    fn test_s3_read_only_denies_write_operations() {
        let auth_manager = CedarAuthorizationManager::new().unwrap();

        // Create S3 read-only policy
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![Statement {
                sid: Some("S3ReadOnly".to_string()),
                effect: Effect::Allow,
                action: ActionValue::Multiple(vec![
                    "s3:GetObject".to_string(),
                    "s3:ListBucket".to_string(),
                ]),
                resource: ResourceValue::Single("arn:aws:s3:::data-bucket/*".to_string()),
                condition: None,
                principal: None,
            }],
        };

        let policies_with_arns = vec![("arn:aws:iam::123456789012:policy/S3ReadOnly".to_string(), &policy)];

        // Test PutObject (should be denied)
        let put_request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:PutObject".to_string(),
            resource: "arn:aws:s3:::data-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&put_request, "read-user", &policies_with_arns);
        assert!(!response.allowed, "S3 PutObject should be denied with read-only policy");
        assert!(response.reason.is_some(), "Denial should include a reason");

        // Test DeleteObject (should be denied)
        let delete_request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:DeleteObject".to_string(),
            resource: "arn:aws:s3:::data-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&delete_request, "read-user", &policies_with_arns);
        assert!(!response.allowed, "S3 DeleteObject should be denied with read-only policy");
        assert!(response.matched_policies.is_empty(), "Denied request should have no matched policies");
    }

    #[test]
    fn test_no_policy_denies_all_access() {
        let auth_manager = CedarAuthorizationManager::new().unwrap();

        // Empty policy list
        let policies_with_arns: Vec<(String, &PolicyDocument)> = vec![];

        // Test any request (should be denied)
        let request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::any-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&request, "user", &policies_with_arns);
        assert!(!response.allowed, "Request with no policies should be denied");
        assert!(response.matched_policies.is_empty(), "No policies should be matched when no policies exist");
    }

    #[test]
    fn test_explicit_deny_policy_blocks_access() {
        let auth_manager = CedarAuthorizationManager::new().unwrap();

        // Create policy with explicit deny
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![
                Statement {
                    sid: Some("AllowS3Access".to_string()),
                    effect: Effect::Allow,
                    action: ActionValue::Single("s3:*".to_string()),
                    resource: ResourceValue::Single("*".to_string()),
                    condition: None,
                    principal: None,
                },
                Statement {
                    sid: Some("DenySecretBucket".to_string()),
                    effect: Effect::Deny,
                    action: ActionValue::Single("s3:*".to_string()),
                    resource: ResourceValue::Single("arn:aws:s3:::secret-bucket/*".to_string()),
                    condition: None,
                    principal: None,
                },
            ],
        };

        let policies_with_arns = vec![("arn:aws:iam::123456789012:policy/S3WithDeny".to_string(), &policy)];

        // Test access to regular bucket (should be allowed)
        let allowed_request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::regular-bucket/file.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&allowed_request, "user", &policies_with_arns);
        assert!(response.allowed, "Access to regular bucket should be allowed by allow statement");

        // Test access to secret bucket (should be denied by explicit deny)
        let denied_request = AuthorizeRequest {
            access_key_id: "AKIATEST123".to_string(),
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::secret-bucket/secret.txt".to_string(),
            context: std::collections::HashMap::new(),
        };

        let response = auth_manager.authorize_for_user_with_arns(&denied_request, "user", &policies_with_arns);
        assert!(!response.allowed, "Access to secret bucket should be denied by explicit deny statement");
    }
}
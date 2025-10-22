use crate::types::*;

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: vec![],
            warnings: vec![],
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
            warnings: vec![],
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

pub struct PreparedPolicy {
    pub original: PolicyDocument,
    pub compiled: Box<dyn std::any::Any + Send + Sync>,
}

pub trait AuthorizationManagerTrait: Send + Sync {
    fn authorize(&self, request: &AuthorizeRequest, policies: &[PolicyDocument]) -> AuthorizeResponse {
        self.authorize_with_arns(request, &policies.iter().enumerate().map(|(i, p)| (format!("policy-{i}"), p)).collect::<Vec<_>>())
    }

    fn authorize_for_user(&self, request: &AuthorizeRequest, user_name: &str, policies: &[PolicyDocument]) -> AuthorizeResponse {
        self.authorize_for_user_with_arns(request, user_name, &policies.iter().enumerate().map(|(i, p)| (format!("policy-{i}"), p)).collect::<Vec<_>>())
    }

    fn authorize_with_arns(&self, request: &AuthorizeRequest, policies_with_arns: &[(String, &PolicyDocument)]) -> AuthorizeResponse;

    fn authorize_for_user_with_arns(&self, request: &AuthorizeRequest, user_name: &str, policies_with_arns: &[(String, &PolicyDocument)]) -> AuthorizeResponse;

    fn validate_policy(&self, policy: &PolicyDocument) -> ValidationResult;

    fn prepare_policy(&self, policy: &PolicyDocument) -> anyhow::Result<PreparedPolicy>;
}


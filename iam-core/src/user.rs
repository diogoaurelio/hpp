use crate::types::*;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Trait defining the user management interface for IAM operations
pub trait UserManagerTrait: Send + Sync {
    fn create_user(&mut self, request: CreateUserRequest) -> Result<User>;
    fn get_user(&self, user_name: &str) -> Option<User>;
    fn list_users(&self) -> Vec<User>;
    fn delete_user(&mut self, user_name: &str) -> Result<()>;
    fn create_access_key(&mut self, request: CreateAccessKeyRequest) -> Result<AccessKey>;
    fn get_access_key(&self, access_key_id: &str) -> Option<AccessKey>;
    fn list_access_keys(&self, user_name: &str) -> Vec<AccessKey>;
    fn delete_access_key(&mut self, access_key_id: &str) -> Result<()>;
    fn update_access_key_status(&mut self, access_key_id: &str, status: KeyStatus) -> Result<()>;
    fn validate_access_key(&self, access_key_id: &str, secret_key: &str) -> bool;
}

pub struct InMemoryUserManager {
    users: HashMap<String, User>,
    access_keys: HashMap<String, AccessKey>,
    user_access_keys: HashMap<String, Vec<String>>, // user_name -> access_key_ids
}

impl InMemoryUserManager {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            access_keys: HashMap::new(),
            user_access_keys: HashMap::new(),
        }
    }
}

impl UserManagerTrait for InMemoryUserManager {
    fn create_user(&mut self, request: CreateUserRequest) -> Result<User> {
        if self.users.contains_key(&request.user_name) {
            return Err(anyhow::anyhow!("User already exists"));
        }

        let user_id = Uuid::new_v4().to_string();
        let path = request.path.unwrap_or_else(|| "/".to_string());
        let arn = format!("arn:aws:iam::123456789012:user{}{}", path, request.user_name);

        let user = User {
            user_id,
            user_name: request.user_name.clone(),
            path,
            create_date: Utc::now(),
            arn,
            max_session_duration: None,
            permissions_boundary: request.permissions_boundary,
            tags: request.tags.unwrap_or_default(),
        };

        self.users.insert(request.user_name, user.clone());
        Ok(user)
    }

    fn get_user(&self, user_name: &str) -> Option<User> {
        self.users.get(user_name).cloned()
    }

    fn list_users(&self) -> Vec<User> {
        self.users.values().cloned().collect()
    }

    fn delete_user(&mut self, user_name: &str) -> Result<()> {
        if !self.users.contains_key(user_name) {
            return Err(anyhow::anyhow!("User does not exist"));
        }

        // Check if user has access keys
        if let Some(access_key_ids) = self.user_access_keys.get(user_name) {
            if !access_key_ids.is_empty() {
                return Err(anyhow::anyhow!("Cannot delete user with active access keys"));
            }
        }

        self.users.remove(user_name);
        Ok(())
    }

    fn create_access_key(&mut self, request: CreateAccessKeyRequest) -> Result<AccessKey> {
        if !self.users.contains_key(&request.user_name) {
            return Err(anyhow::anyhow!("User does not exist"));
        }

        // Check if user already has 2 access keys (AWS limit)
        let existing_keys = self.user_access_keys
            .get(&request.user_name)
            .map(|keys| keys.len())
            .unwrap_or(0);

        if existing_keys >= 2 {
            return Err(anyhow::anyhow!("User already has maximum number of access keys"));
        }

        let access_key_id = format!("AKIA{}", generate_random_string(16));
        let secret_access_key = generate_random_string(40);

        let access_key = AccessKey {
            access_key_id: access_key_id.clone(),
            secret_access_key,
            status: KeyStatus::Active,
            create_date: Utc::now(),
            user_name: request.user_name.clone(),
        };

        self.access_keys.insert(access_key_id.clone(), access_key.clone());
        self.user_access_keys
            .entry(request.user_name)
            .or_insert_with(Vec::new)
            .push(access_key_id);

        Ok(access_key)
    }

    fn get_access_key(&self, access_key_id: &str) -> Option<AccessKey> {
        self.access_keys.get(access_key_id).cloned()
    }

    fn list_access_keys(&self, user_name: &str) -> Vec<AccessKey> {
        if let Some(access_key_ids) = self.user_access_keys.get(user_name) {
            access_key_ids
                .iter()
                .filter_map(|id| self.access_keys.get(id))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    fn delete_access_key(&mut self, access_key_id: &str) -> Result<()> {
        if let Some(access_key) = self.access_keys.remove(access_key_id) {
            if let Some(user_keys) = self.user_access_keys.get_mut(&access_key.user_name) {
                user_keys.retain(|id| id != access_key_id);
            }
            Ok(())
        } else {
            Err(anyhow::anyhow!("Access key does not exist"))
        }
    }

    fn update_access_key_status(&mut self, access_key_id: &str, status: KeyStatus) -> Result<()> {
        if let Some(access_key) = self.access_keys.get_mut(access_key_id) {
            access_key.status = status;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Access key does not exist"))
        }
    }

    fn validate_access_key(&self, access_key_id: &str, secret_key: &str) -> bool {
        if let Some(access_key) = self.access_keys.get(access_key_id) {
            matches!(access_key.status, KeyStatus::Active) && access_key.secret_access_key == secret_key
        } else {
            false
        }
    }
}

pub struct S3UserManager {
    s3_client: Box<dyn shared::S3ObjectStorageRepository>,
    bucket: String,
    // Cache for better performance - invalidated on writes
    users_cache: tokio::sync::RwLock<Option<std::collections::HashMap<String, User>>>,
    access_keys_cache: tokio::sync::RwLock<Option<std::collections::HashMap<String, AccessKey>>>,
    user_access_keys_cache: tokio::sync::RwLock<Option<std::collections::HashMap<String, Vec<String>>>>,
}

impl S3UserManager {
    pub fn new(s3_client: Box<dyn shared::S3ObjectStorageRepository>, bucket: String) -> Self {
        Self {
            s3_client,
            bucket,
            users_cache: tokio::sync::RwLock::new(None),
            access_keys_cache: tokio::sync::RwLock::new(None),
            user_access_keys_cache: tokio::sync::RwLock::new(None),
        }
    }

    async fn load_users(&self) -> Result<std::collections::HashMap<String, User>> {
        let request = shared::GetObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/users.json".to_string(),
        };

        match self.s3_client.get_object(request).await {
            Ok(response) => {
                let users_data = String::from_utf8(response.body.to_vec())?;
                let users: std::collections::HashMap<String, User> = serde_json::from_str(&users_data)?;
                Ok(users)
            }
            Err(_) => {
                // File doesn't exist yet, return empty map
                Ok(std::collections::HashMap::new())
            }
        }
    }

    async fn save_users(&self, users: &std::collections::HashMap<String, User>) -> Result<()> {
        let users_json = serde_json::to_string_pretty(users)?;
        let request = shared::PutObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/users.json".to_string(),
            body: bytes::Bytes::from(users_json),
            content_type: Some("application/json".to_string()),
            metadata: std::collections::HashMap::new(),
        };

        self.s3_client.put_object(request).await?;

        // Invalidate cache
        *self.users_cache.write().await = None;
        Ok(())
    }

    async fn load_access_keys(&self) -> Result<(std::collections::HashMap<String, AccessKey>, std::collections::HashMap<String, Vec<String>>)> {
        let request = shared::GetObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/access_keys.json".to_string(),
        };

        let (access_keys, user_access_keys) = match self.s3_client.get_object(request).await {
            Ok(response) => {
                let data = String::from_utf8(response.body.to_vec())?;
                let stored_data: StoredAccessKeysData = serde_json::from_str(&data)?;
                (stored_data.access_keys, stored_data.user_access_keys)
            }
            Err(_) => {
                // File doesn't exist yet, return empty maps
                (std::collections::HashMap::new(), std::collections::HashMap::new())
            }
        };

        Ok((access_keys, user_access_keys))
    }

    async fn save_access_keys(&self, access_keys: &std::collections::HashMap<String, AccessKey>, user_access_keys: &std::collections::HashMap<String, Vec<String>>) -> Result<()> {
        let data = StoredAccessKeysData {
            access_keys: access_keys.clone(),
            user_access_keys: user_access_keys.clone(),
        };

        let keys_json = serde_json::to_string_pretty(&data)?;
        let request = shared::PutObjectRequest {
            bucket: self.bucket.clone(),
            key: "iam/access_keys.json".to_string(),
            body: bytes::Bytes::from(keys_json),
            content_type: Some("application/json".to_string()),
            metadata: std::collections::HashMap::new(),
        };

        self.s3_client.put_object(request).await?;

        // Invalidate caches
        *self.access_keys_cache.write().await = None;
        *self.user_access_keys_cache.write().await = None;
        Ok(())
    }

    async fn get_users_cached(&self) -> Result<std::collections::HashMap<String, User>> {
        let cache_read = self.users_cache.read().await;
        if let Some(ref cached_users) = *cache_read {
            return Ok(cached_users.clone());
        }
        drop(cache_read);

        let users = self.load_users().await?;
        *self.users_cache.write().await = Some(users.clone());
        Ok(users)
    }

    async fn get_access_keys_cached(&self) -> Result<(std::collections::HashMap<String, AccessKey>, std::collections::HashMap<String, Vec<String>>)> {
        let keys_cache_read = self.access_keys_cache.read().await;
        let user_keys_cache_read = self.user_access_keys_cache.read().await;

        if let (Some(ref cached_keys), Some(ref cached_user_keys)) = (&*keys_cache_read, &*user_keys_cache_read) {
            return Ok((cached_keys.clone(), cached_user_keys.clone()));
        }
        drop(keys_cache_read);
        drop(user_keys_cache_read);

        let (access_keys, user_access_keys) = self.load_access_keys().await?;
        *self.access_keys_cache.write().await = Some(access_keys.clone());
        *self.user_access_keys_cache.write().await = Some(user_access_keys.clone());
        Ok((access_keys, user_access_keys))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredAccessKeysData {
    access_keys: std::collections::HashMap<String, AccessKey>,
    user_access_keys: std::collections::HashMap<String, Vec<String>>,
}

#[async_trait::async_trait]
impl UserManagerTrait for S3UserManager {
    fn create_user(&mut self, request: CreateUserRequest) -> Result<User> {
        // Convert to async by using tokio::task::block_in_place for now
        // In a real implementation, we'd make the trait async
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut users = self.get_users_cached().await?;

                if users.contains_key(&request.user_name) {
                    return Err(anyhow::anyhow!("User already exists"));
                }

                let path = request.path.unwrap_or_else(|| "/".to_string());
                let user = User {
                    user_id: uuid::Uuid::new_v4().to_string(),
                    user_name: request.user_name.clone(),
                    path: path.clone(),
                    create_date: chrono::Utc::now(),
                    arn: format!("arn:aws:iam::123456789012:user{}{}",
                        path,
                        request.user_name),
                    max_session_duration: None,
                    permissions_boundary: request.permissions_boundary,
                    tags: request.tags.unwrap_or_default(),
                };

                users.insert(request.user_name, user.clone());
                self.save_users(&users).await?;
                Ok(user)
            })
        })
    }

    fn get_user(&self, user_name: &str) -> Option<User> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.get_users_cached().await {
                    Ok(users) => users.get(user_name).cloned(),
                    Err(_) => None,
                }
            })
        })
    }

    fn list_users(&self) -> Vec<User> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.get_users_cached().await {
                    Ok(users) => users.values().cloned().collect(),
                    Err(_) => Vec::new(),
                }
            })
        })
    }

    fn delete_user(&mut self, user_name: &str) -> Result<()> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut users = self.get_users_cached().await?;
                let (_access_keys, user_access_keys) = self.get_access_keys_cached().await?;

                if !users.contains_key(user_name) {
                    return Err(anyhow::anyhow!("User does not exist"));
                }

                // Check if user has active access keys
                if let Some(user_keys) = user_access_keys.get(user_name) {
                    if !user_keys.is_empty() {
                        return Err(anyhow::anyhow!("Cannot delete user with active access keys"));
                    }
                }

                users.remove(user_name);
                self.save_users(&users).await?;
                Ok(())
            })
        })
    }

    fn create_access_key(&mut self, request: CreateAccessKeyRequest) -> Result<AccessKey> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let users = self.get_users_cached().await?;
                let (mut access_keys, mut user_access_keys) = self.get_access_keys_cached().await?;

                if !users.contains_key(&request.user_name) {
                    return Err(anyhow::anyhow!("User does not exist"));
                }

                // Check if user already has 2 access keys (AWS limit)
                let current_keys = user_access_keys.get(&request.user_name).map(|v| v.len()).unwrap_or(0);
                if current_keys >= 2 {
                    return Err(anyhow::anyhow!("User already has maximum number of access keys"));
                }

                let access_key = AccessKey {
                    access_key_id: format!("AKIA{}", generate_random_string(16)),
                    secret_access_key: generate_random_string(40),
                    status: KeyStatus::Active,
                    create_date: chrono::Utc::now(),
                    user_name: request.user_name.clone(),
                };

                access_keys.insert(access_key.access_key_id.clone(), access_key.clone());
                user_access_keys.entry(request.user_name).or_insert_with(Vec::new).push(access_key.access_key_id.clone());

                self.save_access_keys(&access_keys, &user_access_keys).await?;
                Ok(access_key)
            })
        })
    }

    fn get_access_key(&self, access_key_id: &str) -> Option<AccessKey> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.get_access_keys_cached().await {
                    Ok((access_keys, _)) => access_keys.get(access_key_id).cloned(),
                    Err(_) => None,
                }
            })
        })
    }

    fn list_access_keys(&self, user_name: &str) -> Vec<AccessKey> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.get_access_keys_cached().await {
                    Ok((access_keys, user_access_keys)) => {
                        if let Some(key_ids) = user_access_keys.get(user_name) {
                            key_ids.iter()
                                .filter_map(|id| access_keys.get(id))
                                .cloned()
                                .collect()
                        } else {
                            Vec::new()
                        }
                    }
                    Err(_) => Vec::new(),
                }
            })
        })
    }

    fn delete_access_key(&mut self, access_key_id: &str) -> Result<()> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (mut access_keys, mut user_access_keys) = self.get_access_keys_cached().await?;

                let access_key = access_keys.get(access_key_id).ok_or_else(|| anyhow::anyhow!("Access key does not exist"))?;
                let user_name = access_key.user_name.clone();

                access_keys.remove(access_key_id);

                if let Some(user_keys) = user_access_keys.get_mut(&user_name) {
                    user_keys.retain(|id| id != access_key_id);
                }

                self.save_access_keys(&access_keys, &user_access_keys).await?;
                Ok(())
            })
        })
    }

    fn update_access_key_status(&mut self, access_key_id: &str, status: KeyStatus) -> Result<()> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (mut access_keys, user_access_keys) = self.get_access_keys_cached().await?;

                let access_key = access_keys.get_mut(access_key_id).ok_or_else(|| anyhow::anyhow!("Access key does not exist"))?;
                access_key.status = status;

                self.save_access_keys(&access_keys, &user_access_keys).await?;
                Ok(())
            })
        })
    }

    fn validate_access_key(&self, access_key_id: &str, secret_key: &str) -> bool {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.get_access_keys_cached().await {
                    Ok((access_keys, _)) => {
                        if let Some(access_key) = access_keys.get(access_key_id) {
                            matches!(access_key.status, KeyStatus::Active) && access_key.secret_access_key == secret_key
                        } else {
                            false
                        }
                    }
                    Err(_) => false,
                }
            })
        })
    }
}

fn generate_random_string(length: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    Utc::now().timestamp_nanos_opt().unwrap_or_default().hash(&mut hasher);
    let hash = hasher.finish();

    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    (0..length)
        .map(|i| chars[(hash.wrapping_add(i as u64) as usize) % chars.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use shared::MockS3ObjectStorageRepository;

    #[test]
    fn test_create_user_success() {
        let mut user_manager = InMemoryUserManager::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: Some("/test/".to_string()),
            permissions_boundary: None,
            tags: None,
        };

        let result = user_manager.create_user(request);
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.user_name, "test-user");
        assert_eq!(user.path, "/test/");
        assert!(user.arn.contains("test-user"));
    }

    #[test]
    fn test_create_user_duplicate() {
        let mut user_manager = InMemoryUserManager::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        user_manager.create_user(request.clone()).unwrap();
        let result = user_manager.create_user(request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "User already exists");
    }

    #[test]
    fn test_get_user_success() {
        let mut user_manager = InMemoryUserManager::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        user_manager.create_user(request).unwrap();
        let user = user_manager.get_user("test-user");
        assert!(user.is_some());
        assert_eq!(user.unwrap().user_name, "test-user");
    }

    #[test]
    fn test_get_user_not_found() {
        let user_manager = InMemoryUserManager::new();
        let user = user_manager.get_user("nonexistent");
        assert!(user.is_none());
    }

    #[test]
    fn test_list_users_empty() {
        let user_manager = InMemoryUserManager::new();
        let users = user_manager.list_users();
        assert!(users.is_empty());
    }

    #[test]
    fn test_list_users_with_data() {
        let mut user_manager = InMemoryUserManager::new();

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

        user_manager.create_user(request1).unwrap();
        user_manager.create_user(request2).unwrap();

        let users = user_manager.list_users();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_delete_user_success() {
        let mut user_manager = InMemoryUserManager::new();
        let request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        user_manager.create_user(request).unwrap();
        let result = user_manager.delete_user("test-user");
        assert!(result.is_ok());

        let user = user_manager.get_user("test-user");
        assert!(user.is_none());
    }

    #[test]
    fn test_delete_user_not_found() {
        let mut user_manager = InMemoryUserManager::new();
        let result = user_manager.delete_user("nonexistent");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "User does not exist");
    }

    #[test]
    fn test_delete_user_with_active_access_keys() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        // Create access key
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        user_manager.create_access_key(key_request).unwrap();

        // Try to delete user
        let result = user_manager.delete_user("test-user");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Cannot delete user with active access keys");
    }

    #[test]
    fn test_create_access_key_success() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user first
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };

        let result = user_manager.create_access_key(key_request);
        assert!(result.is_ok());

        let access_key = result.unwrap();
        assert_eq!(access_key.user_name, "test-user");
        assert!(access_key.access_key_id.starts_with("AKIA"));
        assert_eq!(access_key.status, KeyStatus::Active);
    }

    #[test]
    fn test_create_access_key_user_not_found() {
        let mut user_manager = InMemoryUserManager::new();
        let key_request = CreateAccessKeyRequest {
            user_name: "nonexistent".to_string(),
        };

        let result = user_manager.create_access_key(key_request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "User does not exist");
    }

    #[test]
    fn test_create_access_key_max_limit() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        // Create 2 access keys (AWS limit)
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        user_manager.create_access_key(key_request.clone()).unwrap();
        user_manager.create_access_key(key_request.clone()).unwrap();

        // Try to create a third
        let result = user_manager.create_access_key(key_request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "User already has maximum number of access keys");
    }

    #[test]
    fn test_get_access_key_success() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = user_manager.create_access_key(key_request).unwrap();

        let retrieved_key = user_manager.get_access_key(&created_key.access_key_id);
        assert!(retrieved_key.is_some());
        assert_eq!(retrieved_key.unwrap().access_key_id, created_key.access_key_id);
    }

    #[test]
    fn test_get_access_key_not_found() {
        let user_manager = InMemoryUserManager::new();
        let key = user_manager.get_access_key("nonexistent");
        assert!(key.is_none());
    }

    #[test]
    fn test_list_access_keys() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        // Create access key
        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        user_manager.create_access_key(key_request).unwrap();

        let keys = user_manager.list_access_keys("test-user");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].user_name, "test-user");
    }

    #[test]
    fn test_list_access_keys_empty() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user but no access keys
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let keys = user_manager.list_access_keys("test-user");
        assert!(keys.is_empty());
    }

    #[test]
    fn test_delete_access_key_success() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = user_manager.create_access_key(key_request).unwrap();

        let result = user_manager.delete_access_key(&created_key.access_key_id);
        assert!(result.is_ok());

        let key = user_manager.get_access_key(&created_key.access_key_id);
        assert!(key.is_none());
    }

    #[test]
    fn test_delete_access_key_not_found() {
        let mut user_manager = InMemoryUserManager::new();
        let result = user_manager.delete_access_key("nonexistent");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Access key does not exist");
    }

    #[test]
    fn test_update_access_key_status() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = user_manager.create_access_key(key_request).unwrap();

        let result = user_manager.update_access_key_status(&created_key.access_key_id, KeyStatus::Inactive);
        assert!(result.is_ok());

        let updated_key = user_manager.get_access_key(&created_key.access_key_id).unwrap();
        assert_eq!(updated_key.status, KeyStatus::Inactive);
    }

    #[test]
    fn test_validate_access_key_success() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = user_manager.create_access_key(key_request).unwrap();

        let is_valid = user_manager.validate_access_key(&created_key.access_key_id, &created_key.secret_access_key);
        assert!(is_valid);
    }

    #[test]
    fn test_validate_access_key_invalid_secret() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = user_manager.create_access_key(key_request).unwrap();

        let is_valid = user_manager.validate_access_key(&created_key.access_key_id, "wrong-secret");
        assert!(!is_valid);
    }

    #[test]
    fn test_validate_access_key_inactive() {
        let mut user_manager = InMemoryUserManager::new();

        // Create user and access key
        let user_request = CreateUserRequest {
            user_name: "test-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        user_manager.create_user(user_request).unwrap();

        let key_request = CreateAccessKeyRequest {
            user_name: "test-user".to_string(),
        };
        let created_key = user_manager.create_access_key(key_request).unwrap();

        // Make key inactive
        user_manager.update_access_key_status(&created_key.access_key_id, KeyStatus::Inactive).unwrap();

        let is_valid = user_manager.validate_access_key(&created_key.access_key_id, &created_key.secret_access_key);
        assert!(!is_valid);
    }

    #[test]
    fn test_user_manager_trait_implementation() {
        let mut user_manager: Box<dyn UserManagerTrait> = Box::new(InMemoryUserManager::new());

        // Test create_user through trait
        let request = CreateUserRequest {
            user_name: "trait-user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };

        let result = user_manager.create_user(request);
        assert!(result.is_ok());

        // Test get_user through trait
        let user = user_manager.get_user("trait-user");
        assert!(user.is_some());
        assert_eq!(user.unwrap().user_name, "trait-user");
    }

    // S3UserManager Tests
    #[cfg(feature = "testing")]
    mod s3_user_manager_tests {
        use super::*;
        use bytes::Bytes;
        use std::collections::HashMap;

        fn create_mock_s3_client() -> MockS3ObjectStorageRepository {
            MockS3ObjectStorageRepository::new()
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn test_s3_user_manager_create_user_success() {
            let mut mock_s3 = create_mock_s3_client();

            // Mock get_object to return empty users initially (file not found)
            mock_s3
                .expect_get_object()
                .returning(|_| Box::pin(async { Err(anyhow::anyhow!("File not found")) }));

            // Mock put_object for saving users
            mock_s3
                .expect_put_object()
                .returning(|_| Box::pin(async { Ok("etag".to_string()) }));

            let mut user_manager = S3UserManager::new(Box::new(mock_s3), "test-bucket".to_string());

            let request = CreateUserRequest {
                user_name: "test-user".to_string(),
                path: Some("/test/".to_string()),
                permissions_boundary: None,
                tags: None,
            };

            let result = user_manager.create_user(request);
            assert!(result.is_ok());

            let user = result.unwrap();
            assert_eq!(user.user_name, "test-user");
            assert_eq!(user.path, "/test/");
            assert!(user.arn.contains("test-user"));
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn test_s3_user_manager_get_user_success() {
            let mut mock_s3 = create_mock_s3_client();

            let existing_users = HashMap::from([
                ("test-user".to_string(), User {
                    user_id: "existing-id".to_string(),
                    user_name: "test-user".to_string(),
                    path: "/".to_string(),
                    create_date: chrono::Utc::now(),
                    arn: "arn:aws:iam::123456789012:user/test-user".to_string(),
                    max_session_duration: None,
                    permissions_boundary: None,
                    tags: vec![],
                })
            ]);
            let users_json = serde_json::to_string(&existing_users).unwrap();

            mock_s3
                .expect_get_object()
                .returning(move |_| {
                    let users_json = users_json.clone();
                    Box::pin(async move {
                        let content_length = users_json.len() as u64;
                        Ok(shared::GetObjectResponse {
                            body: Bytes::from(users_json),
                            content_type: Some("application/json".to_string()),
                            content_length,
                            etag: "etag".to_string(),
                            last_modified: chrono::Utc::now(),
                            metadata: HashMap::new(),
                        })
                    })
                });

            let user_manager = S3UserManager::new(Box::new(mock_s3), "test-bucket".to_string());

            let user = user_manager.get_user("test-user");
            assert!(user.is_some());
            assert_eq!(user.unwrap().user_name, "test-user");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn test_s3_user_manager_get_user_not_found() {
            let mut mock_s3 = create_mock_s3_client();

            // Mock get_object to return file not found
            mock_s3
                .expect_get_object()
                .returning(|_| Box::pin(async { Err(anyhow::anyhow!("File not found")) }));

            let user_manager = S3UserManager::new(Box::new(mock_s3), "test-bucket".to_string());

            let user = user_manager.get_user("nonexistent");
            assert!(user.is_none());
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn test_s3_user_manager_list_users() {
            let mut mock_s3 = create_mock_s3_client();

            let existing_users = HashMap::from([
                ("user1".to_string(), User {
                    user_id: "id1".to_string(),
                    user_name: "user1".to_string(),
                    path: "/".to_string(),
                    create_date: chrono::Utc::now(),
                    arn: "arn:aws:iam::123456789012:user/user1".to_string(),
                    max_session_duration: None,
                    permissions_boundary: None,
                    tags: vec![],
                }),
                ("user2".to_string(), User {
                    user_id: "id2".to_string(),
                    user_name: "user2".to_string(),
                    path: "/".to_string(),
                    create_date: chrono::Utc::now(),
                    arn: "arn:aws:iam::123456789012:user/user2".to_string(),
                    max_session_duration: None,
                    permissions_boundary: None,
                    tags: vec![],
                })
            ]);
            let users_json = serde_json::to_string(&existing_users).unwrap();

            mock_s3
                .expect_get_object()
                .returning(move |_| {
                    let users_json = users_json.clone();
                    Box::pin(async move {
                        let content_length = users_json.len() as u64;
                        Ok(shared::GetObjectResponse {
                            body: Bytes::from(users_json),
                            content_type: Some("application/json".to_string()),
                            content_length,
                            etag: "etag".to_string(),
                            last_modified: chrono::Utc::now(),
                            metadata: HashMap::new(),
                        })
                    })
                });

            let user_manager = S3UserManager::new(Box::new(mock_s3), "test-bucket".to_string());

            let users = user_manager.list_users();
            assert_eq!(users.len(), 2);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn test_s3_user_manager_create_access_key_success() {
            let mut mock_s3 = create_mock_s3_client();

            // Mock get_object for users
            let existing_users = HashMap::from([
                ("test-user".to_string(), User {
                    user_id: "existing-id".to_string(),
                    user_name: "test-user".to_string(),
                    path: "/".to_string(),
                    create_date: chrono::Utc::now(),
                    arn: "arn:aws:iam::123456789012:user/test-user".to_string(),
                    max_session_duration: None,
                    permissions_boundary: None,
                    tags: vec![],
                })
            ]);
            let users_json = serde_json::to_string(&existing_users).unwrap();

            let empty_access_keys: HashMap<String, AccessKey> = HashMap::new();
            let empty_user_access_keys: HashMap<String, Vec<String>> = HashMap::new();
            let access_keys_data = StoredAccessKeysData {
                access_keys: empty_access_keys,
                user_access_keys: empty_user_access_keys,
            };
            let access_keys_json = serde_json::to_string(&access_keys_data).unwrap();

            mock_s3
                .expect_get_object()
                .returning(move |req| {
                    let users_json = users_json.clone();
                    let access_keys_json = access_keys_json.clone();
                    Box::pin(async move {
                        if req.key == "iam/users.json" {
                            let content_length = users_json.len() as u64;
                            Ok(shared::GetObjectResponse {
                                body: Bytes::from(users_json),
                                content_type: Some("application/json".to_string()),
                                content_length,
                                etag: "etag".to_string(),
                                last_modified: chrono::Utc::now(),
                                metadata: HashMap::new(),
                            })
                        } else {
                            let content_length = access_keys_json.len() as u64;
                            Ok(shared::GetObjectResponse {
                                body: Bytes::from(access_keys_json),
                                content_type: Some("application/json".to_string()),
                                content_length,
                                etag: "etag".to_string(),
                                last_modified: chrono::Utc::now(),
                                metadata: HashMap::new(),
                            })
                        }
                    })
                });

            // Mock put_object for saving access keys
            mock_s3
                .expect_put_object()
                .returning(|_| Box::pin(async { Ok("etag".to_string()) }));

            let mut user_manager = S3UserManager::new(Box::new(mock_s3), "test-bucket".to_string());

            let request = CreateAccessKeyRequest {
                user_name: "test-user".to_string(),
            };

            let result = user_manager.create_access_key(request);
            assert!(result.is_ok());

            let access_key = result.unwrap();
            assert_eq!(access_key.user_name, "test-user");
            assert!(access_key.access_key_id.starts_with("AKIA"));
            assert_eq!(access_key.status, KeyStatus::Active);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn test_s3_user_manager_validate_access_key() {
            let mut mock_s3 = create_mock_s3_client();

            let access_key = AccessKey {
                access_key_id: "AKIATEST123".to_string(),
                secret_access_key: "secret123".to_string(),
                status: KeyStatus::Active,
                create_date: chrono::Utc::now(),
                user_name: "test-user".to_string(),
            };

            let access_keys = HashMap::from([
                ("AKIATEST123".to_string(), access_key)
            ]);
            let user_access_keys = HashMap::from([
                ("test-user".to_string(), vec!["AKIATEST123".to_string()])
            ]);
            let access_keys_data = StoredAccessKeysData {
                access_keys,
                user_access_keys,
            };
            let access_keys_json = serde_json::to_string(&access_keys_data).unwrap();

            mock_s3
                .expect_get_object()
                .returning(move |_| {
                    let access_keys_json = access_keys_json.clone();
                    Box::pin(async move {
                        let content_length = access_keys_json.len() as u64;
                        Ok(shared::GetObjectResponse {
                            body: Bytes::from(access_keys_json),
                            content_type: Some("application/json".to_string()),
                            content_length,
                            etag: "etag".to_string(),
                            last_modified: chrono::Utc::now(),
                            metadata: HashMap::new(),
                        })
                    })
                });

            let user_manager = S3UserManager::new(Box::new(mock_s3), "test-bucket".to_string());

            let is_valid = user_manager.validate_access_key("AKIATEST123", "secret123");
            assert!(is_valid);

            let is_invalid = user_manager.validate_access_key("AKIATEST123", "wrong-secret");
            assert!(!is_invalid);
        }
    }
}
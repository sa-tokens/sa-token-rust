// Author: 金书记
//
//! Refresh Token Module | Refresh Token 模块
//!
//! Implements token refresh mechanism for long-term authentication
//! 实现长期认证的 Token 刷新机制

use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use sa_token_adapter::storage::SaStorage;
use crate::error::{SaTokenError, SaTokenResult};
use crate::token::TokenValue;
use crate::token::TokenGenerator;
use crate::config::SaTokenConfig;
use uuid::Uuid;

/// Refresh Token Manager | Refresh Token 管理器
///
/// Manages refresh token generation, validation, and access token renewal
/// 管理 refresh token 的生成、验证和访问令牌的更新
#[derive(Clone)]
pub struct RefreshTokenManager {
    storage: Arc<dyn SaStorage>,
    config: Arc<SaTokenConfig>,
}

impl RefreshTokenManager {
    /// Create new refresh token manager | 创建新的 refresh token 管理器
    ///
    /// # Arguments | 参数
    ///
    /// * `storage` - Storage backend | 存储后端
    /// * `config` - Sa-token configuration | Sa-token 配置
    pub fn new(storage: Arc<dyn SaStorage>, config: Arc<SaTokenConfig>) -> Self {
        Self { storage, config }
    }

    /// Generate a new refresh token | 生成新的 refresh token
    ///
    /// # Arguments | 参数
    ///
    /// * `login_id` - User login ID | 用户登录ID
    ///
    /// # Returns | 返回
    ///
    /// Refresh token string | Refresh token 字符串
    pub fn generate(&self, login_id: &str) -> String {
        // Format: refresh_TIMESTAMP_LOGINID_UUID
        format!(
            "refresh_{}_{}_{}",
            Utc::now().timestamp_millis(),
            login_id,
            Uuid::new_v4().simple()
        )
    }

    /// Store refresh token with associated access token | 存储 refresh token 及其关联的访问令牌
    ///
    /// # Arguments | 参数
    ///
    /// * `refresh_token` - Refresh token | Refresh token
    /// * `access_token` - Associated access token | 关联的访问令牌
    /// * `login_id` - User login ID | 用户登录ID
    /// * `extra_data` - Extra data from JWT claims (tenant_id, username, etc.)
    pub async fn store(
        &self,
        refresh_token: &str,
        access_token: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.store_with_extra(refresh_token, access_token, login_id, None).await
    }

    /// Store refresh token with associated access token and extra data
    ///
    /// # Arguments | 参数
    ///
    /// * `refresh_token` - Refresh token | Refresh token
    /// * `access_token` - Associated access token | 关联的访问令牌
    /// * `login_id` - User login ID | 用户登录ID
    /// * `extra_data` - Optional extra data to preserve across refresh
    pub async fn store_with_extra(
        &self,
        refresh_token: &str,
        access_token: &str,
        login_id: &str,
        extra_data: Option<&serde_json::Value>,
    ) -> SaTokenResult<()> {
        let key = format!("sa:refresh:{}", refresh_token);
        let expire_time = if self.config.refresh_token_timeout > 0 {
            Some(Utc::now() + Duration::seconds(self.config.refresh_token_timeout))
        } else {
            None
        };

        let mut obj = serde_json::json!({
            "access_token": access_token,
            "login_id": login_id,
            "created_at": Utc::now().to_rfc3339(),
            "expire_time": expire_time.map(|t| t.to_rfc3339()),
        });
        if let Some(extra) = extra_data {
            obj["extra_data"] = extra.clone();
        }
        let value = obj.to_string();

        let ttl = if self.config.refresh_token_timeout > 0 {
            Some(std::time::Duration::from_secs(self.config.refresh_token_timeout as u64))
        } else {
            None
        };

        self.storage.set(&key, &value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Validate refresh token | 验证 refresh token
    ///
    /// # Arguments | 参数
    ///
    /// * `refresh_token` - Refresh token to validate | 要验证的 refresh token
    ///
    /// # Returns | 返回
    ///
    /// Associated login_id if valid | 如果有效则返回关联的 login_id
    pub async fn validate(&self, refresh_token: &str) -> SaTokenResult<String> {
        let key = format!("sa:refresh:{}", refresh_token);
        
        let value_str = self.storage.get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or_else(|| SaTokenError::RefreshTokenNotFound)?;

        let value: serde_json::Value = serde_json::from_str(&value_str)
            .map_err(|_| SaTokenError::RefreshTokenInvalidData)?;

        let login_id = value["login_id"].as_str()
            .ok_or_else(|| SaTokenError::RefreshTokenMissingLoginId)?
            .to_string();

        // Check expiration if set
        if let Some(expire_str) = value["expire_time"].as_str() {
            let expire_time = DateTime::parse_from_rfc3339(expire_str)
                .map_err(|_| SaTokenError::RefreshTokenInvalidExpireTime)?
                .with_timezone(&Utc);

            if Utc::now() > expire_time {
                // Delete expired refresh token
                self.delete(refresh_token).await?;
                return Err(SaTokenError::TokenExpired);
            }
        }

        Ok(login_id)
    }

    /// Refresh access token using refresh token | 使用 refresh token 刷新访问令牌
    ///
    /// # Arguments | 参数
    ///
    /// * `refresh_token` - Refresh token | Refresh token
    ///
    /// # Returns | 返回
    ///
    /// New access token and login_id | 新的访问令牌和 login_id
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> SaTokenResult<(TokenValue, String)> {
        // Validate refresh token
        let login_id = self.validate(refresh_token).await?;

        // Read stored refresh token data (contains extra_data)
        let key = format!("sa:refresh:{}", refresh_token);
        let value_str = self.storage.get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or_else(|| SaTokenError::RefreshTokenNotFound)?;

        let mut value: serde_json::Value = serde_json::from_str(&value_str)
            .map_err(|_| SaTokenError::RefreshTokenInvalidData)?;

        // Generate new access token (with extra_data if present)
        let extra_data = value.get("extra_data").cloned();
        let new_access_token = match &extra_data {
            Some(extra) => TokenGenerator::generate_with_login_id_and_extra(&self.config, &login_id, extra),
            None => TokenGenerator::generate_with_login_id(&self.config, &login_id),
        };

        // Update stored refresh token with new access token
        value["access_token"] = serde_json::json!(new_access_token.as_str());
        value["refreshed_at"] = serde_json::json!(Utc::now().to_rfc3339());

        let ttl = if self.config.refresh_token_timeout > 0 {
            Some(std::time::Duration::from_secs(self.config.refresh_token_timeout as u64))
        } else {
            None
        };

        self.storage.set(&key, &value.to_string(), ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok((new_access_token, login_id))
    }

    /// Delete refresh token | 删除 refresh token
    ///
    /// # Arguments | 参数
    ///
    /// * `refresh_token` - Refresh token to delete | 要删除的 refresh token
    pub async fn delete(&self, refresh_token: &str) -> SaTokenResult<()> {
        let key = format!("sa:refresh:{}", refresh_token);
        self.storage.delete(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Get all refresh tokens for a user | 获取用户的所有 refresh token
    ///
    /// Note: This requires storage backend to support prefix scanning
    /// 注意：这需要存储后端支持前缀扫描
    pub async fn get_user_refresh_tokens(&self, _login_id: &str) -> SaTokenResult<Vec<String>> {
        // This is a placeholder - actual implementation depends on storage capabilities
        // 这是一个占位符 - 实际实现取决于存储能力
        // Most implementations would need to maintain a separate index
        // 大多数实现需要维护一个单独的索引
        Ok(vec![])
    }

    /// Revoke all refresh tokens for a user | 撤销用户的所有 refresh token
    ///
    /// # Arguments | 参数
    ///
    /// * `login_id` - User login ID | 用户登录ID
    pub async fn revoke_all_for_user(&self, login_id: &str) -> SaTokenResult<()> {
        let tokens = self.get_user_refresh_tokens(login_id).await?;
        for token in tokens {
            self.delete(&token).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;
    use crate::config::TokenStyle;

    fn create_test_config() -> Arc<SaTokenConfig> {
        Arc::new(SaTokenConfig {
            token_style: TokenStyle::Uuid,
            timeout: 3600,
            refresh_token_timeout: 7200,
            enable_refresh_token: true,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_refresh_token_generation() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage, config);

        let token1 = refresh_mgr.generate("user_123");
        let token2 = refresh_mgr.generate("user_123");

        assert_ne!(token1, token2);
        assert!(token1.starts_with("refresh_"));
    }

    #[tokio::test]
    async fn test_refresh_token_store_and_validate() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage, config);

        let refresh_token = refresh_mgr.generate("user_123");
        let access_token = "access_token_123";

        // Store refresh token
        refresh_mgr.store(&refresh_token, access_token, "user_123").await.unwrap();

        // Validate refresh token
        let login_id = refresh_mgr.validate(&refresh_token).await.unwrap();
        assert_eq!(login_id, "user_123");
    }

    #[tokio::test]
    async fn test_refresh_access_token() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage, config);

        let refresh_token = refresh_mgr.generate("user_123");
        let old_access_token = "old_access_token";

        // Store refresh token
        refresh_mgr.store(&refresh_token, old_access_token, "user_123").await.unwrap();

        // Refresh access token
        let (new_access_token, login_id) = refresh_mgr.refresh_access_token(&refresh_token).await.unwrap();

        assert_eq!(login_id, "user_123");
        assert_ne!(new_access_token.as_str(), old_access_token);
    }

    #[tokio::test]
    async fn test_delete_refresh_token() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage, config);

        let refresh_token = refresh_mgr.generate("user_123");
        refresh_mgr.store(&refresh_token, "access", "user_123").await.unwrap();

        // Delete refresh token
        refresh_mgr.delete(&refresh_token).await.unwrap();

        // Validation should fail
        let result = refresh_mgr.validate(&refresh_token).await;
        assert!(result.is_err());
    }
}


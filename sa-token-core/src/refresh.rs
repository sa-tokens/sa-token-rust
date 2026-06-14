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
use crate::token::{TokenInfo, TokenValue, TokenGenerator};
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
    pub fn new(storage: Arc<dyn SaStorage>, config: Arc<SaTokenConfig>) -> Self {
        Self { storage, config }
    }

    /// refresh token 存储键：{prefix}refresh:{token}
    fn refresh_key(&self, refresh_token: &str) -> String {
        self.config.make_key("refresh:", refresh_token)
    }

    /// 用户 refresh token 索引键：{prefix}refresh:user:{login_id}
    fn user_index_key(&self, login_id: &str) -> String {
        self.config.make_key("refresh:user:", login_id)
    }

    async fn load_string_list(&self, key: &str) -> SaTokenResult<Vec<String>> {
        match self
            .storage
            .get(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
        {
            Some(value) => serde_json::from_str(&value).map_err(SaTokenError::SerializationError),
            None => Ok(Vec::new()),
        }
    }

    async fn save_string_list(&self, key: &str, list: &[String]) -> SaTokenResult<()> {
        let value = serde_json::to_string(list).map_err(SaTokenError::SerializationError)?;
        self.storage
            .set(key, &value, None)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 将 refresh token 追加到用户索引（去重）
    async fn append_user_index(&self, login_id: &str, refresh_token: &str) -> SaTokenResult<()> {
        let key = self.user_index_key(login_id);
        let mut list = self.load_string_list(&key).await?;
        if !list.iter().any(|t| t == refresh_token) {
            list.push(refresh_token.to_string());
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// 从用户索引移除 refresh token
    async fn remove_user_index(&self, login_id: &str, refresh_token: &str) -> SaTokenResult<()> {
        let key = self.user_index_key(login_id);
        let mut list = self.load_string_list(&key).await?;
        let before = list.len();
        list.retain(|t| t != refresh_token);
        if list.len() != before {
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// Generate a new refresh token | 生成新的 refresh token
    pub fn generate(&self, login_id: &str) -> String {
        format!(
            "refresh_{}_{}_{}",
            Utc::now().timestamp_millis(),
            login_id,
            Uuid::new_v4().simple()
        )
    }

    /// Store refresh token with associated access token | 存储 refresh token 及其关联的访问令牌
    pub async fn store(
        &self,
        refresh_token: &str,
        access_token: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.store_with_extra(refresh_token, access_token, login_id, None)
            .await
    }

    /// Store refresh token with associated access token and extra data
    pub async fn store_with_extra(
        &self,
        refresh_token: &str,
        access_token: &str,
        login_id: &str,
        extra_data: Option<&serde_json::Value>,
    ) -> SaTokenResult<()> {
        let key = self.refresh_key(refresh_token);
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
            Some(std::time::Duration::from_secs(
                self.config.refresh_token_timeout as u64,
            ))
        } else {
            None
        };

        self.storage
            .set(&key, &value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        self.append_user_index(login_id, refresh_token).await?;
        Ok(())
    }

    /// Validate refresh token | 验证 refresh token
    pub async fn validate(&self, refresh_token: &str) -> SaTokenResult<String> {
        let key = self.refresh_key(refresh_token);

        let value_str = self
            .storage
            .get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::RefreshTokenNotFound)?;

        let value: serde_json::Value = serde_json::from_str(&value_str)
            .map_err(|_| SaTokenError::RefreshTokenInvalidData)?;

        let login_id = value["login_id"]
            .as_str()
            .ok_or(SaTokenError::RefreshTokenMissingLoginId)?
            .to_string();

        if let Some(expire_str) = value["expire_time"].as_str() {
            let expire_time = DateTime::parse_from_rfc3339(expire_str)
                .map_err(|_| SaTokenError::RefreshTokenInvalidExpireTime)?
                .with_timezone(&Utc);

            if Utc::now() > expire_time {
                self.delete(refresh_token).await?;
                return Err(SaTokenError::TokenExpired);
            }
        }

        Ok(login_id)
    }

    /// Refresh access token using refresh token | 使用 refresh token 刷新访问令牌
    ///
    /// 生成新 access token 并回写 `{prefix}token:{token}` 存储，与 SaTokenManager 登录态对齐。
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> SaTokenResult<(TokenValue, String)> {
        let login_id = self.validate(refresh_token).await?;

        let key = self.refresh_key(refresh_token);
        let value_str = self
            .storage
            .get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::RefreshTokenNotFound)?;

        let mut value: serde_json::Value = serde_json::from_str(&value_str)
            .map_err(|_| SaTokenError::RefreshTokenInvalidData)?;

        let extra_data = value.get("extra_data").cloned();
        let new_access_token = match &extra_data {
            Some(extra) => {
                TokenGenerator::generate_with_login_id_and_extra(&self.config, &login_id, extra)
            }
            None => TokenGenerator::generate_with_login_id(&self.config, &login_id),
        };

        // 构造并写入新的 TokenInfo（与 Manager 登录路径一致的存储键）
        let mut token_info = TokenInfo::new(new_access_token.clone(), login_id.clone());
        token_info.update_active_time();
        token_info.refresh_token = Some(refresh_token.to_string());
        if self.config.refresh_token_timeout > 0 {
            token_info.refresh_token_expire_time = Some(
                Utc::now() + Duration::seconds(self.config.refresh_token_timeout),
            );
        }
        if let Some(extra) = &extra_data {
            token_info.extra_data = Some(extra.clone());
        }
        if token_info.expire_time.is_none()
            && let Some(timeout) = self.config.timeout_duration()
        {
            token_info.expire_time =
                Some(Utc::now() + Duration::from_std(timeout).unwrap());
        }

        let token_key = self.config.make_key("token:", new_access_token.as_str());
        let token_json = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;
        self.storage
            .set(&token_key, &token_json, self.config.timeout_duration())
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        // 更新 login_id -> token 映射
        let login_token_key = self.config.make_key("login:token:", &login_id);
        self.storage
            .set(
                &login_token_key,
                new_access_token.as_str(),
                self.config.timeout_duration(),
            )
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        value["access_token"] = serde_json::json!(new_access_token.as_str());
        value["refreshed_at"] = serde_json::json!(Utc::now().to_rfc3339());

        let ttl = if self.config.refresh_token_timeout > 0 {
            Some(std::time::Duration::from_secs(
                self.config.refresh_token_timeout as u64,
            ))
        } else {
            None
        };

        self.storage
            .set(&key, &value.to_string(), ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok((new_access_token, login_id))
    }

    /// Delete refresh token | 删除 refresh token
    pub async fn delete(&self, refresh_token: &str) -> SaTokenResult<()> {
        let key = self.refresh_key(refresh_token);

        // 读取 login_id 以便清理用户索引
        if let Ok(Some(value_str)) = self.storage.get(&key).await {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&value_str)
                && let Some(login_id) = value["login_id"].as_str()
            {
                let _ = self.remove_user_index(login_id, refresh_token).await;
            }
        }

        self.storage
            .delete(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Get all refresh tokens for a user | 获取用户的所有 refresh token
    pub async fn get_user_refresh_tokens(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.load_string_list(&self.user_index_key(login_id)).await
    }

    /// Revoke all refresh tokens for a user | 撤销用户的所有 refresh token
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

        refresh_mgr
            .store(&refresh_token, access_token, "user_123")
            .await
            .unwrap();

        let login_id = refresh_mgr.validate(&refresh_token).await.unwrap();
        assert_eq!(login_id, "user_123");

        let tokens = refresh_mgr.get_user_refresh_tokens("user_123").await.unwrap();
        assert_eq!(tokens, vec![refresh_token]);
    }

    #[tokio::test]
    async fn test_refresh_access_token() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage.clone(), config.clone());

        let refresh_token = refresh_mgr.generate("user_123");
        let old_access_token = "old_access_token";

        refresh_mgr
            .store(&refresh_token, old_access_token, "user_123")
            .await
            .unwrap();

        let (new_access_token, login_id) = refresh_mgr
            .refresh_access_token(&refresh_token)
            .await
            .unwrap();

        assert_eq!(login_id, "user_123");
        assert_ne!(new_access_token.as_str(), old_access_token);

        // 新 access token 应已写入 token 存储
        let token_key = config.make_key("token:", new_access_token.as_str());
        let stored = storage.get(&token_key).await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn test_delete_refresh_token() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage, config);

        let refresh_token = refresh_mgr.generate("user_123");
        refresh_mgr
            .store(&refresh_token, "access", "user_123")
            .await
            .unwrap();

        refresh_mgr.delete(&refresh_token).await.unwrap();

        let result = refresh_mgr.validate(&refresh_token).await;
        assert!(result.is_err());

        let tokens = refresh_mgr.get_user_refresh_tokens("user_123").await.unwrap();
        assert!(tokens.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let storage = Arc::new(MemoryStorage::new());
        let config = create_test_config();
        let refresh_mgr = RefreshTokenManager::new(storage, config);

        let rt1 = refresh_mgr.generate("user_123");
        let rt2 = refresh_mgr.generate("user_123");
        refresh_mgr.store(&rt1, "a1", "user_123").await.unwrap();
        refresh_mgr.store(&rt2, "a2", "user_123").await.unwrap();

        refresh_mgr.revoke_all_for_user("user_123").await.unwrap();

        assert!(refresh_mgr.validate(&rt1).await.is_err());
        assert!(refresh_mgr.validate(&rt2).await.is_err());
        assert!(
            refresh_mgr
                .get_user_refresh_tokens("user_123")
                .await
                .unwrap()
                .is_empty()
        );
    }
}

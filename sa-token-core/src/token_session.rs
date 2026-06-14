// Author: 金书记
//
//! Token-Session 双轨（独立于 Account-Session）

use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;
use crate::session::SaSession;
use crate::token::TokenValue;

impl SaTokenManager {
    fn token_session_key(&self, token: &str) -> String {
        self.config.make_key("token-session:", token)
    }

    /// 获取 Token-Session（不存在时按配置创建）
    pub async fn get_token_session(&self, token: &TokenValue) -> SaTokenResult<SaSession> {
        if self.config.token_session_check_login && !self.is_valid(token).await {
            return Err(SaTokenError::NotLogin);
        }

        let key = self.token_session_key(token.as_str());
        if let Some(value) = self
            .storage
            .get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
        {
            let session: SaSession = serde_json::from_str(&value)?;
            return Ok(session);
        }

        if self.config.right_now_create_token_session {
            let session = SaSession::new(format!("token-session:{}", token.as_str()));
            self.save_token_session(token, &session).await?;
            Ok(session)
        } else {
            Ok(SaSession::new(format!("token-session:{}", token.as_str())))
        }
    }

    /// 匿名 Token-Session（不校验登录）
    pub async fn get_anon_token_session(&self, token: &TokenValue) -> SaTokenResult<SaSession> {
        let key = self.token_session_key(token.as_str());
        if let Some(value) = self
            .storage
            .get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
        {
            return Ok(serde_json::from_str(&value)?);
        }
        Ok(SaSession::new(format!("token-session:{}", token.as_str())))
    }

    pub async fn save_token_session(
        &self,
        token: &TokenValue,
        session: &SaSession,
    ) -> SaTokenResult<()> {
        let key = self.token_session_key(token.as_str());
        let value = serde_json::to_string(session)?;
        let ttl = self.config.timeout_duration();
        self.storage
            .set(&key, &value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    pub async fn delete_token_session(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.storage
            .delete(&self.token_session_key(token.as_str()))
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn token_session_independent_from_account_session() {
        let config = SaTokenConfig::builder()
            .right_now_create_token_session(true)
            .build_config();
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let token = mgr.login("u1").await.unwrap();
        let ts = mgr.get_token_session(&token).await.unwrap();
        let mut ts = ts;
        ts.set("k", "v").unwrap();
        mgr.save_token_session(&token, &ts).await.unwrap();

        let account = mgr.get_session("u1").await.unwrap();
        assert!(account.get::<String>("k").is_none());

        let loaded = mgr.get_token_session(&token).await.unwrap();
        assert_eq!(loaded.get::<String>("k"), Some("v".to_string()));
    }
}

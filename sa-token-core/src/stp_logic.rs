// Author: 金书记
//
//! 多账号体系：SaLogic（对齐 Java StpLogic 实例）+ 全局注册表。
//!
//! 每个 SaLogic 绑定一个 login_type，对同一底层 SaTokenManager 做账号命名空间隔离。

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use crate::disable;
use crate::error::SaTokenResult;
use crate::manager::SaTokenManager;
use crate::session::SaTerminalInfo;
use crate::token::TokenValue;

/// 绑定某一 login_type 的账号逻辑门面
#[derive(Clone)]
pub struct SaLogic {
    login_type: String,
    manager: Arc<SaTokenManager>,
}

impl SaLogic {
    pub fn new(login_type: impl Into<String>, manager: Arc<SaTokenManager>) -> Self {
        Self {
            login_type: login_type.into(),
            manager,
        }
    }

    pub fn login_type(&self) -> &str {
        &self.login_type
    }

    pub fn manager(&self) -> &Arc<SaTokenManager> {
        &self.manager
    }

    pub async fn login(&self, login_id: impl Into<String>) -> SaTokenResult<TokenValue> {
        self.manager
            .login_with_options(
                login_id,
                Some(self.login_type.clone()),
                None,
                None,
                None,
                None,
            )
            .await
    }

    pub async fn login_with_device(
        &self,
        login_id: impl Into<String>,
        device: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> SaTokenResult<TokenValue> {
        self.manager
            .login_with_options(
                login_id,
                Some(self.login_type.clone()),
                device,
                extra,
                None,
                None,
            )
            .await
    }

    pub async fn logout(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.manager.logout(token).await
    }

    pub async fn logout_by_login_id(&self, login_id: &str) -> SaTokenResult<()> {
        let ns = self.manager.account_ns(&self.login_type, login_id);
        let session = self.manager.get_session(&ns).await?;
        let tokens = session.get_token_value_list_by_device_type(None);
        if tokens.is_empty() {
            return Ok(());
        }
        for t in tokens {
            let _ = self.manager.logout(&TokenValue::new(t)).await;
        }
        Ok(())
    }

    pub async fn kick_out(&self, login_id: &str) -> SaTokenResult<()> {
        let ns = self.manager.account_ns(&self.login_type, login_id);
        let session = self.manager.get_session(&ns).await?;
        let tokens = session.get_token_value_list_by_device_type(None);
        for t in tokens {
            self.manager.kick_out_by_token(&TokenValue::new(t)).await?;
        }
        self.manager.delete_session(&ns).await?;
        Ok(())
    }

    pub async fn get_login_id(&self, token: &TokenValue) -> SaTokenResult<String> {
        Ok(self.manager.get_token_info(token).await?.login_id)
    }

    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.manager.is_valid(token).await
    }

    pub async fn get_session(
        &self,
        login_id: &str,
    ) -> SaTokenResult<crate::session::SaSession> {
        let ns = self.manager.account_ns(&self.login_type, login_id);
        self.manager.get_session(&ns).await
    }

    pub async fn get_terminal_list(
        &self,
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<SaTerminalInfo>> {
        self.manager
            .get_terminal_list(&self.login_type, login_id, device_type)
            .await
    }

    pub async fn get_terminal_info_by_token(
        &self,
        token: &TokenValue,
    ) -> SaTokenResult<Option<SaTerminalInfo>> {
        self.manager.get_terminal_info_by_token(token).await
    }

    pub async fn get_permissions(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.manager
            .get_permissions_with_type(&self.login_type, login_id)
            .await
    }

    pub async fn set_permissions(
        &self,
        login_id: &str,
        perms: Vec<String>,
    ) -> SaTokenResult<()> {
        self.manager
            .set_permissions_with_type(&self.login_type, login_id, perms)
            .await
    }

    pub async fn get_roles(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        self.manager
            .get_roles_with_type(&self.login_type, login_id)
            .await
    }

    pub async fn set_roles(&self, login_id: &str, roles: Vec<String>) -> SaTokenResult<()> {
        self.manager
            .set_roles_with_type(&self.login_type, login_id, roles)
            .await
    }

    pub async fn disable(&self, login_id: &str, time: i64) -> SaTokenResult<()> {
        let ns = self.manager.account_ns(&self.login_type, login_id);
        self.manager.disable(&ns, time).await
    }

    pub async fn check_disable(&self, login_id: &str) -> SaTokenResult<()> {
        let ns = self.manager.account_ns(&self.login_type, login_id);
        self.manager
            .check_disable_level(
                &ns,
                disable::DEFAULT_DISABLE_SERVICE,
                disable::MIN_DISABLE_LEVEL,
            )
            .await
    }
}

static STP_LOGIC_MAP: OnceLock<RwLock<HashMap<String, Arc<SaLogic>>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<String, Arc<SaLogic>>> {
    STP_LOGIC_MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn put_stp_logic(logic: Arc<SaLogic>) {
    registry()
        .write()
        .unwrap()
        .insert(logic.login_type().to_string(), logic);
}

pub fn remove_stp_logic(login_type: &str) {
    registry().write().unwrap().remove(login_type);
}

pub fn get_or_create_stp_logic(login_type: &str, manager: Arc<SaTokenManager>) -> Arc<SaLogic> {
    if let Some(found) = registry().read().unwrap().get(login_type).cloned() {
        return found;
    }
    let mut map = registry().write().unwrap();
    if let Some(found) = map.get(login_type).cloned() {
        return found;
    }
    let logic = Arc::new(SaLogic::new(login_type, manager));
    map.insert(login_type.to_string(), logic.clone());
    logic
}

pub fn try_get_stp_logic(login_type: &str) -> Option<Arc<SaLogic>> {
    registry().read().unwrap().get(login_type).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    fn make_manager() -> Arc<SaTokenManager> {
        Arc::new(SaTokenManager::new(
            Arc::new(MemoryStorage::new()),
            crate::SaTokenConfig::default(),
        ))
    }

    #[tokio::test]
    async fn test_sa_logic_permission_isolation() {
        let mgr = make_manager();
        let admin = SaLogic::new("admin", mgr.clone());
        let user = SaLogic::new("user", mgr);

        admin
            .set_permissions("10001", vec!["admin:read".to_string()])
            .await
            .unwrap();
        user.set_permissions("10001", vec!["user:read".to_string()])
            .await
            .unwrap();

        assert_eq!(
            admin.get_permissions("10001").await.unwrap(),
            vec!["admin:read".to_string()]
        );
        assert_eq!(
            user.get_permissions("10001").await.unwrap(),
            vec!["user:read".to_string()]
        );
    }

    #[tokio::test]
    async fn test_registry_put_and_remove() {
        let mgr = make_manager();
        let logic = Arc::new(SaLogic::new("custom", mgr));
        put_stp_logic(logic.clone());
        assert!(try_get_stp_logic("custom").is_some());
        remove_stp_logic("custom");
        assert!(try_get_stp_logic("custom").is_none());
    }

    #[tokio::test]
    async fn test_terminal_isolation_between_login_types() {
        let mgr = make_manager();
        let admin = SaLogic::new("admin", mgr.clone());
        let user = SaLogic::new("user", mgr);

        admin.login("10001").await.unwrap();
        user.login("10001").await.unwrap();

        assert_eq!(admin.get_terminal_list("10001", None).await.unwrap().len(), 1);
        assert_eq!(user.get_terminal_list("10001", None).await.unwrap().len(), 1);
    }
}

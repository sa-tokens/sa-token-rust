// Author: 金书记
//
//! 账号/服务封禁（对齐 Java StpLogic.disable/checkDisable）

use std::time::Duration;

use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;

/// 默认封禁服务标识（对齐 Java `DEFAULT_DISABLE_SERVICE`）
pub const DEFAULT_DISABLE_SERVICE: &str = "login";

/// 最低封禁等级（对齐 Java `MIN_DISABLE_LEVEL`）
pub const MIN_DISABLE_LEVEL: i32 = 1;

/// 未封禁时的等级返回值（对齐 Java `NOT_DISABLE_LEVEL`）
pub const NOT_DISABLE_LEVEL: i32 = -2;

/// 默认写入封禁等级（对齐 Java `DEFAULT_DISABLE_LEVEL`）
pub const DEFAULT_DISABLE_LEVEL: i32 = 1;

impl SaTokenManager {
    fn disable_key(&self, login_id: &str, service: &str) -> String {
        self.config.make_key("disable:", &format!("{}:{}", login_id, service))
    }

    /// 封禁指定账号的指定服务及等级
    ///
    /// `time` 单位为秒，`-1` 表示永久封禁。
    pub async fn disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
        time: i64,
    ) -> SaTokenResult<()> {
        if login_id.trim().is_empty() {
            return Err(SaTokenError::ConfigError(
                "login_id is required for disable".to_string(),
            ));
        }
        if service.trim().is_empty() {
            return Err(SaTokenError::ConfigError(
                "service is required for disable".to_string(),
            ));
        }
        if level < MIN_DISABLE_LEVEL && level != 0 {
            return Err(SaTokenError::ConfigError(format!(
                "disable level must be >= {} (0 allowed)",
                MIN_DISABLE_LEVEL
            )));
        }

        let ttl = if time < 0 {
            None
        } else {
            Some(Duration::from_secs(time as u64))
        };

        self.storage
            .set(
                &self.disable_key(login_id, service),
                &level.to_string(),
                ttl,
            )
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        let event = crate::event::SaTokenEvent::banned(login_id);
        self.event_bus.publish(event).await;

        Ok(())
    }

    /// 封禁指定账号（默认服务 `login`、默认等级）
    pub async fn disable(&self, login_id: &str, time: i64) -> SaTokenResult<()> {
        self.disable_level(
            login_id,
            DEFAULT_DISABLE_SERVICE,
            DEFAULT_DISABLE_LEVEL,
            time,
        )
        .await
    }

    /// 获取封禁等级；未封禁返回 [`NOT_DISABLE_LEVEL`]
    pub async fn get_disable_level(&self, login_id: &str, service: &str) -> SaTokenResult<i32> {
        let key = self.disable_key(login_id, service);
        let value = self
            .storage
            .get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        if let Some(v) = value {
            return v.parse::<i32>().map_err(|_| {
                SaTokenError::StorageError(format!("invalid disable level for key {}", key))
            });
        }

        if let Some(iface) = &self.stp_interface {
            if let Some(level) = iface.is_disabled(login_id, service).await? {
                return Ok(level);
            }
        }

        Ok(NOT_DISABLE_LEVEL)
    }

    /// 是否已被封禁到指定等级（含更高等级）
    pub async fn is_disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
    ) -> SaTokenResult<bool> {
        let disable_level = self.get_disable_level(login_id, service).await?;
        if disable_level == NOT_DISABLE_LEVEL {
            return Ok(false);
        }
        Ok(disable_level >= level)
    }

    /// 校验封禁；若等级达到阈值则抛出 [`SaTokenError::DisableService`]
    pub async fn check_disable_level(
        &self,
        login_id: &str,
        service: &str,
        level: i32,
    ) -> SaTokenResult<()> {
        let disable_level = self.get_disable_level(login_id, service).await?;
        if disable_level == NOT_DISABLE_LEVEL {
            return Ok(());
        }
        if disable_level >= level {
            return Err(SaTokenError::AccountBanned(format!(
                "service={} level={}",
                service, disable_level
            )));
        }
        Ok(())
    }

    /// 校验多个服务的封禁（全部通过才算通过）
    pub async fn check_disable_services(
        &self,
        login_id: &str,
        services: &[&str],
        level: i32,
    ) -> SaTokenResult<()> {
        for service in services {
            self.check_disable_level(login_id, service, level).await?;
        }
        Ok(())
    }

    /// 解封指定服务
    pub async fn untie_disable(&self, login_id: &str, service: &str) -> SaTokenResult<()> {
        self.storage
            .delete(&self.disable_key(login_id, service))
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

    fn manager() -> SaTokenManager {
        SaTokenManager::new(
            Arc::new(MemoryStorage::new()),
            SaTokenConfig::default(),
        )
    }

    #[tokio::test]
    async fn disable_and_check_level() {
        let mgr = manager();
        mgr.disable_level("u1", "login", 2, 60).await.unwrap();
        assert!(mgr.is_disable_level("u1", "login", 1).await.unwrap());
        assert!(mgr.is_disable_level("u1", "login", 2).await.unwrap());
        assert!(!mgr.is_disable_level("u1", "login", 3).await.unwrap());
        assert!(mgr.check_disable_level("u1", "login", 2).await.is_err());
        mgr.untie_disable("u1", "login").await.unwrap();
        assert_eq!(
            mgr.get_disable_level("u1", "login").await.unwrap(),
            NOT_DISABLE_LEVEL
        );
    }
}

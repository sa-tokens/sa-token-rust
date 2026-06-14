// Author: 金书记
//
// 中文 | English
// Tonic 无关的应用状态管理 | Tonic-free application state management

use std::sync::Arc;

use sa_token_adapter::storage::SaStorage;
use sa_token_core::{SaTokenConfig, SaTokenManager, StpUtil};

/// 中文: Tonic gRPC 应用状态（框架无关）
/// English: Tonic gRPC application state (framework-agnostic)
#[derive(Clone)]
pub struct SaTokenState {
    /// 中文: Sa-Token 管理器
    /// English: Sa-Token manager
    pub manager: Arc<SaTokenManager>,
}

impl SaTokenState {
    /// 中文: 从存储和配置创建状态
    /// English: Create state from storage and config
    pub fn new(storage: Arc<dyn SaStorage>, config: SaTokenConfig) -> Self {
        Self {
            manager: Arc::new(SaTokenManager::new(storage, config)),
        }
    }

    /// 中文: 从已有的管理器创建状态
    /// English: Create state from an existing manager
    pub fn from_manager(manager: SaTokenManager) -> Self {
        StpUtil::init_manager(manager.clone());
        Self {
            manager: Arc::new(manager),
        }
    }

    /// 中文: 构建器入口
    /// English: Builder entrypoint
    pub fn builder() -> SaTokenStateBuilder {
        SaTokenStateBuilder::default()
    }
}

/// 中文: SaTokenState 构建器
/// English: Builds [`SaTokenState`]
#[derive(Default)]
pub struct SaTokenStateBuilder {
    config_builder: sa_token_core::config::SaTokenConfigBuilder,
}

impl SaTokenStateBuilder {
    /// 中文: 设置 Token 名称
    /// English: Set token name
    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_name(name);
        self
    }

    /// 中文: 设置 Token 超时时间（秒）
    /// English: Set token timeout (seconds)
    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.timeout(timeout);
        self
    }

    /// 中文: 设置 Token 活跃超时时间（秒）
    /// English: Set token active timeout (seconds)
    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.active_timeout(timeout);
        self
    }

    /// 中文: 启用自动续签
    /// English: Enable automatic renewal when touching the token
    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.auto_renew(enabled);
        self
    }

    /// 中文: 设置是否允许并发登录
    /// English: Set whether to allow concurrent login
    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config_builder = self.config_builder.is_concurrent(concurrent);
        self
    }

    /// 中文: 设置是否共享 Token
    /// English: Set whether to share token
    pub fn is_share(mut self, share: bool) -> Self {
        self.config_builder = self.config_builder.is_share(share);
        self
    }

    /// 中文: 设置 Token 风格
    /// English: Set token style
    pub fn token_style(mut self, style: sa_token_core::config::TokenStyle) -> Self {
        self.config_builder = self.config_builder.token_style(style);
        self
    }



    /// 中文: 设置 JWT 密钥
    /// English: Set JWT secret key
    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_secret_key(key);
        self
    }

    /// 中文: 设置存储实现
    /// English: Set storage implementation
    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.config_builder = self.config_builder.storage(storage);
        self
    }

    /// 中文: 构建 SaTokenState
    /// English: Build SaTokenState
    pub fn build(self) -> SaTokenState {
        let manager = self.config_builder.build();
        SaTokenState {
            manager: Arc::new(manager),
        }
    }
}

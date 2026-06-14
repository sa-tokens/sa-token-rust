use std::sync::Arc;
use sa_token_adapter::storage::SaStorage;
use sa_token_core::{SaTokenManager, SaTokenConfig, StpUtil, SaTokenListener};

/// 中文 | English
/// Sa-Token 状态 | Sa-Token State
/// 
/// 包含 Sa-Token 管理器和配置 | Contains Sa-Token manager and configuration
#[derive(Clone)]
pub struct SaTokenState {
    pub manager: Arc<SaTokenManager>,
}

impl SaTokenState {
    /// 中文 | English
    /// 从存储和配置创建状态 | Create state from storage and config
    pub fn new(storage: Arc<dyn SaStorage>, config: SaTokenConfig) -> Self {
        Self {
            manager: Arc::new(SaTokenManager::new(storage, config)),
        }
    }
    
    /// 中文 | English
    /// 从 SaTokenManager 创建状态 | Create state from SaTokenManager
    pub fn from_manager(manager: SaTokenManager) -> Self {
        // 自动初始化全局 StpUtil | Auto-initialize global StpUtil
        StpUtil::init_manager(manager.clone());
        
        Self {
            manager: Arc::new(manager),
        }
    }
    
    /// 中文 | English
    /// 使用构建器模式创建状态 | Create state using builder pattern
    pub fn builder() -> SaTokenStateBuilder {
        SaTokenStateBuilder::default()
    }
}

/// 中文 | English
/// SaTokenState 构建器 | SaTokenState builder
#[derive(Default)]
pub struct SaTokenStateBuilder {
    config_builder: sa_token_core::config::SaTokenConfigBuilder,
    listeners: Vec<Arc<dyn SaTokenListener>>,
}

impl SaTokenStateBuilder {
    /// 中文 | English
    /// 创建新的构建器 | Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// 中文 | English
    /// 设置 token 名称 | Set token name
    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_name(name);
        self
    }
    
    /// 中文 | English
    /// 设置 token 有效期（秒） | Set token timeout (seconds)
    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.timeout(timeout);
        self
    }
    
    /// 中文 | English
    /// 设置 token 临时有效期（秒） | Set token active timeout (seconds)
    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.active_timeout(timeout);
        self
    }
    
    /// 中文 | English
    /// 设置是否开启自动续签 | Set whether to enable auto renew
    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.auto_renew(enabled);
        self
    }
    
    /// 中文 | English
    /// 设置是否允许并发登录 | Set whether to allow concurrent login
    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config_builder = self.config_builder.is_concurrent(concurrent);
        self
    }
    
    /// 中文 | English
    /// 设置是否共享 token | Set whether to share token
    pub fn is_share(mut self, share: bool) -> Self {
        self.config_builder = self.config_builder.is_share(share);
        self
    }
    
    /// 中文 | English
    /// 设置 token 风格 | Set token style
    pub fn token_style(mut self, style: sa_token_core::config::TokenStyle) -> Self {
        self.config_builder = self.config_builder.token_style(style);
        self
    }
    

    
    /// 中文 | English
    /// 设置 JWT 密钥 | Set JWT secret key
    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_secret_key(key);
        self
    }
    
    /// 中文 | English
    /// 设置存储实现 | Set storage implementation
    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.config_builder = self.config_builder.storage(storage);
        self
    }
    
    /// 中文 | English
    /// 添加事件监听器 | Add event listener
    pub fn listener(mut self, listener: Arc<dyn SaTokenListener>) -> Self {
        self.listeners.push(listener);
        self
    }
    
    /// 中文 | English
    /// 添加多个事件监听器 | Add multiple event listeners
    pub fn listeners(mut self, listeners: Vec<Arc<dyn SaTokenListener>>) -> Self {
        self.listeners.extend(listeners);
        self
    }
    
    /// 中文 | English
    /// 构建 SaTokenState | Build SaTokenState
    pub fn build(self) -> SaTokenState {
        // config_builder.build() 已经自动初始化了 StpUtil
        // config_builder.build() already auto-initializes StpUtil
        let manager = self.config_builder.build();
        
        // 注册事件监听器 | Register event listeners
        for listener in self.listeners {
            manager.event_bus().register(listener);
        }
        
        // 直接创建 SaTokenState，不再调用 from_manager 避免重复初始化
        // Create SaTokenState directly, don't call from_manager to avoid duplicate initialization
        SaTokenState {
            manager: Arc::new(manager),
        }
    }
}

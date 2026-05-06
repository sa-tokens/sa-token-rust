// Author: 金书记
//
//! 配置模块

use std::time::Duration;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sa_token_adapter::storage::SaStorage;
use crate::event::SaTokenListener;

/// sa-token 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaTokenConfig {
    /// Token 名称（例如在 header 或 cookie 中的键名）
    pub token_name: String,
    
    /// Token 有效期（秒），-1 表示永久有效
    pub timeout: i64,
    
    /// Token 最低活跃频率（秒），-1 表示不限制
    /// 
    /// 配合 auto_renew 使用时，表示自动续签的时长
    pub active_timeout: i64,
    
    /// 是否开启自动续签（默认 false）
    /// 
    /// 如果设置为 true，在以下场景会自动续签 token：
    /// - 调用 get_token_info() 时
    /// - 中间件验证 token 时
    /// - 调用无参数的 StpUtil 方法时
    /// 
    /// 续签时长由 active_timeout 决定：
    /// - 如果 active_timeout > 0，则续签 active_timeout 秒
    /// - 如果 active_timeout <= 0，则续签 timeout 秒
    pub auto_renew: bool,
    
    /// 是否允许同一账号并发登录
    pub is_concurrent: bool,
    
    /// 在多人登录同一账号时，是否共享一个 token
    pub is_share: bool,
    
    /// Token 风格（uuid、simple-uuid、random-32、random-64、random-128）
    pub token_style: TokenStyle,
    
    /// 是否输出操作日志
    pub is_log: bool,
    
    /// 是否从 cookie 中读取 token
    pub is_read_cookie: bool,
    
    /// 是否从 header 中读取 token
    pub is_read_header: bool,
    
    /// 是否从请求体中读取 token
    pub is_read_body: bool,
    
    /// token 前缀（例如 "Bearer "）
    pub token_prefix: Option<String>,
    
    /// JWT 密钥（如果使用 JWT）
    pub jwt_secret_key: Option<String>,
    
    /// JWT 算法（默认 HS256）
    pub jwt_algorithm: Option<String>,
    
    /// JWT 签发者
    pub jwt_issuer: Option<String>,
    
    /// JWT 受众
    pub jwt_audience: Option<String>,
    
    /// 是否启用防重放攻击（nonce 机制）
    pub enable_nonce: bool,
    
    /// Nonce 有效期（秒），-1 表示使用 token timeout
    pub nonce_timeout: i64,
    
    /// 是否启用 Refresh Token
    pub enable_refresh_token: bool,
    
    /// Refresh Token 有效期（秒），默认 7 天
    pub refresh_token_timeout: i64,
}

impl Default for SaTokenConfig {
    fn default() -> Self {
        Self {
            token_name: "sa-token".to_string(),
            timeout: 2592000, // 30天
            active_timeout: -1,
            auto_renew: false, // 默认不开启自动续签
            is_concurrent: true,
            is_share: true,
            token_style: TokenStyle::Uuid,
            is_log: false,
            is_read_cookie: true,
            is_read_header: true,
            is_read_body: false,
            token_prefix: None,
            jwt_secret_key: None,
            jwt_algorithm: Some("HS256".to_string()),
            jwt_issuer: None,
            jwt_audience: None,
            enable_nonce: false,
            nonce_timeout: -1,
            enable_refresh_token: false,
            refresh_token_timeout: 604800, // 7 天
        }
    }
}

impl SaTokenConfig {
    pub fn builder() -> SaTokenConfigBuilder {
        SaTokenConfigBuilder::default()
    }
    
    pub fn timeout_duration(&self) -> Option<Duration> {
        if self.timeout < 0 {
            None
        } else {
            Some(Duration::from_secs(self.timeout as u64))
        }
    }
}

/// Token 风格 | Token Style
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TokenStyle {
    /// UUID 风格 | UUID style
    Uuid,
    /// 简化的 UUID（去掉横杠）| Simple UUID (without hyphens)
    SimpleUuid,
    /// 32位随机字符串 | 32-character random string
    Random32,
    /// 64位随机字符串 | 64-character random string
    Random64,
    /// 128位随机字符串 | 128-character random string
    Random128,
    /// JWT 风格（JSON Web Token）| JWT style (JSON Web Token)
    Jwt,
    /// Hash 风格（SHA256哈希）| Hash style (SHA256 hash)
    Hash,
    /// 时间戳风格（毫秒级时间戳+随机数）| Timestamp style (millisecond timestamp + random)
    Timestamp,
    /// Tik 风格（短小精悍的8位字符）| Tik style (short 8-character token)
    Tik,
}

/// 配置构建器
#[derive(Default)]
pub struct SaTokenConfigBuilder {
    config: SaTokenConfig,
    storage: Option<Arc<dyn SaStorage>>,
    listeners: Vec<Arc<dyn SaTokenListener>>,
}


impl SaTokenConfigBuilder {
    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config.token_name = name.into();
        self
    }
    
    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config.timeout = timeout;
        self
    }
    
    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config.active_timeout = timeout;
        self
    }
    
    /// 设置是否开启自动续签
    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config.auto_renew = enabled;
        self
    }
    
    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config.is_concurrent = concurrent;
        self
    }
    
    pub fn is_share(mut self, share: bool) -> Self {
        self.config.is_share = share;
        self
    }
    
    pub fn token_style(mut self, style: TokenStyle) -> Self {
        self.config.token_style = style;
        self
    }
    
    pub fn token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.token_prefix = Some(prefix.into());
        self
    }
    
    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config.jwt_secret_key = Some(key.into());
        self
    }
    
    /// 设置 JWT 算法
    pub fn jwt_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.config.jwt_algorithm = Some(algorithm.into());
        self
    }
    
    /// 设置 JWT 签发者
    pub fn jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config.jwt_issuer = Some(issuer.into());
        self
    }
    
    /// 设置 JWT 受众
    pub fn jwt_audience(mut self, audience: impl Into<String>) -> Self {
        self.config.jwt_audience = Some(audience.into());
        self
    }
    
    /// 启用防重放攻击（nonce 机制）
    pub fn enable_nonce(mut self, enable: bool) -> Self {
        self.config.enable_nonce = enable;
        self
    }
    
    /// 设置 Nonce 有效期（秒）
    pub fn nonce_timeout(mut self, timeout: i64) -> Self {
        self.config.nonce_timeout = timeout;
        self
    }
    
    /// 启用 Refresh Token
    pub fn enable_refresh_token(mut self, enable: bool) -> Self {
        self.config.enable_refresh_token = enable;
        self
    }
    
    /// 设置 Refresh Token 有效期（秒）
    pub fn refresh_token_timeout(mut self, timeout: i64) -> Self {
        self.config.refresh_token_timeout = timeout;
        self
    }
    
    /// 设置存储方式
    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.storage = Some(storage);
        self
    }
    
    /// 注册事件监听器
    /// 
    /// 可以多次调用以注册多个监听器
    /// 
    /// # 示例
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use sa_token_core::{SaTokenConfig, SaTokenListener};
    /// 
    /// struct MyListener;
    /// impl SaTokenListener for MyListener { /* ... */ }
    /// 
    /// let manager = SaTokenConfig::builder()
    ///     .storage(Arc::new(MemoryStorage::new()))
    ///     .register_listener(Arc::new(MyListener))
    ///     .build();
    /// ```
    pub fn register_listener(mut self, listener: Arc<dyn SaTokenListener>) -> Self {
        self.listeners.push(listener);
        self
    }
    
    /// 构建 SaTokenManager（需要先设置 storage）
    /// 
    /// 自动完成以下操作：
    /// 1. 创建 SaTokenManager
    /// 2. 注册所有事件监听器
    /// 3. 初始化 StpUtil
    /// 
    /// Auto-complete the following operations:
    /// 1. Create SaTokenManager
    /// 2. Register all event listeners
    /// 3. Initialize StpUtil
    /// 
    /// # Panics
    /// 如果未设置 storage，会 panic
    /// 
    /// # 示例
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use sa_token_core::SaTokenConfig;
    /// use sa_token_storage_memory::MemoryStorage;
    /// 
    /// // 一行代码完成所有初始化！
    /// // Complete all initialization in one line!
    /// SaTokenConfig::builder()
    ///     .storage(Arc::new(MemoryStorage::new()))
    ///     .timeout(7200)
    ///     .register_listener(Arc::new(MyListener))
    ///     .build();  // 自动初始化 StpUtil！
    /// ```
    pub fn build(self) -> crate::SaTokenManager {
        let storage = self.storage.expect("Storage must be set before building SaTokenManager. Use .storage() method.");
        let manager = crate::SaTokenManager::new(storage, self.config);
        
        // 同步注册所有监听器
        // Register all listeners synchronously
        if !self.listeners.is_empty() {
            let event_bus = manager.event_bus();
            for listener in self.listeners {
                event_bus.register(listener);
            }
        }
        
        // 自动初始化 StpUtil
        // Auto-initialize StpUtil
        crate::StpUtil::init_manager(manager.clone());
        
        manager
    }
    
    /// 仅构建配置（不创建 Manager）
    pub fn build_config(self) -> SaTokenConfig {
        self.config
    }
}

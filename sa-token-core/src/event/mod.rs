// Author: 金书记
//
//! Event Listener Module | 事件监听模块
//! 
//! Provides event listening capabilities for sa-token, supporting monitoring of login, logout, kick-out, and other operations.
//! 
//! 提供 sa-token 的事件监听功能，支持监听登录、登出、踢出等操作。
//! 
//! ## EventBus Code Flow Logic | EventBus 代码流程逻辑
//! 
//! ### Overall Architecture | 整体架构
//! 
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SaTokenEventBus                          │
//! │  ┌────────────────────────────────────────────────────┐    │
//! │  │  listeners: Arc<RwLock<Vec<Arc<dyn SaTokenListener>>>>  │
//! │  │  - Stores all registered listeners                 │
//! │  │    存储所有注册的监听器                             │
//! │  │  - Uses RwLock for thread safety                   │
//! │  │    使用 RwLock 保证线程安全                        │
//! │  │  - Arc wrapping allows multi-thread sharing        │
//! │  │    Arc 包装允许多线程共享                          │
//! │  └────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//! 
//! ### Core Processes | 核心流程
//! 
//! #### 1. Listener Registration Process | 监听器注册流程
//! 
//! ```text
//! ┌──────────┐     ┌──────────────┐     ┌─────────────┐
//! │User Code │────▶│ register()   │────▶│Acquire Write│
//! │用户代码  │     │              │     │Lock 写锁获取│
//! └──────────┘     │ - Receive    │     │             │
//!                  │   listener   │     │ - Get lock  │
//!                  │   接收监听器  │     │   获取写锁   │
//!                  │ - Arc wrap   │     │ - Add to    │
//!                  │   Arc包装    │     │   list      │
//!                  └──────────────┘     │   添加到列表 │
//!                                       │ - Release   │
//!                                       │   释放写锁   │
//!                                       └─────────────┘
//! 
//! Steps | 步骤：
//! 1. User creates custom listener instance
//!    用户创建自定义监听器实例
//! 2. Wrap listener with Arc::new()
//!    使用 Arc::new() 包装监听器
//! 3. Call event_bus.register(listener).await
//!    调用 event_bus.register(listener).await
//! 4. EventBus acquires write lock, adds listener to Vec
//!    EventBus 获取写锁，将监听器添加到 Vec 中
//! 5. Registration complete, waiting for event triggers
//!    监听器注册完成，等待事件触发
//! ```
//! 
//! #### 2. Event Publishing Process | 事件发布流程
//! 
//! ```text
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//! │SaTokenManager│────▶│ publish()    │────▶│Acquire Read  │
//! │(login)       │     │              │     │Lock 读锁获取 │
//! └──────────────┘     │ 1.Create     │     │              │
//!                      │   event      │     │ 2.Iterate    │
//!                      │   创建事件    │     │   listeners  │
//!                      │ 2.Call       │     │   遍历监听器  │
//!                      │   publish    │     │ 3.Invoke     │
//!                      │   调用publish │     │   callbacks  │
//!                      └──────────────┘     │   调用回调    │
//!                             │             └──────────────┘
//!                             ▼                     │
//!                      ┌──────────────┐             ▼
//!                      │ SaTokenEvent │     ┌──────────────┐
//!                      │ - event_type │     │ Listener 1   │
//!                      │ - login_id   │     │ on_login()   │
//!                      │ - token      │     ├──────────────┤
//!                      │ - timestamp  │     │ Listener 2   │
//!                      └──────────────┘     │ on_login()   │
//!                                          ├──────────────┤
//!                                          │ Listener N   │
//!                                          │ on_login()   │
//!                                          └──────────────┘
//! 
//! Steps | 步骤：
//! 1. After business operation (e.g., login) completes, create corresponding event object
//!    业务操作（如 login）完成后，创建对应的事件对象
//! 2. Call event_bus.publish(event).await
//!    调用 event_bus.publish(event).await
//! 3. EventBus acquires read lock, accesses listener list
//!    EventBus 获取读锁，访问监听器列表
//! 4. Call each listener's corresponding method in registration order
//!    按注册顺序依次调用每个监听器的对应方法
//! 5. After all listeners complete, event publishing process ends
//!    所有监听器执行完成后，事件发布流程结束
//! ```
//! 
//! #### 3. Event Dispatching Process | 事件分发流程
//! 
//! ```text
//! ┌──────────────────┐
//! │  publish(event)  │
//! └────────┬─────────┘
//!          │
//!          ▼
//! ┌──────────────────────────────────────┐
//! │ 1. Get all listeners (read lock)     │
//! │    获取所有监听器（读锁）              │
//! └────────┬─────────────────────────────┘
//!          │
//!          ▼
//! ┌──────────────────────────────────────┐
//! │ 2. Iterate listener list             │
//! │    遍历监听器列表                     │
//! └────────┬─────────────────────────────┘
//!          │
//!          ├──▶ on_event(event)  ──▶ Generic event handler
//!          │                         通用事件处理
//!          │
//!          └──▶ Dispatch by event type | 根据事件类型分发：
//!               │
//!               ├─ Login ──────▶ on_login(...)
//!               ├─ Logout ─────▶ on_logout(...)
//!               ├─ KickOut ────▶ on_kick_out(...)
//!               ├─ RenewTimeout ▶ on_renew_timeout(...)
//!               ├─ Replaced ───▶ on_replaced(...)
//!               └─ Banned ─────▶ on_banned(...)
//! 
//! Notes | 注意：
//! - Listeners execute in registration order
//!   监听器按注册顺序执行
//! - Each listener executes asynchronously
//!   每个监听器都是异步执行的
//! - Errors in listeners don't interrupt event propagation
//!   监听器中的错误不会中断事件传播
//! ```
//! 
//! ### Thread Safety Guarantees | 线程安全保证
//! 
//! ```text
//! Arc<RwLock<Vec<Arc<dyn SaTokenListener>>>>
//!  │    │     │    │
//!  │    │     │    └─ Listener trait object | 监听器 trait 对象
//!  │    │     └────── Listener collection | 监听器集合
//!  │    └──────────── Read-write lock protection | 读写锁保护
//!  └───────────────── Cross-thread sharing | 跨线程共享
//! 
//! - Arc: Allows EventBus to be shared across multiple Manager instances
//!        允许 EventBus 被多个 Manager 实例共享
//! - RwLock: Allows multiple readers to publish events concurrently, writer has exclusive registration
//!           允许多个读者同时发布事件，写者独占注册
//! - Inner Arc: Listeners can be shared across multiple EventBus instances
//!              监听器可以被多个 EventBus 共享
//! ```
//! 
//! ### Complete Call Chain Example | 完整调用链示例
//! 
//! ```text
//! User Code | 用户代码
//!   │
//!   └─▶ StpUtil::login("user_123")
//!         │
//!         └─▶ SaTokenManager::login(...)
//!               │
//!               ├─ 1. Generate token | 生成 token
//!               ├─ 2. Save to storage | 保存到存储
//!               └─ 3. Trigger event | 触发事件
//!                     │
//!                     └─▶ event_bus.publish(
//!                           SaTokenEvent::login("user_123", "token_abc")
//!                         )
//!                           │
//!                           ├─▶ LoggingListener::on_login()
//!                           │     └─ Log to file | 记录日志
//!                           │
//!                           ├─▶ DatabaseListener::on_login()
//!                           │     └─ Save to database | 保存到数据库
//!                           │
//!                           └─▶ StatisticsListener::on_login()
//!                                 └─ Update statistics | 更新统计信息
//! 
//! After all listeners complete, login() returns token
//! 所有监听器执行完成后，login() 方法返回 token
//! ```
//! 
//! ### Performance Considerations | 性能考虑
//! 
//! 1. **Async Execution | 异步执行**: All listener methods are async, but execute sequentially
//!    所有监听器方法都是异步的，但按顺序执行
//! 2. **Read-Write Lock | 读写锁**: Multiple events can be published concurrently (read lock), registration requires exclusive access (write lock)
//!    多个事件可以并发发布（读锁），注册需要独占（写锁）
//! 3. **Zero-Copy | 零拷贝**: Event objects are passed by reference, avoiding unnecessary cloning
//!    事件对象通过引用传递，避免不必要的克隆
//! 4. **Error Isolation | 错误隔离**: Errors in one listener don't affect other listeners
//!    单个监听器的错误不会影响其他监听器
//! 
//! ### Error Handling | 错误处理
//! 
//! ```text
//! ┌────────────────┐
//! │ Listener 1     │ ─▶ Success ✓ | 成功 ✓
//! ├────────────────┤
//! │ Listener 2     │ ─▶ Error ✗ (handled internally, doesn't affect others)
//! │                │    错误 ✗ (内部处理，不影响后续)
//! ├────────────────┤
//! │ Listener 3     │ ─▶ Success ✓ (still executes) | 成功 ✓ (仍然执行)
//! └────────────────┘
//! 
//! Recommendation | 建议：
//! Listeners should catch all errors internally and handle them appropriately
//! 监听器内部应捕获所有错误并适当处理
//! ```
//! 
//! ## Usage Example | 使用示例
//! 
//! ```rust,ignore
//! use sa_token_core::event::{SaTokenEvent, SaTokenListener, SaTokenEventBus};
//! 
//! // Custom listener | 自定义监听器
//! struct MyListener;
//! 
//! #[async_trait]
//! impl SaTokenListener for MyListener {
//!     async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
//!         println!("User {} logged in, token: {}", login_id, token);
//!         // 用户 {} 登录了，token: {}
//!     }
//!     
//!     async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
//!         println!("User {} logged out", login_id);
//!         // 用户 {} 登出了
//!     }
//! }
//! 
//! // Register listener | 注册监听器
//! let event_bus = SaTokenEventBus::new();
//! event_bus.register(Arc::new(MyListener)).await;
//! ```

use async_trait::async_trait;
use std::sync::Arc;
use std::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// 事件类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaTokenEventType {
    /// 登录事件
    Login,
    /// 登出事件
    Logout,
    /// 踢出下线事件
    KickOut,
    /// Token 续期事件
    RenewTimeout,
    /// 被顶下线事件（被其他设备登录）
    Replaced,
    /// 被封禁事件
    Banned,
}

/// 事件数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaTokenEvent {
    /// 事件类型
    pub event_type: SaTokenEventType,
    /// 登录ID
    pub login_id: String,
    /// Token 值
    pub token: String,
    /// 登录类型（如 "default", "admin" 等）
    pub login_type: String,
    /// 事件发生时间
    pub timestamp: DateTime<Utc>,
    /// 额外数据（用于扩展）
    pub extra: Option<serde_json::Value>,
}

impl SaTokenEvent {
    /// 创建登录事件
    pub fn login(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Login,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建登出事件
    pub fn logout(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Logout,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建踢出下线事件
    pub fn kick_out(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::KickOut,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建 Token 续期事件
    pub fn renew_timeout(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::RenewTimeout,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建被顶下线事件
    pub fn replaced(login_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Replaced,
            login_id: login_id.into(),
            token: token.into(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 创建被封禁事件
    pub fn banned(login_id: impl Into<String>) -> Self {
        Self {
            event_type: SaTokenEventType::Banned,
            login_id: login_id.into(),
            token: String::new(),
            login_type: "default".to_string(),
            timestamp: Utc::now(),
            extra: None,
        }
    }

    /// 设置登录类型
    pub fn with_login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = login_type.into();
        self
    }

    /// 设置额外数据
    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(extra);
        self
    }
}

/// 事件监听器 trait | Event Listener Trait
/// 
/// 实现此 trait 来自定义事件处理逻辑
/// Implement this trait to customize event handling logic
/// 
/// # 使用示例 | Usage Example
/// 
/// ```rust,ignore
/// use async_trait::async_trait;
/// use sa_token_core::SaTokenListener;
/// 
/// struct MyListener;
/// 
/// #[async_trait]
/// impl SaTokenListener for MyListener {
///     async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
///         // 自定义登录处理 | Custom login handling
///         println!("User {} logged in", login_id);
///     }
/// }
/// ```
#[async_trait]
pub trait SaTokenListener: Send + Sync {
    /// 登录事件 | Login Event
    /// 
    /// 当用户成功登录时触发 | Triggered when user successfully logs in
    /// 
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `token`: Token 值 | Token value
    /// - `login_type`: 登录类型（如 "web", "websocket"）| Login type (e.g., "web", "websocket")
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 登出事件 | Logout Event
    /// 
    /// 当用户主动登出时触发 | Triggered when user actively logs out
    /// 
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `token`: Token 值 | Token value
    /// - `login_type`: 登录类型 | Login type
    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 踢出下线事件 | Kick Out Event
    /// 
    /// 当用户被强制踢出下线时触发 | Triggered when user is forcefully kicked out
    /// 
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `token`: Token 值 | Token value
    /// - `login_type`: 登录类型 | Login type
    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// Token 续期事件 | Token Renewal Event
    /// 
    /// 当 Token 有效期被延长时触发 | Triggered when token validity is extended
    /// 
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `token`: Token 值 | Token value
    /// - `login_type`: 登录类型 | Login type
    async fn on_renew_timeout(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 被顶下线事件 | Replaced Event
    /// 
    /// 当用户在其他设备登录导致当前设备被顶下线时触发
    /// Triggered when user logs in on another device and current device is replaced
    /// 
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `token`: Token 值 | Token value
    /// - `login_type`: 登录类型 | Login type
    async fn on_replaced(&self, login_id: &str, token: &str, login_type: &str) {
        let _ = (login_id, token, login_type);
    }

    /// 被封禁事件 | Banned Event
    /// 
    /// 当用户账号被封禁时触发 | Triggered when user account is banned
    /// 
    /// # 参数 | Parameters
    /// - `login_id`: 登录 ID | Login ID
    /// - `login_type`: 登录类型 | Login type
    async fn on_banned(&self, login_id: &str, login_type: &str) {
        let _ = (login_id, login_type);
    }

    /// 通用事件处理（所有事件都会触发此方法）
    /// Generic Event Handler (triggered by all events)
    /// 
    /// # 参数 | Parameters
    /// - `event`: 事件对象 | Event object
    async fn on_event(&self, event: &SaTokenEvent) {
        let _ = event;
    }
}

/// 事件总线 - 管理所有监听器并分发事件
#[derive(Clone)]
pub struct SaTokenEventBus {
    listeners: Arc<RwLock<Vec<Arc<dyn SaTokenListener>>>>,
}

impl SaTokenEventBus {
    /// 创建新的事件总线
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 注册监听器
    /// Register a listener
    pub fn register(&self, listener: Arc<dyn SaTokenListener>) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.push(listener);
    }
    
    /// 异步注册监听器（为了保持 API 兼容性）
    /// Register a listener asynchronously (for API compatibility)
    pub async fn register_async(&self, listener: Arc<dyn SaTokenListener>) {
        self.register(listener);
    }

    /// 移除所有监听器
    /// Clear all listeners
    pub fn clear(&self) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.clear();
    }

    /// 获取监听器数量
    /// Get listener count
    pub fn listener_count(&self) -> usize {
        let listeners = self.listeners.read().unwrap();
        listeners.len()
    }

    /// 发布事件
    /// Publish an event to all listeners
    pub async fn publish(&self, event: SaTokenEvent) {
        // 克隆监听器列表以避免持有锁时异步等待
        // Clone listener list to avoid holding lock during async operations
        let listeners = {
            let guard = self.listeners.read().unwrap();
            guard.clone()
        };
        
        for listener in listeners.iter() {
            // 触发通用事件处理
            listener.on_event(&event).await;
            
            // 根据事件类型触发特定处理
            match event.event_type {
                SaTokenEventType::Login => {
                    listener.on_login(&event.login_id, &event.token, &event.login_type).await;
                }
                SaTokenEventType::Logout => {
                    listener.on_logout(&event.login_id, &event.token, &event.login_type).await;
                }
                SaTokenEventType::KickOut => {
                    listener.on_kick_out(&event.login_id, &event.token, &event.login_type).await;
                }
                SaTokenEventType::RenewTimeout => {
                    listener.on_renew_timeout(&event.login_id, &event.token, &event.login_type).await;
                }
                SaTokenEventType::Replaced => {
                    listener.on_replaced(&event.login_id, &event.token, &event.login_type).await;
                }
                SaTokenEventType::Banned => {
                    listener.on_banned(&event.login_id, &event.login_type).await;
                }
            }
        }
    }
}

impl Default for SaTokenEventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// 简单的日志监听器示例
pub struct LoggingListener;

#[async_trait]
impl SaTokenListener for LoggingListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::info!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户登录"
        );
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::info!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户登出"
        );
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::warn!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户被踢出下线"
        );
    }

    async fn on_renew_timeout(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::debug!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "Token 续期"
        );
    }

    async fn on_replaced(&self, login_id: &str, token: &str, login_type: &str) {
        tracing::warn!(
            login_id = %login_id,
            token = %token,
            login_type = %login_type,
            "用户被顶下线"
        );
    }

    async fn on_banned(&self, login_id: &str, login_type: &str) {
        tracing::warn!(
            login_id = %login_id,
            login_type = %login_type,
            "用户被封禁"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        login_count: Arc<RwLock<i32>>,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                login_count: Arc::new(RwLock::new(0)),
            }
        }
    }

    #[async_trait]
    impl SaTokenListener for TestListener {
        async fn on_login(&self, _login_id: &str, _token: &str, _login_type: &str) {
            let mut count = self.login_count.write().unwrap();
            *count += 1;
        }
    }

    #[tokio::test]
    async fn test_event_bus() {
        let bus = SaTokenEventBus::new();
        let listener = Arc::new(TestListener::new());
        let login_count = Arc::clone(&listener.login_count);
        
        bus.register(listener);
        
        // 发布登录事件
        let event = SaTokenEvent::login("user_123", "token_abc");
        bus.publish(event).await;
        
        // 验证监听器被调用
        let count = login_count.read().unwrap();
        assert_eq!(*count, 1);
    }

    #[test]
    fn test_event_creation() {
        let event = SaTokenEvent::login("user_123", "token_abc");
        assert_eq!(event.event_type, SaTokenEventType::Login);
        assert_eq!(event.login_id, "user_123");
        assert_eq!(event.token, "token_abc");
    }
}


//! WebSocket Authentication Module | WebSocket 认证模块
//!
//! # Code Flow Logic | 代码流程逻辑
//!
//! ## English
//! 
//! ### Overview
//! This module provides WebSocket authentication capabilities for sa-token-rust.
//! It handles token extraction from various sources (headers, query parameters)
//! and validates them against the token manager.
//! 
//! ### Authentication Flow
//! ```text
//! 1. WebSocket Connection Request
//!    ↓
//! 2. WsAuthManager.authenticate(headers, query)
//!    ↓
//! 3. WsTokenExtractor.extract_token()
//!    ├─→ Check Authorization Header (Bearer Token)
//!    ├─→ Check Sec-WebSocket-Protocol Header
//!    └─→ Check Query Parameter (?token=xxx)
//!    ↓
//! 4. Found Token → Create TokenValue
//!    ↓
//! 5. SaTokenManager.get_token_info(token)
//!    ↓
//! 6. Validate Token Expiration
//!    ├─→ Expired → Return TokenExpired Error
//!    └─→ Valid → Continue
//!    ↓
//! 7. Generate WebSocket Session ID
//!    Format: ws:{login_id}:{uuid}
//!    ↓
//! 8. Create WsAuthInfo
//!    - login_id: User identifier
//!    - token: Original token string
//!    - session_id: Unique WebSocket session ID
//!    - connect_time: Connection timestamp
//!    - metadata: Custom key-value data
//!    ↓
//! 9. Publish Login Event
//!    SaTokenEvent::login(login_id, token)
//!    └─→ Mark as "websocket" login type
//!    └─→ Trigger all registered event listeners
//!    ↓
//! 10. Return WsAuthInfo
//! ```
//! 
//! ### Token Extraction Priority
//! 1. Authorization Header: `Bearer {token}`
//! 2. Sec-WebSocket-Protocol Header: `{token}`
//! 3. Query Parameter: `?token={token}`
//! 
//! ### Extension Points
//! - Custom WsTokenExtractor: Implement your own token extraction logic
//! - WsAuthInfo.metadata: Store custom connection data
//!
//! ## 中文
//! 
//! ### 概述
//! 本模块为 sa-token-rust 提供 WebSocket 认证功能。
//! 它负责从多种来源（请求头、查询参数）提取 Token 并通过 Token 管理器进行验证。
//! 
//! ### 认证流程
//! ```text
//! 1. WebSocket 连接请求
//!    ↓
//! 2. WsAuthManager.authenticate(headers, query)
//!    ↓
//! 3. WsTokenExtractor.extract_token()
//!    ├─→ 检查 Authorization 请求头 (Bearer Token)
//!    ├─→ 检查 Sec-WebSocket-Protocol 请求头
//!    └─→ 检查查询参数 (?token=xxx)
//!    ↓
//! 4. 找到 Token → 创建 TokenValue
//!    ↓
//! 5. SaTokenManager.get_token_info(token)
//!    ↓
//! 6. 验证 Token 过期时间
//!    ├─→ 已过期 → 返回 TokenExpired 错误
//!    └─→ 有效 → 继续
//!    ↓
//! 7. 生成 WebSocket 会话 ID
//!    格式: ws:{login_id}:{uuid}
//!    ↓
//! 8. 创建 WsAuthInfo
//!    - login_id: 用户标识
//!    - token: 原始 Token 字符串
//!    - session_id: 唯一的 WebSocket 会话 ID
//!    - connect_time: 连接时间戳
//!    - metadata: 自定义键值数据
//!    ↓
//! 9. 发布 Login 事件
//!    SaTokenEvent::login(login_id, token)
//!    └─→ 标记为 "websocket" 登录类型
//!    └─→ 触发所有已注册的事件监听器
//!    ↓
//! 10. 返回 WsAuthInfo
//! ```
//! 
//! ### Token 提取优先级
//! 1. Authorization 请求头: `Bearer {token}`
//! 2. Sec-WebSocket-Protocol 请求头: `{token}`
//! 3. 查询参数: `?token={token}`
//! 
//! ### 扩展点
//! - 自定义 WsTokenExtractor: 实现自己的 Token 提取逻辑
//! - WsAuthInfo.metadata: 存储自定义连接数据

use crate::error::SaTokenError;
use crate::manager::SaTokenManager;
use crate::token::TokenValue;
use crate::event::SaTokenEvent;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// WebSocket authentication information
/// WebSocket 认证信息
///
/// Contains all the information about an authenticated WebSocket connection
/// 包含已认证的 WebSocket 连接的所有信息
#[derive(Debug, Clone)]
pub struct WsAuthInfo {
    /// User login ID | 用户登录 ID
    pub login_id: String,
    
    /// Authentication token | 认证 Token
    pub token: String,
    
    /// Unique WebSocket session ID | 唯一的 WebSocket 会话 ID
    /// Format: ws:{login_id}:{uuid}
    pub session_id: String,
    
    /// Connection timestamp | 连接时间戳
    pub connect_time: chrono::DateTime<chrono::Utc>,
    
    /// Custom metadata for this connection | 该连接的自定义元数据
    pub metadata: HashMap<String, String>,
}

/// Token extractor trait for WebSocket connections
/// WebSocket 连接的 Token 提取器 trait
///
/// Implement this trait to customize token extraction logic
/// 实现此 trait 以自定义 Token 提取逻辑
#[async_trait]
pub trait WsTokenExtractor: Send + Sync {
    /// Extract token from headers and query parameters
    /// 从请求头和查询参数中提取 Token
    ///
    /// # Arguments | 参数
    /// * `headers` - HTTP headers | HTTP 请求头
    /// * `query` - Query parameters | 查询参数
    ///
    /// # Returns | 返回值
    /// * `Some(token)` - Token found | 找到 Token
    /// * `None` - No token found | 未找到 Token
    async fn extract_token(&self, headers: &HashMap<String, String>, query: &HashMap<String, String>) -> Option<String>;
}

/// Default token extractor implementation
/// 默认的 Token 提取器实现
///
/// Extracts tokens from:
/// 从以下位置提取 Token:
/// 1. Authorization header (Bearer token)
/// 2. Sec-WebSocket-Protocol header
/// 3. Query parameter "token"
pub struct DefaultWsTokenExtractor;

#[async_trait]
impl WsTokenExtractor for DefaultWsTokenExtractor {
    async fn extract_token(&self, headers: &HashMap<String, String>, query: &HashMap<String, String>) -> Option<String> {
        // Priority 1: Authorization header with Bearer scheme
        // 优先级 1: Authorization 请求头（Bearer 方式）
        if let Some(token) = headers.get("Authorization") {
            return Some(token.trim_start_matches("Bearer ").to_string());
        }
        
        // Priority 2: WebSocket Protocol header
        // 优先级 2: WebSocket Protocol 请求头
        if let Some(token) = headers.get("Sec-WebSocket-Protocol") {
            return Some(token.to_string());
        }
        
        // Priority 3: Query parameter
        // 优先级 3: 查询参数
        if let Some(token) = query.get("token") {
            return Some(token.to_string());
        }
        
        None
    }
}

/// WebSocket authentication manager
/// WebSocket 认证管理器
///
/// Provides authentication and verification for WebSocket connections
/// 为 WebSocket 连接提供认证和验证功能
pub struct WsAuthManager {
    /// Reference to the token manager | Token 管理器引用
    manager: Arc<SaTokenManager>,
    
    /// Token extractor implementation | Token 提取器实现
    extractor: Arc<dyn WsTokenExtractor>,
}

impl WsAuthManager {
    /// Create a new WebSocket authentication manager with default extractor
    /// 使用默认提取器创建新的 WebSocket 认证管理器
    ///
    /// # Arguments | 参数
    /// * `manager` - SaToken manager instance | SaToken 管理器实例
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let ws_auth = WsAuthManager::new(manager);
    /// ```
    pub fn new(manager: Arc<SaTokenManager>) -> Self {
        Self {
            manager,
            extractor: Arc::new(DefaultWsTokenExtractor),
        }
    }

    /// Create a new WebSocket authentication manager with custom extractor
    /// 使用自定义提取器创建新的 WebSocket 认证管理器
    ///
    /// # Arguments | 参数
    /// * `manager` - SaToken manager instance | SaToken 管理器实例
    /// * `extractor` - Custom token extractor | 自定义 Token 提取器
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let custom_extractor = Arc::new(MyCustomExtractor);
    /// let ws_auth = WsAuthManager::with_extractor(manager, custom_extractor);
    /// ```
    pub fn with_extractor(manager: Arc<SaTokenManager>, extractor: Arc<dyn WsTokenExtractor>) -> Self {
        Self {
            manager,
            extractor,
        }
    }

    /// Authenticate a WebSocket connection
    /// 认证 WebSocket 连接
    ///
    /// This method will trigger a Login event after successful authentication
    /// 此方法在认证成功后会触发 Login 事件
    ///
    /// # Arguments | 参数
    /// * `headers` - HTTP headers from the WebSocket handshake | WebSocket 握手的 HTTP 请求头
    /// * `query` - Query parameters from the connection URL | 连接 URL 的查询参数
    ///
    /// # Returns | 返回值
    /// * `Ok(WsAuthInfo)` - Authentication successful | 认证成功
    /// * `Err(SaTokenError)` - Authentication failed | 认证失败
    ///
    /// # Errors | 错误
    /// * `NotLogin` - No token found | 未找到 Token
    /// * `TokenNotFound` - Token not found in storage | 存储中未找到 Token
    /// * `TokenExpired` - Token has expired | Token 已过期
    ///
    /// # Events | 事件
    /// Publishes `SaTokenEvent::Login` with login_type = "websocket"
    /// 发布 `SaTokenEvent::Login` 事件，login_type = "websocket"
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let mut headers = HashMap::new();
    /// headers.insert("Authorization".to_string(), "Bearer token123".to_string());
    /// 
    /// let auth_info = ws_auth.authenticate(&headers, &HashMap::new()).await?;
    /// println!("User {} connected", auth_info.login_id);
    /// 
    /// // Event listeners will be notified of WebSocket authentication
    /// // 事件监听器将收到 WebSocket 认证通知
    /// ```
    pub async fn authenticate(
        &self,
        headers: &HashMap<String, String>,
        query: &HashMap<String, String>,
    ) -> Result<WsAuthInfo, SaTokenError> {
        // Step 1: Extract token from request
        // 步骤 1: 从请求中提取 Token
        let token_str = self.extractor.extract_token(headers, query).await
            .ok_or(SaTokenError::NotLogin)?;

        // Step 2: Convert to TokenValue and get token info
        // 步骤 2: 转换为 TokenValue 并获取 Token 信息
        let token = TokenValue::new(token_str.clone());
        let token_info = self.manager.get_token_info(&token).await?;
        
        // Step 3: Validate token expiration
        // 步骤 3: 验证 Token 过期时间
        if let Some(expire_time) = token_info.expire_time
            && chrono::Utc::now() > expire_time {
                return Err(SaTokenError::TokenExpired);
            }

        // Step 4: Generate unique WebSocket session ID
        // 步骤 4: 生成唯一的 WebSocket 会话 ID
        let login_id = token_info.login_id.clone();
        let session_id = format!("ws:{}:{}", login_id, uuid::Uuid::new_v4());

        // Step 5: Create authentication info
        // 步骤 5: 创建认证信息
        let auth_info = WsAuthInfo {
            login_id: login_id.clone(),
            token: token_str.clone(),
            session_id,
            connect_time: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        // Step 6: Publish WebSocket authentication event (Login event with websocket type)
        // 步骤 6: 发布 WebSocket 认证事件（标记为 websocket 类型的 Login 事件）
        let event = SaTokenEvent::login(login_id, &token_str)
            .with_login_type("websocket");
        self.manager.event_bus().publish(event).await;

        // Step 7: Return authentication info
        // 步骤 7: 返回认证信息
        Ok(auth_info)
    }

    /// Verify a token and return the login ID
    /// 验证 Token 并返回登录 ID
    ///
    /// # Arguments | 参数
    /// * `token` - Token string to verify | 要验证的 Token 字符串
    ///
    /// # Returns | 返回值
    /// * `Ok(login_id)` - Token is valid | Token 有效
    /// * `Err(SaTokenError)` - Token is invalid or expired | Token 无效或已过期
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// let login_id = ws_auth.verify_token("token123").await?;
    /// println!("Token belongs to user: {}", login_id);
    /// ```
    pub async fn verify_token(&self, token: &str) -> Result<String, SaTokenError> {
        let token_value = TokenValue::new(token.to_string());
        let token_info = self.manager.get_token_info(&token_value).await?;
        
        // Validate expiration | 验证过期时间
        if let Some(expire_time) = token_info.expire_time
            && chrono::Utc::now() > expire_time {
                return Err(SaTokenError::TokenExpired);
            }

        Ok(token_info.login_id)
    }

    /// Refresh a WebSocket session by verifying its token
    /// 通过验证 Token 刷新 WebSocket 会话
    ///
    /// # Arguments | 参数
    /// * `auth_info` - WebSocket authentication info | WebSocket 认证信息
    ///
    /// # Returns | 返回值
    /// * `Ok(())` - Session refreshed successfully | 会话刷新成功
    /// * `Err(SaTokenError)` - Token is invalid or expired | Token 无效或已过期
    ///
    /// # Example | 示例
    /// ```rust,ignore
    /// ws_auth.refresh_ws_session(&auth_info).await?;
    /// ```
    pub async fn refresh_ws_session(&self, auth_info: &WsAuthInfo) -> Result<(), SaTokenError> {
        self.verify_token(&auth_info.token).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;

    #[tokio::test]
    async fn test_ws_auth_manager() {
        let config = SaTokenConfig::default();
        let storage = Arc::new(MemoryStorage::new());
        let manager = Arc::new(SaTokenManager::new(storage, config));
        
        let ws_manager = WsAuthManager::new(manager.clone());
        
        let token = manager.login("user123").await.unwrap();
        
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", token.as_str()));
        
        let auth_info = ws_manager.authenticate(&headers, &HashMap::new()).await.unwrap();
        assert_eq!(auth_info.login_id, "user123");
    }

    #[tokio::test]
    async fn test_token_extraction_from_query() {
        let config = SaTokenConfig::default();
        let storage = Arc::new(MemoryStorage::new());
        let manager = Arc::new(SaTokenManager::new(storage, config));
        
        let ws_manager = WsAuthManager::new(manager.clone());
        
        let token = manager.login("user456").await.unwrap();
        
        let mut query = HashMap::new();
        query.insert("token".to_string(), token.as_str().to_string());
        
        let auth_info = ws_manager.authenticate(&HashMap::new(), &query).await.unwrap();
        assert_eq!(auth_info.login_id, "user456");
    }

    #[tokio::test]
    async fn test_verify_token() {
        let config = SaTokenConfig::default();
        let storage = Arc::new(MemoryStorage::new());
        let manager = Arc::new(SaTokenManager::new(storage, config));
        
        let ws_manager = WsAuthManager::new(manager.clone());
        
        let token = manager.login("user789").await.unwrap();
        
        let login_id = ws_manager.verify_token(token.as_str()).await.unwrap();
        assert_eq!(login_id, "user789");
    }
}

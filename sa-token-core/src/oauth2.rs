//! OAuth2 Authorization Code Flow Implementation | OAuth2 授权码模式实现
//!
//! ## Code Flow Logic | 代码流程逻辑
//!
//! ### Overall Architecture | 整体架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      OAuth2Manager                              │
//! │                    OAuth2 管理器核心                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
//! │  │ Client Mgmt  │  │ Auth Code    │  │ Token Mgmt   │         │
//! │  │ 客户端管理   │  │ 授权码管理   │  │ 令牌管理     │         │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
//! │         │                  │                  │                 │
//! │         ▼                  ▼                  ▼                 │
//! │  ┌────────────────────────────────────────────────┐            │
//! │  │          Storage Backend (SaStorage)           │            │
//! │  │          存储后端（Memory/Redis/Database）      │            │
//! │  └────────────────────────────────────────────────┘            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Core Processes | 核心流程
//!
//! #### 1. Authorization Code Flow | 授权码流程
//!
//! ```text
//! User/Client            OAuth2Manager            Storage
//! 用户/客户端            OAuth2管理器             存储
//!     │                      │                      │
//!     │  register_client()   │                      │
//!     │─────────────────────▶│                      │
//!     │                      │  store client        │
//!     │                      │─────────────────────▶│
//!     │                      │                      │
//!     │  authorize request   │                      │
//!     │─────────────────────▶│                      │
//!     │                      │                      │
//!     │  generate_auth_code()│                      │
//!     │                      │  validate redirect   │
//!     │                      │  validate scope      │
//!     │                      │  create code         │
//!     │                      │                      │
//!     │                      │  store code (TTL)    │
//!     │                      │─────────────────────▶│
//!     │                      │                      │
//!     │  return code         │                      │
//!     │◀─────────────────────│                      │
//!     │                      │                      │
//!     │  exchange_code()     │                      │
//!     │─────────────────────▶│                      │
//!     │                      │  verify client       │
//!     │                      │  consume code        │
//!     │                      │─────────────────────▶│
//!     │                      │  delete code         │
//!     │                      │                      │
//!     │                      │  generate tokens     │
//!     │                      │  - access_token      │
//!     │                      │  - refresh_token     │
//!     │                      │                      │
//!     │                      │  store tokens (TTL)  │
//!     │                      │─────────────────────▶│
//!     │                      │                      │
//!     │  return tokens       │                      │
//!     │◀─────────────────────│                      │
//!     │                      │                      │
//! ```
//!
//! #### 2. Token Refresh Flow | 令牌刷新流程
//!
//! ```text
//! Client                 OAuth2Manager            Storage
//! 客户端                 OAuth2管理器             存储
//!     │                      │                      │
//!     │  refresh_token()     │                      │
//!     │─────────────────────▶│                      │
//!     │                      │  verify client       │
//!     │                      │  credentials         │
//!     │                      │                      │
//!     │                      │  get refresh_token   │
//!     │                      │─────────────────────▶│
//!     │                      │  return data         │
//!     │                      │◀─────────────────────│
//!     │                      │                      │
//!     │                      │  validate client_id  │
//!     │                      │  validate not expired│
//!     │                      │                      │
//!     │                      │  generate new tokens │
//!     │                      │  - new access_token  │
//!     │                      │  - new refresh_token │
//!     │                      │                      │
//!     │                      │  store new tokens    │
//!     │                      │─────────────────────▶│
//!     │                      │                      │
//!     │  return new tokens   │                      │
//!     │◀─────────────────────│                      │
//!     │                      │                      │
//! ```
//!
//! ### Storage Keys | 存储键格式
//!
//! ```text
//! oauth2:client:{client_id}         - Client information | 客户端信息
//! oauth2:code:{authorization_code}  - Authorization code | 授权码 (TTL: 10 min)
//! oauth2:token:{access_token}       - Token info | 令牌信息 (TTL: 1 hour)
//! oauth2:refresh:{refresh_token}    - Refresh token | 刷新令牌 (TTL: 30 days)
//! ```
//!
//! ### Security Validations | 安全验证
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │ 1. Client Verification | 客户端验证                     │
//! │    - client_id + client_secret match | 凭据匹配        │
//! │    - client exists in registry | 客户端已注册           │
//! ├────────────────────────────────────────────────────────┤
//! │ 2. Redirect URI Validation | 回调URI验证                │
//! │    - URI in whitelist | URI在白名单中                   │
//! │    - Exact match (no wildcards) | 精确匹配              │
//! ├────────────────────────────────────────────────────────┤
//! │ 3. Scope Validation | 权限范围验证                      │
//! │    - Requested scopes ⊆ client scopes | 请求范围子集    │
//! │    - All scopes valid | 所有范围合法                    │
//! ├────────────────────────────────────────────────────────┤
//! │ 4. Code Validation | 授权码验证                         │
//! │    - Code exists | 授权码存在                           │
//! │    - Not expired | 未过期                               │
//! │    - Single use (consumed after exchange) | 单次使用    │
//! │    - Client ID match | 客户端ID匹配                     │
//! │    - Redirect URI match | 回调URI匹配                   │
//! ├────────────────────────────────────────────────────────┤
//! │ 5. Token Validation | 令牌验证                          │
//! │    - Token exists | 令牌存在                            │
//! │    - Not expired | 未过期                               │
//! │    - Signature valid | 签名有效                         │
//! └────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Performance Considerations | 性能考虑
//!
//! 1. **Async Operations | 异步操作**
//!    - All storage operations are async | 所有存储操作异步
//!    - Non-blocking I/O | 非阻塞IO
//!
//! 2. **TTL Management | TTL管理**
//!    - Storage-level expiration | 存储层级过期
//!    - Automatic cleanup | 自动清理
//!    - No manual garbage collection | 无需手动垃圾回收
//!
//! 3. **Code Consumption | 授权码消费**
//!    - Read + Delete in one flow | 读取和删除一次性
//!    - Prevents replay attacks | 防止重放攻击
//!
//! ### Error Handling | 错误处理
//!
//! ```text
//! Error Type                    When It Occurs | 发生时机
//! ────────────────────────────────────────────────────────
//! InvalidToken                  - Invalid client credentials | 无效客户端凭据
//!                              - Code not found | 授权码不存在
//!                              - Client ID mismatch | 客户端ID不匹配
//!                              - Redirect URI mismatch | 回调URI不匹配
//!
//! TokenExpired                  - Authorization code expired | 授权码过期
//!                              - Access token expired | 访问令牌过期
//!                              - Refresh token expired | 刷新令牌过期
//!
//! StorageError                  - Storage operation failed | 存储操作失败
//!                              - Network error | 网络错误
//!
//! SerializationError            - JSON encode/decode failed | JSON序列化失败
//! ```

use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sa_token_adapter::storage::SaStorage;
use crate::error::{SaTokenError, SaTokenResult};

/// OAuth2 Client Information | OAuth2 客户端信息
/// 
/// Represents a registered OAuth2 client application with its credentials and configuration.
/// 表示一个已注册的 OAuth2 客户端应用程序及其凭据和配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    /// Unique identifier for the client | 客户端的唯一标识符
    pub client_id: String,
    
    /// Secret key for client authentication | 客户端认证的密钥
    pub client_secret: String,
    
    /// Allowed redirect URIs (whitelist) | 允许的回调 URI（白名单）
    pub redirect_uris: Vec<String>,
    
    /// Supported grant types (e.g., "authorization_code", "refresh_token") 
    /// 支持的授权类型（例如："authorization_code"、"refresh_token"）
    pub grant_types: Vec<String>,
    
    /// Permitted scopes for this client | 此客户端允许的权限范围
    pub scope: Vec<String>,
}

/// Authorization Code | 授权码
/// 
/// Temporary code issued after user authorization, exchanged for access token.
/// 用户授权后颁发的临时代码，用于交换访问令牌。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// The authorization code value | 授权码的值
    pub code: String,
    
    /// Client ID that requested the code | 请求授权码的客户端 ID
    pub client_id: String,
    
    /// User ID who authorized | 授权的用户 ID
    pub user_id: String,
    
    /// Redirect URI used in authorization request | 授权请求中使用的回调 URI
    pub redirect_uri: String,
    
    /// Granted scopes | 授予的权限范围
    pub scope: Vec<String>,
    
    /// Code creation timestamp | 授权码创建时间戳
    pub created_at: DateTime<Utc>,
    
    /// Code expiration timestamp | 授权码过期时间戳
    pub expires_at: DateTime<Utc>,
}

/// Access Token Response | 访问令牌响应
/// 
/// Token response returned to the client after successful authorization.
/// 成功授权后返回给客户端的令牌响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The access token value | 访问令牌的值
    pub access_token: String,
    
    /// Token type (typically "Bearer") | 令牌类型（通常为 "Bearer"）
    pub token_type: String,
    
    /// Token lifetime in seconds | 令牌有效期（秒）
    pub expires_in: i64,
    
    /// Optional refresh token for token renewal | 可选的刷新令牌，用于令牌续期
    pub refresh_token: Option<String>,
    
    /// Granted scopes | 授予的权限范围
    pub scope: Vec<String>,
}

/// OAuth2 Token Information (for storage) | OAuth2 令牌信息（用于存储）
/// 
/// Internal structure for storing token details in the backend.
/// 用于在后端存储令牌详细信息的内部结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2TokenInfo {
    /// Access token value | 访问令牌值
    pub access_token: String,
    
    /// Client ID that owns this token | 拥有此令牌的客户端 ID
    pub client_id: String,
    
    /// User ID associated with this token | 与此令牌关联的用户 ID
    pub user_id: String,
    
    /// Granted scopes | 授予的权限范围
    pub scope: Vec<String>,
    
    /// Token creation timestamp | 令牌创建时间戳
    pub created_at: DateTime<Utc>,
    
    /// Token expiration timestamp | 令牌过期时间戳
    pub expires_at: DateTime<Utc>,
    
    /// Optional refresh token | 可选的刷新令牌
    pub refresh_token: Option<String>,
}

/// OAuth2 Manager | OAuth2 管理器
/// 
/// Core manager for OAuth2 authorization code flow operations.
/// OAuth2 授权码模式的核心管理器。
/// 
/// # Responsibilities | 职责
/// - Client registration and verification | 客户端注册和验证
/// - Authorization code generation and validation | 授权码生成和验证
/// - Access token issuance and verification | 访问令牌颁发和验证
/// - Refresh token management | 刷新令牌管理
/// - Security validation (redirect URI, scope, etc.) | 安全验证（回调 URI、权限范围等）
pub struct OAuth2Manager {
    /// Storage backend for tokens and clients | 令牌和客户端的存储后端
    storage: Arc<dyn SaStorage>,
    
    /// Authorization code TTL in seconds (default: 600 = 10 minutes)
    /// 授权码有效期（秒）（默认：600 = 10 分钟）
    code_ttl: i64,
    
    /// Access token TTL in seconds (default: 3600 = 1 hour)
    /// 访问令牌有效期（秒）（默认：3600 = 1 小时）
    token_ttl: i64,
    
    /// Refresh token TTL in seconds (default: 2592000 = 30 days)
    /// 刷新令牌有效期（秒）（默认：2592000 = 30 天）
    refresh_token_ttl: i64,
}

impl OAuth2Manager {
    /// Create a new OAuth2Manager with default TTL values
    /// 使用默认 TTL 值创建新的 OAuth2Manager
    /// 
    /// # Default TTL | 默认 TTL
    /// - Authorization code: 600 seconds (10 minutes) | 授权码：600 秒（10 分钟）
    /// - Access token: 3600 seconds (1 hour) | 访问令牌：3600 秒（1 小时）
    /// - Refresh token: 2592000 seconds (30 days) | 刷新令牌：2592000 秒（30 天）
    /// 
    /// # Arguments | 参数
    /// * `storage` - Storage backend for persistence | 用于持久化的存储后端
    pub fn new(storage: Arc<dyn SaStorage>) -> Self {
        Self {
            storage,
            code_ttl: 600,        // 10 minutes
            token_ttl: 3600,      // 1 hour
            refresh_token_ttl: 2592000, // 30 days
        }
    }

    /// Set custom TTL values for codes and tokens
    /// 设置授权码和令牌的自定义 TTL 值
    /// 
    /// # Arguments | 参数
    /// * `code_ttl` - Authorization code TTL in seconds | 授权码 TTL（秒）
    /// * `token_ttl` - Access token TTL in seconds | 访问令牌 TTL（秒）
    /// * `refresh_token_ttl` - Refresh token TTL in seconds | 刷新令牌 TTL（秒）
    /// 
    /// # Example | 示例
    /// ```ignore
    /// let oauth2 = OAuth2Manager::new(storage)
    ///     .with_ttl(300, 1800, 604800); // 5min, 30min, 7days
    /// ```
    pub fn with_ttl(mut self, code_ttl: i64, token_ttl: i64, refresh_token_ttl: i64) -> Self {
        self.code_ttl = code_ttl;
        self.token_ttl = token_ttl;
        self.refresh_token_ttl = refresh_token_ttl;
        self
    }

    /// Register a new OAuth2 client | 注册新的 OAuth2 客户端
    /// 
    /// Stores client information in the backend for future authentication.
    /// 将客户端信息存储在后端，用于未来的认证。
    /// 
    /// # Arguments | 参数
    /// * `client` - Client information to register | 要注册的客户端信息
    /// 
    /// # Returns | 返回
    /// * `Ok(())` on success | 成功时返回 `Ok(())`
    /// * `Err(SaTokenError)` on storage or serialization error | 存储或序列化错误时返回错误
    /// 
    /// # Example | 示例
    /// ```ignore
    /// let client = OAuth2Client {
    ///     client_id: "app_001".to_string(),
    ///     client_secret: "secret".to_string(),
    ///     redirect_uris: vec!["http://localhost/callback".to_string()],
    ///     grant_types: vec!["authorization_code".to_string()],
    ///     scope: vec!["read".to_string(), "write".to_string()],
    /// };
    /// oauth2.register_client(&client).await?;
    /// ```
    pub async fn register_client(&self, client: &OAuth2Client) -> SaTokenResult<()> {
        let key = format!("oauth2:client:{}", client.client_id);
        let value = serde_json::to_string(client)
            .map_err(SaTokenError::SerializationError)?;
        
        self.storage.set(&key, &value, None).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        Ok(())
    }

    /// Retrieve client information by client ID | 通过客户端 ID 检索客户端信息
    /// 
    /// # Arguments | 参数
    /// * `client_id` - Client identifier | 客户端标识符
    /// 
    /// # Returns | 返回
    /// * `Ok(OAuth2Client)` if found | 找到时返回客户端信息
    /// * `Err(OAuth2ClientNotFound)` if client doesn't exist | 客户端不存在时返回错误
    pub async fn get_client(&self, client_id: &str) -> SaTokenResult<OAuth2Client> {
        let key = format!("oauth2:client:{}", client_id);
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::OAuth2ClientNotFound)?;
        
        serde_json::from_str(&value)
            .map_err(SaTokenError::SerializationError)
    }

    /// Verify client credentials | 验证客户端凭据
    /// 
    /// Checks if the provided client_id and client_secret match.
    /// 检查提供的 client_id 和 client_secret 是否匹配。
    /// 
    /// # Arguments | 参数
    /// * `client_id` - Client identifier | 客户端标识符
    /// * `client_secret` - Client secret key | 客户端密钥
    /// 
    /// # Returns | 返回
    /// * `Ok(true)` if credentials are valid | 凭据有效时返回 `true`
    /// * `Ok(false)` if credentials are invalid | 凭据无效时返回 `false`
    /// * `Err(OAuth2ClientNotFound)` if client doesn't exist | 客户端不存在时返回错误
    pub async fn verify_client(&self, client_id: &str, client_secret: &str) -> SaTokenResult<bool> {
        let client = self.get_client(client_id).await?;
        Ok(client.client_secret == client_secret)
    }

    /// Generate a new authorization code | 生成新的授权码
    /// 
    /// Creates a temporary authorization code after user consent.
    /// 在用户同意后创建临时授权码。
    /// 
    /// # Arguments | 参数
    /// * `client_id` - Client requesting authorization | 请求授权的客户端
    /// * `user_id` - User granting authorization | 授予授权的用户
    /// * `redirect_uri` - Callback URI for this authorization | 此授权的回调 URI
    /// * `scope` - Granted permissions | 授予的权限
    /// 
    /// # Returns | 返回
    /// * `AuthorizationCode` with unique code and expiration | 带有唯一代码和过期时间的授权码
    /// 
    /// # Note | 注意
    /// This code must be stored using `store_authorization_code()` before returning to client.
    /// 此代码必须在返回给客户端之前使用 `store_authorization_code()` 存储。
    pub fn generate_authorization_code(
        &self,
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scope: Vec<String>,
    ) -> AuthorizationCode {
        let now = Utc::now();
        let code = format!("code_{}", Uuid::new_v4().simple());
        
        AuthorizationCode {
            code,
            client_id,
            user_id,
            redirect_uri,
            scope,
            created_at: now,
            expires_at: now + Duration::seconds(self.code_ttl),
        }
    }

    /// Store authorization code in backend | 在后端存储授权码
    /// 
    /// Persists the authorization code with TTL for later exchange.
    /// 使用 TTL 持久化授权码，以便稍后交换。
    /// 
    /// # Arguments | 参数
    /// * `auth_code` - Authorization code to store | 要存储的授权码
    /// 
    /// # Storage Key Format | 存储键格式
    /// `oauth2:code:{authorization_code}`
    pub async fn store_authorization_code(&self, auth_code: &AuthorizationCode) -> SaTokenResult<()> {
        let key = format!("oauth2:code:{}", auth_code.code);
        let value = serde_json::to_string(auth_code)
            .map_err(SaTokenError::SerializationError)?;
        
        let ttl = Some(std::time::Duration::from_secs(self.code_ttl as u64));
        self.storage.set(&key, &value, ttl).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        Ok(())
    }

    /// Retrieve authorization code information | 获取授权码信息
    ///
    /// Fetches the stored authorization code and validates its expiration.
    /// 获取存储的授权码并验证其过期状态。
    ///
    /// # Arguments | 参数
    /// * `code` - Authorization code to retrieve | 要获取的授权码
    ///
    /// # Returns | 返回
    /// * `Ok(AuthorizationCode)` if code exists and is valid | 授权码存在且有效时返回
    /// * `Err(OAuth2CodeNotFound)` if code not found | 授权码未找到时
    /// * `Err(TokenExpired)` if code has expired | 授权码已过期时
    ///
    /// # Note | 注意
    /// Expired codes are automatically cleaned up from storage.
    /// 过期的授权码会自动从存储中清理。
    pub async fn get_authorization_code(&self, code: &str) -> SaTokenResult<AuthorizationCode> {
        let key = format!("oauth2:code:{}", code);
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::OAuth2CodeNotFound)?;
        
        let auth_code: AuthorizationCode = serde_json::from_str(&value)
            .map_err(SaTokenError::SerializationError)?;
        
        // Check expiration and auto-cleanup if expired
        if Utc::now() > auth_code.expires_at {
            self.storage.delete(&key).await.ok();
            return Err(SaTokenError::TokenExpired);
        }
        
        Ok(auth_code)
    }

    /// Consume authorization code (one-time use) | 消费授权码（一次性使用）
    ///
    /// Retrieves and deletes the authorization code in one operation.
    /// 在一次操作中检索并删除授权码。
    ///
    /// # Arguments | 参数
    /// * `code` - Authorization code to consume | 要消费的授权码
    ///
    /// # Returns | 返回
    /// * `Ok(AuthorizationCode)` if code is valid and consumed | 授权码有效且已消费时返回
    /// * `Err(OAuth2CodeNotFound)` if code not found | 授权码未找到时
    /// * `Err(TokenExpired)` if code has expired | 授权码已过期时
    ///
    /// # Security | 安全性
    /// This ensures the code can only be used once, preventing replay attacks.
    /// 这确保授权码只能使用一次，防止重放攻击。
    pub async fn consume_authorization_code(&self, code: &str) -> SaTokenResult<AuthorizationCode> {
        // First, get and validate the code
        let auth_code = self.get_authorization_code(code).await?;
        
        // Then delete it (consume it)
        let key = format!("oauth2:code:{}", code);
        self.storage.delete(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        Ok(auth_code)
    }

    /// Exchange authorization code for access token | 用授权码换取访问令牌
    /// 
    /// Core of the authorization code flow. Validates the code and issues tokens.
    /// 授权码流程的核心。验证授权码并颁发令牌。
    /// 
    /// # Validations | 验证
    /// 1. Client credentials (client_id + client_secret) | 客户端凭据
    /// 2. Authorization code exists and not expired | 授权码存在且未过期
    /// 3. Client ID matches the code | 客户端 ID 与授权码匹配
    /// 4. Redirect URI matches the code | 回调 URI 与授权码匹配
    /// 
    /// # Arguments | 参数
    /// * `code` - Authorization code | 授权码
    /// * `client_id` - Client identifier | 客户端标识符
    /// * `client_secret` - Client secret | 客户端密钥
    /// * `redirect_uri` - Redirect URI used in authorization | 授权时使用的回调 URI
    /// 
    /// # Returns | 返回
    /// * `Ok(AccessToken)` with access_token and optional refresh_token | 带有访问令牌和可选刷新令牌
    /// * `Err(OAuth2InvalidCredentials)` if client credentials invalid | 客户端凭据无效时
    /// * `Err(OAuth2CodeNotFound)` if code not found or expired | 授权码未找到或已过期时
    /// * `Err(OAuth2ClientIdMismatch)` if client ID doesn't match | 客户端 ID 不匹配时
    /// * `Err(OAuth2RedirectUriMismatch)` if redirect URI doesn't match | 回调 URI 不匹配时
    /// 
    /// # Security | 安全性
    /// The authorization code is consumed (deleted) after use to prevent replay attacks.
    /// 授权码在使用后被消费（删除），以防止重放攻击。
    pub async fn exchange_code_for_token(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> SaTokenResult<AccessToken> {
        // 1. Verify client credentials
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }

        // 2. Consume the authorization code (one-time use)
        let auth_code = self.consume_authorization_code(code).await?;

        // 3. Validate client ID matches
        if auth_code.client_id != client_id {
            return Err(SaTokenError::OAuth2ClientIdMismatch);
        }

        // 4. Validate redirect URI matches
        if auth_code.redirect_uri != redirect_uri {
            return Err(SaTokenError::OAuth2RedirectUriMismatch);
        }

        // 5. Generate and return access token
        self.generate_access_token(&auth_code.client_id, &auth_code.user_id, auth_code.scope).await
    }

    /// Generate access token and refresh token | 生成访问令牌和刷新令牌
    ///
    /// Creates a new access token with an optional refresh token for the user.
    /// 为用户创建新的访问令牌和可选的刷新令牌。
    ///
    /// # Arguments | 参数
    /// * `client_id` - Client identifier | 客户端标识符
    /// * `user_id` - User identifier | 用户标识符
    /// * `scope` - Granted permissions | 授予的权限范围
    ///
    /// # Returns | 返回
    /// * `Ok(AccessToken)` with access_token and refresh_token | 带有访问令牌和刷新令牌
    ///
    /// # Storage | 存储
    /// - Access token: `oauth2:token:{access_token}` (TTL: token_ttl)
    /// - Refresh token: `oauth2:refresh:{refresh_token}` (TTL: refresh_token_ttl)
    ///
    /// # Note | 注意
    /// Both tokens are stored with TTL for automatic expiration cleanup.
    /// 两个令牌都使用 TTL 存储，以便自动清理过期令牌。
    pub async fn generate_access_token(
        &self,
        client_id: &str,
        user_id: &str,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        let now = Utc::now();
        let access_token = format!("at_{}", Uuid::new_v4().simple());
        let refresh_token = format!("rt_{}", Uuid::new_v4().simple());

        // Create token info for storage
        let token_info = OAuth2TokenInfo {
            access_token: access_token.clone(),
            client_id: client_id.to_string(),
            user_id: user_id.to_string(),
            scope: scope.clone(),
            created_at: now,
            expires_at: now + Duration::seconds(self.token_ttl),
            refresh_token: Some(refresh_token.clone()),
        };

        // Store access token with TTL
        let key = format!("oauth2:token:{}", access_token);
        let value = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;
        
        let ttl = Some(std::time::Duration::from_secs(self.token_ttl as u64));
        self.storage.set(&key, &value, ttl).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        // Store refresh token with longer TTL
        let refresh_key = format!("oauth2:refresh:{}", refresh_token);
        let refresh_value = serde_json::json!({
            "user_id": user_id,
            "client_id": client_id,
            "scope": scope,
        }).to_string();
        
        let refresh_ttl = Some(std::time::Duration::from_secs(self.refresh_token_ttl as u64));
        self.storage.set(&refresh_key, &refresh_value, refresh_ttl).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        // Return the access token response
        Ok(AccessToken {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.token_ttl,
            refresh_token: Some(refresh_token),
            scope,
        })
    }

    /// Verify access token and retrieve token information | 验证访问令牌并检索令牌信息
    /// 
    /// Checks if the access token is valid and not expired.
    /// 检查访问令牌是否有效且未过期。
    /// 
    /// # Arguments | 参数
    /// * `access_token` - Access token to verify | 要验证的访问令牌
    /// 
    /// # Returns | 返回
    /// * `Ok(OAuth2TokenInfo)` if token is valid | 令牌有效时返回令牌信息
    /// * `Err(OAuth2AccessTokenNotFound)` if token not found | 令牌未找到时
    /// * `Err(TokenExpired)` if token has expired | 令牌已过期时
    /// 
    /// # Note | 注意
    /// Expired tokens are automatically cleaned up from storage.
    /// 过期的令牌会自动从存储中清理。
    pub async fn verify_access_token(&self, access_token: &str) -> SaTokenResult<OAuth2TokenInfo> {
        let key = format!("oauth2:token:{}", access_token);
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::OAuth2AccessTokenNotFound)?;
        
        let token_info: OAuth2TokenInfo = serde_json::from_str(&value)
            .map_err(SaTokenError::SerializationError)?;
        
        // Check expiration and auto-cleanup if expired
        if Utc::now() > token_info.expires_at {
            self.storage.delete(&key).await.ok();
            return Err(SaTokenError::TokenExpired);
        }
        
        Ok(token_info)
    }

    /// Refresh access token using refresh token | 使用刷新令牌刷新访问令牌
    /// 
    /// Issues a new access token (and optionally a new refresh token) when the old one expires.
    /// 当旧令牌过期时颁发新的访问令牌（以及可选的新刷新令牌）。
    /// 
    /// # Validations | 验证
    /// 1. Client credentials are valid | 客户端凭据有效
    /// 2. Refresh token exists and belongs to the client | 刷新令牌存在且属于该客户端
    /// 3. Client ID matches the refresh token | 客户端 ID 与刷新令牌匹配
    /// 
    /// # Arguments | 参数
    /// * `refresh_token` - Refresh token | 刷新令牌
    /// * `client_id` - Client identifier | 客户端标识符
    /// * `client_secret` - Client secret | 客户端密钥
    /// 
    /// # Returns | 返回
    /// * `Ok(AccessToken)` with new access_token and refresh_token | 新的访问令牌和刷新令牌
    /// * `Err(OAuth2InvalidCredentials)` if credentials invalid | 凭据无效时
    /// * `Err(OAuth2RefreshTokenNotFound)` if refresh token not found | 刷新令牌未找到时
    /// * `Err(OAuth2ClientIdMismatch)` if client ID doesn't match | 客户端 ID 不匹配时
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> SaTokenResult<AccessToken> {
        // 1. Verify client credentials
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }

        // 2. Get refresh token data from storage
        let key = format!("oauth2:refresh:{}", refresh_token);
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::OAuth2RefreshTokenNotFound)?;
        
        let data: serde_json::Value = serde_json::from_str(&value)
            .map_err(SaTokenError::SerializationError)?;
        
        // 3. Validate client ID matches
        let stored_client_id = data["client_id"].as_str()
            .ok_or(SaTokenError::OAuth2InvalidRefreshToken)?;
        
        if stored_client_id != client_id {
            return Err(SaTokenError::OAuth2ClientIdMismatch);
        }

        // 4. Extract user ID and scope
        let user_id = data["user_id"].as_str()
            .ok_or(SaTokenError::OAuth2InvalidRefreshToken)?;
        
        let scope: Vec<String> = data["scope"].as_array()
            .ok_or(SaTokenError::OAuth2InvalidScope)?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        // 5. Generate new access token with same scope
        self.generate_access_token(client_id, user_id, scope).await
    }

    /// Revoke an access token or refresh token | 撤销访问令牌或刷新令牌
    /// 
    /// Deletes the token from storage, making it immediately invalid.
    /// 从存储中删除令牌，使其立即失效。
    /// 
    /// # Arguments | 参数
    /// * `token` - Token to revoke (access or refresh) | 要撤销的令牌（访问或刷新）
    /// 
    /// # Use Cases | 使用场景
    /// - User logout | 用户登出
    /// - Security breach | 安全漏洞
    /// - Client revocation | 客户端撤销
    pub async fn revoke_token(&self, token: &str) -> SaTokenResult<()> {
        let access_key = format!("oauth2:token:{}", token);
        let refresh_key = format!("oauth2:refresh:{}", token);
        
        self.storage.delete(&access_key).await.ok();
        self.storage.delete(&refresh_key).await.ok();
        
        Ok(())
    }

    /// Validate redirect URI against client's whitelist | 根据客户端白名单验证回调 URI
    /// 
    /// Security check to prevent redirect URI hijacking.
    /// 安全检查以防止回调 URI 劫持。
    /// 
    /// # Arguments | 参数
    /// * `client` - Client information with registered URIs | 带有注册 URI 的客户端信息
    /// * `redirect_uri` - URI to validate | 要验证的 URI
    /// 
    /// # Returns | 返回
    /// * `true` if URI is in the whitelist | URI 在白名单中时返回 `true`
    /// * `false` if URI is not allowed | URI 不被允许时返回 `false`
    pub fn validate_redirect_uri(&self, client: &OAuth2Client, redirect_uri: &str) -> bool {
        client.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }

    /// Validate requested scopes against client's permitted scopes | 根据客户端允许的范围验证请求的权限范围
    /// 
    /// Ensures requested scopes are a subset of client's permitted scopes.
    /// 确保请求的权限范围是客户端允许范围的子集。
    /// 
    /// # Arguments | 参数
    /// * `client` - Client information with permitted scopes | 带有允许权限范围的客户端信息
    /// * `requested_scope` - Scopes being requested | 正在请求的权限范围
    /// 
    /// # Returns | 返回
    /// * `true` if all requested scopes are permitted | 所有请求的权限范围都被允许时返回 `true`
    /// * `false` if any requested scope is not permitted | 任何请求的权限范围不被允许时返回 `false`
    pub fn validate_scope(&self, client: &OAuth2Client, requested_scope: &[String]) -> bool {
        requested_scope.iter().all(|s| client.scope.contains(s))
    }

    /// 客户端是否支持指定 grant_type
    pub fn supports_grant_type(client: &OAuth2Client, grant_type: &str) -> bool {
        client.grant_types.iter().any(|g| g == grant_type)
    }

    /// Resource Owner Password Credentials Grant
    ///
    /// 密码校验应由业务层完成后再调用；此处以 `username` 作为 `user_id` 签发令牌。
    pub async fn password_grant(
        &self,
        client_id: &str,
        client_secret: &str,
        username: &str,
        _password: &str,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        let client = self.get_client(client_id).await?;
        if !Self::supports_grant_type(&client, "password") {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.validate_scope(&client, &scope) {
            return Err(SaTokenError::OAuth2InvalidScope);
        }
        self.generate_access_token(client_id, username, scope).await
    }

    /// Client Credentials Grant（以 client_id 作为 subject）
    pub async fn client_credentials_grant(
        &self,
        client_id: &str,
        client_secret: &str,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        let client = self.get_client(client_id).await?;
        if !Self::supports_grant_type(&client, "client_credentials") {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.verify_client(client_id, client_secret).await? {
            return Err(SaTokenError::OAuth2InvalidCredentials);
        }
        if !self.validate_scope(&client, &scope) {
            return Err(SaTokenError::OAuth2InvalidScope);
        }
        let subject = format!("client:{}", client_id);
        self.generate_access_token(client_id, &subject, scope).await
    }

    /// 按 grant_type 分发令牌请求
    ///
    /// OAuth2 刷新与 Sa-Token [`RefreshTokenManager`] 职责分离：本模块仅管理 `oauth2:refresh:*` 键。
    pub async fn issue_token(
        &self,
        grant_type: &str,
        client_id: &str,
        client_secret: &str,
        code: Option<&str>,
        redirect_uri: Option<&str>,
        refresh_token: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        scope: Vec<String>,
    ) -> SaTokenResult<AccessToken> {
        match grant_type {
            "authorization_code" => {
                let code = code.ok_or(SaTokenError::OAuth2CodeNotFound)?;
                let redirect_uri = redirect_uri.ok_or(SaTokenError::OAuth2RedirectUriMismatch)?;
                self.exchange_code_for_token(code, client_id, client_secret, redirect_uri)
                    .await
            }
            "refresh_token" => {
                let refresh = refresh_token.ok_or(SaTokenError::OAuth2RefreshTokenNotFound)?;
                self.refresh_access_token(refresh, client_id, client_secret)
                    .await
            }
            "password" => {
                let username = username.ok_or(SaTokenError::OAuth2InvalidCredentials)?;
                let password = password.ok_or(SaTokenError::OAuth2InvalidCredentials)?;
                self.password_grant(client_id, client_secret, username, password, scope)
                    .await
            }
            "client_credentials" => {
                self.client_credentials_grant(client_id, client_secret, scope)
                    .await
            }
            _ => Err(SaTokenError::OAuth2InvalidCredentials),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    #[tokio::test]
    async fn test_oauth2_authorization_code_flow() {
        let storage = Arc::new(MemoryStorage::new());
        let oauth2 = OAuth2Manager::new(storage);

        let client = OAuth2Client {
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            redirect_uris: vec!["http://localhost:3000/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scope: vec!["read".to_string(), "write".to_string()],
        };

        oauth2.register_client(&client).await.unwrap();

        let auth_code = oauth2.generate_authorization_code(
            "test_client".to_string(),
            "user_123".to_string(),
            "http://localhost:3000/callback".to_string(),
            vec!["read".to_string()],
        );

        oauth2.store_authorization_code(&auth_code).await.unwrap();

        let token = oauth2.exchange_code_for_token(
            &auth_code.code,
            "test_client",
            "test_secret",
            "http://localhost:3000/callback",
        ).await.unwrap();

        assert_eq!(token.token_type, "Bearer");
        assert!(token.refresh_token.is_some());

        let token_info = oauth2.verify_access_token(&token.access_token).await.unwrap();
        assert_eq!(token_info.user_id, "user_123");
        assert_eq!(token_info.client_id, "test_client");
    }

    #[tokio::test]
    async fn test_refresh_token() {
        let storage = Arc::new(MemoryStorage::new());
        let oauth2 = OAuth2Manager::new(storage);

        let client = OAuth2Client {
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            redirect_uris: vec!["http://localhost:3000/callback".to_string()],
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            scope: vec!["read".to_string()],
        };

        oauth2.register_client(&client).await.unwrap();

        let token = oauth2.generate_access_token(
            "test_client",
            "user_123",
            vec!["read".to_string()],
        ).await.unwrap();

        let refresh_token = token.refresh_token.as_ref().unwrap();
        let new_token = oauth2.refresh_access_token(
            refresh_token,
            "test_client",
            "test_secret",
        ).await.unwrap();

        assert_ne!(new_token.access_token, token.access_token);
    }
}


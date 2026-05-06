//! # SSO 单点登录模块 | SSO Single Sign-On Module
//!
//! 提供完整的单点登录功能实现，支持票据认证和统一登出。
//! Provides complete Single Sign-On functionality with ticket-based authentication and unified logout.
//!
//! ## 代码流程逻辑 | Code Flow Logic
//!
//! ### 1. 核心组件 | Core Components
//!
//! ```text
//! SsoServer（SSO 服务端）
//!   ├── 票据管理 | Ticket Management
//!   │   ├── 生成票据 create_ticket()
//!   │   ├── 验证票据 validate_ticket()
//!   │   └── 清理过期票据 cleanup_expired_tickets()
//!   ├── 会话管理 | Session Management
//!   │   ├── 创建会话 login()
//!   │   ├── 获取会话 get_session()
//!   │   └── 删除会话 logout()
//!   └── 客户端追踪 | Client Tracking
//!       └── 获取活跃客户端 get_active_clients()
//!
//! SsoClient（SSO 客户端）
//!   ├── URL 生成 | URL Generation
//!   │   ├── 登录 URL get_login_url()
//!   │   └── 登出 URL get_logout_url()
//!   ├── 本地会话 | Local Session
//!   │   ├── 检查登录 check_local_login()
//!   │   └── 票据登录 login_by_ticket()
//!   └── 登出处理 | Logout Handling
//!       └── 处理登出 handle_logout()
//! ```
//!
//! ### 2. 登录流程 | Login Flow
//!
//! ```text
//! 步骤 1: 用户访问应用 → 重定向到 SSO Server
//! Step 1: User accesses app → Redirect to SSO Server
//!
//! 步骤 2: SSO Server 验证凭证
//! Step 2: SSO Server validates credentials
//!   └─> login(login_id, service) 
//!       ├─> 创建 Token
//!       ├─> 创建或更新 SsoSession
//!       └─> 生成 SsoTicket
//!
//! 步骤 3: 客户端应用验证票据
//! Step 3: Client app validates ticket
//!   └─> validate_ticket(ticket_id, service)
//!       ├─> 检查票据存在
//!       ├─> 验证票据有效性（未过期、未使用）
//!       ├─> 验证服务 URL 匹配
//!       ├─> 标记票据为已使用
//!       └─> 返回 login_id
//!
//! 步骤 4: 创建本地会话
//! Step 4: Create local session
//!   └─> client.login_by_ticket(login_id)
//!       └─> manager.login(login_id) → 创建本地 Token
//! ```
//!
//! ### 3. SSO 无缝登录流程 | SSO Seamless Login Flow
//!
//! ```text
//! 用户已在应用1登录，访问应用2：
//! User logged in App1, accessing App2:
//!
//! 应用2 → SSO Server: 请求认证
//! App2 → SSO Server: Request authentication
//!   └─> is_logged_in(login_id) → true
//!       └─> create_ticket(login_id, app2_url)
//!           └─> 直接返回票据（无需再次登录）
//!               Return ticket (no re-login required)
//!
//! 应用2 → 验证票据 → 创建本地会话 → 访问授权
//! App2 → Validate ticket → Create local session → Access granted
//! ```
//!
//! ### 4. 统一登出流程 | Unified Logout Flow
//!
//! ```text
//! 用户从任一应用登出：
//! User logs out from any app:
//!
//! logout(login_id)
//!   ├─> 获取 SsoSession
//!   ├─> 获取所有已登录客户端列表
//!   ├─> 删除 SsoSession
//!   ├─> 删除用户的所有 Token
//!   └─> 返回客户端列表
//!
//! 通知所有客户端：
//! Notify all clients:
//!   └─> for each client_url
//!       └─> client.handle_logout(login_id)
//!           └─> 清除本地会话 | Clear local session
//! ```
//!
//! ### 5. 票据生命周期 | Ticket Lifecycle
//!
//! ```text
//! 创建 | Create: ticket.create_time = now
//!   └─> 设置过期时间 | Set expiration: expire_time = now + timeout
//!   └─> 状态 | Status: used = false
//!
//! 验证 | Validate:
//!   ├─> 检查过期 | Check expiration: now > expire_time?
//!   ├─> 检查使用状态 | Check usage: used == true?
//!   └─> 验证服务 | Verify service: service == expected?
//!
//! 使用 | Use: 验证成功后 | After validation
//!   └─> ticket.used = true（一次性使用 | One-time use）
//!
//! 清理 | Cleanup: cleanup_expired_tickets()
//!   └─> 删除所有过期或已使用的票据
//!       Remove all expired or used tickets
//! ```
//!
//! ### 6. 安全机制 | Security Mechanisms
//!
//! ```text
//! 1. 票据一次性使用 | One-time ticket usage
//!    └─> validate_ticket() 后立即设置 used = true
//!
//! 2. 服务 URL 匹配 | Service URL matching
//!    └─> ticket.service 必须与请求的 service 完全匹配
//!
//! 3. 票据过期 | Ticket expiration
//!    └─> 默认 5 分钟过期，可配置
//!
//! 4. 跨域保护 | Cross-domain protection
//!    └─> SsoConfig.allowed_origins 白名单机制
//!
//! 5. UUID 票据 ID | UUID ticket ID
//!    └─> 使用 UUID 防止票据 ID 被猜测
//! ```

use std::sync::Arc;
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration as ChronoDuration};
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use crate::{SaTokenError, SaTokenResult, SaTokenManager};

type LogoutCallback = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// SSO 票据结构 | SSO Ticket Structure
///
/// 票据是一个短期、一次性使用的认证令牌
/// A ticket is a short-lived, one-time use authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoTicket {
    /// 票据唯一标识符（UUID）| Unique ticket identifier (UUID)
    pub ticket_id: String,
    /// 目标服务 URL | Target service URL
    pub service: String,
    /// 用户登录 ID | User login ID
    pub login_id: String,
    /// 票据创建时间 | Ticket creation time
    pub create_time: DateTime<Utc>,
    /// 票据过期时间 | Ticket expiration time
    pub expire_time: DateTime<Utc>,
    /// 是否已使用（一次性使用）| Whether used (one-time use)
    pub used: bool,
}

impl SsoTicket {
    /// 创建新票据 | Create a new ticket
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    /// * `service` - 目标服务 URL | Target service URL
    /// * `timeout_seconds` - 票据有效期（秒）| Ticket validity period (seconds)
    pub fn new(login_id: String, service: String, timeout_seconds: i64) -> Self {
        let now = Utc::now();
        Self {
            ticket_id: uuid::Uuid::new_v4().to_string(),
            service,
            login_id,
            create_time: now,
            expire_time: now + ChronoDuration::seconds(timeout_seconds),
            used: false,
        }
    }

    /// 检查票据是否过期 | Check if ticket is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expire_time
    }

    /// 检查票据是否有效（未使用且未过期）| Check if ticket is valid (not used and not expired)
    pub fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }
}

/// SSO 全局会话 | SSO Global Session
///
/// 跟踪用户在所有应用中的登录状态
/// Tracks user's login status across all applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    /// 用户登录 ID | User login ID
    pub login_id: String,
    /// 已登录的客户端列表 | List of logged-in clients
    pub clients: Vec<String>,
    /// 会话创建时间 | Session creation time
    pub create_time: DateTime<Utc>,
    /// 最后活动时间 | Last activity time
    pub last_active_time: DateTime<Utc>,
}

impl SsoSession {
    /// 创建新会话 | Create a new session
    pub fn new(login_id: String) -> Self {
        let now = Utc::now();
        Self {
            login_id,
            clients: Vec::new(),
            create_time: now,
            last_active_time: now,
        }
    }

    /// 添加客户端到会话 | Add client to session
    ///
    /// 如果客户端不在列表中，则添加
    /// Adds client if not already in the list
    pub fn add_client(&mut self, service: String) {
        if !self.clients.contains(&service) {
            self.clients.push(service);
        }
        self.last_active_time = Utc::now();
    }

    /// 从会话中移除客户端 | Remove client from session
    pub fn remove_client(&mut self, service: &str) {
        self.clients.retain(|c| c != service);
        self.last_active_time = Utc::now();
    }
}

/// SSO 服务端 | SSO Server
///
/// 中央认证服务，负责票据生成、验证和会话管理
/// Central authentication service responsible for ticket generation, validation, and session management
pub struct SsoServer {
    manager: Arc<SaTokenManager>,
    tickets: Arc<RwLock<HashMap<String, SsoTicket>>>,
    sessions: Arc<RwLock<HashMap<String, SsoSession>>>,
    ticket_timeout: i64,
}

impl SsoServer {
    /// 创建新的 SSO 服务端 | Create a new SSO Server
    ///
    /// # 参数 | Parameters
    /// * `manager` - SaTokenManager 实例 | SaTokenManager instance
    pub fn new(manager: Arc<SaTokenManager>) -> Self {
        Self {
            manager,
            tickets: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ticket_timeout: 300, // 默认 5 分钟 | Default 5 minutes
        }
    }

    /// 设置票据超时时间 | Set ticket timeout
    ///
    /// # 参数 | Parameters
    /// * `timeout` - 超时时间（秒）| Timeout in seconds
    pub fn with_ticket_timeout(mut self, timeout: i64) -> Self {
        self.ticket_timeout = timeout;
        self
    }

    /// 检查用户是否已登录 | Check if user is logged in
    ///
    /// 通过检查 SSO 会话是否存在来判断
    /// Determined by checking if SSO session exists
    pub async fn is_logged_in(&self, login_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        let has_session = sessions.contains_key(login_id);
        drop(sessions);
        
        // 如果会话存在，进一步验证 Token 是否有效
        if has_session {
            let key = format!("sa:login:token:{}:sso", login_id);
            matches!(self.manager.storage.get(&key).await, Ok(Some(_)))
        } else {
            false
        }
    }

    /// 创建票据 | Create ticket
    ///
    /// 为已登录用户创建访问特定服务的票据
    /// Creates a ticket for logged-in user to access specific service
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    /// * `service` - 目标服务 URL | Target service URL
    ///
    /// # 返回 | Returns
    /// 新创建的票据 | Newly created ticket
    pub async fn create_ticket(&self, login_id: String, service: String) -> SaTokenResult<SsoTicket> {
        // 生成票据 | Generate ticket
        let ticket = SsoTicket::new(login_id.clone(), service.clone(), self.ticket_timeout);
        
        // 存储票据 | Store ticket
        let mut tickets = self.tickets.write().await;
        tickets.insert(ticket.ticket_id.clone(), ticket.clone());

        // 更新会话，添加客户端 | Update session, add client
        let mut sessions = self.sessions.write().await;
        sessions.entry(login_id.clone())
            .or_insert_with(|| SsoSession::new(login_id))
            .add_client(service);

        Ok(ticket)
    }

    /// 验证票据 | Validate ticket
    ///
    /// 验证票据的有效性并将其标记为已使用（一次性使用）
    /// Validates ticket and marks it as used (one-time use)
    ///
    /// # 参数 | Parameters
    /// * `ticket_id` - 票据 ID | Ticket ID
    /// * `service` - 请求的服务 URL | Requested service URL
    ///
    /// # 返回 | Returns
    /// 用户登录 ID | User login ID
    ///
    /// # 错误 | Errors
    /// * `InvalidTicket` - 票据不存在 | Ticket not found
    /// * `TicketExpired` - 票据已过期或已使用 | Ticket expired or used
    /// * `ServiceMismatch` - 服务 URL 不匹配 | Service URL mismatch
    pub async fn validate_ticket(&self, ticket_id: &str, service: &str) -> SaTokenResult<String> {
        let mut tickets = self.tickets.write().await;
        
        // 1. 检查票据是否存在 | Check if ticket exists
        let ticket = tickets.get_mut(ticket_id)
            .ok_or(SaTokenError::InvalidTicket)?;

        // 2. 验证票据有效性（未过期、未使用）| Validate ticket (not expired, not used)
        if !ticket.is_valid() {
            return Err(SaTokenError::TicketExpired);
        }

        // 3. 验证服务 URL 匹配 | Verify service URL matches
        if ticket.service != service {
            return Err(SaTokenError::ServiceMismatch);
        }

        // 4. 标记票据为已使用（一次性使用）| Mark ticket as used (one-time use)
        ticket.used = true;
        let login_id = ticket.login_id.clone();

        Ok(login_id)
    }

    /// 用户登录 | User login
    ///
    /// 完整的登录流程：创建 Token、会话和票据
    /// Complete login flow: create Token, session, and ticket
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    /// * `service` - 目标服务 URL | Target service URL
    ///
    /// # 返回 | Returns
    /// 生成的票据 | Generated ticket
    pub async fn login(&self, login_id: String, service: String) -> SaTokenResult<SsoTicket> {
        // 使用 login_with_options 创建 SSO 类型的 Token
        let _token = self.manager.login_with_options(
            &login_id,
            Some("sso".to_string()), // 设置 login_type 为 "sso"
            None,
            Some(serde_json::json!({
                "sso_mode": true,
                "service": service.clone()
            })),
            None,
            None,
        ).await?;
        
        // 更新会话
        let mut sessions = self.sessions.write().await;
        sessions.entry(login_id.clone())
            .or_insert_with(|| SsoSession::new(login_id.clone()))
            .add_client(service.clone());

        drop(sessions);

        // 创建并返回票据
        self.create_ticket(login_id, service).await
    }

    /// 统一登出 | Unified logout
    ///
    /// 从 SSO 服务端登出，并返回需要通知的客户端列表
    /// Logout from SSO Server and return list of clients to notify
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    ///
    /// # 返回 | Returns
    /// 需要清除会话的客户端 URL 列表 | List of client URLs to clear sessions
    pub async fn logout(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        // 1. 获取并删除 SSO 会话 | Get and remove SSO session
        let mut sessions = self.sessions.write().await;
        let session = sessions.remove(login_id);
        
        // 2. 提取客户端列表 | Extract client list
        let clients = session.map(|s| s.clients).unwrap_or_default();

        drop(sessions);

        // 3. 从 Token 管理器中登出（登出所有类型的 Token）| Logout from Token manager (all token types)
        // 3.1 登出 SSO 服务端 Token
        let sso_key = format!("sa:login:token:{}:sso", login_id);
        let _ = self.manager.storage.delete(&sso_key).await;
        
        // 3.2 登出默认类型 Token
        self.manager.logout_by_login_id(login_id).await?;

        // 4. 返回客户端列表供通知 | Return client list for notification
        Ok(clients)
    }

    /// 获取 SSO 会话 | Get SSO session
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    ///
    /// # 返回 | Returns
    /// SSO 会话信息（如果存在）| SSO session info (if exists)
    pub async fn get_session(&self, login_id: &str) -> Option<SsoSession> {
        let sessions = self.sessions.read().await;
        sessions.get(login_id).cloned()
    }

    /// 检查会话是否存在 | Check if session exists
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    ///
    /// # 返回 | Returns
    /// 会话是否存在 | Whether session exists
    pub async fn check_session(&self, login_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(login_id)
    }

    /// 清理过期票据 | Cleanup expired tickets
    ///
    /// 删除所有过期或已使用的票据
    /// Removes all expired or used tickets
    pub async fn cleanup_expired_tickets(&self) {
        let mut tickets = self.tickets.write().await;
        tickets.retain(|_, ticket| ticket.is_valid());
    }

    /// 获取活跃客户端列表 | Get active clients list
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    ///
    /// # 返回 | Returns
    /// 客户端 URL 列表 | List of client URLs
    pub async fn get_active_clients(&self, login_id: &str) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.get(login_id)
            .map(|s| s.clients.clone())
            .unwrap_or_default()
    }
}

/// SSO 客户端 | SSO Client
///
/// 每个应用作为 SSO 客户端，处理本地会话和票据验证
/// Each application acts as SSO Client, handling local sessions and ticket validation
pub struct SsoClient {
    /// Token 管理器 | Token manager
    manager: Arc<SaTokenManager>,
    /// SSO 服务端 URL | SSO Server URL
    server_url: String,
    /// 当前服务 URL | Current service URL
    service_url: String,
    /// 登出回调函数 | Logout callback function
    logout_callback: Option<LogoutCallback>,
}

impl SsoClient {
    /// 创建新的 SSO 客户端 | Create a new SSO Client
    ///
    /// # 参数 | Parameters
    /// * `manager` - SaTokenManager 实例 | SaTokenManager instance
    /// * `server_url` - SSO 服务端 URL | SSO Server URL
    /// * `service_url` - 当前服务 URL | Current service URL
    pub fn new(
        manager: Arc<SaTokenManager>,
        server_url: String,
        service_url: String,
    ) -> Self {
        Self {
            manager,
            server_url,
            service_url,
            logout_callback: None,
        }
    }

    /// 设置登出回调函数 | Set logout callback
    ///
    /// # 参数 | Parameters
    /// * `callback` - 登出时执行的回调函数 | Callback function to execute on logout
    pub fn with_logout_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.logout_callback = Some(Arc::new(callback));
        self
    }

    /// 生成登录 URL | Generate login URL
    ///
    /// # 返回 | Returns
    /// SSO 服务端登录 URL，包含当前服务的回调地址
    /// SSO Server login URL with current service callback
    pub fn get_login_url(&self) -> String {
        format!("{}?service={}", self.server_url, urlencoding::encode(&self.service_url))
    }

    /// 生成登出 URL | Generate logout URL
    ///
    /// # 返回 | Returns
    /// SSO 服务端登出 URL，包含当前服务的回调地址
    /// SSO Server logout URL with current service callback
    pub fn get_logout_url(&self) -> String {
        format!("{}/logout?service={}", self.server_url, urlencoding::encode(&self.service_url))
    }

    /// 检查本地是否已登录 | Check if locally logged in
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    ///
    /// # 返回 | Returns
    /// 是否已登录 | Whether logged in
    pub async fn check_local_login(&self, login_id: &str) -> bool {
        // 检查 SSO 客户端类型的登录
        let key = format!("sa:login:token:{}:sso_client", login_id);
        match self.manager.storage.get(&key).await {
            Ok(Some(_)) => true,
            _ => {
                // 兼容旧的无类型登录
                let key_default = format!("sa:login:token:{}", login_id);
                matches!(self.manager.storage.get(&key_default).await, Ok(Some(_)))
            }
        }
    }

    /// 处理票据（验证票据合法性）| Process ticket (validate ticket)
    ///
    /// # 参数 | Parameters
    /// * `ticket` - 票据 ID | Ticket ID
    /// * `service` - 服务 URL | Service URL
    ///
    /// # 返回 | Returns
    /// 处理后的票据信息 | Processed ticket info
    ///
    /// # 错误 | Errors
    /// * `ServiceMismatch` - 服务 URL 不匹配 | Service URL mismatch
    pub async fn process_ticket(&self, ticket: &str, service: &str) -> SaTokenResult<String> {
        // 验证服务 URL 是否匹配
        if service != self.service_url {
            return Err(SaTokenError::ServiceMismatch);
        }

        Ok(ticket.to_string())
    }

    /// 通过票据登录（客户端本地登录）| Login by ticket (client-side local login)
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    ///
    /// # 返回 | Returns
    /// 生成的本地 Token | Generated local token
    pub async fn login_by_ticket(&self, login_id: String) -> SaTokenResult<String> {
        // 使用 login_with_options 创建客户端 Token，标记为 SSO 客户端登录
        let token = self.manager.login_with_options(
            &login_id,
            Some("sso_client".to_string()), // 标记为 SSO 客户端
            None,
            Some(serde_json::json!({
                "sso_client": true,
                "service_url": self.service_url.clone()
            })),
            None,
            None,
        ).await?;
        Ok(token.to_string())
    }

    /// 处理登出（客户端）| Handle logout (client-side)
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 用户登录 ID | User login ID
    pub async fn handle_logout(&self, login_id: &str) -> SaTokenResult<()> {
        // 1. 执行登出回调 | Execute logout callback
        if let Some(callback) = &self.logout_callback {
            callback(login_id);
        }
        
        // 2. 登出 SSO 客户端类型的 Token | Logout SSO client token
        let sso_client_key = format!("sa:login:token:{}:sso_client", login_id);
        let _ = self.manager.storage.delete(&sso_client_key).await;
        
        // 3. 登出默认类型的 Token（兼容）| Logout default token (compatibility)
        self.manager.logout_by_login_id(login_id).await?;
        
        Ok(())
    }

    /// 获取 SSO 服务端 URL | Get SSO Server URL
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// 获取当前服务 URL | Get current service URL
    pub fn service_url(&self) -> &str {
        &self.service_url
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    pub server_url: String,
    pub ticket_timeout: i64,
    pub allow_cross_domain: bool,
    pub allowed_origins: Vec<String>,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080/sso".to_string(),
            ticket_timeout: 300,
            allow_cross_domain: true,
            allowed_origins: vec!["*".to_string()],
        }
    }
}

impl SsoConfig {
    pub fn builder() -> SsoConfigBuilder {
        SsoConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct SsoConfigBuilder {
    config: SsoConfig,
}

impl SsoConfigBuilder {
    pub fn server_url(mut self, url: impl Into<String>) -> Self {
        self.config.server_url = url.into();
        self
    }

    pub fn ticket_timeout(mut self, timeout: i64) -> Self {
        self.config.ticket_timeout = timeout;
        self
    }

    pub fn allow_cross_domain(mut self, allow: bool) -> Self {
        self.config.allow_cross_domain = allow;
        self
    }

    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config.allowed_origins = origins;
        self
    }

    pub fn add_allowed_origin(mut self, origin: String) -> Self {
        if self.config.allowed_origins == vec!["*".to_string()] {
            self.config.allowed_origins = vec![origin];
        } else {
            self.config.allowed_origins.push(origin);
        }
        self
    }

    pub fn build(self) -> SsoConfig {
        self.config
    }
}

pub struct SsoManager {
    server: Option<Arc<SsoServer>>,
    client: Option<Arc<SsoClient>>,
    config: SsoConfig,
}

impl SsoManager {
    pub fn new(config: SsoConfig) -> Self {
        Self {
            server: None,
            client: None,
            config,
        }
    }

    pub fn with_server(mut self, server: Arc<SsoServer>) -> Self {
        self.server = Some(server);
        self
    }

    pub fn with_client(mut self, client: Arc<SsoClient>) -> Self {
        self.client = Some(client);
        self
    }

    pub fn server(&self) -> Option<&Arc<SsoServer>> {
        self.server.as_ref()
    }

    pub fn client(&self) -> Option<&Arc<SsoClient>> {
        self.client.as_ref()
    }

    pub fn config(&self) -> &SsoConfig {
        &self.config
    }

    pub fn is_allowed_origin(&self, origin: &str) -> bool {
        if !self.config.allow_cross_domain {
            return false;
        }

        self.config.allowed_origins.contains(&"*".to_string()) ||
        self.config.allowed_origins.contains(&origin.to_string())
    }
}


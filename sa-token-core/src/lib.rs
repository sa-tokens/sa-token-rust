// Author: 金书记
//
//! # sa-token-core
//! 
//! sa-token-rust 的核心库，提供与框架无关的认证授权功能
//! 
//! ## 主要功能
//! 
//! - Token 管理：生成、验证、刷新
//! - Session 管理：会话存储与管理
//! - 权限验证：基于角色/权限的访问控制
//! - 账号管理：登录、登出、踢人下线、封禁等
//! 
//! ## 使用示例
//! 
//! ```rust,ignore
//! use sa_token_core::SaTokenManager;
//! 
//! let manager = SaTokenManager::new(storage, config);
//! let token = manager.create_token("user_123").await?;
//! ```

pub mod token;
pub mod session;
pub mod permission;
pub mod context;
pub mod config;
pub mod util;
pub mod event;
pub mod nonce;
pub mod refresh;
pub mod oauth2;
pub mod ws;
pub mod online;
pub mod distributed;
pub mod sso;
pub mod router;
pub mod disable;
pub mod safe;
pub mod token_session;
pub mod stp_interface;
pub mod stp_logic;
pub mod prelude;

pub mod error;
mod manager;

pub use error::{SaTokenError, SaTokenResult};
pub use manager::SaTokenManager;
pub use config::{SaTokenConfig, LogoutMode, ReplacedLoginExitMode, ReplacedRange, LogoutRange};
pub use stp_interface::StpInterface;
pub use util::{StpUtil, LoginId};
pub use context::SaTokenContext;

// 重新导出核心类型
pub use token::{TokenInfo, TokenValue, JwtManager, JwtClaims, JwtAlgorithm};
pub use session::SaSession;
pub use session::SaTerminalInfo;
pub use stp_logic::SaLogic;
pub use permission::{PermissionChecker, RoleChecker};
pub use event::{
    SaTokenEvent, SaTokenEventType, SaTokenListener, 
    SaTokenEventBus, LoggingListener
};
pub use nonce::NonceManager;
pub use refresh::RefreshTokenManager;
pub use oauth2::{OAuth2Manager, OAuth2Client, AuthorizationCode, AccessToken, OAuth2TokenInfo};
pub use ws::{WsAuthManager, WsAuthInfo, WsTokenExtractor, DefaultWsTokenExtractor};
pub use online::{OnlineManager, OnlineUser, PushMessage, MessageType, MessagePusher, InMemoryPusher};
pub use distributed::{
    DistributedSessionManager, DistributedSession, DistributedSessionStorage,
    ServiceCredential, InMemoryDistributedStorage, SaStorageDistributedStorage
};
pub use disable::{
    DEFAULT_DISABLE_SERVICE, MIN_DISABLE_LEVEL, NOT_DISABLE_LEVEL, DEFAULT_DISABLE_LEVEL,
};
pub use safe::{DEFAULT_SAFE_SERVICE, SAFE_AUTH_VALUE};
pub use sso::{
    SsoServer, SsoClient, SsoManager, SsoTicket, SsoSession, SsoConfig, CheckTicketResult,
};
pub use router::{
    match_path, match_any, need_auth, PathAuthConfig, extract_token, run_auth_flow, AuthFlowResult,
};

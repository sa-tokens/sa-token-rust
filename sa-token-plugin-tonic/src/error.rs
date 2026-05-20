// Author: 金书记
//
// 中文 | English
// gRPC 认证错误类型与扩展类型 | gRPC authentication error types and extension types

use sa_token_core::{error::messages, token::TokenValue};
use tonic::{Code, Status};

// ============================================================================
// 中文: Extension 类型（写入 Request::extensions）
// English: Extension types (inserted into Request::extensions)
// ============================================================================

/// 中文: 已校验的登录 ID，由 Layer / Interceptor 写入 `Request::extensions`
/// English: Validated login ID, inserted into `Request::extensions` by Layer / Interceptor
///
/// 中文: 使用专用类型而非裸 `String`，避免与其他 extension 冲突
/// English: Uses a dedicated type instead of bare `String` to avoid extension conflicts
#[derive(Clone, Debug)]
pub struct SaTokenLoginId(pub String);

/// 中文: 原始 Bearer Token，由 Layer / Interceptor 写入 `Request::extensions`
/// English: Raw Bearer Token, inserted into `Request::extensions` by Layer / Interceptor
///
/// 中文: 供 logout 等需要原始 token 的场景使用
/// English: Used for scenarios like logout that need the raw token
#[derive(Clone, Debug)]
pub struct SaTokenBearerToken(pub TokenValue);

/// 中文: gRPC URI path，由 `SaTokenGrpcLayer` 写入，供 `GrpcServerInterceptor` 解析路径规则
/// English: gRPC URI path, written by `SaTokenGrpcLayer` for `GrpcServerInterceptor` path rules
#[derive(Clone, Debug)]
pub struct SaTokenGrpcPath(pub String);

// ============================================================================
// 中文: Token 数据
// English: Token data
// ============================================================================

/// 中文: 从 gRPC metadata 中提取的 Token 数据
/// English: Token data extracted from gRPC metadata
#[derive(Clone, Debug)]
pub struct GrpcTokenData {
    /// 中文: Token 值
    /// English: Token value
    pub token: Option<TokenValue>,
    /// 中文: 登录 ID
    /// English: Login ID
    pub login_id: Option<String>,
}

// ============================================================================
// 中文: 认证错误
// English: Authentication error
// ============================================================================

/// 中文: gRPC 认证错误
/// English: gRPC authentication error
#[derive(Debug)]
pub struct AuthError {
    message: &'static str,
}

impl AuthError {
    /// 中文: 创建新的认证错误
    /// English: Create a new authentication error
    pub fn new() -> Self {
        Self {
            message: messages::AUTH_ERROR,
        }
    }

    /// 中文: 使用自定义消息创建认证错误
    /// English: Create from custom message
    pub fn with_message(msg: &'static str) -> Self {
        Self { message: msg }
    }

    /// 中文: 转换为 tonic Status
    /// English: Convert to tonic Status
    pub fn into_status(self) -> Status {
        Status::new(Code::Unauthenticated, self.message)
    }
}

impl Default for AuthError {
    fn default() -> Self {
        Self::new()
    }
}

impl From<AuthError> for Status {
    fn from(err: AuthError) -> Self {
        err.into_status()
    }
}

// ============================================================================
// 中文: 权限错误
// English: Permission error
// ============================================================================

/// 中文: gRPC 权限错误
/// English: gRPC permission error
#[derive(Debug)]
pub struct PermissionError {
    message: &'static str,
}

impl PermissionError {
    /// 中文: 创建新的权限错误
    /// English: Create a new permission error
    pub fn new() -> Self {
        Self {
            message: messages::PERMISSION_REQUIRED,
        }
    }

    /// 中文: 使用自定义消息创建权限错误
    /// English: Create from custom message
    pub fn with_message(msg: &'static str) -> Self {
        Self { message: msg }
    }

    /// 中文: 转换为 tonic Status
    /// English: Convert to tonic Status
    pub fn into_status(self) -> Status {
        Status::new(Code::PermissionDenied, self.message)
    }
}

impl Default for PermissionError {
    fn default() -> Self {
        Self::new()
    }
}

impl From<PermissionError> for Status {
    fn from(err: PermissionError) -> Self {
        err.into_status()
    }
}

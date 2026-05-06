// Author: 金书记
//
// 中文 | English
// Warp 提取器 | Warp extractors

use sa_token_core::{token::TokenValue, error::messages};
use warp_03::reject::Reject;
use serde_json::json;

/// 中文 | English
/// 认证错误 | Authentication error
#[derive(Debug)]
pub struct AuthError;

impl AuthError {
    /// 中文 | English
    /// 创建新的认证错误 | Create new authentication error
    pub fn new() -> Self {
        Self
    }
    
    /// 中文 | English
    /// 获取错误消息 | Get error message
    pub fn message(&self) -> &'static str {
        messages::AUTH_ERROR
    }
    
    /// 中文 | English
    /// 转换为 JSON 字符串 | Convert to JSON string
    pub fn to_json(&self) -> String {
        json!({
            "code": 401,
            "message": self.message()
        }).to_string()
    }
}

impl Default for AuthError {
    fn default() -> Self {
        Self::new()
    }
}

impl Reject for AuthError {}

/// 中文 | English
/// 权限错误 | Permission error
#[derive(Debug)]
pub struct PermissionError;

impl PermissionError {
    /// 中文 | English
    /// 创建新的权限错误 | Create new permission error
    pub fn new() -> Self {
        Self
    }
    
    /// 中文 | English
    /// 获取错误消息 | Get error message
    pub fn message(&self) -> &'static str {
        messages::PERMISSION_REQUIRED
    }
    
    /// 中文 | English
    /// 转换为 JSON 字符串 | Convert to JSON string
    pub fn to_json(&self) -> String {
        json!({
            "code": 403,
            "message": self.message()
        }).to_string()
    }
}

impl Default for PermissionError {
    fn default() -> Self {
        Self::new()
    }
}

impl Reject for PermissionError {}

/// 中文 | English
/// 角色错误 | Role error
#[derive(Debug)]
pub struct RoleError;

impl RoleError {
    /// 中文 | English
    /// 创建新的角色错误 | Create new role error
    pub fn new() -> Self {
        Self
    }
    
    /// 中文 | English
    /// 获取错误消息 | Get error message
    pub fn message(&self) -> &'static str {
        messages::ROLE_REQUIRED
    }
    
    /// 中文 | English
    /// 转换为 JSON 字符串 | Convert to JSON string
    pub fn to_json(&self) -> String {
        json!({
            "code": 403,
            "message": self.message()
        }).to_string()
    }
}

impl Default for RoleError {
    fn default() -> Self {
        Self::new()
    }
}

impl Reject for RoleError {}

/// 中文 | English
/// Token 提取器 - 从请求中提取 Token | Token extractor - extract token from request
pub struct SaTokenExtractor(pub TokenValue);

impl SaTokenExtractor {
    /// 中文 | English
    /// 获取 Token 值 | Get token value
    pub fn token(&self) -> &TokenValue {
        &self.0
    }
}

/// 中文 | English
/// 可选 Token 提取器 - 从请求中提取可选 Token | Optional token extractor - extract optional token from request
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    /// 中文 | English
    /// 获取 Option<TokenValue> | Get Option<TokenValue>
    pub fn token(&self) -> Option<&TokenValue> {
        self.0.as_ref()
    }
}

/// 中文 | English
/// LoginId 提取器 - 从请求中提取 LoginId | LoginId extractor - extract login ID from request
pub struct LoginIdExtractor(pub String);

impl LoginIdExtractor {
    /// 中文 | English
    /// 获取登录 ID | Get login ID
    pub fn login_id(&self) -> &str {
        &self.0
    }
}

/// 中文 | English
/// 处理 Warp 拒绝 | Handle Warp rejection
///
/// 将 Sa-Token 错误转换为 HTTP 响应 | Convert Sa-Token errors to HTTP responses
pub async fn handle_rejection(err: warp_03::Rejection) -> Result<impl warp_03::Reply, std::convert::Infallible> {
    let (code, message) = if err.is_not_found() {
        (404, json!({"code": 404, "message": "Not Found"}).to_string())
    } else if let Some(auth_error) = err.find::<AuthError>() {
        (401, auth_error.to_json())
    } else if let Some(perm_error) = err.find::<PermissionError>() {
        (403, perm_error.to_json())
    } else if let Some(role_error) = err.find::<RoleError>() {
        (403, role_error.to_json())
    } else {
        (500, json!({"code": 500, "message": "Internal Server Error"}).to_string())
    };
    
    Ok(warp_03::reply::with_status(
        warp_03::reply::json(&serde_json::from_str::<serde_json::Value>(&message).unwrap_or_default()),
        warp_03::http::StatusCode::from_u16(code).unwrap_or(warp_03::http::StatusCode::INTERNAL_SERVER_ERROR)
    ))
}
use salvo::prelude::*;
use sa_token_core::{token::TokenValue, error::messages};
use serde_json::json;

/// 中文: 认证错误 | English: Authentication error
#[derive(Debug)]
pub struct AuthError;

impl AuthError {
    /// 中文: 创建新的认证错误 | English: Create new authentication error
    pub fn new() -> Self {
        Self
    }
    
    /// 中文: 获取错误消息 | English: Get error message
    pub fn message(&self) -> &'static str {
        messages::AUTH_ERROR
    }
    
    /// 中文: 转换为 JSON 字符串 | English: Convert to JSON string
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

/// 中文: 必填 Token 提取器，从 Salvo Request 扩展里读取 Token
/// English: Required token extractor reading TokenValue from Salvo request extensions
pub struct SaTokenExtractor(pub TokenValue);

impl SaTokenExtractor {
    /// 中文: 获取 Token 值 | English: Get token value
    pub fn token(&self) -> &TokenValue {
        &self.0
    }
    
    /// 中文: 中间件注入 Token 后，从 extensions 中取出
    /// English: Fetches TokenValue injected by middleware in extensions
    pub fn from_request(req: &Request) -> Result<Self, AuthError> {
        req.extensions()
            .get::<TokenValue>()
            .cloned()
            .map(SaTokenExtractor)
            .ok_or_else(AuthError::new)
    }
}

/// 中文: 可选 Token 提取器，适用于无需强制登录的场景
/// English: Optional token extractor for routes without mandatory login
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    /// 中文: 获取 Option<TokenValue> | English: Get Option<TokenValue>
    pub fn token(&self) -> Option<&TokenValue> {
        self.0.as_ref()
    }
    
    /// 中文: 返回 Option<TokenValue>，不存在则为 None
    /// English: Returns Option<TokenValue>, None when token absent
    pub fn from_request(req: &Request) -> Self {
        let token = req.extensions().get::<TokenValue>().cloned();
        OptionalSaTokenExtractor(token)
    }
}

/// 中文: 登录 ID 提取器，从请求扩展中获取 login_id
/// English: Login ID extractor fetching login_id from request extensions
pub struct LoginIdExtractor(pub String);

impl LoginIdExtractor {
    /// 中文: 获取登录 ID | English: Get login ID
    pub fn login_id(&self) -> &str {
        &self.0
    }
    
    /// 中文: 若登录状态已建立，中间件会写入 login_id
    /// English: Middleware stores login_id when session is authenticated
    pub fn from_request(req: &Request) -> Result<Self, AuthError> {
        req.extensions()
            .get::<String>()
            .cloned()
            .map(LoginIdExtractor)
            .ok_or_else(AuthError::new)
    }
}

// 这些处理程序可以在应用中定义，而不是在库中
// These handlers can be defined in the application, not in the library

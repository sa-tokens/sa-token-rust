use tide_017::{Request, Response, StatusCode};
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
    
    /// 中文: 转换为 Response | English: Convert to Response
    pub fn to_response(&self) -> Response {
        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(self.to_json());
        res.set_content_type("application/json");
        res
    }
}

impl Default for AuthError {
    fn default() -> Self {
        Self::new()
    }
}

/// 中文: 必填 Token 提取器，读取扩展中的 TokenValue
/// English: Required token extractor reading TokenValue from request extensions
pub struct SaTokenExtractor(pub TokenValue);

impl SaTokenExtractor {
    /// 中文: 获取 Token 值 | English: Get token value
    pub fn token(&self) -> &TokenValue {
        &self.0
    }
    
    /// 中文: 中间件将 Token 写入扩展，这里提取 | English: Middleware writes TokenValue into extensions
    pub fn from_request<State: Clone + Send + Sync + 'static>(req: &Request<State>) -> Result<Self, AuthError> {
        req.ext::<TokenValue>()
            .cloned()
            .map(SaTokenExtractor)
            .ok_or_else(AuthError::new)
    }
}

/// 中文: 可选 Token 提取器，用于无需强制鉴权的接口
/// English: Optional token extractor for routes without mandatory auth
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl OptionalSaTokenExtractor {
    /// 中文: 获取 Option<TokenValue> | English: Get Option<TokenValue>
    pub fn token(&self) -> Option<&TokenValue> {
        self.0.as_ref()
    }
    
    /// 中文: 直接返回 Option<TokenValue> | English: Returns Option<TokenValue> directly
    pub fn from_request<State: Clone + Send + Sync + 'static>(req: &Request<State>) -> Self {
        let token = req.ext::<TokenValue>().cloned();
        OptionalSaTokenExtractor(token)
    }
}

/// 中文: 登录 ID 提取器，从扩展中获取 login_id
/// English: Login ID extractor retrieving login_id from extensions
pub struct LoginIdExtractor(pub String);

impl LoginIdExtractor {
    /// 中文: 获取登录 ID | English: Get login ID
    pub fn login_id(&self) -> &str {
        &self.0
    }
    
    /// 中文: 若登录成功，中间件会注入 login_id | English: Middleware injects login_id when user authenticated
    pub fn from_request<State: Clone + Send + Sync + 'static>(req: &Request<State>) -> Result<Self, AuthError> {
        req.ext::<String>()
            .cloned()
            .map(LoginIdExtractor)
            .ok_or_else(AuthError::new)
    }
}
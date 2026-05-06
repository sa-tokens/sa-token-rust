// Author: 金书记
//
//! Poem Extractor 实现

use poem_03::{Request, Result, FromRequest, RequestBody};
use poem_03::http::StatusCode;
use sa_token_core::{token::TokenValue, error::messages};
use serde_json::json;

/// Token 提取器
/// 
/// 用于从请求中提取和验证 token
/// 
/// # 示例
/// ```rust,ignore
/// use poem_03::{handler, web::Data};
/// use sa_token_plugin_poem::SaTokenExtractor;
/// 
/// #[handler]
/// async fn user_info(token: SaTokenExtractor) -> String {
///     format!("User ID: {}", token.login_id())
/// }
/// ```
#[derive(Clone)]
pub struct SaTokenExtractor {
    token: TokenValue,
    login_id: String,
}

impl SaTokenExtractor {
    /// 获取 token
    pub fn token(&self) -> &TokenValue {
        &self.token
    }
    
    /// 获取登录 ID
    pub fn login_id(&self) -> &str {
        &self.login_id
    }
}

impl<'a> FromRequest<'a> for SaTokenExtractor {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        // 从请求扩展中获取 token
        let token = req
            .extensions()
            .get::<TokenValue>()
            .cloned()
            .ok_or_else(|| {
                poem_03::Error::from_string(
                    json!({
                        "code": 401,
                        "message": messages::AUTH_ERROR
                    }).to_string(),
                    StatusCode::UNAUTHORIZED
                )
            })?;
        
        // 从请求扩展中获取 login_id
        let login_id = req
            .extensions()
            .get::<String>()
            .cloned()
            .ok_or_else(|| {
                poem_03::Error::from_string(
                    json!({
                        "code": 401,
                        "message": messages::AUTH_ERROR
                    }).to_string(),
                    StatusCode::UNAUTHORIZED
                )
            })?;
        
        Ok(Self { token, login_id })
    }
}

/// 可选的 Token 提取器
/// 
/// 如果 token 不存在或无效，不会报错，而是返回 None
/// 
/// # 示例
/// ```rust,ignore
/// use poem_03::handler;
/// use sa_token_plugin_poem::OptionalSaTokenExtractor;
/// 
/// #[handler]
/// async fn user_info(token: OptionalSaTokenExtractor) -> String {
///     match token.0 {
///         Some(extractor) => format!("User ID: {}", extractor.login_id()),
///         None => "Guest".to_string(),
///     }
/// }
/// ```
pub struct OptionalSaTokenExtractor(pub Option<SaTokenExtractor>);

impl<'a> FromRequest<'a> for OptionalSaTokenExtractor {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        // 尝试从请求扩展中获取 token
        let token = req.extensions().get::<TokenValue>().cloned();
        let login_id = req.extensions().get::<String>().cloned();
        
        match (token, login_id) {
            (Some(token), Some(login_id)) => {
                Ok(Self(Some(SaTokenExtractor { token, login_id })))
            }
            _ => Ok(Self(None)),
        }
    }
}

/// LoginId 提取器
/// 
/// 直接提取登录 ID
/// 
/// # 示例
/// ```rust,ignore
/// use poem_03::handler;
/// use sa_token_plugin_poem::LoginIdExtractor;
/// 
/// #[handler]
/// async fn user_info(LoginIdExtractor(user_id): LoginIdExtractor) -> String {
///     format!("User ID: {}", user_id)
/// }
/// ```
pub struct LoginIdExtractor(pub String);

impl<'a> FromRequest<'a> for LoginIdExtractor {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> Result<Self> {
        let login_id = req
            .extensions()
            .get::<String>()
            .cloned()
            .ok_or_else(|| {
                poem_03::Error::from_string(
                    json!({
                        "code": 401,
                        "message": messages::AUTH_ERROR
                    }).to_string(),
                    StatusCode::UNAUTHORIZED
                )
            })?;
        
        Ok(Self(login_id))
    }
}

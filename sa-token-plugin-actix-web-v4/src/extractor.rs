// Author: 金书记
//
//! Actix-web提取器

use actix_web::{FromRequest, HttpRequest, HttpMessage, dev::Payload, error::ErrorUnauthorized};
use std::future::{ready, Ready};
use sa_token_core::{token::TokenValue, error::messages};

/// Token 提取器 - 必须存在，否则返回错误
pub struct SaTokenExtractor(pub TokenValue);

impl FromRequest for SaTokenExtractor {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;
    
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<TokenValue>() {
            Some(token) => ready(Ok(SaTokenExtractor(token.clone()))),
            None => ready(Err(ErrorUnauthorized(serde_json::json!({
                "code": 401,
                "message": messages::AUTH_ERROR
            })))),
        }
    }
}

/// 可选 Token 提取器 - 不存在也不报错
pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl FromRequest for OptionalSaTokenExtractor {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;
    
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req.extensions().get::<TokenValue>().cloned();
        ready(Ok(OptionalSaTokenExtractor(token)))
    }
}

/// LoginId 提取器 - 直接获取登录用户的 ID
pub struct LoginIdExtractor(pub String);

impl FromRequest for LoginIdExtractor {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;
    
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<String>() {
            Some(login_id) => ready(Ok(LoginIdExtractor(login_id.clone()))),
            None => ready(Err(ErrorUnauthorized(serde_json::json!({
                "code": 401,
                "message": messages::AUTH_ERROR
            })))),
        }
    }
}

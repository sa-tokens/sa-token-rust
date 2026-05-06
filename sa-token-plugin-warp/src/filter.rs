// Author: 金书记
//
//! Warp Filter (中间件)

use warp_03::{http::HeaderMap, Filter, Rejection};
use warp_03 as warp;

use crate::SaTokenState;
use sa_token_adapter::utils::{extract_bearer_or_value, parse_cookies};
use sa_token_core::token::TokenValue;

/// Token 数据，存储在请求中
#[derive(Clone)]
pub struct TokenData {
    pub token: Option<TokenValue>,
    pub login_id: Option<String>,
}

/// sa-token 基础过滤器 - 提取并验证 token
pub fn sa_token_filter(
    state: SaTokenState,
) -> impl Filter<Extract = (TokenData,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and(
            warp::query::<std::collections::HashMap<String, String>>().or_else(|_| async {
                Ok::<(std::collections::HashMap<String, String>,), Rejection>((
                    std::collections::HashMap::new(),
                ))
            }),
        )
        .and(warp::any().map(move || state.clone()))
        .and_then(extract_and_validate_token)
}

/// sa-token 登录检查过滤器 - 强制要求登录
pub fn sa_check_login_filter(
    state: SaTokenState,
) -> impl Filter<Extract = (TokenData,), Error = Rejection> + Clone {
    sa_token_filter(state).and_then(|token_data: TokenData| async move {
        if token_data.token.is_some() && token_data.login_id.is_some() {
            Ok(token_data)
        } else {
            Err(warp::reject::custom(UnauthorizedError))
        }
    })
}

/// 提取并验证 token（cookie 名使用 `config.token_name`，不再硬编码）
async fn extract_and_validate_token(
    headers: HeaderMap,
    query: std::collections::HashMap<String, String>,
    state: SaTokenState,
) -> Result<TokenData, Rejection> {
    let token_name = state.manager.config.token_name.as_str();

    let mut token_str: Option<String> = None;

    if let Some(header_val) = headers.get(token_name)
        && let Ok(s) = header_val.to_str() {
            let v = extract_bearer_or_value(s);
            if !v.is_empty() {
                token_str = Some(v);
            }
        }

    if token_str.is_none() && !token_name.eq_ignore_ascii_case("authorization")
        && let Some(header_val) = headers
            .get("Authorization")
            .or_else(|| headers.get("authorization"))
            && let Ok(s) = header_val.to_str() {
                let v = extract_bearer_or_value(s);
                if !v.is_empty() {
                    token_str = Some(v);
                }
            }

    if token_str.is_none()
        && let Some(cookie_header) = headers.get("cookie").and_then(|c| c.to_str().ok()) {
            let cookies = parse_cookies(cookie_header);
            if let Some(t) = cookies.get(token_name)
                && !t.is_empty() {
                    token_str = Some(t.clone());
                }
        }

    if token_str.is_none() {
        token_str = query
            .get(token_name)
            .cloned()
            .filter(|s| !s.trim().is_empty());
    }

    if let Some(token_str) = token_str {
        let token = TokenValue::new(token_str);

        if state.manager.is_valid(&token).await
            && let Ok(token_info) = state.manager.get_token_info(&token).await {
                return Ok(TokenData {
                    token: Some(token),
                    login_id: Some(token_info.login_id),
                });
            }
    }

    Ok(TokenData {
        token: None,
        login_id: None,
    })
}

/// 未授权错误
#[derive(Debug)]
pub struct UnauthorizedError;

impl warp::reject::Reject for UnauthorizedError {}

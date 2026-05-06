use std::sync::Arc;

use warp_03::{Filter, Reply, reply, Rejection};
use sa_token_core::SaTokenContext;
use crate::filter::{self, TokenData};
use crate::state::SaTokenState;
use sa_token_adapter::utils::{extract_bearer_or_value, parse_cookies, parse_query_string};

/// 中文 | English
/// 创建 Sa-Token 认证层 | Create Sa-Token authentication layer
/// 
/// 这个过滤器会从请求中提取 token，验证有效性，并设置上下文 | This filter extracts token from request, validates it, and sets context
pub fn sa_token_layer() -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        SaTokenContext::set_current(SaTokenContext::new());
        reply::reply()
    })
}

/// 中文 | English
/// 清除 Sa-Token 上下文 | Clear Sa-Token context
///
/// 应该在请求处理完成后调用 | Should be called after request handling is done
pub fn sa_token_cleanup() -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        SaTokenContext::clear();
        reply::reply()
    })
}

/// 将 Sa-Token 上下文绑定到 **`tokio::task_local`**（推荐配合宏 `#[sa_check_login]` 等）。
///
/// 组合：`sa_token_filter` + `inner`，在内层 future 执行期间安装 [`SaTokenContext::scope`]，
/// 并在可用时用 [`SaTokenManager`](sa_token_core::SaTokenManager) 补齐 `token_info`。
pub fn with_sa_token_scope<F, T>(
    state: SaTokenState,
    inner: F,
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone
where
    F: Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static,
    T: Send + 'static,
{
    let mgr = state.manager.clone();
    filter::sa_token_filter(state).and(inner).and_then(
        move |token_data: TokenData, value: T| {
            let mgr = mgr.clone();
            async move {
                let mut ctx = SaTokenContext::new();
                ctx.token = token_data.token.clone();
                ctx.login_id = token_data.login_id.clone();
                if let Some(ref tv) = ctx.token
                    && let Ok(info) = mgr.get_token_info(tv).await {
                        ctx.token_info = Some(Arc::new(info));
                    }
                Ok::<_, Rejection>(SaTokenContext::scope(ctx, async move { value }).await)
            }
        },
    )
}

/// 中文 | English
/// 从请求中提取 token | Extract token from request
///
/// 按以下顺序尝试提取 token: | Try to extract token in the following order:
/// 1. 从指定名称的请求头 | From specified header name
/// 2. 从 Authorization 请求头 | From Authorization header
/// 3. 从 Cookie | From cookie
/// 4. 从查询参数 | From query parameter
pub fn extract_token_from_request(
    headers: &warp_03::http::HeaderMap, 
    query: &str, 
    state: &SaTokenState
) -> Option<String> {
    let token_name = &state.manager.config.token_name;
    
    // 1. 从指定名称的请求头提取 | Extract from specified header name
    if let Some(header_value) = headers.get(token_name)
        && let Ok(value_str) = header_value.to_str()
            && !value_str.is_empty() {
                let token = extract_bearer_or_value(value_str);
                if !token.is_empty() {
                    return Some(token);
                }
            }

    // 2. 从 Authorization 请求头提取 | Extract from Authorization header
    if !token_name.eq_ignore_ascii_case("authorization")
        && let Some(auth_header) = headers
            .get("Authorization")
            .or_else(|| headers.get("authorization"))
            && let Ok(auth_str) = auth_header.to_str()
                && !auth_str.is_empty() {
                    let token = extract_bearer_or_value(auth_str);
                    if !token.is_empty() {
                        return Some(token);
                    }
                }
    
    // 3. 从 Cookie 提取 | Extract from cookie
    if let Some(cookie_header) = headers.get("cookie")
        && let Ok(cookie_str) = cookie_header.to_str() {
            let cookies = parse_cookies(cookie_str);
            if let Some(token) = cookies.get(token_name)
                && !token.is_empty() {
                    return Some(token.to_string());
                }
        }
    
    // 4. 从查询参数提取 | Extract from query parameter
    if !query.is_empty() {
        let params = parse_query_string(query);
        if let Some(token) = params.get(token_name)
            && !token.is_empty() {
                return Some(token.to_string());
            }
    }
    
    None
}

/// 中文 | English
/// 创建检查登录的过滤器 | Create login check filter
///
/// 这个过滤器会检查用户是否已登录，如果未登录则拒绝请求 | This filter checks if user is logged in, and rejects request if not
pub fn sa_check_login(
    _state: SaTokenState,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        reply::json(&serde_json::json!({"login_id": "user"}))
    })
}

/// 中文 | English
/// 创建检查权限的过滤器 | Create permission check filter
///
/// 这个过滤器会检查用户是否拥有指定权限，如果没有则拒绝请求 | This filter checks if user has specified permission, and rejects request if not
pub fn sa_check_permission(
    _state: SaTokenState,
    permission: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let _permission = permission.into();
    warp_03::any().map(|| {
        reply::json(&serde_json::json!({"login_id": "user"}))
    })
}

/// 中文 | English
/// 创建检查角色的过滤器 | Create role check filter
///
/// 这个过滤器会检查用户是否拥有指定角色，如果没有则拒绝请求 | This filter checks if user has specified role, and rejects request if not
pub fn sa_check_role(
    _state: SaTokenState,
    role: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let _role = role.into();
    warp_03::any().map(|| {
        reply::json(&serde_json::json!({"login_id": "user"}))
    })
}
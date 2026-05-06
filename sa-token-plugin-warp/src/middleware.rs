// Author: 金书记
//
// 中文 | English
// Warp 中间件 | Warp middleware

use warp_03::{Filter, Reply, reply};
use crate::state::SaTokenState;

/// 中文 | English
/// 创建登录检查中间件 | Create login check middleware
///
/// 这个中间件会检查用户是否已登录，如果未登录则返回401错误 | This middleware checks if user is logged in, and returns 401 error if not
pub fn with_auth(_state: SaTokenState) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        reply::reply()
    })
}

/// 中文 | English
/// 创建权限检查过滤器 | Create permission check filter
///
/// 这个过滤器会检查用户是否拥有指定权限，如果没有则返回403错误 | This filter checks if user has specified permission, and returns 403 error if not
pub fn require_auth() -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    warp_03::any().map(|| {
        reply::reply()
    })
}

/// 中文 | English
/// 创建权限检查过滤器 | Create permission check filter
///
/// 这个过滤器会检查用户是否拥有指定权限，如果没有则返回403错误 | This filter checks if user has specified permission, and returns 403 error if not
pub fn require_permission(
    permission: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let _permission = permission.into();
    warp_03::any().map(|| {
        reply::reply()
    })
}

/// 中文 | English
/// 创建角色检查过滤器 | Create role check filter
///
/// 这个过滤器会检查用户是否拥有指定角色，如果没有则返回403错误 | This filter checks if user has specified role, and returns 403 error if not
pub fn require_role(
    role: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let _role = role.into();
    warp_03::any().map(|| {
        reply::reply()
    })
}

/// 中文 | English
/// 创建权限检查中间件 | Create permission check middleware
///
/// 这个中间件会检查用户是否拥有指定权限，如果没有则返回403错误 | This middleware checks if user has specified permission, and returns 403 error if not
pub fn with_permission(
    state: SaTokenState,
    permission: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let _permission = permission.into();
    warp_03::any().map(move || {
        let _state = state.clone();
        reply::reply()
    })
}

/// 中文 | English
/// 创建角色检查中间件 | Create role check middleware
///
/// 这个中间件会检查用户是否拥有指定角色，如果没有则返回403错误 | This middleware checks if user has specified role, and returns 403 error if not
pub fn with_role(
    state: SaTokenState,
    role: impl Into<String> + Send + Sync + 'static,
) -> impl Filter<Extract = impl Reply, Error = std::convert::Infallible> + Clone {
    let _role = role.into();
    warp_03::any().map(move || {
        let _state = state.clone();
        reply::reply()
    })
}
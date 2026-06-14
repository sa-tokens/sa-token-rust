// Author: 金书记
//
//! # sa-token-macro
//! 
//! sa-token-rust的过程宏
//! 
//! 提供类似Java注解的功能：
//! - `#[sa_check_login]` - 检查登录
//! - `#[sa_check_permission("permission")]` - 检查权限
//! - `#[sa_check_role("role")]` - 检查角色
//! - `#[sa_ignore]` - 忽略认证（跳过所有认证检查）
//! 
//! ## 使用示例
//! 
//! ```rust,ignore
//! use sa_token_macro::*;
//! 
//! #[sa_check_login]
//! async fn user_info() -> impl Responder {
//!     // 自动验证登录，未登录会返回401
//!     "User info"
//! }
//! 
//! #[sa_check_permission("user:delete")]
//! async fn delete_user(id: u64) -> impl Responder {
//!     // 自动验证权限，无权限会返回403
//!     "User deleted"
//! }
//! 
//! #[sa_check_role("admin")]
//! async fn admin_panel() -> impl Responder {
//!     // 自动验证角色，无角色会返回403
//!     "Admin panel"
//! }
//! 
//! #[sa_ignore]
//! async fn public_api() -> impl Responder {
//!     // 此接口不需要任何认证
//!     "Public API"
//! }
//! 
//! // 也可以用在结构体上，表示整个控制器都忽略认证
//! #[sa_ignore]
//! struct PublicController;
//! ```

use proc_macro::TokenStream;

mod macros;
mod utils;

// 导出所有宏的实现
use macros::{
    check_login::sa_check_login_impl,
    check_permission::sa_check_permission_impl,
    check_role::sa_check_role_impl,
    check_permissions_and::sa_check_permissions_and_impl,
    check_permissions_or::sa_check_permissions_or_impl,
    check_roles_and::sa_check_roles_and_impl,
    check_roles_or::sa_check_roles_or_impl,
    check_safe::sa_check_safe_impl,
    check_disable::sa_check_disable_impl,
    check_or::sa_check_or_impl,
    ignore::sa_ignore_impl,
};

/// 检查登录状态的宏
#[proc_macro_attribute]
pub fn sa_check_login(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_login_impl(attr, item)
}

/// 检查权限的宏
#[proc_macro_attribute]
pub fn sa_check_permission(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_permission_impl(attr, item)
}

/// 检查角色的宏
#[proc_macro_attribute]
pub fn sa_check_role(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_role_impl(attr, item)
}

/// 同时检查多个权限（AND逻辑）
#[proc_macro_attribute]
pub fn sa_check_permissions_and(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_permissions_and_impl(attr, item)
}

/// 同时检查多个权限（OR逻辑）
#[proc_macro_attribute]
pub fn sa_check_permissions_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_permissions_or_impl(attr, item)
}

/// 同时检查多个角色（AND逻辑）
#[proc_macro_attribute]
pub fn sa_check_roles_and(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_roles_and_impl(attr, item)
}

/// 同时检查多个角色（OR逻辑）
#[proc_macro_attribute]
pub fn sa_check_roles_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_roles_or_impl(attr, item)
}

/// 忽略认证检查的宏
#[proc_macro_attribute]
pub fn sa_ignore(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_ignore_impl(attr, item)
}

/// 检查二级认证
#[proc_macro_attribute]
pub fn sa_check_safe(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_safe_impl(attr, item)
}

/// 检查账号封禁
#[proc_macro_attribute]
pub fn sa_check_disable(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_disable_impl(attr, item)
}

/// 组合鉴权（OR）：任一子检查通过即可
#[proc_macro_attribute]
pub fn sa_check_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    sa_check_or_impl(attr, item)
}

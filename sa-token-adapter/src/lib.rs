// Author: 金书记
//
//! # sa-token-adapter
//! 
//! 适配器trait定义，用于实现框架无关的抽象层
//! 
//! 这个crate定义了所有需要适配的接口，包括：
//! - 存储适配器
//! - 请求/响应上下文适配器
//! - 框架集成适配器

pub mod storage;
pub mod context;
pub mod framework;
pub mod utils;

pub use storage::SaStorage;
pub use context::{SaRequest, SaResponse, CookieOptions, SameSite};
pub use framework::FrameworkAdapter;
pub use utils::{
    parse_cookies,
    parse_query_string,
    build_cookie_string,
    strip_bearer_prefix,
    extract_bearer_or_value,
    strip_bearer_or_passthrough,
};

/// 向后兼容；新代码请用 [`strip_bearer_prefix`](utils::strip_bearer_prefix) 或 [`extract_bearer_or_value`](utils::extract_bearer_or_value)。
#[allow(deprecated)]
pub use utils::extract_bearer_token;

//! Framework-agnostic core for Rocket integration (**no `rocket` dependency**).
//! Rocket 集成的框架无关共享层（**不依赖 `rocket`**）。
//!
//! Holds [`SaTokenState`] / builder and JSON error helpers; re-exports router APIs for bindings.
//! 包含 [`SaTokenState`] / Builder、JSON 错误体辅助；为重绑定层重导出路由相关 API。

pub use sa_token_core::router::{
    create_context, extract_token, process_auth, run_auth_flow, AuthFlowResult, AuthResult,
    PathAuthConfig,
};

pub mod error_response;
pub mod state;

pub use state::{SaTokenState, SaTokenStateBuilder};

//! Framework-agnostic core for Actix-web integration (**no `actix-web` dependency**).
//! Actix-web 集成的框架无关共享层（**不依赖 `actix-web`**）。
//!
//! Re-exports [`run_auth_flow`] / [`PathAuthConfig`] from `sa-token-core::router`; versioned crates (`*-v4`, `*-v5`) implement HTTP wiring.
//! 再从 `sa-token-core::router` 重导出 [`run_auth_flow`]、[`PathAuthConfig`]；具体 HTTP 由各版本绑定 crate（`*-v4`、`*-v5`）实现。

pub use sa_token_core::router::{
    create_context, extract_token, process_auth, run_auth_flow, AuthFlowResult, AuthResult,
    PathAuthConfig,
};

pub mod error_response;
pub mod state;

pub use state::{SaTokenState, SaTokenStateBuilder};

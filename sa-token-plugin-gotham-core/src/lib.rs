//! Framework-agnostic core for Gotham integration (**no `gotham` dependency**).
//! Gotham 集成的框架无关共享层（**不依赖 `gotham`**）。

pub use sa_token_core::router::{
    create_context, extract_token, process_auth, run_auth_flow, AuthFlowResult, AuthResult,
    PathAuthConfig,
};

pub mod error_response;
pub mod state;

pub use state::{SaTokenState, SaTokenStateBuilder};

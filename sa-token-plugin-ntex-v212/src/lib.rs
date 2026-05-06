// Author: 金书记
//
//! Ntex **`2.12+`** binding:**`NtexCapturedRequest`**/**`run_auth_flow`**, **`SaTokenLayer::with_path_auth`** for route rules.
//! Ntex **`2.12+`** 绑定：**`NtexCapturedRequest`** / **`run_auth_flow`**，路径规则用 **`SaTokenLayer::with_path_auth`**。

pub use sa_token_plugin_ntex_core::{
    error_response, run_auth_flow, AuthFlowResult, PathAuthConfig, SaTokenState, SaTokenStateBuilder,
};

pub mod adapter;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use sa_token_core::{self, prelude::*};
pub use sa_token_adapter::{framework::FrameworkAdapter, storage::SaStorage};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::*;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::*;

#[cfg(feature = "database")]
pub use sa_token_storage_database::*;

pub use adapter::*;
pub use extractor::*;
pub use middleware::*;
pub use layer::SaTokenLayer;

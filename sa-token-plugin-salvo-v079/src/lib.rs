// Author: 金书记
//
//! Salvo **0.79.x** binding: `Handler`-style **`SaTokenLayer`**, **`SalvoCapturedRequest`** snapshot before `await`, optional **`PathAuthConfig`**.
//! Salvo **0.79.x** 绑定：`Handler` 式 **`SaTokenLayer`**、`await` 前 **`SalvoCapturedRequest`** 快照、可选 **`PathAuthConfig`**。

pub use sa_token_plugin_salvo_core::{
    error_response, run_auth_flow, AuthFlowResult, PathAuthConfig, SaTokenState, SaTokenStateBuilder,
};

pub mod adapter;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use adapter::*;
pub use extractor::*;
pub use middleware::{
    auth_middleware, permission_middleware, SaCheckLoginMiddleware, SaCheckPermissionMiddleware,
    SaCheckRoleMiddleware,
};
pub use layer::{extract_token_from_request, SaTokenLayer};

pub use sa_token_core::{self, prelude::*};
pub use sa_token_adapter::{self, framework::FrameworkAdapter, storage::SaStorage};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::*;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::*;

#[cfg(feature = "database")]
pub use sa_token_storage_database::*;

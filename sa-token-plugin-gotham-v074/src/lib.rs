// Author: 金书记
//
//! Gotham **0.7.x** binding / Gotham **0.7.x** 绑定：**`GothamCapturedRequest`** + **`run_auth_flow`**; `StateData` wrappers in **`wrapper`**.
//! **`GothamCapturedRequest`** + **`run_auth_flow`**；**`wrapper`** 中提供 **`StateData`** 包装类型。

pub use sa_token_plugin_gotham_core::{
    error_response, run_auth_flow, AuthFlowResult, PathAuthConfig, SaTokenState, SaTokenStateBuilder,
};

pub mod adapter;
pub mod extractor;
pub mod middleware;
pub mod layer;
pub mod wrapper;

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
#[allow(deprecated)]
pub use middleware::{
    AuthMiddleware, SaCheckLoginMiddleware, SaCheckPermissionMiddleware, SaCheckRoleMiddleware,
    SaTokenMiddleware,
};
pub use layer::SaTokenLayer;
pub use wrapper::{LoginIdWrapper, TokenValueWrapper};

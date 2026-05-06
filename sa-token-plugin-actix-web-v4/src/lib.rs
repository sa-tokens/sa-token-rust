//! Actix-web **4.x** binding: middleware + layer call **`run_auth_flow`** with **`ActixRequestAdapter`** (borrows `HttpRequest`, valid inside the service `call` future).
//! Actix-web **4.x** 绑定：中间件与 Layer 用 **`ActixRequestAdapter`**（借 `HttpRequest`）在 **`run_auth_flow`** 中完成鉴权流水线。

pub use sa_token_plugin_actix_web_core::{
    error_response, run_auth_flow, AuthFlowResult, PathAuthConfig, SaTokenState, SaTokenStateBuilder,
};

pub mod adapter;
pub mod ext;
pub mod extractor;
pub mod layer;
pub mod middleware;

pub use adapter::{ActixRequestAdapter, ActixResponseAdapter};
pub use ext::{into_data, SaTokenData};
pub use extractor::{LoginIdExtractor, OptionalSaTokenExtractor, SaTokenExtractor};
pub use layer::SaTokenLayer;
pub use middleware::{SaCheckLoginMiddleware, SaTokenMiddleware};

pub use sa_token_core::{self, prelude::*};
pub use sa_token_adapter::{framework::FrameworkAdapter, storage::SaStorage};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;

// Author: 金书记
//
//! # sa-token-plugin-axum
//!
//! Axum framework integration for sa-token-rust.
//!
//! Enable **`axum-08`** (default) for Axum 0.8; dependencies use Cargo keys `axum-08` /
//! `tower-08` so additional Axum majors can be added later without renaming the crate.

#[cfg(not(feature = "axum-08"))]
compile_error!(
    "sa-token-plugin-axum: enable feature `axum-08` (default). \
     Future Axum versions will be additional opt-in features."
);

pub mod shared;

pub use shared::adapter::{AxumRequestAdapter, AxumRequestSnapshot, AxumResponseAdapter};
pub use shared::state::{SaTokenState, SaTokenStateBuilder};

#[cfg(feature = "axum-08")]
mod v08;

#[cfg(feature = "axum-08")]
pub use v08::{
    LoginIdExtractor, OptionalSaTokenExtractor, SaCheckLoginLayer, SaCheckLoginMiddleware,
    SaCheckPermissionLayer, SaCheckPermissionMiddleware, SaTokenExtractor, SaTokenLayer,
    SaTokenMiddleware,
};

pub use sa_token_core::{self, prelude::*};
pub use sa_token_adapter::{self, framework::FrameworkAdapter, storage::SaStorage};
pub use sa_token_macro::*;

#[cfg(feature = "memory")]
pub use sa_token_storage_memory::MemoryStorage;

#[cfg(feature = "redis")]
pub use sa_token_storage_redis::RedisStorage;

#[cfg(feature = "database")]
pub use sa_token_storage_database::DatabaseStorage;

// Author: 金书记
//
//! Axum 0.8 bindings (`axum_08` / `tower_08` dependency keys).

pub mod extractor;
pub mod layer;
pub mod middleware;

pub use extractor::{LoginIdExtractor, OptionalSaTokenExtractor, SaTokenExtractor};
pub use layer::{SaTokenLayer, SaTokenMiddleware};
pub use middleware::{
    SaCheckLoginLayer, SaCheckLoginMiddleware, SaCheckPermissionLayer, SaCheckPermissionMiddleware,
};

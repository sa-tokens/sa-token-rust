//! Placeholder crate for Actix-web **5.x** (no HTTP binding yet — keep **`v4`**).
//! Actix-web **5.x** 占位 crate（暂无 HTTP 绑定 — 请继续使用 **`v4`**）。
//!
//! Re-exports **`actix-web-core`** types only so the workspace compiles feature graphs.
//! 仅再导出 **`actix-web-core`** 类型，便于 workspace 能通过 feature 图编译。
#![deny(unsafe_code)]

pub use sa_token_plugin_actix_web_core::*;

#[doc(hidden)]
pub const __V5_NOT_IMPLEMENTED__: &str = "actix-web 5.x binding is not implemented; use feature v4.";

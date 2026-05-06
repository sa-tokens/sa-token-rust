//! Shared JSON bodies for Actix bindings.

use sa_token_core::error::messages;
use serde_json::{json, Value};

pub fn unauthorized_body() -> Value {
    json!({ "code": 401, "message": messages::AUTH_ERROR })
}

pub fn forbidden_body(reason: &str) -> Value {
    json!({ "code": 403, "message": reason })
}

pub const CONTENT_TYPE_JSON: &str = "application/json";

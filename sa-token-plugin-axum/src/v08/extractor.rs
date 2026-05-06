// Author: 金书记
//
//! Axum 0.8 extractors.

use axum_08 as axum;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use sa_token_core::{error::messages, token::TokenValue};
use serde_json::json;

pub struct SaTokenExtractor(pub TokenValue);

impl<S: Send + Sync> FromRequestParts<S> for SaTokenExtractor {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<TokenValue>() {
            Some(token) => Ok(SaTokenExtractor(token.clone())),
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                })),
            )
                .into_response()),
        }
    }
}

pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalSaTokenExtractor {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.extensions.get::<TokenValue>().cloned();
        Ok(OptionalSaTokenExtractor(token))
    }
}

pub struct LoginIdExtractor(pub String);

impl<S: Send + Sync> FromRequestParts<S> for LoginIdExtractor {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<String>() {
            Some(login_id) => Ok(LoginIdExtractor(login_id.clone())),
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                })),
            )
                .into_response()),
        }
    }
}

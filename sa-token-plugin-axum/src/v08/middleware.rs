// Author: 金书记
//
//! Axum 0.8 check-login / check-permission middleware.

use std::task::{Context, Poll};

use http::{Request, Response, StatusCode};
use http_body;
use serde_json::json;
use tower_08 as tower;
use tower::{Layer, Service};

use sa_token_core::error::messages;

/// Layer that installs [`SaCheckLoginMiddleware`].
#[derive(Clone)]
pub struct SaCheckLoginLayer;

impl Default for SaCheckLoginLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl SaCheckLoginLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for SaCheckLoginLayer {
    type Service = SaCheckLoginMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaCheckLoginMiddleware { inner }
    }
}

/// Requires an authenticated user (`String` login id in request extensions).
#[derive(Clone)]
pub struct SaCheckLoginMiddleware<S> {
    inner: S,
}

/// Layer for [`SaCheckPermissionMiddleware`].
#[derive(Clone)]
pub struct SaCheckPermissionLayer {
    permission: String,
}

impl SaCheckPermissionLayer {
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
        }
    }
}

impl<S> Layer<S> for SaCheckPermissionLayer {
    type Service = SaCheckPermissionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaCheckPermissionMiddleware {
            inner,
            permission: self.permission.clone(),
        }
    }
}

/// Permission gate middleware.
#[derive(Clone)]
pub struct SaCheckPermissionMiddleware<S> {
    inner: S,
    permission: String,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaCheckLoginMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if request.extensions().get::<String>().is_none() {
                let mut response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(ResBody::default())
                    .expect("Unable to create response");

                let error_json = serde_json::to_string(&json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                }))
                .unwrap_or_default();

                if let Ok(header_value) = http::header::HeaderValue::from_str(&error_json) {
                    response.headers_mut().insert("X-Sa-Token-Error", header_value);
                }

                return Ok(response);
            }

            inner.call(request).await
        })
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaCheckPermissionMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let permission = self.permission.clone();

        Box::pin(async move {
            if let Some(login_id) = request.extensions().get::<String>()
                && sa_token_core::StpUtil::has_permission(login_id, &permission).await {
                    return inner.call(request).await;
                }

            let mut response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(ResBody::default())
                .expect("Unable to create response");

            let error_json = serde_json::to_string(&json!({
                "code": 403,
                "message": messages::PERMISSION_REQUIRED
            }))
            .unwrap_or_default();

            if let Ok(header_value) = http::header::HeaderValue::from_str(&error_json) {
                response.headers_mut().insert("X-Sa-Token-Error", header_value);
            }

            Ok(response)
        })
    }
}

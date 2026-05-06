// Author: 金书记
//
//! Axum **0.8** Tower `Layer`：`AxumRequestSnapshot` + **`run_auth_flow`**（可选 **`PathAuthConfig`**）。

use std::pin::Pin;
use std::task::{Context, Poll};
use http::{Request, Response};
use http_body;
use sa_token_core::{router::PathAuthConfig, router::run_auth_flow};
use tower_08 as tower;
use tower::{Layer, Service};

use crate::shared::adapter::AxumRequestSnapshot;
use crate::shared::state::SaTokenState;

/// Sa-Token layer with optional path-based authentication.
#[derive(Clone)]
pub struct SaTokenLayer {
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl SaTokenLayer {
    pub fn new(state: SaTokenState) -> Self {
        Self {
            state,
            path_config: None,
        }
    }

    pub fn with_path_auth(state: SaTokenState, config: PathAuthConfig) -> Self {
        Self {
            state,
            path_config: Some(config),
        }
    }
}

impl<S> Layer<S> for SaTokenLayer {
    type Service = SaTokenMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SaTokenMiddleware {
            inner,
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SaTokenMiddleware<S> {
    pub(crate) inner: S,
    pub(crate) state: SaTokenState,
    pub(crate) path_config: Option<PathAuthConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SaTokenMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let state = self.state.clone();
        let path_config = self.path_config.clone();

        Box::pin(async move {
            let snapshot = AxumRequestSnapshot::capture(&request);
            let flow = run_auth_flow(&snapshot, &state.manager, path_config.as_ref()).await;

            if flow.should_reject() {
                let mut response = Response::new(ResBody::default());
                *response.status_mut() = http::StatusCode::UNAUTHORIZED;
                return Ok(response);
            }

            if let Some(t) = &flow.token {
                request.extensions_mut().insert(t.clone());
            }
            if let Some(id) = &flow.login_id {
                request.extensions_mut().insert(id.clone());
            }

            flow.run(inner.call(request)).await
        })
    }
}

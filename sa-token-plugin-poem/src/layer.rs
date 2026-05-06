// Author: 金书记
//
//! Poem middleware layer for Sa-Token
//! Poem 中间件层，用于 Sa-Token

use poem_03::{Endpoint, Middleware, Request, Result};

use sa_token_core::router::PathAuthConfig;
use sa_token_core::router::run_auth_flow;

use crate::adapter::PoemRequestAdapter;
use crate::SaTokenState;

/// Sa-Token layer for Poem with optional path-based authentication
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

impl<E> Middleware<E> for SaTokenLayer
where
    E: Endpoint,
{
    type Output = SaTokenMiddleware<E>;

    fn transform(&self, ep: E) -> Self::Output {
        SaTokenMiddleware {
            inner: ep,
            state: self.state.clone(),
            path_config: self.path_config.clone(),
        }
    }
}

/// Sa-Token middleware for Poem endpoints
pub struct SaTokenMiddleware<E> {
    inner: E,
    state: SaTokenState,
    path_config: Option<PathAuthConfig>,
}

impl<E> Endpoint for SaTokenMiddleware<E>
where
    E: Endpoint,
{
    type Output = E::Output;

    async fn call(&self, mut req: Request) -> Result<Self::Output> {
        let adapter = PoemRequestAdapter::new(&req);
        let flow = run_auth_flow(&adapter, &self.state.manager, self.path_config.as_ref()).await;

        if flow.should_reject() {
            return Err(poem_03::Error::from_status(
                poem_03::http::StatusCode::UNAUTHORIZED,
            ));
        }

        if let Some(t) = &flow.token {
            req.extensions_mut().insert(t.clone());
        }
        if let Some(id) = &flow.login_id {
            req.extensions_mut().insert(id.clone());
        }

        flow.run(self.inner.call(req)).await
    }
}

/// Extract token string (for filters / other helpers). Uses `sa_token_core::router::extract_token`.
pub fn extract_token_from_request(req: &Request, token_name: &str) -> Option<String> {
    let adapter = PoemRequestAdapter::new(req);
    sa_token_core::router::extract_token(&adapter, token_name)
}

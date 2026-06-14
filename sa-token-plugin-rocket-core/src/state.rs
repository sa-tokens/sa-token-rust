//! Application state without Rocket types.

use std::sync::Arc;

use sa_token_adapter::storage::SaStorage;
use sa_token_core::{config::TokenStyle, SaTokenManager};

/// Shared application state (register with [`rocket::manage`] in the v0.5 binding).
#[derive(Clone)]
pub struct SaTokenState {
    pub manager: Arc<SaTokenManager>,
}

impl SaTokenState {
    pub fn builder() -> SaTokenStateBuilder {
        SaTokenStateBuilder::default()
    }
}

#[derive(Default)]
pub struct SaTokenStateBuilder {
    config_builder: sa_token_core::config::SaTokenConfigBuilder,
}

impl SaTokenStateBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn storage(mut self, storage: Arc<dyn SaStorage>) -> Self {
        self.config_builder = self.config_builder.storage(storage);
        self
    }

    pub fn token_name(mut self, name: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.token_name(name);
        self
    }

    pub fn timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.timeout(timeout);
        self
    }

    pub fn active_timeout(mut self, timeout: i64) -> Self {
        self.config_builder = self.config_builder.active_timeout(timeout);
        self
    }

    pub fn auto_renew(mut self, enabled: bool) -> Self {
        self.config_builder = self.config_builder.auto_renew(enabled);
        self
    }

    pub fn is_concurrent(mut self, concurrent: bool) -> Self {
        self.config_builder = self.config_builder.is_concurrent(concurrent);
        self
    }

    pub fn is_share(mut self, share: bool) -> Self {
        self.config_builder = self.config_builder.is_share(share);
        self
    }

    pub fn token_style(mut self, style: TokenStyle) -> Self {
        self.config_builder = self.config_builder.token_style(style);
        self
    }

    pub fn jwt_secret_key(mut self, key: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.jwt_secret_key(key);
        self
    }

    pub fn build(self) -> SaTokenState {
        SaTokenState {
            manager: Arc::new(self.config_builder.build()),
        }
    }
}

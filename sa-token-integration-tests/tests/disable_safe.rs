//! Phase3: disable / safe API integration tests

mod common;

use sa_token_core::{SaTokenConfig, SaTokenError, SaTokenManager};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

fn manager() -> Arc<SaTokenManager> {
    let storage = Arc::new(MemoryStorage::new());
    let config = SaTokenConfig::builder().timeout(3600).build_config();
    Arc::new(SaTokenManager::new(storage, config))
}

#[tokio::test]
async fn disable_blocks_check_disable() {
    let mgr = manager();
    mgr.disable_level("u1", "login", 2, 120).await.unwrap();
    let err = mgr.check_disable_level("u1", "login", 1).await.unwrap_err();
    assert!(matches!(err, SaTokenError::AccountBanned(_)));
}

#[tokio::test]
async fn safe_open_and_check() {
    let mgr = manager();
    let token = mgr.login("u_safe").await.unwrap();
    mgr.open_safe(&token, "", 120).await.unwrap();
    mgr.check_safe(&token, "").await.unwrap();
    mgr.close_safe(&token, "").await.unwrap();
    assert!(mgr.check_safe(&token, "").await.is_err());
}

#[tokio::test]
async fn untie_disable_clears_ban() {
    let mgr = manager();
    mgr.disable("u2", 60).await.unwrap();
    assert!(mgr.is_disable_level("u2", "login", 1).await.unwrap());
    mgr.untie_disable("u2", "login").await.unwrap();
    assert!(!mgr.is_disable_level("u2", "login", 1).await.unwrap());
}

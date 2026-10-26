//! 路径鉴权路由：`match_path` / `need_auth` / `extract_token` / `run_auth_flow`。
//!
//! 过期用灰盒拨钟，禁止 sleep。Layer 级 path_auth 见 `plugin_axum` / `plugin_actix`。
//! 覆盖 PathAuth 假 401 根治：单次加载、存储失败→503、exclude 可跳过存储。

mod common;

use async_trait::async_trait;
use common::setup;
use sa_token_adapter::context::SaRequest;
use sa_token_adapter::storage::{SaStorage, ScanPage, StorageError, StorageResult};
use sa_token_core::router::{
    PathAuthConfig, extract_token, match_any, match_path, need_auth, process_auth, run_auth_flow,
};
use sa_token_core::{SaTokenError, SaTokenManager};
use sa_token_storage_memory::MemoryStorage;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ── Mock SaRequest ────────────────────────────────────────────────────────

struct MockRequest {
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    params: HashMap<String, String>,
    path: String,
    method: String,
}

impl MockRequest {
    fn new(path: &str) -> Self {
        Self {
            headers: HashMap::new(),
            cookies: HashMap::new(),
            params: HashMap::new(),
            path: path.to_string(),
            method: "GET".to_string(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name.to_string(), value.to_string());
        self
    }

    fn with_param(mut self, name: &str, value: &str) -> Self {
        self.params.insert(name.to_string(), value.to_string());
        self
    }
}

impl SaRequest for MockRequest {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers.get(name).cloned()
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.cookies.get(name).cloned()
    }

    fn get_param(&self, name: &str) -> Option<String> {
        self.params.get(name).cloned()
    }

    fn get_path(&self) -> String {
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}

// ── match_path / need_auth / PathAuthConfig ───────────────────────────────

#[test]
fn test_match_path_exact() {
    assert!(match_path("/api/user", "/api/user"));
    assert!(!match_path("/api/user", "/api/admin"));
}

#[test]
fn test_match_path_double_star() {
    assert!(match_path("/api/user", "/api/**"));
    assert!(match_path("/api/user/profile", "/api/**"));
    assert!(match_path("/api/a/b/c/d", "/api/**"));
    assert!(!match_path("/other/user", "/api/**"));
}

#[test]
fn test_match_path_single_star() {
    assert!(match_path("/api/user", "/api/*"));
    assert!(!match_path("/api/user/profile", "/api/*"));
    assert!(match_path("/api/", "/api/*"));
}

#[test]
fn test_match_path_suffix() {
    assert!(match_path("/page.html", "*.html"));
    assert!(match_path("/sub/page.html", "*.html"));
    assert!(!match_path("/page.htm", "*.html"));
}

#[test]
fn test_match_path_all() {
    assert!(match_path("/anything", "/**"));
    assert!(match_path("/", "/**"));
    assert!(match_path("/a/b/c", "/**"));
}

#[test]
fn test_match_any_matches_first() {
    let patterns = ["/api/**", "/admin/**"];
    assert!(match_any("/api/user", &patterns));
    assert!(match_any("/admin/dashboard", &patterns));
    assert!(!match_any("/public/page", &patterns));
}

#[test]
fn test_need_auth_include_only() {
    let include = ["/api/**"];
    let exclude = [];
    assert!(need_auth("/api/user", &include, &exclude));
    assert!(!need_auth("/public/page", &include, &exclude));
}

#[test]
fn test_need_auth_exclude_overrides() {
    let include = ["/api/**"];
    let exclude = ["/api/public/**"];
    assert!(need_auth("/api/user", &include, &exclude));
    assert!(!need_auth("/api/public/info", &include, &exclude));
}

#[test]
fn test_need_auth_no_include_returns_false() {
    let include = [];
    let exclude = ["/api/**"];
    assert!(!need_auth("/api/user", &include, &exclude));
}

#[test]
fn test_path_auth_config_include_exclude() {
    let config = PathAuthConfig::new()
        .include(vec!["/api/**".into(), "/admin/**".into()])
        .exclude(vec!["/api/public/**".into(), "/api/health".into()]);
    assert!(config.check("/api/user"));
    assert!(config.check("/admin/dashboard"));
    assert!(!config.check("/api/public/info"));
    assert!(!config.check("/api/health"));
    assert!(!config.check("/public/home"));
}

#[test]
fn test_path_auth_config_with_validator() {
    let config = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .validator(|login_id| login_id.starts_with("user_"));
    assert!(config.check("/api/data"));
    assert!(config.validate_login_id("user_123"));
    assert!(!config.validate_login_id("admin_123"));
}

#[test]
fn test_match_path_no_match() {
    assert!(!match_path("/api/user", "/other/*"));
    assert!(!match_path("/about", "/api/**"));
    assert!(!match_path("/page.htm", "*.html"));
}

// ── extract_token：Header / Cookie / Query / Bearer ───────────────────────

#[test]
fn test_extract_token_from_header() {
    let req = MockRequest::new("/api/user").with_header("sa-token", "my_token_value");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("my_token_value"));
}

#[test]
fn test_extract_token_bearer_prefix() {
    let req = MockRequest::new("/api/user").with_header("sa-token", "Bearer my_jwt_token");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("my_jwt_token"));
}

#[test]
fn test_extract_token_from_cookie() {
    let req = MockRequest::new("/api/user").with_cookie("sa-token", "cookie_token_value");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("cookie_token_value"));
}

#[test]
fn test_extract_token_from_query() {
    let req = MockRequest::new("/api/user").with_param("sa-token", "query_token_value");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("query_token_value"));
}

#[test]
fn test_extract_token_header_priority_over_cookie() {
    let req = MockRequest::new("/api/user")
        .with_header("sa-token", "header_token")
        .with_cookie("sa-token", "cookie_token");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("header_token"));
}

#[test]
fn test_extract_token_falls_back_to_authorization_header() {
    let req = MockRequest::new("/api/user").with_header("Authorization", "Bearer auth_token");
    let token = extract_token(&req, "sa-token");
    assert_eq!(token.as_deref(), Some("auth_token"));
}

#[test]
fn test_extract_token_no_token() {
    let req = MockRequest::new("/api/user");
    let token = extract_token(&req, "sa-token");
    assert!(token.is_none());
}

#[test]
fn test_extract_token_empty_header_value_skipped() {
    let req = MockRequest::new("/api/user").with_header("sa-token", "");
    let token = extract_token(&req, "sa-token");
    assert!(token.is_none(), "empty header value should be skipped");
}

// ── run_auth_flow ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_run_auth_flow_valid_token() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_router");
    let token = mgr.login(&id).await.expect("login");
    let req = MockRequest::new("/api/user").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, None).await;
    assert!(!flow.should_reject());
    assert_eq!(flow.login_id.as_deref(), Some(id.as_str()));
}

#[tokio::test]
async fn test_run_auth_flow_with_path_config() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_path");
    let token = mgr.login(&id).await.expect("login");
    let path_config = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .exclude(vec!["/api/public/**".into()]);
    let req = MockRequest::new("/api/user").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(!flow.should_reject());
    assert_eq!(flow.login_id.as_deref(), Some(id.as_str()));
}

#[tokio::test]
async fn test_auth_flow_result_run_scope() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_scope");
    let token = mgr.login(&id).await.expect("login");
    let req = MockRequest::new("/api/data").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, None).await;
    let result = flow.run(async { "handler_result" }).await;
    assert_eq!(result, "handler_result");
}

#[tokio::test]
async fn test_run_auth_flow_no_token_path_requires_auth() {
    let mgr = setup::fresh_manager();
    let path_config = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let req = MockRequest::new("/api/user");
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(
        flow.should_reject(),
        "no token + path requires auth → reject"
    );
}

#[tokio::test]
async fn test_run_auth_flow_expired_token() {
    let mgr = setup::fresh_manager();
    let id = setup::unique_login_id("user_exp_router");
    let token = mgr.login(&id).await.expect("login");
    setup::expire_token(&mgr, &token).await;
    let path_config = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let req = MockRequest::new("/api/user").with_header("sa-token", token.as_str());
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(
        flow.should_reject(),
        "expired token + path requires auth → reject"
    );
}

#[tokio::test]
async fn test_run_auth_flow_no_path_config_no_token_no_reject() {
    let mgr = setup::fresh_manager();
    let req = MockRequest::new("/public/hello");
    let flow = run_auth_flow(&req, &mgr, None).await;
    assert!(
        !flow.should_reject(),
        "no path config → no reject on missing token"
    );
    assert!(flow.login_id.is_none());
}

// ── PathAuth 假 401 根治：存储失败 / exclude 跳过 / 单次加载 ───────────────

/// 恒失败的存储：模拟 Redis 瞬时不可用
struct FailingStorage;

#[async_trait]
impl SaStorage for FailingStorage {
    async fn get(&self, _key: &str) -> StorageResult<Option<String>> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn set(&self, _: &str, _: &str, _: Option<Duration>) -> StorageResult<()> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn delete(&self, _: &str) -> StorageResult<()> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn exists(&self, _: &str) -> StorageResult<bool> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn expire(&self, _: &str, _: Duration) -> StorageResult<()> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn ttl(&self, _: &str) -> StorageResult<Option<Duration>> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn clear(&self) -> StorageResult<()> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn set_if_absent(&self, _: &str, _: &str, _: Option<Duration>) -> StorageResult<bool> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn get_del(&self, _: &str) -> StorageResult<Option<String>> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: Option<&str>,
        _: &str,
        _: Option<Duration>,
    ) -> StorageResult<bool> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn compare_and_delete(&self, _: &str, _: &str) -> StorageResult<bool> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn list_push(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: Option<Duration>,
    ) -> StorageResult<usize> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn list_remove(&self, _: &str, _: &str) -> StorageResult<bool> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn list_range(&self, _: &str, _: usize, _: Option<usize>) -> StorageResult<Vec<String>> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn list_len(&self, _: &str) -> StorageResult<usize> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
    async fn scan(&self, _: &str, _: u64, _: usize) -> StorageResult<ScanPage> {
        Err(StorageError::OperationFailed("injected failure".into()))
    }
}

/// 计数包装：统计 get/set 次数
struct CountingMemory {
    inner: MemoryStorage,
    gets: AtomicUsize,
    sets: AtomicUsize,
}

impl CountingMemory {
    fn new() -> Self {
        Self {
            inner: MemoryStorage::new(),
            gets: AtomicUsize::new(0),
            sets: AtomicUsize::new(0),
        }
    }
    fn get_count(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }
    fn set_count(&self) -> usize {
        self.sets.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SaStorage for CountingMemory {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        self.sets.fetch_add(1, Ordering::SeqCst);
        self.inner.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> StorageResult<bool> {
        self.inner.exists(key).await
    }
    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        self.inner.expire(key, ttl).await
    }
    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        self.inner.ttl(key).await
    }
    async fn clear(&self) -> StorageResult<()> {
        self.inner.clear().await
    }
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        self.inner.set_if_absent(key, value, ttl).await
    }
    async fn get_del(&self, key: &str) -> StorageResult<Option<String>> {
        self.inner.get_del(key).await
    }
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        self.inner
            .compare_and_swap(key, expected, new_value, ttl)
            .await
    }
    async fn compare_and_delete(&self, key: &str, expected: &str) -> StorageResult<bool> {
        self.inner.compare_and_delete(key, expected).await
    }
    async fn list_push(
        &self,
        key: &str,
        member: &str,
        unique: bool,
        ttl: Option<Duration>,
    ) -> StorageResult<usize> {
        self.inner.list_push(key, member, unique, ttl).await
    }
    async fn list_remove(&self, key: &str, member: &str) -> StorageResult<bool> {
        self.inner.list_remove(key, member).await
    }
    async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> StorageResult<Vec<String>> {
        self.inner.list_range(key, start, limit).await
    }
    async fn list_len(&self, key: &str) -> StorageResult<usize> {
        self.inner.list_len(key).await
    }
    async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> StorageResult<ScanPage> {
        self.inner.scan(pattern, cursor, limit).await
    }
}

#[tokio::test]
async fn test_storage_failure_maps_to_service_unavailable_not_reject() {
    let mgr = SaTokenManager::new(Arc::new(FailingStorage), setup::default_config());
    let path_config = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let req = MockRequest::new("/api/user").with_header("sa-token", "any-token");
    let flow = run_auth_flow(&req, &mgr, Some(&path_config)).await;
    assert!(
        flow.should_service_unavailable(),
        "storage outage on protected path → 503"
    );
    assert!(
        !flow.should_reject(),
        "storage outage must not look like 401"
    );
}

#[tokio::test]
async fn test_exclude_check_token_on_exclude_false_skips_storage() {
    let counter = Arc::new(CountingMemory::new());
    let mgr = SaTokenManager::new(counter.clone(), setup::default_config());
    let path_config = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .exclude(vec!["/health".into()])
        .check_token_on_exclude(false);
    let before = counter.get_count();
    let auth = process_auth("/health", Some("garbage-token".into()), &path_config, &mgr).await;
    assert_eq!(
        counter.get_count(),
        before,
        "exclude + check_token_on_exclude(false) must not hit storage"
    );
    assert!(!auth.should_reject());
    assert!(!auth.should_service_unavailable());
    assert!(auth.login_id().is_none());
}

#[tokio::test]
async fn test_process_auth_single_load_get_delta() {
    let counter = Arc::new(CountingMemory::new());
    // auto_renew 默认 false：有效 token 鉴权不应写存储
    let mgr = SaTokenManager::new(counter.clone(), setup::default_config());
    let id = setup::unique_login_id("single_load");
    let token = mgr.login(&id).await.expect("login");
    let gets_after_login = counter.get_count();
    let sets_after_login = counter.set_count();

    let path_config = PathAuthConfig::new().include(vec!["/api/**".into()]);
    let auth = process_auth(
        "/api/me",
        Some(token.as_str().to_string()),
        &path_config,
        &mgr,
    )
    .await;

    assert!(auth.is_valid);
    assert!(!auth.should_reject());
    let get_delta = counter.get_count() - gets_after_login;
    let set_delta = counter.set_count() - sets_after_login;
    // mapping marker + token body = 2 reads；无续签则 0 writes
    assert_eq!(get_delta, 2, "process_auth must load once (mapping+token)");
    assert_eq!(set_delta, 0, "auto_renew=false → no renew write");
}

#[tokio::test]
async fn test_is_storage_error_helper() {
    let err = SaTokenError::StorageError("boom".into());
    assert!(err.is_storage_error());
    assert!(!SaTokenError::TokenExpired.is_storage_error());
}

#[tokio::test]
async fn test_exclude_storage_failure_does_not_503() {
    let mgr = SaTokenManager::new(Arc::new(FailingStorage), setup::default_config());
    let path_config = PathAuthConfig::new()
        .include(vec!["/api/**".into()])
        .exclude(vec!["/health".into()]);
    // exclude 默认仍软校验：存储失败但不 need_auth → 不 401 也不 503
    let auth = process_auth("/health", Some("any".into()), &path_config, &mgr).await;
    assert!(!auth.need_auth);
    assert!(!auth.should_reject());
    assert!(!auth.should_service_unavailable());
}

// Author: 金书记
//
// Path-based authentication router module
// 基于路径的鉴权路由模块

use std::sync::Arc;

use sa_token_adapter::context::SaRequest;

use crate::config::SaTokenConfig;
use crate::token_io;

type LoginIdValidator = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Match a path against a pattern (Ant-style wildcard)
/// 匹配路径与模式（Ant 风格通配符）
///
/// # Arguments
/// - `path`: The request path to match
/// - `pattern`: The pattern to match against
///
/// # Patterns Supported
/// - `/**`: Match all paths
/// - `/api/**`: Match all paths starting with `/api/`
/// - `/api/*`: Match single-level paths under `/api/`
/// - `*.html`: Match paths ending with `.html`
/// - `/exact`: Exact match
///
/// # Examples
/// ```
/// use sa_token_core::router::match_path;
/// assert!(match_path("/api/user", "/api/**"));
/// assert!(match_path("/api/user", "/api/*"));
/// assert!(!match_path("/api/user/profile", "/api/*"));
/// ```
pub fn match_path(path: &str, pattern: &str) -> bool {
    if pattern == "/**" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix("*") {
        return path.ends_with(suffix);
    }
    // `/*`: single path segment after prefix (e.g. `/api/*` matches `/api/user`, not `/api/a/b`).
    // `/*`：前缀后仅一层路径段（如 `/api/*` 匹配 `/api/user`，不匹配 `/api/a/b`）。
    if let Some(prefix) = pattern.strip_suffix("/*") {
        if !path.starts_with(prefix) {
            return false;
        }
        let rest = &path[prefix.len()..];
        if rest.is_empty() || rest == "/" {
            return true;
        }
        let rest = rest.trim_start_matches('/');
        return !rest.contains('/');
    }
    path == pattern
}

/// Check if path matches any pattern in the list
/// 检查路径是否匹配列表中的任意模式
pub fn match_any(path: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| match_path(path, p))
}

/// Determine if authentication is needed for a path
/// 判断路径是否需要鉴权
///
/// Returns `true` if path matches include patterns but not exclude patterns
/// 如果路径匹配包含模式但不匹配排除模式，返回 `true`
pub fn need_auth(path: &str, include: &[&str], exclude: &[&str]) -> bool {
    match_any(path, include) && !match_any(path, exclude)
}

/// Path-based authentication configuration
/// 基于路径的鉴权配置
///
/// Configure which paths require authentication and which are excluded
/// 配置哪些路径需要鉴权，哪些路径被排除
#[derive(Clone)]
pub struct PathAuthConfig {
    /// Paths that require authentication (include patterns)
    /// 需要鉴权的路径（包含模式）
    include: Vec<String>,
    /// Paths excluded from authentication (exclude patterns)
    /// 排除鉴权的路径（排除模式）
    exclude: Vec<String>,
    /// Optional login ID validator function
    /// 可选的登录ID验证函数
    validator: Option<LoginIdValidator>,
    /// exclude 路径是否仍尝试解析/校验 token（软登录）。
    /// `true`=兼容旧行为；`false`=纯公开，完全跳过存储。
    /// Whether exclude paths still soft-validate a token (default `true`).
    check_token_on_exclude: bool,
}

impl std::fmt::Debug for PathAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PathAuthConfig { .. }")
    }
}

impl PathAuthConfig {
    /// Create a new path authentication configuration
    /// 创建新的路径鉴权配置
    pub fn new() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            validator: None,
            check_token_on_exclude: true,
        }
    }

    /// Set paths that require authentication
    /// 设置需要鉴权的路径
    pub fn include(mut self, patterns: Vec<String>) -> Self {
        self.include = patterns;
        self
    }

    /// Set paths excluded from authentication
    /// 设置排除鉴权的路径
    pub fn exclude(mut self, patterns: Vec<String>) -> Self {
        self.exclude = patterns;
        self
    }

    /// Set a custom login ID validator function
    /// 设置自定义的登录ID验证函数
    pub fn validator<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.validator = Some(Arc::new(f));
        self
    }

    /// 设置 exclude 路径是否做软登录校验（默认 true）
    /// Whether exclude paths still hit storage for soft login (default `true`).
    pub fn check_token_on_exclude(mut self, enabled: bool) -> Self {
        self.check_token_on_exclude = enabled;
        self
    }

    /// Check if a path requires authentication
    /// 检查路径是否需要鉴权
    pub fn check(&self, path: &str) -> bool {
        let inc: Vec<&str> = self.include.iter().map(|s| s.as_str()).collect();
        let exc: Vec<&str> = self.exclude.iter().map(|s| s.as_str()).collect();
        need_auth(path, &inc, &exc)
    }

    /// Validate a login ID using the configured validator
    /// 使用配置的验证器验证登录ID
    pub fn validate_login_id(&self, login_id: &str) -> bool {
        self.validator.as_ref().is_none_or(|v| v(login_id))
    }
}

impl Default for PathAuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

use crate::context::{RequestAuthMeta, SaTokenContext};
use crate::{SaTokenManager, TokenValue, token::TokenInfo};

/// 鉴权失败分类：区分「未登录」与「存储挂了」
/// Auth failure kind: distinguish missing/invalid token from storage outage.
#[derive(Debug, Clone)]
pub enum AuthFailureKind {
    /// 请求未携带 token | Request has no token
    MissingToken,
    /// token 无效 / 过期 / 冻结 / 踢下线 / validator 失败等
    /// Token invalid, expired, frozen, kicked, or validator rejected
    InvalidToken,
    /// Redis 等存储瞬时不可用 | Storage temporarily unavailable
    StorageUnavailable(String),
}

/// Authentication result after processing
/// 处理后的鉴权结果
pub struct AuthResult {
    /// Whether authentication is required for this path
    /// 此路径是否需要鉴权
    pub need_auth: bool,
    /// Extracted token value
    /// 提取的token值
    pub token: Option<TokenValue>,
    /// Token information if valid
    /// 如果有效则包含token信息
    pub token_info: Option<TokenInfo>,
    /// Whether the token is valid
    /// token是否有效
    pub is_valid: bool,
    /// 失败原因；成功为 None | Failure reason; `None` on success
    pub failure: Option<AuthFailureKind>,
}

impl std::fmt::Debug for AuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthResult { .. }")
    }
}

impl AuthResult {
    /// 路径需要登录且确认为鉴权失败（非存储故障）→ 绑定层应 401
    /// Path requires login and failure is auth (not storage) → binding should 401
    pub fn should_reject(&self) -> bool {
        if !self.need_auth || self.is_valid {
            return false;
        }
        match &self.failure {
            Some(AuthFailureKind::StorageUnavailable(_)) => false,
            Some(AuthFailureKind::MissingToken | AuthFailureKind::InvalidToken) => true,
            None => true,
        }
    }

    /// 路径需要登录但存储不可用 → 绑定层应 503
    /// Path requires login but storage is down → binding should 503
    pub fn should_service_unavailable(&self) -> bool {
        self.need_auth && matches!(self.failure, Some(AuthFailureKind::StorageUnavailable(_)))
    }

    /// Get the login ID from token info
    /// 从token信息中获取登录ID
    pub fn login_id(&self) -> Option<&str> {
        self.token_info.as_ref().map(|t| t.login_id.as_ref())
    }
}

/// Process authentication for a request path (single `load_and_touch`).
/// 处理请求路径的鉴权（单次 `load_and_touch`）。
///
/// # Arguments
/// - `path`: The request path
/// - `token_str`: Optional token string from request
/// - `config`: Path authentication configuration
/// - `manager`: SaTokenManager instance
pub async fn process_auth(
    path: &str,
    token_str: Option<String>,
    config: &PathAuthConfig,
    manager: &SaTokenManager,
) -> AuthResult {
    let need_auth = config.check(path);
    let token = token_str.map(TokenValue::new);

    // exclude 且配置为跳过校验：不打存储
    if !need_auth && !config.check_token_on_exclude {
        return AuthResult {
            need_auth,
            token,
            token_info: None,
            is_valid: false,
            failure: None,
        };
    }

    let (mut is_valid, token_info, mut failure) = match &token {
        None => (false, None, Some(AuthFailureKind::MissingToken)),
        Some(t) => match manager.load_and_touch(t).await {
            Ok(info) => (true, Some(info), None),
            Err(e) if e.is_storage_error() => (
                false,
                None,
                Some(AuthFailureKind::StorageUnavailable(e.to_string())),
            ),
            Err(_) => (false, None, Some(AuthFailureKind::InvalidToken)),
        },
    };

    // 仅强制鉴权路径跑自定义 login_id 校验
    if need_auth && is_valid {
        let ok = token_info
            .as_ref()
            .is_some_and(|info| config.validate_login_id(info.login_id.as_ref()));
        if !ok {
            is_valid = false;
            failure = Some(AuthFailureKind::InvalidToken);
        }
    }

    AuthResult {
        need_auth,
        token,
        token_info,
        is_valid,
        failure,
    }
}

/// 从鉴权结果创建 SaTokenContext（共享 Arc Inner，供 scope 内 switch_to 突变）
///
/// Create `SaTokenContext` from auth result (shared Arc Inner for `switch_to` mutations inside scope).
pub fn create_context(result: &AuthResult, auth_meta: RequestAuthMeta) -> SaTokenContext {
    let mut builder = SaTokenContext::builder().auth_meta(auth_meta);
    if let (Some(token), Some(info)) = (&result.token, &result.token_info) {
        builder = builder
            .token(token.clone())
            .token_info(Arc::new(info.clone()))
            .login_id(info.login_id.as_ref());
    }
    builder.build()
}

/// Backward-compatible extract: all read flags true, no custom prefix.
/// 兼容旧签名：读取开关全开、无自定义前缀。
pub fn extract_token<R: SaRequest>(req: &R, token_name: &str) -> Option<String> {
    let cfg = SaTokenConfig {
        token_name: token_name.to_string(),
        ..SaTokenConfig::default()
    };
    token_io::read_token(req, &cfg)
}

/// Extract using the live manager config (`is_read_*` / `token_prefix`).
/// 使用当前 Manager 配置抽取（尊重 `is_read_*` / `token_prefix`）。
pub fn extract_token_from<R: SaRequest>(req: &R, config: &SaTokenConfig) -> Option<String> {
    token_io::read_token(req, config)
}

/// Outcome of [`run_auth_flow`]; bindings copy token/login_id/context into framework-specific storage (extensions, depot, etc.).
/// [`run_auth_flow`] 的返回结果；各框架绑定把 token / login_id / context 写入自身存储（extensions、Depot 等）。
pub struct AuthFlowResult {
    /// Path rules + validation summary. | 路径规则与校验摘要。
    pub auth: AuthResult,
    /// Login id when token is valid. | 登录 id（token 有效时）。
    pub login_id: Option<String>,
    /// Parsed token value when present. | 解析后的 token（若有）。
    pub token: Option<TokenValue>,
    /// Request-scoped context for `StpUtil` / handlers. | 请求级上下文，供 `StpUtil` / 处理器使用。
    pub context: SaTokenContext,
}

impl std::fmt::Debug for AuthFlowResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthFlowResult { .. }")
    }
}

impl AuthFlowResult {
    /// `true` if the binding should respond **401** (path requires auth but token missing or invalid).
    /// 若路径要求鉴权但 token 缺失或无效，绑定层应返回 **401**，则返回 `true`。
    pub fn should_reject(&self) -> bool {
        self.auth.should_reject()
    }

    /// `true` if the binding should respond **503** (path requires auth but storage is unavailable).
    /// 若路径要求鉴权但存储不可用，绑定层应返回 **503**，则返回 `true`。
    pub fn should_service_unavailable(&self) -> bool {
        self.auth.should_service_unavailable()
    }

    /// Run `fut` with [`SaTokenContext::scope`] using this flow's [`AuthFlowResult::context`] (await-safe).
    /// 用本流的 [`AuthFlowResult::context`] 调用 [`SaTokenContext::scope`] 执行 `fut`（可跨 await）。
    ///
    /// Context 内部可变：scope 后 `switch_to` 可就地突变共享 Arc。
    /// 同时建立授权快照：B2 特性，请求级权限缓存。
    ///
    /// Context is internally mutable: `switch_to` can mutate shared Arc in-place after scope.
    /// Also establishes authz snapshot (B2 feature, request-level permission cache).
    pub async fn run<F, R>(self, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        SaTokenContext::scope(self.context, fut).await
    }
}

/// Full auth pipeline: [`extract_token_from`] → optional [`PathAuthConfig`] via [`process_auth`], else default check → [`create_context`].
/// 完整鉴权流水线：[`extract_token_from`] → 若有 [`PathAuthConfig`] 则 [`process_auth`]，否则默认校验 → [`create_context`]。
///
/// Pass `path_config: None` for “validate token if present, no path-based reject”.
/// `path_config` 为 `None` 时表示：有 token 则校验并填上下文，不按路径规则拒绝。
pub async fn run_auth_flow<R: SaRequest>(
    req: &R,
    manager: &SaTokenManager,
    path_config: Option<&PathAuthConfig>,
) -> AuthFlowResult {
    let token_str = extract_token_from(req, &manager.config);
    let path = req.get_path();
    let auth_meta = RequestAuthMeta::from_request(req, manager.config.same_token_header.as_str());

    let (auth, ctx) = match path_config {
        Some(cfg) => {
            // Path-based rules: may set need_auth / should_reject / should_service_unavailable.
            // 基于路径的规则：可产生 need_auth / should_reject / should_service_unavailable。
            let auth = process_auth(path.as_str(), token_str.clone(), cfg, manager).await;
            let ctx = create_context(&auth, auth_meta);
            (auth, ctx)
        }
        None => {
            // 无路径配置：有 token 则单次校验并注入；永不 reject / 503
            let token = token_str.map(TokenValue::new);
            let (is_valid, token_info, failure) = if let Some(ref t) = token {
                match manager.load_and_touch(t).await {
                    Ok(info) => (true, Some(info), None),
                    Err(e) if e.is_storage_error() => (
                        false,
                        None,
                        Some(AuthFailureKind::StorageUnavailable(e.to_string())),
                    ),
                    Err(_) => (false, None, Some(AuthFailureKind::InvalidToken)),
                }
            } else {
                (false, None, Some(AuthFailureKind::MissingToken))
            };
            let auth = AuthResult {
                need_auth: false,
                token: token.clone(),
                token_info,
                is_valid,
                failure,
            };
            let ctx = create_context(&auth, auth_meta);
            (auth, ctx)
        }
    };

    let login_id = auth.login_id().map(str::to_string);
    let token = auth.token.clone();
    AuthFlowResult {
        auth,
        login_id,
        token,
        context: ctx,
    }
}

// Author: 金书记
//
// Path-based authentication router module
// 基于路径的鉴权路由模块

use std::sync::Arc;

use sa_token_adapter::context::SaRequest;
use sa_token_adapter::utils::extract_bearer_or_value;

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
}

impl PathAuthConfig {
    /// Create a new path authentication configuration
    /// 创建新的路径鉴权配置
    pub fn new() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            validator: None,
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

use crate::{SaTokenManager, TokenValue, SaTokenContext, token::TokenInfo};

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
}

impl AuthResult {
    /// Check if the request should be rejected
    /// 检查请求是否应该被拒绝
    pub fn should_reject(&self) -> bool {
        self.need_auth && (!self.is_valid || self.token.is_none())
    }

    /// Get the login ID from token info
    /// 从token信息中获取登录ID
    pub fn login_id(&self) -> Option<&str> {
        self.token_info.as_ref().map(|t| t.login_id.as_str())
    }
}

/// Process authentication for a request path
/// 处理请求路径的鉴权
///
/// This function checks if the path requires authentication, validates the token,
/// and returns an AuthResult with all relevant information.
/// 此函数检查路径是否需要鉴权，验证token，并返回包含所有相关信息的AuthResult。
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
    
    let (is_valid, token_info) = if let Some(ref t) = token {
        let valid = manager.is_valid(t).await;
        let info = if valid {
            manager.get_token_info(t).await.ok()
        } else {
            None
        };
        (valid, info)
    } else {
        (false, None)
    };

    let is_valid = is_valid && if need_auth {
        token_info.as_ref().is_some_and(|info| config.validate_login_id(&info.login_id))
    } else {
        true
    };

    AuthResult {
        need_auth,
        token,
        token_info,
        is_valid,
    }
}

/// Create SaTokenContext from authentication result
/// 从鉴权结果创建SaTokenContext
pub fn create_context(result: &AuthResult) -> SaTokenContext {
    let mut ctx = SaTokenContext::new();
    if let (Some(token), Some(info)) = (&result.token, &result.token_info) {
        ctx.token = Some(token.clone());
        ctx.token_info = Some(Arc::new(info.clone()));
        ctx.login_id = Some(info.login_id.clone());
    }
    ctx
}

/// Generic token extraction from any [`SaRequest`] implementation.
/// 从任意 [`SaRequest`] 实现中按统一顺序提取 Token。
///
/// Order | 顺序:
/// 1. Header `[token_name]` (Bearer semantics via [`extract_bearer_or_value`]).
/// 2. `Authorization` header if `token_name` is not already Authorization (case-insensitive match on read side is adapter-specific).
/// 3. Cookie `[token_name]`.
/// 4. Query parameter `[token_name]`.
///
/// Empty strings are skipped. Returns `None` if nothing found.
/// 空字符串跳过；均未命中则返回 `None`。
pub fn extract_token<R: SaRequest>(req: &R, token_name: &str) -> Option<String> {
    if let Some(v) = req.get_header(token_name) {
        let s = extract_bearer_or_value(&v);
        if !s.is_empty() {
            return Some(s);
        }
    }
    if !token_name.eq_ignore_ascii_case("authorization")
        && let Some(v) = req.get_header("Authorization") {
            let s = extract_bearer_or_value(&v);
            if !s.is_empty() {
                return Some(s);
            }
        }
    if let Some(v) = req.get_cookie(token_name) {
        let s = v.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    if let Some(v) = req.get_param(token_name) {
        let s = v.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
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

impl AuthFlowResult {
    /// `true` if the binding should respond **401** (path requires auth but token missing or invalid).
    /// 若路径要求鉴权但 token 缺失或无效，绑定层应返回 **401**，则返回 `true`。
    pub fn should_reject(&self) -> bool {
        self.auth.should_reject()
    }

    /// Run `fut` with [`SaTokenContext::scope`] using this flow's [`AuthFlowResult::context`] (await-safe).
    /// 用本流的 [`AuthFlowResult::context`] 调用 [`SaTokenContext::scope`] 执行 `fut`（可跨 await）。
    pub async fn run<F, R>(self, fut: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        SaTokenContext::scope(self.context, fut).await
    }
}

/// Full auth pipeline: [`extract_token`] → optional [`PathAuthConfig`] via [`process_auth`], else default check → [`create_context`].
/// 完整鉴权流水线：[`extract_token`] → 若有 [`PathAuthConfig`] 则 [`process_auth`]，否则默认校验 → [`create_context`]。
///
/// Pass `path_config: None` for “validate token if present, no path-based reject”.
/// `path_config` 为 `None` 时表示：有 token 则校验并填上下文，不按路径规则拒绝。
pub async fn run_auth_flow<R: SaRequest>(
    req: &R,
    manager: &SaTokenManager,
    path_config: Option<&PathAuthConfig>,
) -> AuthFlowResult {
    let token_name = manager.config.token_name.as_str();
    let token_str = extract_token(req, token_name);
    let path = req.get_path();

    let (auth, ctx) = match path_config {
        Some(cfg) => {
            // Path-based rules: may set need_auth / should_reject.
            // 基于路径的规则：可产生 need_auth / should_reject。
            let auth = process_auth(path.as_str(), token_str.clone(), cfg, manager).await;
            let ctx = create_context(&auth);
            (auth, ctx)
        }
        None => {
            // No path config: only validate token when present.
            // 无路径配置：仅在有 token 时做有效性校验。
            let token = token_str.map(TokenValue::new);
            let (is_valid, token_info) = if let Some(ref t) = token {
                let valid = manager.is_valid(t).await;
                let info = if valid {
                    manager.get_token_info(t).await.ok()
                } else {
                    None
                };
                (valid, info)
            } else {
                (false, None)
            };
            let auth = AuthResult {
                need_auth: false,
                token: token.clone(),
                token_info,
                is_valid,
            };
            let ctx = create_context(&auth);
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


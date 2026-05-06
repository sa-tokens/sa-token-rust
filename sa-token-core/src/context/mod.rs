// Author: 金书记
//
//! 上下文模块 - 用于在请求处理过程中传递 token 信息
//!
//! - **`tokio::task_local!`**：跨 `await`、跨 Tokio worker 线程仍与同一异步任务绑定（推荐）。
//! - **`thread_local`**：兼容旧代码与同步路径（[`SaTokenContext::set_current`] / [`SaTokenContext::clear`]）。
//!
//! Context module — carries token info during a request.
//! **`tokio::task_local!`**: stays bound to the same logical async task across awaits/workers (preferred).
//! **`thread_local`**: backward-compatible synchronous path (`set_current` / `clear`).

use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;

use crate::token::{TokenInfo, TokenValue};

thread_local! {
    static TLS_CTX: RefCell<Option<SaTokenContext>> = const { RefCell::new(None) };
}

tokio::task_local! {
    static TASK_CTX: SaTokenContext;
}

/// sa-token 上下文 | sa-token Context
///
/// # 字段说明 | Field Description
/// - `token`: 当前请求的 token | Current request's token
/// - `token_info`: Token 详细信息 | Token detailed information
/// - `login_id`: 登录用户 ID | Logged-in user ID
#[derive(Debug, Clone)]
pub struct SaTokenContext {
    /// 当前请求的 token | Current request's token
    pub token: Option<TokenValue>,

    /// 当前请求的 token 信息 | Current request's token info
    pub token_info: Option<Arc<TokenInfo>>,

    /// 登录 ID | Login ID
    pub login_id: Option<String>,
}

impl SaTokenContext {
    pub fn new() -> Self {
        Self {
            token: None,
            token_info: None,
            login_id: None,
        }
    }

    /// Bind `ctx` for the whole lifetime of `fut` (await-safe across worker threads).
    /// 在 `fut` 全生命周期内绑定 `ctx`（跨 await / 跨 worker 仍有效）。
    pub async fn scope<F, R>(ctx: SaTokenContext, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        TASK_CTX.scope(ctx, fut).await
    }

    /// Clone of current context: **task-local first**, then thread-local fallback.
    /// 当前上下文副本：**优先 task-local**，再回落 thread-local。
    pub fn try_current() -> Option<SaTokenContext> {
        match TASK_CTX.try_with(|c| c.clone()) {
            Ok(c) => Some(c),
            Err(_) => TLS_CTX.with(|c| c.borrow().clone()),
        }
    }

    /// 设置当前上下文（thread-local 兼容路径）| Set current context (thread-local compat)
    pub fn set_current(ctx: SaTokenContext) {
        TLS_CTX.with(|c| {
            *c.borrow_mut() = Some(ctx);
        });
    }

    /// 获取当前上下文 | Get current context
    pub fn get_current() -> Option<SaTokenContext> {
        Self::try_current()
    }

    /// 清除当前上下文（thread-local 兼容路径）| Clear current context (thread-local compat)
    pub fn clear() {
        TLS_CTX.with(|c| {
            *c.borrow_mut() = None;
        });
    }
}

impl Default for SaTokenContext {
    fn default() -> Self {
        Self::new()
    }
}

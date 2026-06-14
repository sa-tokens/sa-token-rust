// Author: 金书记
//
//! StpUtil - sa-token 便捷工具类
//!
//! 提供类似 Java 版 StpUtil 的静态方法，方便进行认证和权限操作
//!
//! ## 使用示例
//!
//! ```rust,ignore
//! use sa_token_core::StpUtil;
//!
//! // 初始化全局 Manager（应用启动时调用一次）
//! StpUtil::init_manager(manager);
//!
//! // 之后就可以直接使用，支持多种 ID 类型
//! let token = StpUtil::login("user_123").await?;  // 字符串 ID
//! let token = StpUtil::login(10001).await?;       // 数字 ID (i32)
//! let token = StpUtil::login(10001_i64).await?;   // 数字 ID (i64)
//!
//! StpUtil::set_permissions(10001, vec!["user:list".to_string()]).await?;
//! ```

use std::sync::Arc;
use std::fmt::Display;
use std::sync::OnceLock;
use crate::{SaTokenManager, SaTokenResult, SaTokenError};
use crate::token::{TokenValue, TokenInfo};
use crate::session::SaSession;
use crate::context::SaTokenContext;
use crate::event::{SaTokenEventBus, SaTokenListener};

/// 全局 SaTokenManager 实例（标准库 OnceLock，Rust 1.70+）
static GLOBAL_MANAGER: OnceLock<Arc<SaTokenManager>> = OnceLock::new();

/// LoginId trait - 支持任何可以转换为字符串的类型作为登录 ID
///
/// 自动实现了 String, &str, i32, i64, u32, u64 等常用类型
pub trait LoginId {
    fn to_login_id(&self) -> String;
}

// 为所有实现了 Display 的类型自动实现 LoginId
impl<T: Display> LoginId for T {
    fn to_login_id(&self) -> String {
        self.to_string()
    }
}

/// StpUtil - 权限认证工具类
///
/// 提供便捷的认证和授权操作方法，类似于 Java 版 sa-token 的 StpUtil
pub struct StpUtil;

impl StpUtil {
    // ==================== 初始化 ====================

    /// 初始化全局 SaTokenManager（应用启动时调用一次）
    ///
    /// # 示例
    /// ```rust,ignore
    /// let manager = SaTokenConfig::builder()
    ///     .storage(Arc::new(MemoryStorage::new()))
    ///     .build();
    /// StpUtil::init_manager(manager);
    /// ```
    pub fn init_manager(manager: SaTokenManager) {
        GLOBAL_MANAGER.set(Arc::new(manager))
            .unwrap_or_else(|_| panic!("StpUtil manager already initialized"));
    }

    /// 获取全局 Manager
    fn get_manager() -> &'static Arc<SaTokenManager> {
        GLOBAL_MANAGER.get()
            .expect("StpUtil not initialized. Call StpUtil::init_manager() first.")
    }

    /// 获取事件总线，用于注册监听器
    ///
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_core::{StpUtil, SaTokenListener};
    /// use async_trait::async_trait;
    ///
    /// struct MyListener;
    ///
    /// #[async_trait]
    /// impl SaTokenListener for MyListener {
    ///     async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
    ///         println!("用户 {} 登录了", login_id);
    ///     }
    /// }
    ///
    /// // 注册监听器
    /// StpUtil::event_bus().register(Arc::new(MyListener)).await;
    /// ```
    pub fn event_bus() -> &'static SaTokenEventBus {
        &Self::get_manager().event_bus
    }

    /// 注册事件监听器（便捷方法）
    ///
    /// # 示例
    /// ```rust,ignore
    /// StpUtil::register_listener(Arc::new(MyListener)).await;
    /// ```
    pub fn register_listener(listener: Arc<dyn SaTokenListener>) {
        Self::event_bus().register(listener);
    }

    // ==================== 登录相关 ====================

    /// 会话登录
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 支持字符串 ID
    /// let token = StpUtil::login("user_123").await?;
    ///
    /// // 支持数字 ID
    /// let token = StpUtil::login(10001).await?;
    /// let token = StpUtil::login(10001_i64).await?;
    /// ```
    pub async fn login(login_id: impl LoginId) -> SaTokenResult<TokenValue> {
        Self::get_manager().login(login_id.to_login_id()).await
    }

    pub async fn login_with_type(
        login_id: impl LoginId,
        login_type: impl Into<String>,
    ) -> SaTokenResult<TokenValue> {
        Self::get_manager()
            .login_with_options(
                login_id.to_login_id(),
                Some(login_type.into()),
                None,
                None,
                None,
                None,
            )
            .await
    }

    /// 登录并设置额外数据 | Login with extra data
    ///
    /// # 参数 | Arguments
    /// * `login_id` - 登录ID | Login ID
    /// * `extra_data` - 额外数据 | Extra data
    pub async fn login_with_extra(
        login_id: impl LoginId,
        extra_data: serde_json::Value,
    ) -> SaTokenResult<TokenValue> {
        Self::get_manager().login_with_options(
            login_id.to_login_id(),
            None,    // login_type
            None,    // device
            Some(extra_data),
            None,    // nonce
            None,    // expire_time
        ).await
    }

    /// 会话登录（带 manager 参数的版本，向后兼容）
    pub async fn login_with_manager(
        manager: &SaTokenManager,
        login_id: impl Into<String>,
    ) -> SaTokenResult<TokenValue> {
        manager.login(login_id).await
    }

    /// 会话登出
    pub async fn logout(token: &TokenValue) -> SaTokenResult<()> {
        tracing::debug!("开始执行 logout，token: {}", token);
        let result = Self::get_manager().logout(token).await;
        match &result {
            Ok(_) => tracing::debug!("logout 执行成功，token: {}", token),
            Err(e) => tracing::debug!("logout 执行失败，token: {}, 错误: {}", token, e),
        }
        result
    }

    pub async fn logout_with_manager(
        manager: &SaTokenManager,
        token: &TokenValue,
    ) -> SaTokenResult<()> {
        manager.logout(token).await
    }

    /// 踢人下线（根据登录ID）
    pub async fn kick_out(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::get_manager().kick_out(&login_id.to_login_id()).await
    }

    pub async fn kick_out_with_manager(
        manager: &SaTokenManager,
        login_id: &str,
    ) -> SaTokenResult<()> {
        manager.kick_out(login_id).await
    }

    /// 强制登出（根据登录ID）
    pub async fn logout_by_login_id(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::get_manager().logout_by_login_id(&login_id.to_login_id()).await
    }

    /// 根据 token 登出（别名方法，更直观）
    pub async fn logout_by_token(token: &TokenValue) -> SaTokenResult<()> {
        Self::logout(token).await
    }

    // ==================== 当前会话操作（无参数，从上下文获取）====================

    /// 获取当前请求的 token（无参数，从上下文获取）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let token = StpUtil::get_token_value()?;
    /// ```
    pub fn get_token_value() -> SaTokenResult<TokenValue> {
        let ctx = SaTokenContext::try_current().ok_or(SaTokenError::NotLogin)?;
        ctx.token.ok_or(SaTokenError::NotLogin)
    }

    /// 当前会话登出（无参数，从上下文获取 token）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// StpUtil::logout_current().await?;
    /// ```
    pub async fn logout_current() -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        tracing::debug!("成功获取 token: {}", token);

        let result = Self::logout(&token).await;
        match &result {
            Ok(_) => tracing::debug!("logout_current 执行成功，token: {}", token),
            Err(e) => tracing::debug!("logout_current 执行失败，token: {}, 错误: {}", token, e),
        }
        result
    }

    /// 检查当前会话是否登录（无参数，返回 bool）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// if StpUtil::is_login_current() {
    ///     println!("当前用户已登录");
    /// }
    /// ```
    pub fn is_login_current() -> bool {
        if let Ok(_token) = Self::get_token_value() {
            // 注意：这里使用同步检查，只检查上下文中是否有 token
            // 如果需要异步验证，需要使用 is_login(&token).await
            true
        } else {
            false
        }
    }

    /// 检查当前会话登录状态，未登录则抛出异常（无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// StpUtil::check_login_current()?;
    /// ```
    pub fn check_login_current() -> SaTokenResult<()> {
        Self::get_token_value()?;
        Ok(())
    }

    /// 获取当前会话的 login_id（String 类型，无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let login_id = StpUtil::get_login_id_as_string().await?;
    /// ```
    pub async fn get_login_id_as_string() -> SaTokenResult<String> {
        if let Some(ctx) = SaTokenContext::get_current()
            && let Some(switch_id) = ctx.switch_login_id {
                return Ok(switch_id);
            }
        let token = Self::get_token_value()?;
        Self::get_login_id(&token).await
    }

    /// 获取当前会话的 login_id（i64 类型，无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let user_id = StpUtil::get_login_id_as_long().await?;
    /// ```
    pub async fn get_login_id_as_long() -> SaTokenResult<i64> {
        let login_id_str = Self::get_login_id_as_string().await?;
        login_id_str.parse::<i64>()
            .map_err(|_| SaTokenError::LoginIdNotNumber)
    }

    /// 获取当前会话的 token 信息（无参数）
    ///
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let token_info = StpUtil::get_token_info_current()?;
    /// println!("Token 创建时间: {:?}", token_info.create_time);
    /// ```
    pub fn get_token_info_current() -> SaTokenResult<Arc<TokenInfo>> {
        let ctx = SaTokenContext::try_current().ok_or(SaTokenError::NotLogin)?;
        ctx.token_info.ok_or(SaTokenError::NotLogin)
    }

    // ==================== Token 验证 ====================

    /// 检查当前 token 是否已登录
    pub async fn is_login(token: &TokenValue) -> bool {
        Self::get_manager().is_valid(token).await
    }

    /// 根据登录 ID 检查是否已登录
    ///
    /// # 示例
    /// ```rust,ignore
    /// let is_logged_in = StpUtil::is_login_by_login_id("user_123").await;
    /// let is_logged_in = StpUtil::is_login_by_login_id(10001).await;
    /// ```
    pub async fn is_login_by_login_id(login_id: impl LoginId) -> bool {
        match Self::get_token_by_login_id(login_id).await {
            Ok(token) => Self::is_login(&token).await,
            Err(_) => false,
        }
    }

    pub async fn is_login_with_manager(
        manager: &SaTokenManager,
        token: &TokenValue,
    ) -> bool {
        manager.is_valid(token).await
    }

    /// 检查当前 token 是否已登录，如果未登录则抛出异常
    pub async fn check_login(token: &TokenValue) -> SaTokenResult<()> {
        if !Self::is_login(token).await {
            return Err(SaTokenError::NotLogin);
        }
        Ok(())
    }

    /// 获取 token 信息
    pub async fn get_token_info(token: &TokenValue) -> SaTokenResult<TokenInfo> {
        Self::get_manager().get_token_info(token).await
    }

    /// 获取当前 token 的登录ID
    pub async fn get_login_id(token: &TokenValue) -> SaTokenResult<String> {
        let token_info = Self::get_manager().get_token_info(token).await?;
        Ok(token_info.login_id)
    }

    /// 获取当前 token 的登录ID，如果未登录则返回默认值
    pub async fn get_login_id_or_default(
        token: &TokenValue,
        default: impl Into<String>,
    ) -> String {
        Self::get_login_id(token)
            .await
            .unwrap_or_else(|_| default.into())
    }

    /// 根据登录 ID 获取当前用户的 token
    ///
    /// # 示例
    /// ```rust,ignore
    /// let token = StpUtil::get_token_by_login_id("user_123").await?;
    /// let token = StpUtil::get_token_by_login_id(10001).await?;
    /// ```
    pub async fn get_token_by_login_id(login_id: impl LoginId) -> SaTokenResult<TokenValue> {
        let manager = Self::get_manager();
        let login_id_str = login_id.to_login_id();

        // 从存储中获取该用户的 token
        let key = manager.config.make_key("login:token:", &login_id_str);
        match manager.storage.get(&key).await {
            Ok(Some(token_str)) => Ok(TokenValue::new(token_str)),
            Ok(None) => Err(SaTokenError::NotLogin),
            Err(e) => Err(SaTokenError::StorageError(e.to_string())),
        }
    }

    /// 根据登录 ID 获取所有在线的 token 列表（支持多设备登录）
    ///
    /// # 示例
    /// ```rust,ignore
    /// let tokens = StpUtil::get_all_tokens_by_login_id("user_123").await?;
    /// ```
    pub async fn get_all_tokens_by_login_id(login_id: impl LoginId) -> SaTokenResult<Vec<TokenValue>> {
        let manager = Self::get_manager();
        let login_id_str = login_id.to_login_id();

        // 从存储中获取该用户的所有 token
        let key = manager.config.make_key("login:tokens:", &login_id_str);
        match manager.storage.get(&key).await {
            Ok(Some(tokens_str)) => {
                let token_strings: Vec<String> = serde_json::from_str(&tokens_str)
                    .map_err(SaTokenError::SerializationError)?;
                Ok(token_strings.into_iter().map(TokenValue::new).collect())
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(SaTokenError::StorageError(e.to_string())),
        }
    }

    // ==================== Session 会话 ====================

    /// 获取当前登录账号的 Session
    pub async fn get_session(login_id: impl LoginId) -> SaTokenResult<SaSession> {
        Self::get_manager().get_session(&login_id.to_login_id()).await
    }

    /// 保存 Session
    pub async fn save_session(session: &SaSession) -> SaTokenResult<()> {
        Self::get_manager().save_session(session).await
    }

    /// 删除 Session
    pub async fn delete_session(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::get_manager().delete_session(&login_id.to_login_id()).await
    }

    /// 在 Session 中设置值
    pub async fn set_session_value<T: serde::Serialize>(
        login_id: impl LoginId,
        key: &str,
        value: T,
    ) -> SaTokenResult<()> {
        let manager = Self::get_manager();
        let login_id_str = login_id.to_login_id();
        let mut session = manager.get_session(&login_id_str).await?;
        session.set(key, value)?;
        manager.save_session(&session).await
    }

    /// 从 Session 中获取值
    pub async fn get_session_value<T: serde::de::DeserializeOwned>(
        login_id: impl LoginId,
        key: &str,
    ) -> SaTokenResult<Option<T>> {
        let session = Self::get_manager().get_session(&login_id.to_login_id()).await?;
        Ok(session.get::<T>(key))
    }

    // ==================== Token 相关 ====================

    /// 创建一个新的 token（但不登录）
    pub fn create_token(token_value: impl Into<String>) -> TokenValue {
        TokenValue::new(token_value.into())
    }

    /// 检查 token 格式是否有效（仅检查格式，不检查是否存在于存储中）
    pub fn is_valid_token_format(token: &str) -> bool {
        !token.is_empty() && token.len() >= 16
    }
}

// ==================== 权限管理 ====================

impl StpUtil {
    /// 覆盖设置用户权限列表
    /// 会完全替换该用户的所有权限
    pub async fn set_permissions(
        login_id: impl LoginId,
        permissions: Vec<String>,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .set_permissions(&login_id.to_login_id(), permissions)
            .await
    }

    /// 为用户追加单个权限（已存在则跳过）
    pub async fn add_permission(
        login_id: impl LoginId,
        permission: impl Into<String>,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .add_permission(&login_id.to_login_id(), permission.into())
            .await
    }

    /// 移除用户的某个权限
    pub async fn remove_permission(
        login_id: impl LoginId,
        permission: &str,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .remove_permission(&login_id.to_login_id(), permission)
            .await
    }

    /// 清除用户的所有权限
    pub async fn clear_permissions(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::get_manager()
            .clear_permissions(&login_id.to_login_id())
            .await
    }

    /// 获取用户的所有权限
    /// 存储异常时返回空列表，保持原有 API 语义（返回 Vec 而非 Result）
    pub async fn get_permissions(login_id: impl LoginId) -> Vec<String> {
        Self::get_manager()
            .get_permissions(&login_id.to_login_id())
            .await
            .unwrap_or_default()
    }

    /// 检查用户是否拥有指定权限
    /// 支持精确匹配与通配符匹配（如 `admin:*` 匹配 `admin:read`）
    /// 存储读取失败时按"无权限"处理
    pub async fn has_permission(
        login_id: impl LoginId,
        permission: &str,
    ) -> bool {
        let permissions = match Self::get_manager()
            .get_permissions(&login_id.to_login_id())
            .await
        {
            Ok(list) => list,
            Err(_) => return false,
        };

        // 1. 精确匹配
        if permissions.iter().any(|p| p == permission) {
            return true;
        }
        // 2. 全局通配符：* 匹配一切
        if permissions.iter().any(|p| p == "*") {
            return true;
        }
        // 3. 前缀通配符：admin:* 匹配 admin:read
        permissions.iter().any(|perm| {
            perm.strip_suffix(":*")
                .is_some_and(|prefix| permission.starts_with(prefix))
        })
    }

    /// 检查用户是否拥有所有指定权限（AND 逻辑）
    pub async fn has_all_permissions(
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> bool {
        let login_id_str = login_id.to_login_id();
        for permission in permissions {
            if !Self::has_permission(&login_id_str, permission).await {
                return false;
            }
        }
        true
    }

    /// 检查用户是否拥有所有指定权限（别名，AND 逻辑）
    pub async fn has_permissions_and(
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> bool {
        Self::has_all_permissions(login_id, permissions).await
    }

    /// 检查用户是否拥有任一指定权限（OR 逻辑）
    pub async fn has_any_permission(
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> bool {
        let login_id_str = login_id.to_login_id();
        for permission in permissions {
            if Self::has_permission(&login_id_str, permission).await {
                return true;
            }
        }
        false
    }

    /// 检查用户是否拥有任一指定权限（别名，OR 逻辑）
    pub async fn has_permissions_or(
        login_id: impl LoginId,
        permissions: &[&str],
    ) -> bool {
        Self::has_any_permission(login_id, permissions).await
    }

    /// 检查权限，如果没有则抛出异常
    pub async fn check_permission(
        login_id: impl LoginId,
        permission: &str,
    ) -> SaTokenResult<()> {
        if !Self::has_permission(login_id, permission).await {
            return Err(SaTokenError::PermissionDeniedDetail(permission.to_string()));
        }
        Ok(())
    }
}

// ==================== 角色管理 ====================

impl StpUtil {
    /// 覆盖设置用户角色列表
    /// 会完全替换该用户的所有角色
    pub async fn set_roles(
        login_id: impl LoginId,
        roles: Vec<String>,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .set_roles(&login_id.to_login_id(), roles)
            .await
    }

    /// 为用户追加单个角色（已存在则跳过）
    pub async fn add_role(
        login_id: impl LoginId,
        role: impl Into<String>,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .add_role(&login_id.to_login_id(), role.into())
            .await
    }

    /// 移除用户的某个角色
    pub async fn remove_role(
        login_id: impl LoginId,
        role: &str,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .remove_role(&login_id.to_login_id(), role)
            .await
    }

    /// 清除用户的所有角色
    pub async fn clear_roles(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::get_manager()
            .clear_roles(&login_id.to_login_id())
            .await
    }

    /// 获取用户的所有角色
    /// 存储异常时返回空列表，保持原有 API 语义
    pub async fn get_roles(login_id: impl LoginId) -> Vec<String> {
        Self::get_manager()
            .get_roles(&login_id.to_login_id())
            .await
            .unwrap_or_default()
    }

    /// 检查用户是否拥有指定角色（精确匹配）
    /// 存储读取失败时按"无角色"处理
    pub async fn has_role(
        login_id: impl LoginId,
        role: &str,
    ) -> bool {
        match Self::get_manager().get_roles(&login_id.to_login_id()).await {
            Ok(roles) => roles.iter().any(|r| r == role),
            Err(_) => false,
        }
    }

    /// 检查用户是否拥有所有指定角色（AND 逻辑）
    pub async fn has_all_roles(
        login_id: impl LoginId,
        roles: &[&str],
    ) -> bool {
        let login_id_str = login_id.to_login_id();
        for role in roles {
            if !Self::has_role(&login_id_str, role).await {
                return false;
            }
        }
        true
    }

    /// 检查用户是否拥有所有指定角色（别名，AND 逻辑）
    pub async fn has_roles_and(
        login_id: impl LoginId,
        roles: &[&str],
    ) -> bool {
        Self::has_all_roles(login_id, roles).await
    }

    /// 检查用户是否拥有任一指定角色（OR 逻辑）
    pub async fn has_any_role(
        login_id: impl LoginId,
        roles: &[&str],
    ) -> bool {
        let login_id_str = login_id.to_login_id();
        for role in roles {
            if Self::has_role(&login_id_str, role).await {
                return true;
            }
        }
        false
    }

    /// 检查用户是否拥有任一指定角色（别名，OR 逻辑）
    pub async fn has_roles_or(
        login_id: impl LoginId,
        roles: &[&str],
    ) -> bool {
        Self::has_any_role(login_id, roles).await
    }

    /// 检查角色，如果没有则抛出异常
    pub async fn check_role(
        login_id: impl LoginId,
        role: &str,
    ) -> SaTokenResult<()> {
        if !Self::has_role(login_id, role).await {
            return Err(SaTokenError::RoleDenied(role.to_string()));
        }
        Ok(())
    }
}

// ==================== 封禁（disable） ====================

impl StpUtil {
    /// 封禁账号（默认服务 login）
    pub async fn disable(login_id: impl LoginId, time: i64) -> SaTokenResult<()> {
        Self::get_manager()
            .disable(&login_id.to_login_id(), time)
            .await
    }

    /// 封禁账号指定服务与等级
    pub async fn disable_level(
        login_id: impl LoginId,
        service: &str,
        level: i32,
        time: i64,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .disable_level(&login_id.to_login_id(), service, level, time)
            .await
    }

    /// 校验封禁（默认服务 login、最低等级）
    pub async fn check_disable(login_id: impl LoginId) -> SaTokenResult<()> {
        Self::check_disable_level(login_id, crate::disable::DEFAULT_DISABLE_SERVICE, crate::disable::MIN_DISABLE_LEVEL).await
    }

    /// 校验指定服务的封禁
    pub async fn check_disable_service(
        login_id: impl LoginId,
        service: &str,
    ) -> SaTokenResult<()> {
        Self::check_disable_level(login_id, service, crate::disable::MIN_DISABLE_LEVEL).await
    }

    /// 校验多个服务的封禁
    pub async fn check_disable_services(
        login_id: impl LoginId,
        services: &[&str],
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .check_disable_services(
                &login_id.to_login_id(),
                services,
                crate::disable::MIN_DISABLE_LEVEL,
            )
            .await
    }

    /// 校验封禁等级
    pub async fn check_disable_level(
        login_id: impl LoginId,
        service: &str,
        level: i32,
    ) -> SaTokenResult<()> {
        Self::get_manager()
            .check_disable_level(&login_id.to_login_id(), service, level)
            .await
    }

    /// 解封
    pub async fn untie_disable(login_id: impl LoginId, service: &str) -> SaTokenResult<()> {
        Self::get_manager()
            .untie_disable(&login_id.to_login_id(), service)
            .await
    }
}

// ==================== 二级认证（safe） ====================

impl StpUtil {
    /// 为当前 token 开启二级认证
    pub async fn open_safe(service: &str, safe_time: i64) -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        Self::get_manager().open_safe(&token, service, safe_time).await
    }

    /// 当前 token 是否已通过二级认证
    pub async fn is_safe(service: &str) -> SaTokenResult<bool> {
        let token = Self::get_token_value()?;
        Self::get_manager().is_safe(&token, service).await
    }

    /// 校验当前 token 的二级认证
    pub async fn check_safe(service: &str) -> SaTokenResult<()> {
        Self::check_login_current()?;
        let token = Self::get_token_value()?;
        Self::get_manager().check_safe(&token, service).await
    }

    /// 关闭当前 token 的二级认证
    pub async fn close_safe(service: &str) -> SaTokenResult<()> {
        let token = Self::get_token_value()?;
        Self::get_manager().close_safe(&token, service).await
    }
}

// ==================== 身份临时切换 ====================

impl StpUtil {
    /// 临时切换为指定 login_id（写入请求上下文）
    pub fn switch_to(login_id: impl LoginId) {
        let mut ctx = SaTokenContext::get_current().unwrap_or_default();
        ctx.switch_login_id = Some(login_id.to_login_id());
        SaTokenContext::set_current(ctx);
    }

    /// 结束临时身份切换
    pub fn end_switch() {
        if let Some(mut ctx) = SaTokenContext::get_current() {
            ctx.switch_login_id = None;
            SaTokenContext::set_current(ctx);
        }
    }

    /// 是否处于临时身份切换中
    pub fn is_switch() -> bool {
        SaTokenContext::get_current()
            .and_then(|c| c.switch_login_id)
            .is_some()
    }

    /// 获取临时切换的 login_id
    pub fn get_switch_login_id() -> Option<String> {
        SaTokenContext::get_current().and_then(|c| c.switch_login_id)
    }
}

// ==================== 扩展工具方法 ====================

impl StpUtil {
    /// 批量踢人下线
    pub async fn kick_out_batch<T: LoginId>(
        login_ids: &[T],
    ) -> SaTokenResult<Vec<Result<(), SaTokenError>>> {
        let manager = Self::get_manager();
        let mut results = Vec::new();
        for login_id in login_ids {
            results.push(manager.kick_out(&login_id.to_login_id()).await);
        }
        Ok(results)
    }

    /// 获取 token 剩余有效时间（秒）
    pub async fn get_token_timeout(token: &TokenValue) -> SaTokenResult<Option<i64>> {
        let manager = Self::get_manager();
        let token_info = manager.get_token_info(token).await?;

        if let Some(expire_time) = token_info.expire_time {
            let now = chrono::Utc::now();
            let duration = expire_time.signed_duration_since(now);
            Ok(Some(duration.num_seconds()))
        } else {
            Ok(None) // 永久有效
        }
    }

    /// 续期 token（重置过期时间）
    pub async fn renew_timeout(
        token: &TokenValue,
        timeout_seconds: i64,
    ) -> SaTokenResult<()> {
        let manager = Self::get_manager();
        let mut token_info = manager.get_token_info(token).await?;

        // 设置新的过期时间
        let new_expire_time = chrono::Utc::now() + chrono::Duration::seconds(timeout_seconds);
        token_info.expire_time = Some(new_expire_time);

        // 保存更新后的 token 信息
        let key = manager.config.make_key("token:", token.as_str());
        let value = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;

        let timeout = std::time::Duration::from_secs(timeout_seconds as u64);
        manager.storage.set(&key, &value, Some(timeout)).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok(())
    }

    // ==================== 额外数据操作 | Extra Data Operations ====================

    /// 设置 Token 的额外数据 | Set extra data for token
    ///
    /// # 参数 | Arguments
    /// * `token` - Token值 | Token value
    /// * `extra_data` - 额外数据 | Extra data
    pub async fn set_extra_data(
        token: &TokenValue,
        extra_data: serde_json::Value,
    ) -> SaTokenResult<()> {
        let manager = Self::get_manager();
        let mut token_info = manager.get_token_info(token).await?;
        token_info.extra_data = Some(extra_data);

        let key = manager.config.make_key("token:", token.as_str());
        let value = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;

        manager.storage.set(&key, &value, manager.config.timeout_duration()).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// 获取 Token 的额外数据 | Get extra data from token
    ///
    /// # 参数 | Arguments
    /// * `token` - Token值 | Token value
    pub async fn get_extra_data(token: &TokenValue) -> SaTokenResult<Option<serde_json::Value>> {
        let manager = Self::get_manager();
        let token_info = manager.get_token_info(token).await?;
        Ok(token_info.extra_data)
    }

    // ==================== 终端信息 ====================

    pub async fn get_terminal_list(
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<crate::session::SaTerminalInfo>> {
        Self::get_manager()
            .get_terminal_list("default", login_id, device_type)
            .await
    }

    pub async fn get_token_value_list_by_login_id(
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<String>> {
        Self::get_manager()
            .get_token_value_list_by_login_id("default", login_id, device_type)
            .await
    }

    pub async fn get_terminal_info_by_token(
        token: &TokenValue,
    ) -> SaTokenResult<Option<crate::session::SaTerminalInfo>> {
        Self::get_manager()
            .get_terminal_info_by_token(token)
            .await
    }

    // ==================== 多账号体系 ====================

    pub fn stp_logic(login_type: &str) -> Arc<crate::stp_logic::SaLogic> {
        crate::stp_logic::get_or_create_stp_logic(login_type, Self::get_manager().clone())
    }

    pub fn put_stp_logic(logic: Arc<crate::stp_logic::SaLogic>) {
        crate::stp_logic::put_stp_logic(logic);
    }

    pub fn remove_stp_logic(login_type: &str) {
        crate::stp_logic::remove_stp_logic(login_type);
    }

    // ==================== 链式调用 | Chain Call ====================

    /// 创建 Token 构建器，用于链式调用 | Create token builder for chain calls
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// use serde_json::json;
    ///
    /// // 链式调用示例
    /// let token = StpUtil::builder("user_123")
    ///     .extra_data(json!({"ip": "192.168.1.1"}))
    ///     .device("pc")
    ///     .login_type("admin")
    ///     .login()
    ///     .await?;
    /// ```
    pub fn builder(login_id: impl LoginId) -> TokenBuilder {
        TokenBuilder::new(login_id.to_login_id())
    }
}

/// Token 构建器 - 支持链式调用 | Token Builder - Supports chain calls
pub struct TokenBuilder {
    login_id: String,
    extra_data: Option<serde_json::Value>,
    device: Option<String>,
    login_type: Option<String>,
}

impl TokenBuilder {
    /// 创建新的 Token 构建器 | Create new token builder
    pub fn new(login_id: String) -> Self {
        Self {
            login_id,
            extra_data: None,
            device: None,
            login_type: None,
        }
    }

    /// 设置额外数据 | Set extra data
    pub fn extra_data(mut self, data: serde_json::Value) -> Self {
        self.extra_data = Some(data);
        self
    }

    /// 设置设备信息 | Set device info
    pub fn device(mut self, device: impl Into<String>) -> Self {
        self.device = Some(device.into());
        self
    }

    /// 设置登录类型 | Set login type
    pub fn login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = Some(login_type.into());
        self
    }

    /// 执行登录操作 | Execute login
    ///
    /// 如果不提供 login_id 参数，则使用构建器中的 login_id
    pub async fn login<T: LoginId>(self, login_id: Option<T>) -> SaTokenResult<TokenValue> {
        let manager = StpUtil::get_manager();

        // 登录获取 token，使用传入的 login_id 或构建器中的 login_id
        let final_login_id = match login_id {
            Some(id) => id.to_login_id(),
            None => self.login_id,
        };
        let token = manager.login(final_login_id).await?;

        // 获取 token 信息并修改
        let mut token_info = manager.get_token_info(&token).await?;

        // 设置额外属性
        if let Some(data) = self.extra_data {
            token_info.extra_data = Some(data);
        }

        if let Some(device) = self.device {
            token_info.device = Some(device);
        }

        if let Some(login_type) = self.login_type {
            token_info.login_type = login_type;
        }

        // 保存更新后的 token 信息
        let key = manager.config.make_key("token:", token.as_str());
        let value = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;

        manager.storage.set(&key, &value, manager.config.timeout_duration()).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_format_validation() {
        assert!(StpUtil::is_valid_token_format("1234567890abcdef"));
        assert!(!StpUtil::is_valid_token_format(""));
        assert!(!StpUtil::is_valid_token_format("short"));
    }

    #[test]
    fn test_create_token() {
        let token = StpUtil::create_token("test-token-123");
        assert_eq!(token.as_str(), "test-token-123");
    }
}

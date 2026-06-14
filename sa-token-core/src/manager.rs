// Author: 金书记
//
//! Token 管理器 - sa-token 的核心入口

use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use sa_token_adapter::storage::SaStorage;
use crate::config::{LogoutMode, ReplacedLoginExitMode, SaTokenConfig};
use crate::error::{SaTokenError, SaTokenResult};
use crate::token::{TokenInfo, TokenValue, TokenGenerator};
use crate::token::map::{
    TOKEN_MAP_BE_REPLACED, TOKEN_MAP_KICK_OUT, is_kick_out_marker, is_replaced_marker,
};
use crate::session::SaSession;
use crate::event::{SaTokenEventBus, SaTokenEvent};
use crate::online::OnlineManager;
use crate::distributed::DistributedSessionManager;
use crate::nonce::NonceManager;
use crate::refresh::RefreshTokenManager;
use crate::stp_interface::StpInterface;

/// sa-token 管理器
#[derive(Clone)]
pub struct SaTokenManager {
    /// 底层存储适配器
    pub(crate) storage: Arc<dyn SaStorage>,
    /// 配置信息
    pub config: SaTokenConfig,
    /// 事件总线
    pub(crate) event_bus: SaTokenEventBus,
    /// 在线用户管理器
    online_manager: Option<Arc<OnlineManager>>,
    /// 分布式 Session 管理器
    distributed_manager: Option<Arc<DistributedSessionManager>>,
    /// 权限/角色/封禁数据源回调
    pub(crate) stp_interface: Option<Arc<dyn StpInterface>>,
}

impl SaTokenManager {
    /// 创建新的管理器实例
    pub fn new(storage: Arc<dyn SaStorage>, config: SaTokenConfig) -> Self {
        Self {
            storage,
            config,
            event_bus: SaTokenEventBus::new(),
            online_manager: None,
            distributed_manager: None,
            stp_interface: None,
        }
    }

    pub fn with_stp_interface(mut self, iface: Arc<dyn StpInterface>) -> Self {
        self.stp_interface = Some(iface);
        self
    }
    
    pub fn with_online_manager(mut self, manager: Arc<OnlineManager>) -> Self {
        self.online_manager = Some(manager);
        self
    }
    
    pub fn with_distributed_manager(mut self, manager: Arc<DistributedSessionManager>) -> Self {
        self.distributed_manager = Some(manager);
        self
    }
    
    pub fn online_manager(&self) -> Option<&Arc<OnlineManager>> {
        self.online_manager.as_ref()
    }
    
    pub fn distributed_manager(&self) -> Option<&Arc<DistributedSessionManager>> {
        self.distributed_manager.as_ref()
    }
    
    /// 获取事件总线的引用
    pub fn event_bus(&self) -> &SaTokenEventBus {
        &self.event_bus
    }
    
    /// 登录：为指定账号创建 token
    pub async fn login(&self, login_id: impl Into<String>) -> SaTokenResult<TokenValue> {
        self.login_with_options(login_id, None, None, None, None, None).await
    }
    
    /// 登录：为指定账号创建 token（支持自定义 TokenInfo 字段）
    /// 
    /// # 参数 | Parameters
    /// * `login_id` - 登录用户 ID | Login user ID
    /// * `login_type` - 登录类型（如 "user", "admin"）| Login type (e.g., "user", "admin")
    /// * `device` - 设备标识 | Device identifier
    /// * `extra_data` - 额外数据 | Extra data
    /// * `nonce` - 防重放攻击的一次性令牌 | One-time token for replay attack prevention
    /// * `expire_time` - 自定义过期时间（如果为 None，则使用配置的过期时间）| Custom expiration time (if None, use configured timeout)
    /// 
    /// # 示例 | Example
    /// ```rust,ignore
    /// let token = manager.login_with_options(
    ///     "user_123",
    ///     Some("admin".to_string()),
    ///     Some("iPhone".to_string()),
    ///     Some(json!({"ip": "192.168.1.1"})),
    ///     Some("nonce_123".to_string()),
    ///     None,
    /// ).await?;
    /// ```
    pub async fn login_with_options(
        &self,
        login_id: impl Into<String>,
        login_type: Option<String>,
        device: Option<String>,
        extra_data: Option<serde_json::Value>,
        nonce: Option<String>,
        expire_time: Option<DateTime<Utc>>,
    ) -> SaTokenResult<TokenValue> {
        let login_id = login_id.into();
        
        // 生成 token（支持 JWT，如果有 extra_data 则签入 token）
        let token = match &extra_data {
            Some(extra) => TokenGenerator::generate_with_login_id_and_extra(&self.config, &login_id, extra),
            None => TokenGenerator::generate_with_login_id(&self.config, &login_id),
        };
        
        // 创建 token 信息
        let mut token_info = TokenInfo::new(token.clone(), login_id.clone());
        
        // 设置登录类型
        token_info.login_type = login_type.unwrap_or_else(|| "default".to_string());
        
        // 设置设备标识
        if let Some(device_str) = device {
            token_info.device = Some(device_str);
        }
        
        // 设置额外数据
        if let Some(extra) = extra_data {
            token_info.extra_data = Some(extra);
        }
        
        // 设置 nonce
        if let Some(nonce_str) = nonce {
            token_info.nonce = Some(nonce_str);
        }
        
        // 设置过期时间
        if let Some(custom_expire_time) = expire_time {
            token_info.expire_time = Some(custom_expire_time);
        }
        // 注意：如果 expire_time 为 None，login_with_token_info 会自动使用配置的过期时间
        
        // 调用底层方法
        self.login_with_token_info(token_info).await
    }
    
    /// 登录：使用完整的 TokenInfo 对象创建 token
    /// 
    /// # 参数 | Parameters
    /// * `token_info` - 完整的 TokenInfo 对象，包含所有 token 信息 | Complete TokenInfo object containing all token information
    /// 
    /// # 说明 | Notes
    /// * TokenInfo 中的 `token` 字段将被使用（如果已设置），否则会自动生成
    /// * TokenInfo 中的 `login_id` 字段必须设置
    /// * 如果 `expire_time` 为 None，将使用配置的过期时间
    /// * The `token` field in TokenInfo will be used (if set), otherwise will be auto-generated
    /// * The `login_id` field in TokenInfo must be set
    /// * If `expire_time` is None, will use configured timeout
    /// 
    /// # 示例 | Example
    /// ```rust,ignore
    /// use sa_token_core::token::{TokenInfo, TokenValue};
    /// use chrono::Utc;
    /// 
    /// let mut token_info = TokenInfo::new(
    ///     TokenValue::new("custom_token_123"),
    ///     "user_123"
    /// );
    /// token_info.login_type = "admin".to_string();
    /// token_info.device = Some("iPhone".to_string());
    /// token_info.extra_data = Some(json!({"ip": "192.168.1.1"}));
    /// 
    /// let token = manager.login_with_token_info(token_info).await?;
    /// ```
    pub async fn login_with_token_info(&self, mut token_info: TokenInfo) -> SaTokenResult<TokenValue> {
        let login_id = token_info.login_id.clone();
        
        // 如果 token_info 中没有 token，则生成一个
        let token = if token_info.token.as_str().is_empty() {
            TokenGenerator::generate_with_login_id(&self.config, &login_id)
        } else {
            token_info.token.clone()
        };
        
        // 更新 token_info 中的 token
        token_info.token = token.clone();
        
        // 更新最后活跃时间为当前时间
        token_info.update_active_time();
        
        // 如果过期时间为 None，使用配置的过期时间
        let now = Utc::now();
        if token_info.expire_time.is_none()
            && let Some(timeout) = self.config.timeout_duration() {
                token_info.expire_time = Some(now + Duration::from_std(timeout).unwrap());
            }
        
        // 确保登录类型不为空
        if token_info.login_type.is_empty() {
            token_info.login_type = "default".to_string();
        }
        
        // 计算 login_id -> token 映射键（非并发踢旧与写入映射均依赖此键）
        let login_token_key = self.login_token_mapping_key(&login_id, &token_info.login_type);

        // is_share：同 login_id + login_type 复用已有 token
        if self.config.is_share {
            if let Ok(Some(existing)) = self.storage.get(&login_token_key).await {
                let existing_token = TokenValue::new(existing);
                if self.is_valid(&existing_token).await {
                    return Ok(existing_token);
                }
            }
        }

        // 启用 nonce 时：登录前校验并消费一次性 nonce，防止重放
        if self.config.enable_nonce
            && let Some(ref nonce_str) = token_info.nonce {
                let nonce_timeout = if self.config.nonce_timeout > 0 {
                    self.config.nonce_timeout
                } else {
                    self.config.timeout
                };
                let nonce_mgr = NonceManager::new(self.storage.clone(), nonce_timeout);
                nonce_mgr.validate_and_consume(nonce_str, &login_id).await?;
            }

        // 非并发登录：顶旧 token（replaced）或拒绝新登录
        if !self.config.is_concurrent
            && let Ok(Some(old_token)) = self.storage.get(&login_token_key).await
            && old_token != token.as_str() {
                match self.config.replaced_login_exit_mode {
                    ReplacedLoginExitMode::OldDevice => {
                        self.replaced_by_token(&TokenValue::new(old_token)).await?;
                    }
                    ReplacedLoginExitMode::NewDevice => {
                        return Err(SaTokenError::AccountReplaced);
                    }
                }
            }

        // 启用 Refresh Token 时预生成并写入 TokenInfo
        let refresh_mgr = if self.config.enable_refresh_token {
            Some(RefreshTokenManager::new(
                self.storage.clone(),
                Arc::new(self.config.clone()),
            ))
        } else {
            None
        };
        if let Some(ref mgr) = refresh_mgr {
            let rt = mgr.generate(&login_id);
            token_info.refresh_token = Some(rt);
            if self.config.refresh_token_timeout > 0 {
                token_info.refresh_token_expire_time = Some(
                    Utc::now() + Duration::seconds(self.config.refresh_token_timeout),
                );
            }
        }
        
        // 存储 token 信息
        let key = self.config.make_key("token:", token.as_str());
        let value = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;
        
        self.storage.set(&key, &value, self.config.timeout_duration()).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        // 保存 login_id 到 token 的映射
        self.storage.set(&login_token_key, token.as_str(), self.config.timeout_duration()).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        // token -> login_id 反向映射（kickout/replaced 标记依赖此键）
        self.save_token_id_mapping(token.as_str(), &login_id).await?;

        let account_ns = self.account_ns(&token_info.login_type, &login_id);

        // 维护多设备 token 列表（并发场景下 get_all_tokens_by_login_id 依赖此索引）
        self.append_token_index(&account_ns, token.as_str()).await?;

        // 在 Account-Session 上记录本次登录的终端信息
        {
            let mut session = self.get_session(&account_ns).await?;
            let mut terminal = crate::session::SaTerminalInfo::new(
                token.as_str(),
                token_info.device.as_deref().unwrap_or(""),
            );
            if let Some(extra) = token_info.extra_data.clone() {
                terminal = terminal.with_extra_data(extra);
            }
            session.add_terminal(terminal);
            self.save_session(&session).await?;
        }

        self.enforce_max_login_count(&account_ns).await?;

        if self.config.right_now_create_token_session {
            let session = SaSession::new(format!("token-session:{}", token.as_str()));
            let _ = self.save_token_session(&token, &session).await;
        }

        // 持久化 refresh token 与 access token 的关联
        if let Some(ref mgr) = refresh_mgr
            && let Some(ref rt) = token_info.refresh_token {
                mgr.store_with_extra(
                    rt,
                    token.as_str(),
                    &login_id,
                    token_info.extra_data.as_ref(),
                )
                .await?;
            }
        
        // 触发登录事件
        let event = SaTokenEvent::login(login_id.clone(), token.as_str())
            .with_login_type(&token_info.login_type);
        self.event_bus.publish(event).await;
        
        Ok(token)
    }
    
    /// 登出：删除指定 token（LOGOUT 模式）
    pub async fn logout(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.logout_internal(token, LogoutMode::Logout, self.config.is_logout_keep_token_session)
            .await
    }

    /// 踢人下线（KICKOUT 模式：保留映射标记 -5）
    pub async fn kick_out_by_token(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.logout_internal(token, LogoutMode::KickOut, self.config.is_logout_keep_token_session)
            .await
    }

    /// 顶号下线（REPLACED 模式：保留映射标记 -4）
    pub async fn replaced_by_token(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.logout_internal(token, LogoutMode::Replaced, self.config.is_logout_keep_token_session)
            .await
    }

    async fn logout_internal(
        &self,
        token: &TokenValue,
        mode: LogoutMode,
        keep_token_session: bool,
    ) -> SaTokenResult<()> {
        tracing::debug!("Manager: logout_internal mode={:?}, token={}", mode, token);

        let key = self.config.make_key("token:", token.as_str());
        let token_info_str = self
            .storage
            .get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        let token_info = token_info_str
            .as_ref()
            .and_then(|value| serde_json::from_str::<TokenInfo>(value).ok());

        let login_id = if let Some(ref info) = token_info {
            Some(info.login_id.clone())
        } else if let Ok(Some(mapped)) = self.get_token_id_mapping(token.as_str()).await {
            if is_kick_out_marker(&mapped) || is_replaced_marker(&mapped) {
                None
            } else {
                Some(mapped)
            }
        } else {
            None
        };

        if mode == LogoutMode::Logout {
            self.storage
                .delete(&key)
                .await
                .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
            self.delete_token_id_mapping(token.as_str()).await?;
        } else if mode == LogoutMode::KickOut {
            self.update_token_id_mapping(token.as_str(), TOKEN_MAP_KICK_OUT)
                .await?;
        } else {
            self.update_token_id_mapping(token.as_str(), TOKEN_MAP_BE_REPLACED)
                .await?;
        }

        if !keep_token_session {
            let _ = self.delete_token_session(token).await;
        }

        if let Some(info) = token_info {
            let account_ns = self.account_ns(&info.login_type, &info.login_id);

            if let Ok(mut session) = self.get_session(&account_ns).await {
                if session.remove_terminal(token.as_str()).is_some() {
                    if session.terminal_count() == 0 && mode != LogoutMode::Replaced {
                        let _ = self.delete_session(&account_ns).await;
                    } else {
                        let _ = self.save_session(&session).await;
                    }
                }
            }

            let login_token_key =
                self.login_token_mapping_key(&info.login_id, &info.login_type);
            if mode == LogoutMode::Logout {
                if let Ok(Some(mapped)) = self.storage.get(&login_token_key).await
                    && mapped == token.as_str() {
                        let _ = self.storage.delete(&login_token_key).await;
                    }
                let _ = self.remove_token_index(&account_ns, token.as_str()).await;
            }

            if let Some(online_mgr) = &self.online_manager {
                online_mgr.mark_offline(&info.login_id, token.as_str()).await;
            }

            let event = match mode {
                LogoutMode::Logout => {
                    SaTokenEvent::logout(&info.login_id, token.as_str())
                        .with_login_type(&info.login_type)
                }
                LogoutMode::KickOut => {
                    SaTokenEvent::kick_out(&info.login_id, token.as_str())
                        .with_login_type(&info.login_type)
                }
                LogoutMode::Replaced => {
                    SaTokenEvent::replaced(&info.login_id, token.as_str())
                        .with_login_type(&info.login_type)
                }
            };
            self.event_bus.publish(event).await;
        } else if let Some(id) = login_id {
            let event = match mode {
                LogoutMode::Logout => SaTokenEvent::logout(&id, token.as_str()),
                LogoutMode::KickOut => SaTokenEvent::kick_out(&id, token.as_str()),
                LogoutMode::Replaced => SaTokenEvent::replaced(&id, token.as_str()),
            };
            self.event_bus.publish(event).await;
        }

        Ok(())
    }
    
    /// 根据登录 ID 登出所有 token
    pub async fn logout_by_login_id(&self, login_id: &str) -> SaTokenResult<()> {
        // 优先使用多设备索引精确登出，避免依赖 keys 全表扫描
        let idx_key = self.config.make_key("login:tokens:", login_id);
        let tokens = self.load_string_list(&idx_key).await.unwrap_or_default();
        if !tokens.is_empty() {
            for t in tokens {
                let _ = self.logout(&TokenValue::new(t)).await;
            }
            return Ok(());
        }

        // 回退：全量扫描 token 键（依赖 storage.keys，Redis 需实现 keys）
        let token_prefix = format!("{}token:", self.config.key_prefix());
        
        if let Ok(keys) = self.storage.keys(&format!("{}*", token_prefix)).await {
            for key in keys {
                if let Ok(Some(token_info_str)) = self.storage.get(&key).await {
                    if let Ok(token_info) = serde_json::from_str::<TokenInfo>(&token_info_str) {
                        let ti_ns = self.account_ns(&token_info.login_type, &token_info.login_id);
                        if ti_ns == login_id {
                            let token_str = key[token_prefix.len()..].to_string();
                            let _ = self.logout(&TokenValue::new(token_str)).await;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// 获取 token 信息
    pub async fn get_token_info(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        if let Some(mapped) = self.get_token_id_mapping(token.as_str()).await? {
            if is_kick_out_marker(&mapped) {
                return Err(SaTokenError::AccountKickedOut);
            }
            if is_replaced_marker(&mapped) {
                return Err(SaTokenError::AccountReplaced);
            }
        }

        let key = self.config.make_key("token:", token.as_str());
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::TokenNotFound)?;
        
        let token_info: TokenInfo = serde_json::from_str(&value)
            .map_err(SaTokenError::SerializationError)?;
        
        // 检查是否过期
        if token_info.is_expired() {
            self.logout(token).await?;
            return Err(SaTokenError::TokenExpired);
        }

        // 活跃超时冻结：超过 active_timeout 未活跃则拒绝（对齐 Java checkActiveTimeout）
        if token_info.is_freeze(self.config.active_timeout) {
            return Err(SaTokenError::TokenInactive);
        }
        
        // 自动续签：刷新 last_active_time 并延长 token TTL（对齐 Java updateLastActiveToNow + autoRenew）
        if self.config.auto_renew {
            let renew_timeout = if self.config.active_timeout > 0 {
                self.config.active_timeout
            } else {
                self.config.timeout
            };

            let mut renewed = token_info.clone();
            renewed.update_active_time();
            if renew_timeout > 0 {
                renewed.expire_time =
                    Some(Utc::now() + Duration::seconds(renew_timeout));
            }

            let key = self.config.make_key("token:", token.as_str());
            if let Ok(value) = serde_json::to_string(&renewed) {
                let storage_ttl = if renew_timeout > 0 {
                    Some(std::time::Duration::from_secs(renew_timeout as u64))
                } else {
                    self.config.timeout_duration()
                };
                let _ = self.storage.set(&key, &value, storage_ttl).await;
            }
            return Ok(renewed);
        }
        
        Ok(token_info)
    }
    
    /// 检查 token 是否有效
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.get_token_info(token).await.is_ok()
    }
    
    /// 获取 session
    pub async fn get_session(&self, login_id: &str) -> SaTokenResult<SaSession> {
        let key = self.config.make_key("session:", login_id);
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        if let Some(value) = value {
            let session: SaSession = serde_json::from_str(&value)
                .map_err(SaTokenError::SerializationError)?;
            Ok(session)
        } else {
            Ok(SaSession::new(login_id))
        }
    }
    
    /// 保存 session
    pub async fn save_session(&self, session: &SaSession) -> SaTokenResult<()> {
        let key = self.config.make_key("session:", &session.id);
        let value = serde_json::to_string(session)
            .map_err(SaTokenError::SerializationError)?;
        
        self.storage.set(&key, &value, None).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        Ok(())
    }
    
    /// 删除 session
    pub async fn delete_session(&self, login_id: &str) -> SaTokenResult<()> {
        let key = self.config.make_key("session:", login_id);
        self.storage.delete(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        Ok(())
    }
    
    /// 续期 token（重置过期时间）
    pub async fn renew_timeout(
        &self,
        token: &TokenValue,
        timeout_seconds: i64,
    ) -> SaTokenResult<()> {
        let token_info = self.get_token_info(token).await?;
        self.renew_timeout_internal(token, timeout_seconds, &token_info).await
    }
    
    /// 内部续期方法（避免递归调用 get_token_info）
    async fn renew_timeout_internal(
        &self,
        token: &TokenValue,
        timeout_seconds: i64,
        token_info: &TokenInfo,
    ) -> SaTokenResult<()> {
        let mut new_token_info = token_info.clone();
        
        // 设置新的过期时间
        use chrono::{Utc, Duration};
        let new_expire_time = Utc::now() + Duration::seconds(timeout_seconds);
        new_token_info.expire_time = Some(new_expire_time);
        
        // 保存更新后的 token 信息
        let key = self.config.make_key("token:", token.as_str());
        let value = serde_json::to_string(&new_token_info)
            .map_err(SaTokenError::SerializationError)?;
        
        let timeout = std::time::Duration::from_secs(timeout_seconds as u64);
        self.storage.set(&key, &value, Some(timeout)).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        Ok(())
    }
    
    /// 踢人下线（按 login_id，对该账号所有 token 执行 KICKOUT）
    pub async fn kick_out(&self, login_id: &str) -> SaTokenResult<()> {
        if let Some(online_mgr) = &self.online_manager {
            let _ = online_mgr
                .kick_out_notify(login_id, "Account kicked out".to_string())
                .await;
        }

        let idx_key = self.config.make_key("login:tokens:", login_id);
        let tokens = self.load_string_list(&idx_key).await.unwrap_or_default();
        if !tokens.is_empty() {
            for t in tokens {
                self.kick_out_by_token(&TokenValue::new(t)).await?;
            }
        } else if let Ok(Some(token_str)) = self
            .storage
            .get(&self.config.make_key("login:token:", login_id))
            .await
        {
            self.kick_out_by_token(&TokenValue::new(token_str)).await?;
        }

        self.delete_session(login_id).await?;
        Ok(())
    }

    fn token_id_mapping_key(&self, token: &str) -> String {
        self.config.make_key("token-id:", token)
    }

    async fn save_token_id_mapping(&self, token: &str, login_id: &str) -> SaTokenResult<()> {
        self.storage
            .set(
                &self.token_id_mapping_key(token),
                login_id,
                self.config.timeout_duration(),
            )
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    async fn update_token_id_mapping(&self, token: &str, value: &str) -> SaTokenResult<()> {
        self.storage
            .set(&self.token_id_mapping_key(token), value, None)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    async fn delete_token_id_mapping(&self, token: &str) -> SaTokenResult<()> {
        self.storage
            .delete(&self.token_id_mapping_key(token))
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    async fn get_token_id_mapping(&self, token: &str) -> SaTokenResult<Option<String>> {
        self.storage
            .get(&self.token_id_mapping_key(token))
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    async fn enforce_max_login_count(&self, login_id: &str) -> SaTokenResult<()> {
        if self.config.max_login_count <= 0 || !self.config.is_concurrent {
            return Ok(());
        }
        let idx_key = self.config.make_key("login:tokens:", login_id);
        loop {
            let list = self.load_string_list(&idx_key).await?;
            if list.len() as i64 <= self.config.max_login_count {
                break;
            }
            let Some(oldest) = list.first().cloned() else {
                break;
            };
            let mut trimmed = list;
            trimmed.remove(0);
            self.save_string_list(&idx_key, &trimmed).await?;
            let token = TokenValue::new(oldest);
            match self.config.overflow_logout_mode {
                LogoutMode::Logout => self.logout(&token).await?,
                LogoutMode::KickOut => self.kick_out_by_token(&token).await?,
                LogoutMode::Replaced => self.replaced_by_token(&token).await?,
            }
        }
        Ok(())
    }

    /// 账号命名空间：将 (login_type, login_id) 转为存储键的 id 段。
    ///
    /// - default/""/"login" → 返回 login_id 本身（兼容历史键）
    /// - 其它 → 返回 "{login_type}:{login_id}"（多账号隔离）
    pub(crate) fn account_ns(&self, login_type: &str, login_id: &str) -> String {
        if login_type.is_empty() || login_type == "default" || login_type == "login" {
            login_id.to_string()
        } else {
            format!("{}:{}", login_type, login_id)
        }
    }

    /// 构造 login_id -> token 映射键（区分 default 与带 login_type 的键）
    fn login_token_mapping_key(&self, login_id: &str, login_type: &str) -> String {
        let ns = self.account_ns(login_type, login_id);
        self.config.make_key("login:token:", &ns)
    }

    /// 获取指定账号已登录设备终端列表
    pub async fn get_terminal_list(
        &self,
        login_type: &str,
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<crate::session::SaTerminalInfo>> {
        let ns = self.account_ns(login_type, login_id);
        let session = self.get_session(&ns).await?;
        Ok(session.get_terminal_list_by_device_type(device_type))
    }

    /// 获取指定账号的 token 列表（来自终端列表）
    pub async fn get_token_value_list_by_login_id(
        &self,
        login_type: &str,
        login_id: &str,
        device_type: Option<&str>,
    ) -> SaTokenResult<Vec<String>> {
        let ns = self.account_ns(login_type, login_id);
        let session = self.get_session(&ns).await?;
        Ok(session.get_token_value_list_by_device_type(device_type))
    }

    /// 按 token 反查终端信息
    pub async fn get_terminal_info_by_token(
        &self,
        token: &TokenValue,
    ) -> SaTokenResult<Option<crate::session::SaTerminalInfo>> {
        let info = match self.get_token_info(token).await {
            Ok(i) => i,
            Err(_) => return Ok(None),
        };
        let ns = self.account_ns(&info.login_type, &info.login_id);
        let session = self.get_session(&ns).await?;
        Ok(session.get_terminal(token.as_str()).cloned())
    }

    /// 追加 token 到多设备列表 login:tokens:{login_id}（去重）
    async fn append_token_index(&self, login_id: &str, token: &str) -> SaTokenResult<()> {
        let key = self.config.make_key("login:tokens:", login_id);
        let mut list = self.load_string_list(&key).await?;
        if !list.iter().any(|t| t == token) {
            list.push(token.to_string());
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// 从多设备列表移除某个 token（logout 时调用）
    async fn remove_token_index(&self, login_id: &str, token: &str) -> SaTokenResult<()> {
        let key = self.config.make_key("login:tokens:", login_id);
        let mut list = self.load_string_list(&key).await?;
        let before = list.len();
        list.retain(|t| t != token);
        if list.len() != before {
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }
}

// ==================== 权限 / 角色持久化（基于 SaStorage） ====================

impl SaTokenManager {
    /// 构造权限存储键：{prefix}permission:{login_id}
    fn permission_key(&self, login_id: &str) -> String {
        self.config.make_key("permission:", login_id)
    }

    /// 构造角色存储键：{prefix}role:{login_id}
    fn role_key(&self, login_id: &str) -> String {
        self.config.make_key("role:", login_id)
    }

    fn permission_key_ns(&self, login_type: &str, login_id: &str) -> String {
        let ns = self.account_ns(login_type, login_id);
        self.config.make_key("permission:", &ns)
    }

    fn role_key_ns(&self, login_type: &str, login_id: &str) -> String {
        let ns = self.account_ns(login_type, login_id);
        self.config.make_key("role:", &ns)
    }

    pub async fn get_permissions_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        if let Some(iface) = &self.stp_interface {
            return iface.get_permission_list(login_id, login_type).await;
        }
        self.load_string_list(&self.permission_key_ns(login_type, login_id))
            .await
    }

    pub async fn set_permissions_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        permissions: Vec<String>,
    ) -> SaTokenResult<()> {
        self.save_string_list(
            &self.permission_key_ns(login_type, login_id),
            &permissions,
        )
        .await
    }

    pub async fn get_roles_with_type(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        if let Some(iface) = &self.stp_interface {
            return iface.get_role_list(login_id, login_type).await;
        }
        self.load_string_list(&self.role_key_ns(login_type, login_id))
            .await
    }

    pub async fn set_roles_with_type(
        &self,
        login_type: &str,
        login_id: &str,
        roles: Vec<String>,
    ) -> SaTokenResult<()> {
        self.save_string_list(&self.role_key_ns(login_type, login_id), &roles)
            .await
    }

    /// 将字符串列表序列化为 JSON 并写入存储
    /// 权限/角色无过期需求，TTL 固定使用 None（永久保存）
    async fn save_string_list(&self, key: &str, list: &[String]) -> SaTokenResult<()> {
        let value = serde_json::to_string(list).map_err(SaTokenError::SerializationError)?;
        self.storage
            .set(key, &value, None)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 从存储读取字符串列表
    /// 键不存在时返回空 Vec（视为该用户无任何权限/角色）
    async fn load_string_list(&self, key: &str) -> SaTokenResult<Vec<String>> {
        match self
            .storage
            .get(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
        {
            Some(value) => serde_json::from_str(&value).map_err(SaTokenError::SerializationError),
            None => Ok(Vec::new()),
        }
    }

    /// 覆盖设置用户权限列表
    /// 会完全替换该用户的所有权限
    pub async fn set_permissions(&self, login_id: &str, permissions: Vec<String>) -> SaTokenResult<()> {
        self.save_string_list(&self.permission_key(login_id), &permissions).await
    }

    /// 获取用户全部权限列表
    /// 用户不存在或无权限时返回空列表
    pub async fn get_permissions(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        if let Some(iface) = &self.stp_interface {
            return iface.get_permission_list(login_id, "default").await;
        }
        self.load_string_list(&self.permission_key(login_id)).await
    }

    /// 追加单个权限（已存在则跳过，避免重复）
    /// 采用读-改-写模式，分布式高并发下存在竞态风险
    pub async fn add_permission(&self, login_id: &str, permission: String) -> SaTokenResult<()> {
        let key = self.permission_key(login_id);
        let mut list = self.load_string_list(&key).await?;
        if !list.contains(&permission) {
            list.push(permission);
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// 移除用户的某个权限
    /// 不存在时无操作，仅在确实删除了元素时才回写存储
    pub async fn remove_permission(&self, login_id: &str, permission: &str) -> SaTokenResult<()> {
        let key = self.permission_key(login_id);
        let mut list = self.load_string_list(&key).await?;
        let before = list.len();
        list.retain(|p| p != permission);
        if list.len() != before {
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// 清除用户的全部权限
    /// 直接删除对应存储键
    pub async fn clear_permissions(&self, login_id: &str) -> SaTokenResult<()> {
        self.storage
            .delete(&self.permission_key(login_id))
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 覆盖设置用户角色列表
    /// 会完全替换该用户的所有角色
    pub async fn set_roles(&self, login_id: &str, roles: Vec<String>) -> SaTokenResult<()> {
        self.save_string_list(&self.role_key(login_id), &roles).await
    }

    /// 获取用户全部角色列表
    /// 用户不存在或无角色时返回空列表
    pub async fn get_roles(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        if let Some(iface) = &self.stp_interface {
            return iface.get_role_list(login_id, "default").await;
        }
        self.load_string_list(&self.role_key(login_id)).await
    }

    /// 追加单个角色（已存在则跳过，避免重复）
    /// 采用读-改-写模式，分布式高并发下存在竞态风险
    pub async fn add_role(&self, login_id: &str, role: String) -> SaTokenResult<()> {
        let key = self.role_key(login_id);
        let mut list = self.load_string_list(&key).await?;
        if !list.contains(&role) {
            list.push(role);
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// 移除用户的某个角色
    /// 不存在时无操作，仅在确实删除了元素时才回写存储
    pub async fn remove_role(&self, login_id: &str, role: &str) -> SaTokenResult<()> {
        let key = self.role_key(login_id);
        let mut list = self.load_string_list(&key).await?;
        let before = list.len();
        list.retain(|r| r != role);
        if list.len() != before {
            self.save_string_list(&key, &list).await?;
        }
        Ok(())
    }

    /// 清除用户的全部角色
    /// 直接删除对应存储键
    pub async fn clear_roles(&self, login_id: &str) -> SaTokenResult<()> {
        self.storage
            .delete(&self.role_key(login_id))
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;
    use crate::config::{LogoutMode, TokenStyle};

    fn make_manager(is_concurrent: bool, auto_renew: bool, active_timeout: i64) -> SaTokenManager {
        let config = SaTokenConfig {
            timeout: 3600,
            token_style: TokenStyle::Uuid,
            is_concurrent,
            auto_renew,
            active_timeout,
            ..Default::default()
        };
        SaTokenManager::new(Arc::new(MemoryStorage::new()), config)
    }

    #[tokio::test]
    async fn test_non_concurrent_login_invalidates_previous_token() {
        let mgr = make_manager(false, false, -1);
        let t1 = mgr.login("user_1").await.unwrap();
        assert!(mgr.is_valid(&t1).await);
        let t2 = mgr.login("user_1").await.unwrap();
        assert!(!mgr.is_valid(&t1).await);
        assert!(mgr.is_valid(&t2).await);
    }

    #[tokio::test]
    async fn test_logout_clears_login_token_mapping() {
        let mgr = make_manager(true, false, -1);
        let token = mgr.login("user_1").await.unwrap();
        let map_key = mgr.config.make_key("login:token:", "user_1");
        assert!(mgr.storage.get(&map_key).await.unwrap().is_some());
        mgr.logout(&token).await.unwrap();
        assert!(mgr.storage.get(&map_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_concurrent_login_appends_token_index() {
        let mgr = make_manager(true, false, -1);
        let t1 = mgr.login("user_1").await.unwrap();
        let t2 = mgr.login("user_1").await.unwrap();
        let idx_key = mgr.config.make_key("login:tokens:", "user_1");
        let list: Vec<String> = serde_json::from_str(
            &mgr.storage.get(&idx_key).await.unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&t1.as_str().to_string()));
        assert!(list.contains(&t2.as_str().to_string()));
    }

    #[tokio::test]
    async fn test_active_timeout_freeze_returns_inactive() {
        let mgr = make_manager(true, false, 1);
        let token = mgr.login("user_1").await.unwrap();
        let key = mgr.config.make_key("token:", token.as_str());
        let mut info = mgr.get_token_info(&token).await.unwrap();
        info.last_active_time = Utc::now() - Duration::seconds(10);
        mgr.storage
            .set(
                &key,
                &serde_json::to_string(&info).unwrap(),
                mgr.config.timeout_duration(),
            )
            .await
            .unwrap();
        let result = mgr.get_token_info(&token).await;
        assert!(matches!(result, Err(SaTokenError::TokenInactive)));
    }

    #[tokio::test]
    async fn test_auto_renew_updates_last_active_time() {
        let mgr = make_manager(true, true, 3600);
        let token = mgr.login("user_1").await.unwrap();
        let before = mgr.get_token_info(&token).await.unwrap().last_active_time;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let after = mgr.get_token_info(&token).await.unwrap().last_active_time;
        assert!(after >= before);
    }

    #[tokio::test]
    async fn test_login_with_nonce_when_enabled() {
        let config = SaTokenConfig {
            enable_nonce: true,
            nonce_timeout: 60,
            auto_renew: false,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let nonce_mgr = crate::nonce::NonceManager::new(mgr.storage.clone(), 60);
        let nonce = nonce_mgr.generate();
        let token = mgr
            .login_with_options("user_1", None, None, None, Some(nonce.clone()), None)
            .await
            .unwrap();
        assert!(mgr.is_valid(&token).await);
        let result = mgr
            .login_with_options("user_1", None, None, None, Some(nonce), None)
            .await;
        assert!(matches!(result, Err(SaTokenError::NonceAlreadyUsed)));
    }

    #[tokio::test]
    async fn test_kickout_token_returns_kicked_out() {
        let mgr = make_manager(true, false, -1);
        let token = mgr.login("user_kick").await.unwrap();
        mgr.kick_out_by_token(&token).await.unwrap();
        let err = mgr.get_token_info(&token).await.unwrap_err();
        assert!(matches!(err, SaTokenError::AccountKickedOut));
    }

    #[tokio::test]
    async fn test_replaced_token_returns_replaced() {
        let mgr = make_manager(false, false, -1);
        let t1 = mgr.login("user_rep").await.unwrap();
        let _t2 = mgr.login("user_rep").await.unwrap();
        let err = mgr.get_token_info(&t1).await.unwrap_err();
        assert!(matches!(err, SaTokenError::AccountReplaced));
    }

    #[tokio::test]
    async fn test_is_share_reuses_token() {
        let config = SaTokenConfig {
            is_share: true,
            is_concurrent: true,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let t1 = mgr.login("user_share").await.unwrap();
        let t2 = mgr.login("user_share").await.unwrap();
        assert_eq!(t1.as_str(), t2.as_str());
    }

    #[tokio::test]
    async fn test_max_login_count_overflow_kickout() {
        let config = SaTokenConfig {
            is_concurrent: true,
            max_login_count: 2,
            overflow_logout_mode: LogoutMode::KickOut,
            ..Default::default()
        };
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), config);
        let t1 = mgr.login("user_max").await.unwrap();
        let _t2 = mgr.login("user_max").await.unwrap();
        let t3 = mgr.login("user_max").await.unwrap();
        assert!(matches!(
            mgr.get_token_info(&t1).await,
            Err(SaTokenError::AccountKickedOut)
        ));
        assert!(mgr.is_valid(&t3).await);
    }

    #[test]
    fn test_account_ns_default_unchanged() {
        let mgr = make_manager(true, false, -1);
        assert_eq!(mgr.account_ns("default", "u1"), "u1");
        assert_eq!(mgr.account_ns("login", "u1"), "u1");
        assert_eq!(mgr.account_ns("", "u1"), "u1");
        assert_eq!(mgr.account_ns("admin", "u1"), "admin:u1");
    }

    #[tokio::test]
    async fn test_login_writes_terminal_and_logout_removes() {
        let mgr = make_manager(true, false, -1);
        let token = mgr
            .login_with_options("u1", None, Some("PC".to_string()), None, None, None)
            .await
            .unwrap();
        let terminals = mgr.get_terminal_list("default", "u1", None).await.unwrap();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].token_value, token.as_str());
        assert_eq!(terminals[0].device_type, "PC");
        assert_eq!(terminals[0].index, 1);

        mgr.logout(&token).await.unwrap();
        let terminals = mgr.get_terminal_list("default", "u1", None).await.unwrap();
        assert!(terminals.is_empty());
    }

    #[tokio::test]
    async fn test_terminal_filter_by_device_type() {
        let mgr = make_manager(true, false, -1);
        mgr.login_with_options("u1", None, Some("PC".to_string()), None, None, None)
            .await
            .unwrap();
        mgr.login_with_options("u1", None, Some("APP".to_string()), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            mgr.get_terminal_list("default", "u1", Some("PC"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            mgr.get_token_value_list_by_login_id("default", "u1", None)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn test_permissions_isolated_by_login_type() {
        let mgr = make_manager(true, false, -1);
        mgr.set_permissions_with_type("admin", "u1", vec!["a:read".to_string()])
            .await
            .unwrap();
        mgr.set_permissions_with_type("user", "u1", vec!["u:read".to_string()])
            .await
            .unwrap();
        let admin_perms = mgr.get_permissions_with_type("admin", "u1").await.unwrap();
        let user_perms = mgr.get_permissions_with_type("user", "u1").await.unwrap();
        assert_eq!(admin_perms, vec!["a:read".to_string()]);
        assert_eq!(user_perms, vec!["u:read".to_string()]);
    }
}

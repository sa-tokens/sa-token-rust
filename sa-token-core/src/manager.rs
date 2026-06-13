// Author: 金书记
//
//! Token 管理器 - sa-token 的核心入口

use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use sa_token_adapter::storage::SaStorage;
use crate::config::SaTokenConfig;
use crate::error::{SaTokenError, SaTokenResult};
use crate::token::{TokenInfo, TokenValue, TokenGenerator};
use crate::session::SaSession;
use crate::event::{SaTokenEventBus, SaTokenEvent};
use crate::online::OnlineManager;
use crate::distributed::DistributedSessionManager;

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
        }
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
        
        // 存储 token 信息
        let key = self.config.make_key("token:", token.as_str());
        let value = serde_json::to_string(&token_info)
            .map_err(SaTokenError::SerializationError)?;
        
        self.storage.set(&key, &value, self.config.timeout_duration()).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        // 保存 login_id 到 token 的映射（用于根据 login_id 查找 token）
        // 如果 login_type 不为空，使用包含 login_type 的 key 格式避免冲突
        // If login_type is not empty, use key format with login_type to avoid conflicts
        let login_token_key = if !token_info.login_type.is_empty() && token_info.login_type != "default" {
            self.config.make_key("login:token:", &format!("{}:{}", login_id, token_info.login_type))
        } else {
            self.config.make_key("login:token:", &login_id)
        };
        self.storage.set(&login_token_key, token.as_str(), self.config.timeout_duration()).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        // 如果不允许并发登录，踢掉之前的 token
        if !self.config.is_concurrent {
            self.logout_by_login_id(&login_id).await?;
        }
        
        // 触发登录事件
        let event = SaTokenEvent::login(login_id.clone(), token.as_str())
            .with_login_type(&token_info.login_type);
        self.event_bus.publish(event).await;
        
        Ok(token)
    }
    
    /// 登出：删除指定 token
    pub async fn logout(&self, token: &TokenValue) -> SaTokenResult<()> {
        tracing::debug!("Manager: 开始 logout，token: {}", token);
        
        // 先从存储获取 token 信息，用于触发事件（不调用 get_token_info 避免递归）
        let key = self.config.make_key("token:", token.as_str());
        tracing::debug!("Manager: 查询 token 信息，key: {}", key);
        
        let token_info_str = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        
        let token_info = if let Some(value) = token_info_str {
            tracing::debug!("Manager: 找到 token 信息: {}", value);
            serde_json::from_str::<TokenInfo>(&value).ok()
        } else {
            tracing::debug!("Manager: 未找到 token 信息");
            None
        };
        
        // 删除 token
        tracing::debug!("Manager: 删除 token，key: {}", key);
        self.storage.delete(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;
        tracing::debug!("Manager: token 已从存储中删除");
        
        // 触发登出事件
        if let Some(info) = token_info.clone() {
            tracing::debug!("Manager: 触发登出事件，login_id: {}, login_type: {}", info.login_id, info.login_type);
            let event = SaTokenEvent::logout(&info.login_id, token.as_str())
                .with_login_type(&info.login_type);
            self.event_bus.publish(event).await;
            
            // 如果有在线用户管理，通知用户下线
            if let Some(online_mgr) = &self.online_manager {
                tracing::debug!("Manager: 标记用户下线，login_id: {}", info.login_id);
                online_mgr.mark_offline(&info.login_id, token.as_str()).await;
            }
        }
        
        tracing::debug!("Manager: logout 完成，token: {}", token);
        Ok(())
    }
    
    /// 根据登录 ID 登出所有 token
    pub async fn logout_by_login_id(&self, login_id: &str) -> SaTokenResult<()> {
        // 获取所有 token 键的前缀
        let token_prefix = format!("{}token:", self.config.key_prefix());
        
        // 获取所有 token 键
        if let Ok(keys) = self.storage.keys(&format!("{}*", token_prefix)).await {
            // 遍历所有 token 键
            for key in keys {
                // 获取 token 值
                if let Ok(Some(token_info_str)) = self.storage.get(&key).await {
                    // 反序列化 token 信息
                    if let Ok(token_info) = serde_json::from_str::<TokenInfo>(&token_info_str) {
                        // 如果 login_id 匹配，则登出该 token
                        if token_info.login_id == login_id {
                            // 提取 token 字符串（从键中移除前缀）
                            let token_str = key[token_prefix.len()..].to_string();
                            let token = TokenValue::new(token_str);
                            
                            // 调用登出方法（logout 方法内部会处理删除映射和在线用户管理）
                            let _ = self.logout(&token).await;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// 获取 token 信息
    pub async fn get_token_info(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        let key = self.config.make_key("token:", token.as_str());
        let value = self.storage.get(&key).await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .ok_or(SaTokenError::TokenNotFound)?;
        
        let token_info: TokenInfo = serde_json::from_str(&value)
            .map_err(SaTokenError::SerializationError)?;
        
        // 检查是否过期
        if token_info.is_expired() {
            // 删除过期的 token
            self.logout(token).await?;
            return Err(SaTokenError::TokenExpired);
        }
        
        // 如果开启了自动续签，则自动续签
        // 注意：为了避免递归调用 get_token_info，这里直接更新过期时间
        if self.config.auto_renew {
            let renew_timeout = if self.config.active_timeout > 0 {
                self.config.active_timeout
            } else {
                self.config.timeout
            };
            
            // 直接续签（不递归调用 get_token_info）
            let _ = self.renew_timeout_internal(token, renew_timeout, &token_info).await;
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
    
    /// 踢人下线
    pub async fn kick_out(&self, login_id: &str) -> SaTokenResult<()> {
        let token_result = self.storage.get(&self.config.make_key("login:token:", login_id)).await;
        
        if let Some(online_mgr) = &self.online_manager {
            let _ = online_mgr.kick_out_notify(login_id, "Account kicked out".to_string()).await;
        }
        
        self.logout_by_login_id(login_id).await?;
        self.delete_session(login_id).await?;
        
        if let Ok(Some(token_str)) = token_result {
            let event = SaTokenEvent::kick_out(login_id, token_str);
            self.event_bus.publish(event).await;
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

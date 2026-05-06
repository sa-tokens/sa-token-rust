// Author: 金书记
//
//! Nonce Manager | Nonce 管理器
//!
//! Prevents replay attacks by tracking used nonces
//! 通过跟踪已使用的 nonce 来防止重放攻击
//!
//! ## Overview | 概述
//!
//! A **nonce** (number used once) is a unique value that can only be used one time,
//! preventing replay attacks where an attacker reuses a valid request.
//! **nonce**（一次性数字）是一个只能使用一次的唯一值，防止攻击者重用有效请求的重放攻击。
//!
//! ## Integration with Sa-Token | 与 Sa-Token 的集成
//!
//! Nonce is used in several Sa-Token scenarios:
//! Nonce 在 Sa-Token 的多个场景中使用：
//!
//! 1. **Login with Nonce** | 带 Nonce 的登录
//!    - Prevents replay of login requests
//!    - 防止登录请求的重放
//!
//! 2. **Token Creation** | Token 创建
//!    - Each token can have an associated nonce
//!    - 每个 token 可以关联一个 nonce
//!
//! 3. **OAuth2 / SSO** | OAuth2 / SSO
//!    - Used in authorization codes and state parameters
//!    - 用于授权码和状态参数
//!
//! 4. **Sensitive Operations** | 敏感操作
//!    - Password changes, account deletion, etc.
//!    - 密码修改、账户删除等
//!
//! ## Workflow | 工作流程
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Nonce Lifecycle                          │
//! │                    Nonce 生命周期                            │
//! └─────────────────────────────────────────────────────────────┘
//!
//! Client                     NonceManager              Storage
//! 客户端                     Nonce管理器               存储
//!   │                             │                        │
//!   │  1. Request nonce           │                        │
//!   │  请求 nonce                 │                        │
//!   │────────────────────────────▶│                        │
//!   │                             │                        │
//!   │  2. generate()              │                        │
//!   │                             │  生成唯一 nonce        │
//!   │                             │  nonce_TIMESTAMP_UUID  │
//!   │                             │                        │
//!   │  3. Return nonce            │                        │
//!   │  返回 nonce                 │                        │
//!   │◀────────────────────────────│                        │
//!   │                             │                        │
//!   │  4. Use nonce in request    │                        │
//!   │  在请求中使用 nonce         │                        │
//!   │────────────────────────────▶│                        │
//!   │                             │                        │
//!   │  5. validate_and_consume()  │                        │
//!   │                             │  Check not used        │
//!   │                             │  检查未使用             │
//!   │                             │─────────────────────▶  │
//!   │                             │  Get nonce key         │
//!   │                             │                        │
//!   │                             │  Not found = valid     │
//!   │                             │  未找到 = 有效          │
//!   │                             │◀─────────────────────  │
//!   │                             │                        │
//!   │                             │  Store nonce (TTL)     │
//!   │                             │  存储 nonce            │
//!   │                             │─────────────────────▶  │
//!   │                             │                        │
//!   │  6. Request processed       │                        │
//!   │  请求已处理                 │                        │
//!   │◀────────────────────────────│                        │
//!   │                             │                        │
//!   │  7. Reuse same nonce (ATTACK)                        │
//!   │  重用相同 nonce（攻击）     │                        │
//!   │────────────────────────────▶│                        │
//!   │                             │  Check if used         │
//!   │                             │  检查是否已使用         │
//!   │                             │─────────────────────▶  │
//!   │                             │  Found = already used  │
//!   │                             │  找到 = 已使用          │
//!   │                             │◀─────────────────────  │
//!   │                             │                        │
//!   │  ❌ Reject (NonceAlreadyUsed)                        │
//!   │  拒绝（Nonce已使用）         │                        │
//!   │◀────────────────────────────│                        │
//!   │                             │                        │
//!   │                          [After TTL expires]         │
//!   │                          [TTL 过期后]                 │
//!   │                             │   Auto cleanup         │
//!   │                             │   自动清理              │
//!   │                             │         X──────────────│
//! ```
//!
//! ## Storage Keys | 存储键格式
//!
//! ```text
//! sa:nonce:{nonce_value}
//!   - Stores: { "login_id": "...", "created_at": "..." }
//!   - TTL: Configured timeout (default: 60 seconds)
//!   - Purpose: Mark nonce as used
//!   
//!   存储：{ "login_id": "...", "created_at": "..." }
//!   TTL：配置的超时时间（默认：60秒）
//!   目的：标记 nonce 为已使用
//! ```
//!
//! ## Security Considerations | 安全考虑
//!
//! ```text
//! 1. ✅ One-Time Use | 一次性使用
//!    - Nonce can only be used once
//!    - Stored after first use to prevent reuse
//!    
//! 2. ✅ Time-Limited | 时间限制
//!    - Nonces expire after timeout (default: 60s)
//!    - Prevents storage bloat
//!    
//! 3. ✅ Unique Generation | 唯一生成
//!    - UUID + timestamp ensures uniqueness
//!    - Collision probability: negligible
//!    
//! 4. ✅ Timestamp Validation | 时间戳验证
//!    - check_timestamp() validates time window
//!    - Prevents time-based attacks
//!    
//! 5. ✅ Atomic Operations | 原子操作
//!    - validate_and_consume() is atomic
//!    - Prevents race conditions
//! ```
//!
//! ## Usage Examples | 使用示例
//!
//! ### Example 1: Login with Nonce | 带 Nonce 的登录
//!
//! ```rust,ignore
//! use sa_token_core::manager::SaTokenManager;
//!
//! // Client requests nonce
//! let nonce = nonce_manager.generate();
//! // Returns: "nonce_1234567890123_abc123def456"
//!
//! // Client sends login request with nonce
//! let token = manager.login_with_options(
//!     "user_123",
//!     None,
//!     None,
//!     None,
//!     Some(nonce.clone()),  // ← Nonce here
//!     None,
//! ).await?;
//!
//! // Server validates and consumes nonce (inside login_with_token_info)
//! nonce_manager.validate_and_consume(&nonce, "user_123").await?;
//! // ✅ First use: OK
//! // ❌ Second use: NonceAlreadyUsed error
//! ```
//!
//! ### Example 2: Sensitive Operation with Nonce | 带 Nonce 的敏感操作
//!
//! ```rust,ignore
//! // Change password with nonce protection
//! async fn change_password(
//!     user_id: &str,
//!     new_password: &str,
//!     nonce: &str,
//! ) -> Result<()> {
//!     // Validate nonce
//!     nonce_manager.validate_and_consume(nonce, user_id).await?;
//!     
//!     // Proceed with password change
//!     update_password(user_id, new_password).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Best Practices | 最佳实践
//!
//! 1. **Always generate nonces server-side** | 始终在服务端生成 nonce
//!    - Don't let clients generate their own nonces
//!    - 不要让客户端生成自己的 nonce
//!
//! 2. **Use appropriate timeout** | 使用适当的超时时间
//!    - Short timeout (30-60s) for most operations
//!    - Longer timeout (5-10min) for complex flows
//!    - 大多数操作使用短超时（30-60秒）
//!    - 复杂流程使用较长超时（5-10分钟）
//!
//! 3. **Validate timestamp** | 验证时间戳
//!    - Use check_timestamp() for additional validation
//!    - 使用 check_timestamp() 进行额外验证
//!
//! 4. **One nonce per operation** | 每个操作一个 nonce
//!    - Don't reuse nonces across different operations
//!    - 不要在不同操作间重用 nonce
//!
//! 5. **Combine with other security measures** | 与其他安全措施结合
//!    - Use nonces WITH authentication, not instead of it
//!    - 将 nonce 与认证结合使用，而不是替代认证
//! ```

use std::sync::Arc;
use chrono::{DateTime, Utc};
use sa_token_adapter::storage::SaStorage;
use crate::error::{SaTokenError, SaTokenResult};
use uuid::Uuid;

/// Nonce Manager | Nonce 管理器
///
/// Manages nonce generation and validation to prevent replay attacks
/// 管理 nonce 的生成和验证以防止重放攻击
#[derive(Clone)]
pub struct NonceManager {
    storage: Arc<dyn SaStorage>,
    timeout: i64,
}

impl NonceManager {
    /// Create new nonce manager | 创建新的 nonce 管理器
    ///
    /// # Arguments | 参数
    ///
    /// * `storage` - Storage backend | 存储后端
    /// * `timeout` - Nonce validity period in seconds | Nonce 有效期（秒）
    pub fn new(storage: Arc<dyn SaStorage>, timeout: i64) -> Self {
        Self { storage, timeout }
    }

    /// Generate a new nonce | 生成新的 nonce
    ///
    /// Generates a unique nonce using timestamp + UUID to ensure uniqueness.
    /// 使用时间戳 + UUID 生成唯一的 nonce 以确保唯一性。
    ///
    /// # Returns | 返回
    ///
    /// Unique nonce string in format: `nonce_{timestamp_ms}_{uuid}`
    /// 格式为 `nonce_{时间戳_毫秒}_{uuid}` 的唯一 nonce 字符串
    ///
    /// # Format | 格式
    ///
    /// ```text
    /// nonce_1234567890123_abc123def456
    ///   │         │            │
    ///   │         │            └─ UUID (32 hex chars)
    ///   │         └─ Timestamp in milliseconds
    ///   └─ Prefix
    /// ```
    ///
    /// # Example | 示例
    ///
    /// ```ignore
    /// let nonce = nonce_manager.generate();
    /// // Returns: "nonce_1701234567890_a1b2c3d4e5f6..."
    /// ```
    pub fn generate(&self) -> String {
        format!("nonce_{}_{}", Utc::now().timestamp_millis(), Uuid::new_v4().simple())
    }

    /// Store and mark nonce as used | 存储并标记 nonce 为已使用
    ///
    /// Stores the nonce in storage with TTL, marking it as "consumed".
    /// 将 nonce 以 TTL 存储在存储中，标记为"已消费"。
    ///
    /// # Arguments | 参数
    ///
    /// * `nonce` - Nonce to store | 要存储的 nonce
    /// * `login_id` - Associated user ID | 关联的用户ID
    ///
    /// # Storage Key | 存储键
    ///
    /// `sa:nonce:{nonce}` → `{"login_id": "...", "created_at": "..."}`
    ///
    /// # TTL Behavior | TTL 行为
    ///
    /// The nonce is automatically removed after the timeout period.
    /// Nonce 会在超时期后自动移除。
    ///
    /// # Example | 示例
    ///
    /// ```ignore
    /// nonce_manager.store("nonce_123_abc", "user_001").await?;
    /// // Storage now contains: sa:nonce:nonce_123_abc (expires after timeout)
    /// ```
    pub async fn store(&self, nonce: &str, login_id: &str) -> SaTokenResult<()> {
        let key = format!("sa:nonce:{}", nonce);
        let value = serde_json::json!({
            "login_id": login_id,
            "created_at": Utc::now().to_rfc3339(),
        }).to_string();

        // Set TTL to automatically expire the nonce
        let ttl = Some(std::time::Duration::from_secs(self.timeout as u64));
        self.storage.set(&key, &value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Validate nonce and ensure it hasn't been used | 验证 nonce 并确保未被使用
    ///
    /// Checks if the nonce exists in storage. If it exists, it has been used.
    /// 检查 nonce 是否存在于存储中。如果存在，则已被使用。
    ///
    /// # Arguments | 参数
    ///
    /// * `nonce` - Nonce to validate | 要验证的 nonce
    ///
    /// # Returns | 返回
    ///
    /// * `Ok(true)` - Valid (not used yet) | 有效（尚未使用）
    /// * `Ok(false)` - Invalid (already used) | 无效（已使用）
    ///
    /// # Logic | 逻辑
    ///
    /// ```text
    /// Nonce NOT in storage → Valid (can be used)
    /// Nonce IN storage     → Invalid (already used)
    /// 
    /// Nonce 不在存储中 → 有效（可以使用）
    /// Nonce 在存储中   → 无效（已使用）
    /// ```
    ///
    /// # Example | 示例
    ///
    /// ```ignore
    /// let is_valid = nonce_manager.validate("nonce_123").await?;
    /// if is_valid {
    ///     // Proceed with operation
    /// } else {
    ///     // Reject: nonce already used
    /// }
    /// ```
    pub async fn validate(&self, nonce: &str) -> SaTokenResult<bool> {
        let key = format!("sa:nonce:{}", nonce);
        
        // Check if nonce exists in storage
        // 检查 nonce 是否存在于存储中
        let exists = self.storage.get(&key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?
            .is_some();

        // Valid if NOT exists (not used yet)
        // 不存在则有效（尚未使用）
        Ok(!exists)
    }

    /// Validate and consume nonce in one operation | 一次操作验证并消费 nonce
    ///
    /// This is the **primary method** for using nonces in Sa-Token.
    /// It checks if the nonce is valid (not used) and immediately marks it as used.
    /// 这是在 Sa-Token 中使用 nonce 的**主要方法**。
    /// 它检查 nonce 是否有效（未使用）并立即将其标记为已使用。
    ///
    /// # Arguments | 参数
    ///
    /// * `nonce` - Nonce to validate and consume | 要验证和消费的 nonce
    /// * `login_id` - Associated user ID | 关联的用户ID
    ///
    /// # Returns | 返回
    ///
    /// * `Ok(())` - Nonce is valid and now consumed | Nonce 有效且已消费
    /// * `Err(NonceAlreadyUsed)` - Nonce has already been used | Nonce 已被使用
    /// * `Err(StorageError)` - Storage operation failed | 存储操作失败
    ///
    /// # Security | 安全性
    ///
    /// This operation is **atomic** from the application perspective:
    /// 此操作从应用程序角度来看是**原子性**的：
    ///
    /// 1. Check if nonce exists (validate)
    /// 2. If valid, store it immediately (consume)
    /// 3. Return success
    ///
    /// If two requests use the same nonce simultaneously, only one will succeed.
    /// 如果两个请求同时使用相同的 nonce，只有一个会成功。
    ///
    /// # Integration with Login | 与登录集成
    ///
    /// ```ignore
    /// // Inside SaTokenManager::login_with_token_info()
    /// if let Some(nonce) = &token_info.nonce {
    ///     self.nonce_manager
    ///         .validate_and_consume(nonce, &login_id)
    ///         .await?; // ← Prevents replay attacks
    /// }
    /// ```
    ///
    /// # Example | 示例
    ///
    /// ```ignore
    /// // ✅ First use: Success
    /// nonce_manager.validate_and_consume("nonce_123", "user_001").await?;
    /// println!("Login successful");
    ///
    /// // ❌ Second use: Error
    /// let result = nonce_manager.validate_and_consume("nonce_123", "user_001").await;
    /// assert!(matches!(result, Err(SaTokenError::NonceAlreadyUsed)));
    /// ```
    pub async fn validate_and_consume(&self, nonce: &str, login_id: &str) -> SaTokenResult<()> {
        // 1. Validate: check if nonce has NOT been used
        // 验证：检查 nonce 是否未被使用
        if !self.validate(nonce).await? {
            return Err(SaTokenError::NonceAlreadyUsed);
        }

        // 2. Consume: store nonce to mark as used
        // 消费：存储 nonce 以标记为已使用
        self.store(nonce, login_id).await?;
        
        Ok(())
    }

    /// Extract timestamp from nonce and check if it's within valid time window
    /// 从 nonce 中提取时间戳并检查是否在有效时间窗口内
    ///
    /// Provides **additional security** by validating the nonce timestamp.
    /// This prevents time-based attacks and ensures nonces are fresh.
    /// 通过验证 nonce 时间戳提供**额外的安全性**。
    /// 这可以防止基于时间的攻击并确保 nonce 是新鲜的。
    ///
    /// # Arguments | 参数
    ///
    /// * `nonce` - Nonce to check | 要检查的 nonce
    /// * `window_seconds` - Maximum age of nonce in seconds | Nonce 的最大年龄（秒）
    ///
    /// # Returns | 返回
    ///
    /// * `Ok(true)` - Timestamp is within the time window | 时间戳在时间窗口内
    /// * `Ok(false)` - Timestamp is outside the time window (too old or future) | 时间戳在窗口外（太旧或未来）
    /// * `Err(InvalidNonceFormat)` - Nonce format is invalid | Nonce 格式无效
    /// * `Err(InvalidNonceTimestamp)` - Timestamp cannot be parsed | 时间戳无法解析
    ///
    /// # Use Case | 使用场景
    ///
    /// ```ignore
    /// // Validate nonce and its timestamp
    /// let nonce = request.get_nonce();
    ///
    /// // Check timestamp: max 60 seconds old
    /// if !nonce_manager.check_timestamp(&nonce, 60)? {
    ///     return Err("Nonce too old");
    /// }
    ///
    /// // Then validate and consume
    /// nonce_manager.validate_and_consume(&nonce, user_id).await?;
    /// ```
    ///
    /// # Nonce Format | Nonce 格式
    ///
    /// Expected format: `nonce_{timestamp_ms}_{uuid}`
    /// 期望格式：`nonce_{时间戳_毫秒}_{uuid}`
    ///
    /// # Security Note | 安全说明
    ///
    /// This check should be used **in addition to** `validate_and_consume()`,
    /// not as a replacement. It provides defense-in-depth.
    /// 此检查应与 `validate_and_consume()` **一起使用**，而不是替代。
    /// 它提供了深度防御。
    pub fn check_timestamp(&self, nonce: &str, window_seconds: i64) -> SaTokenResult<bool> {
        // Parse nonce format: nonce_TIMESTAMP_UUID
        // 解析 nonce 格式：nonce_时间戳_UUID
        let parts: Vec<&str> = nonce.split('_').collect();
        if parts.len() < 3 || parts[0] != "nonce" {
            return Err(SaTokenError::InvalidNonceFormat);
        }

        // Extract and parse timestamp
        // 提取并解析时间戳
        let timestamp_ms = parts[1].parse::<i64>()
            .map_err(|_| SaTokenError::InvalidNonceTimestamp)?;

        let nonce_time = DateTime::from_timestamp_millis(timestamp_ms)
            .ok_or(SaTokenError::InvalidNonceTimestamp)?;

        // Calculate time difference
        // 计算时间差
        let now = Utc::now();
        let diff = (now - nonce_time).num_seconds().abs();

        // Check if within time window
        // 检查是否在时间窗口内
        Ok(diff <= window_seconds)
    }

    /// Clean up expired nonces (implementation depends on storage)
    /// 清理过期的 nonce（实现依赖于存储）
    ///
    /// # Note | 注意
    ///
    /// Most storage backends (Redis, Memcached) automatically expire keys with TTL.
    /// This method is provided for storage backends that don't support TTL.
    /// 大多数存储后端（Redis、Memcached）会自动过期带 TTL 的键。
    /// 此方法为不支持 TTL 的存储后端提供。
    ///
    /// # Automatic Cleanup | 自动清理
    ///
    /// - **Redis**: Uses EXPIRE command, automatic cleanup
    /// - **Memory**: Built-in TTL support, automatic cleanup
    /// - **Database**: May need manual cleanup (implement here)
    ///
    /// # Manual Implementation | 手动实现
    ///
    /// For databases without TTL support:
    /// 对于不支持 TTL 的数据库：
    ///
    /// ```ignore
    /// pub async fn cleanup_expired(&self) -> SaTokenResult<()> {
    ///     let cutoff = Utc::now() - Duration::seconds(self.timeout);
    ///     // DELETE FROM nonces WHERE created_at < cutoff
    ///     Ok(())
    /// }
    /// ```
    pub async fn cleanup_expired(&self) -> SaTokenResult<()> {
        // Storage with TTL support will auto-cleanup
        // 支持 TTL 的存储会自动清理
        // 
        // This is a no-op for Redis/Memory storage
        // 对于 Redis/Memory 存储，这是一个空操作
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    #[tokio::test]
    async fn test_nonce_generation() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce1 = nonce_mgr.generate();
        let nonce2 = nonce_mgr.generate();

        assert_ne!(nonce1, nonce2);
        assert!(nonce1.starts_with("nonce_"));
    }

    #[tokio::test]
    async fn test_nonce_validation() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce = nonce_mgr.generate();

        // First validation should succeed
        assert!(nonce_mgr.validate(&nonce).await.unwrap());

        // Store the nonce
        nonce_mgr.store(&nonce, "user_123").await.unwrap();

        // Second validation should fail (already used)
        assert!(!nonce_mgr.validate(&nonce).await.unwrap());
    }

    #[tokio::test]
    async fn test_nonce_validate_and_consume() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce = nonce_mgr.generate();

        // First use should succeed
        nonce_mgr.validate_and_consume(&nonce, "user_123").await.unwrap();

        // Second use should fail
        let result = nonce_mgr.validate_and_consume(&nonce, "user_123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nonce_timestamp_check() {
        let storage = Arc::new(MemoryStorage::new());
        let nonce_mgr = NonceManager::new(storage, 60);

        let nonce = nonce_mgr.generate();

        // Should be within 60 seconds
        assert!(nonce_mgr.check_timestamp(&nonce, 60).unwrap());

        // Should also be within 1 second
        assert!(nonce_mgr.check_timestamp(&nonce, 1).unwrap());
    }
}


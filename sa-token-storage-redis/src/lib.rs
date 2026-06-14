// Author: 金书记
//
//! # sa-token-storage-redis
//! 
//! Redis存储实现
//! 
//! 适用于：
//! - 分布式部署
//! - 需要数据持久化
//! - 高性能要求的场景
//! 
//! ## 使用方式
//! 
//! ### 方式 1: 使用 Redis URL
//! ```rust,ignore
//! use sa_token_storage_redis::RedisStorage;
//! 
//! // 无密码
//! let storage = RedisStorage::new("redis://localhost:6379/0", "sa-token:").await?;
//! 
//! // 有密码
//! let storage = RedisStorage::new("redis://:password@localhost:6379/0", "sa-token:").await?;
//! ```
//! 
//! ### 方式 2: 使用配置结构体
//! ```rust,ignore
//! use sa_token_storage_redis::{RedisStorage, RedisConfig};
//! 
//! let config = RedisConfig {
//!     host: "localhost".to_string(),
//!     port: 6379,
//!     password: Some("your-password".to_string()),
//!     database: 0,
//!     pool_size: 10,
//! };
//! 
//! let storage = RedisStorage::from_config(config, "sa-token:").await?;
//! ```

use std::time::Duration;
use async_trait::async_trait;
use redis::{Client, AsyncCommands, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use sa_token_adapter::storage::{SaStorage, StorageResult, StorageError};

/// Redis 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis 主机地址
    #[serde(default = "default_host")]
    pub host: String,
    
    /// Redis 端口
    #[serde(default = "default_port")]
    pub port: u16,
    
    /// Redis 密码（可选）
    #[serde(default)]
    pub password: Option<String>,
    
    /// 数据库编号
    #[serde(default)]
    pub database: u8,
    
    /// 连接池大小（暂未使用，保留用于未来扩展）
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            password: None,
            database: 0,
            pool_size: default_pool_size(),
        }
    }
}

impl RedisConfig {
    /// 转换为 Redis URL
    /// 
    /// 支持的格式：
    /// - `redis://localhost:6379/0` （无密码）
    /// - `redis://:password@localhost:6379/0` （有密码）
    pub fn to_url(&self) -> String {
        if let Some(password) = &self.password {
            format!("redis://:{}@{}:{}/{}", password, self.host, self.port, self.database)
        } else {
            format!("redis://{}:{}/{}", self.host, self.port, self.database)
        }
    }
}

fn default_host() -> String {
    "localhost".to_string()
}

fn default_port() -> u16 {
    6379
}

fn default_pool_size() -> u32 {
    10
}

/// Redis存储实现
#[derive(Clone)]
pub struct RedisStorage {
    client: ConnectionManager,
    key_prefix: String,
}

impl RedisStorage {
    /// 使用 Redis URL 创建存储
    /// 
    /// # 参数
    /// * `redis_url` - Redis 连接 URL
    /// * `key_prefix` - 键前缀（例如：`sa-token:`）
    /// 
    /// # URL 格式
    /// - 无密码：`redis://localhost:6379/0`
    /// - 有密码：`redis://:password@localhost:6379/0`
    /// - 复杂密码：`redis://:Aq23-hjPwFB3mBDNFp3W1@localhost:6379/0`
    /// 
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_storage_redis::RedisStorage;
    /// 
    /// // 无密码
    /// let storage = RedisStorage::new("redis://localhost:6379/0", "sa-token:").await?;
    /// 
    /// // 有密码
    /// let storage = RedisStorage::new(
    ///     "redis://:Aq23-hjPwFB3mBDNFp3W1@localhost:6379/0", 
    ///     "sa-token:"
    /// ).await?;
    /// ```
    pub async fn new(redis_url: &str, key_prefix: impl Into<String>) -> StorageResult<Self> {
        let client = Client::open(redis_url)
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
        
        let connection_manager = ConnectionManager::new(client).await
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
        
        Ok(Self {
            client: connection_manager,
            key_prefix: key_prefix.into(),
        })
    }
    
    /// 使用配置结构体创建存储
    /// 
    /// # 参数
    /// * `config` - Redis 配置
    /// * `key_prefix` - 键前缀（例如：`sa-token:`）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_storage_redis::{RedisStorage, RedisConfig};
    /// 
    /// let config = RedisConfig {
    ///     host: "localhost".to_string(),
    ///     port: 6379,
    ///     password: Some("Aq23-hjPwFB3mBDNFp3W1".to_string()),
    ///     database: 0,
    ///     pool_size: 10,
    /// };
    /// 
    /// let storage = RedisStorage::from_config(config, "sa-token:").await?;
    /// ```
    pub async fn from_config(config: RedisConfig, key_prefix: impl Into<String>) -> StorageResult<Self> {
        let redis_url = config.to_url();
        Self::new(&redis_url, key_prefix).await
    }
    
    /// 使用构建器模式创建存储
    /// 
    /// # 示例
    /// ```rust,ignore
    /// use sa_token_storage_redis::RedisStorage;
    /// 
    /// let storage = RedisStorage::builder()
    ///     .host("localhost")
    ///     .port(6379)
    ///     .password("Aq23-hjPwFB3mBDNFp3W1")
    ///     .database(0)
    ///     .key_prefix("sa-token:")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn builder() -> RedisStorageBuilder {
        RedisStorageBuilder::default()
    }
    
    /// 获取完整的键名（带前缀）
    fn full_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }
}

/// Redis 存储构建器
#[derive(Default)]
pub struct RedisStorageBuilder {
    config: RedisConfig,
    key_prefix: Option<String>,
}

impl RedisStorageBuilder {
    /// 设置 Redis 主机地址
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }
    
    /// 设置 Redis 端口
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }
    
    /// 设置 Redis 密码
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.config.password = Some(password.into());
        self
    }
    
    /// 设置数据库编号
    pub fn database(mut self, database: u8) -> Self {
        self.config.database = database;
        self
    }
    
    /// 设置连接池大小（保留用于未来扩展）
    pub fn pool_size(mut self, size: u32) -> Self {
        self.config.pool_size = size;
        self
    }
    
    /// 设置键前缀
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }
    
    /// 构建 RedisStorage
    /// 
    /// # Panics
    /// 如果未设置 key_prefix，会 panic
    pub async fn build(self) -> StorageResult<RedisStorage> {
        let key_prefix = self.key_prefix
            .expect("key_prefix must be set before building RedisStorage");
        
        RedisStorage::from_config(self.config, key_prefix).await
    }
}

#[async_trait]
impl SaStorage for RedisStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        conn.get(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        if let Some(ttl) = ttl {
            conn.set_ex(&full_key, value, ttl.as_secs()).await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))
        } else {
            conn.set(&full_key, value).await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))
        }
    }
    
    async fn delete(&self, key: &str) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        conn.del(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        conn.exists(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        conn.expire(&full_key, ttl.as_secs() as i64).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        let ttl_secs: i64 = conn.ttl(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        
        match ttl_secs {
            -2 => Ok(None), // 键不存在
            -1 => Ok(None), // 永不过期
            secs if secs > 0 => Ok(Some(Duration::from_secs(secs as u64))),
            _ => Ok(Some(Duration::from_secs(0))),
        }
    }
    
    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let mut conn = self.client.clone();
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();

        // redis 1.x 的 `get` 只接受 ToSingleRedisArg，批量取值需走 `mget`
        // redis 1.x's `get` only accepts ToSingleRedisArg; use `mget` for multi-key reads
        conn.mget(&full_keys).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_items: Vec<(String, &str)> = items.iter()
            .map(|(k, v)| (self.full_key(k), *v))
            .collect();
        
        // 使用 pipeline 批量操作
        let mut pipe = redis::pipe();
        for (key, value) in &full_items {
            if let Some(ttl) = ttl {
                pipe.set_ex(key, *value, ttl.as_secs());
            } else {
                pipe.set(key, *value);
            }
        }
        
        pipe.query_async(&mut conn).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();
        
        conn.del(&full_keys).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        conn.incr(&full_key, 1).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);
        
        conn.decr(&full_key, 1).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }
    
    async fn clear(&self) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let pattern = format!("{}*", self.key_prefix);
        
        // 获取所有匹配的键
        let keys: Vec<String> = conn.keys(&pattern).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        
        if !keys.is_empty() {
            conn.del::<_, ()>(&keys).await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        }
        
        Ok(())
    }

    /// 按模式列出逻辑键（Manager 传入如 `sa:token:*`，此处叠加物理前缀后匹配，返回时剥离前缀）
    async fn keys(&self, pattern: &str) -> StorageResult<Vec<String>> {
        let mut conn = self.client.clone();
        let full_pattern = self.full_key(pattern);
        let raw: Vec<String> = conn
            .keys(&full_pattern)
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        let prefix_len = self.key_prefix.len();
        Ok(raw
            .into_iter()
            .map(|k| k.get(prefix_len..).map(str::to_string).unwrap_or(k))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_logical_key_stripping_matches_manager_expectations() {
        let prefix = "phys:";
        let raw = vec![
            "phys:sa:token:a".to_string(),
            "phys:sa:token:b".to_string(),
        ];
        let n = prefix.len();
        let logical: Vec<String> = raw
            .into_iter()
            .map(|k| k.get(n..).map(str::to_string).unwrap_or(k))
            .collect();
        assert_eq!(logical, vec!["sa:token:a", "sa:token:b"]);
    }
}

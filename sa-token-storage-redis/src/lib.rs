// Author: 金书记
//
//! # sa-token-storage-redis
//!
//! Redis 存储：`pool_size` 个独立 `ConnectionManager` 轮询 + 命令级短暂重试。
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
//! // 无密码（默认建 10 个 ConnectionManager）
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

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use redis::{AsyncCommands, Client, aio::ConnectionManager};
use sa_token_adapter::storage::{SaStorage, ScanPage, StorageError, StorageResult};
use serde::{Deserialize, Serialize};

/// 命令失败时的最大尝试次数（含首次）
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// 两次尝试之间的间隔
const RETRY_INTERVAL: Duration = Duration::from_millis(10);

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

    /// 连接池大小：创建多少个独立的 ConnectionManager（至少 1）
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
            format!(
                "redis://:{}@{}:{}/{}",
                password, self.host, self.port, self.database
            )
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

/// Redis 存储：多 ConnectionManager 轮询池
#[derive(Clone)]
pub struct RedisStorage {
    /// 独立复用连接集合；clone RedisStorage 只增加 Arc 引用
    pool: Arc<Vec<ConnectionManager>>,
    /// 轮询游标
    next: Arc<AtomicUsize>,
    key_prefix: String,
    /// 单次命令最大尝试次数
    max_attempts: u32,
}

impl std::fmt::Debug for RedisStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorage")
            .field("pool_len", &self.pool.len())
            .field("key_prefix", &self.key_prefix)
            .field("max_attempts", &self.max_attempts)
            .finish_non_exhaustive()
    }
}

impl RedisStorage {
    /// 使用 Redis URL 创建存储（默认 pool_size=10）
    pub async fn new(redis_url: &str, key_prefix: impl Into<String>) -> StorageResult<Self> {
        Self::new_with_pool(redis_url, key_prefix, default_pool_size()).await
    }

    /// URL + 显式池大小
    pub async fn new_with_pool(
        redis_url: &str,
        key_prefix: impl Into<String>,
        pool_size: u32,
    ) -> StorageResult<Self> {
        let n = pool_connection_count(pool_size);
        let client =
            Client::open(redis_url).map_err(|e| StorageError::ConnectionError(e.to_string()))?;

        let mut managers = Vec::with_capacity(n);
        for _ in 0..n {
            // 每个 ConnectionManager 独立建连，分担并发鉴权压力
            let mgr = ConnectionManager::new(client.clone())
                .await
                .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
            managers.push(mgr);
        }

        Ok(Self {
            pool: Arc::new(managers),
            next: Arc::new(AtomicUsize::new(0)),
            key_prefix: key_prefix.into(),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        })
    }

    /// 使用配置结构体创建存储（**消费 pool_size**）
    pub async fn from_config(
        config: RedisConfig,
        key_prefix: impl Into<String>,
    ) -> StorageResult<Self> {
        Self::new_with_pool(&config.to_url(), key_prefix, config.pool_size).await
    }

    /// 使用构建器模式创建存储
    pub fn builder() -> RedisStorageBuilder {
        RedisStorageBuilder::default()
    }

    /// 测试/运维：当前池内 ConnectionManager 数量
    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    /// 获取完整的键名（带前缀）
    fn full_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }

    /// 列表键使用独立前缀，避免与字符串键类型冲突
    fn list_key(&self, key: &str) -> String {
        format!("{}list:{}", self.key_prefix, key)
    }

    /// 将物理键剥离为逻辑键；前缀不匹配时返回 `None`
    fn strip_prefix<'a>(&self, raw: &'a str) -> Option<&'a str> {
        raw.strip_prefix(&self.key_prefix)
    }

    /// 便捷构造：物理前缀默认为空（逻辑键由 SaKeys 提供）
    pub async fn connect(redis_url: &str) -> StorageResult<Self> {
        Self::new(redis_url, "").await
    }

    /// 轮询取出一个 ConnectionManager 句柄（clone 廉价）
    fn acquire(&self) -> ConnectionManager {
        let len = self.pool.len();
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % len;
        self.pool[idx].clone()
    }

    /// 对瞬时失败做有限次重试；每次重试换一条池内连接
    async fn with_retry<T, F, Fut>(&self, mut op: F) -> StorageResult<T>
    where
        F: FnMut(ConnectionManager) -> Fut,
        Fut: Future<Output = Result<T, redis::RedisError>>,
    {
        let mut last_err: Option<redis::RedisError> = None;
        for attempt in 0..self.max_attempts {
            let conn = self.acquire();
            match op(conn).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < self.max_attempts {
                        tokio::time::sleep(RETRY_INTERVAL).await;
                    }
                }
            }
        }
        Err(StorageError::OperationFailed(
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown redis error".to_string()),
        ))
    }
}

/// Redis 存储构建器
#[derive(Default)]
pub struct RedisStorageBuilder {
    config: RedisConfig,
    key_prefix: Option<String>,
}

impl std::fmt::Debug for RedisStorageBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStorageBuilder")
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
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

    /// 设置连接池大小（创建对应数量的 ConnectionManager）
    pub fn pool_size(mut self, size: u32) -> Self {
        self.config.pool_size = size;
        self
    }

    /// 设置键前缀
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }

    /// 构建 RedisStorage（未设置 `key_prefix` 时默认为空字符串）
    pub async fn build(self) -> StorageResult<RedisStorage> {
        let key_prefix = self.key_prefix.unwrap_or_default();
        RedisStorage::from_config(self.config, key_prefix).await
    }
}

#[async_trait]
impl SaStorage for RedisStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let full_key = self.full_key(key);
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { conn.get(fk).await }
        })
        .await
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let full_key = self.full_key(key);
        let value = value.to_string();
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            let val = value.clone();
            async move {
                if let Some(ttl) = ttl {
                    conn.set_ex(fk, val, ttl.as_secs()).await
                } else {
                    conn.set(fk, val).await
                }
            }
        })
        .await
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let full_key = self.full_key(key);
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { conn.del(fk).await }
        })
        .await
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let full_key = self.full_key(key);
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { conn.exists(fk).await }
        })
        .await
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let full_key = self.full_key(key);
        let secs = ttl.as_secs() as i64;
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { conn.expire(fk, secs).await }
        })
        .await
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let full_key = self.full_key(key);
        let ttl_secs: i64 = self
            .with_retry(|mut conn| {
                let fk = full_key.clone();
                async move { conn.ttl(fk).await }
            })
            .await?;

        match ttl_secs {
            -2 => Ok(None),
            -1 => Ok(None),
            secs if secs > 0 => Ok(Some(Duration::from_secs(secs as u64))),
            _ => Ok(Some(Duration::from_secs(0))),
        }
    }

    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();
        self.with_retry(|mut conn| {
            let fk = full_keys.clone();
            async move { conn.mget(fk).await }
        })
        .await
    }

    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        let full_items: Vec<(String, String)> = items
            .iter()
            .map(|(k, v)| (self.full_key(k), (*v).to_string()))
            .collect();
        self.with_retry(|mut conn| {
            let items = full_items.clone();
            async move {
                let mut pipe = redis::pipe();
                for (key, value) in &items {
                    if let Some(ttl) = ttl {
                        pipe.set_ex(key, value, ttl.as_secs());
                    } else {
                        pipe.set(key, value);
                    }
                }
                pipe.query_async(&mut conn).await
            }
        })
        .await
    }

    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();
        self.with_retry(|mut conn| {
            let fk = full_keys.clone();
            async move { conn.del(fk).await }
        })
        .await
    }

    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let full_key = self.full_key(key);
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { conn.incr(fk, 1).await }
        })
        .await
    }

    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let full_key = self.full_key(key);
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { conn.decr(fk, 1).await }
        })
        .await
    }

    async fn clear(&self) -> StorageResult<()> {
        let pattern = format!("{}*", self.key_prefix);
        let mut cursor: u64 = 0;

        loop {
            let (next, keys): (u64, Vec<String>) = self
                .with_retry(|mut conn| {
                    let p = pattern.clone();
                    async move {
                        redis::cmd("SCAN")
                            .arg(cursor)
                            .arg("MATCH")
                            .arg(&p)
                            .arg("COUNT")
                            .arg(100)
                            .query_async(&mut conn)
                            .await
                    }
                })
                .await?;

            if !keys.is_empty() {
                self.with_retry(|mut conn| {
                    let k = keys.clone();
                    async move { conn.del::<_, ()>(k).await }
                })
                .await?;
            }

            if next == 0 {
                break;
            }
            cursor = next;
        }

        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        let full_key = self.full_key(key);
        let value = value.to_string();
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            let val = value.clone();
            async move {
                if let Some(ttl) = ttl {
                    redis::cmd("SET")
                        .arg(&fk)
                        .arg(&val)
                        .arg("NX")
                        .arg("EX")
                        .arg(ttl.as_secs())
                        .query_async(&mut conn)
                        .await
                } else {
                    conn.set_nx(fk, val).await
                }
            }
        })
        .await
    }

    async fn get_del(&self, key: &str) -> StorageResult<Option<String>> {
        let full_key = self.full_key(key);
        self.with_retry(|mut conn| {
            let fk = full_key.clone();
            async move { redis::cmd("GETDEL").arg(&fk).query_async(&mut conn).await }
        })
        .await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> StorageResult<bool> {
        let full_key = self.full_key(key);
        let expected_str = expected.unwrap_or("").to_string();
        let new_value = new_value.to_string();
        let ttl_secs = ttl.map(|d| d.as_secs()).unwrap_or(0);

        // Lua 保证 GET + 比较 + SET 单键原子，避免 WATCH 竞态。
        let script = r#"
            local current = redis.call('GET', KEYS[1])
            if current == false then current = '' end
            if current ~= ARGV[1] then return 0 end
            if tonumber(ARGV[3]) > 0 then
                redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
            else
                redis.call('SET', KEYS[1], ARGV[2])
            end
            return 1
        "#;

        let swapped: i32 = self
            .with_retry(|mut conn| {
                let fk = full_key.clone();
                let exp = expected_str.clone();
                let nv = new_value.clone();
                async move {
                    redis::Script::new(script)
                        .key(&fk)
                        .arg(exp)
                        .arg(nv)
                        .arg(ttl_secs)
                        .invoke_async(&mut conn)
                        .await
                }
            })
            .await?;

        Ok(swapped == 1)
    }

    async fn compare_and_delete(&self, key: &str, expected: &str) -> StorageResult<bool> {
        let full_key = self.full_key(key);
        let expected = expected.to_string();

        let script = r#"
            local current = redis.call('GET', KEYS[1])
            if current == false then current = '' end
            if current ~= ARGV[1] then return 0 end
            redis.call('DEL', KEYS[1])
            return 1
        "#;

        let deleted: i32 = self
            .with_retry(|mut conn| {
                let fk = full_key.clone();
                let exp = expected.clone();
                async move {
                    redis::Script::new(script)
                        .key(&fk)
                        .arg(exp)
                        .invoke_async(&mut conn)
                        .await
                }
            })
            .await?;

        Ok(deleted == 1)
    }

    async fn list_push(
        &self,
        key: &str,
        member: &str,
        unique: bool,
        ttl: Option<Duration>,
    ) -> StorageResult<usize> {
        // Lua 原子去重：LRANGE + 判断 + RPUSH + EXPIRE 在同一脚本内完成
        let list_key = self.list_key(key);
        let member = member.to_string();
        let ttl_secs = ttl.map(|d| d.as_secs()).unwrap_or(0);
        let unique_flag = if unique { 1 } else { 0 };

        let script = r#"
            local list_key = KEYS[1]
            local member = ARGV[1]
            local unique = tonumber(ARGV[2])
            local ttl_secs = tonumber(ARGV[3])

            if unique == 1 then
                local items = redis.call('LRANGE', list_key, 0, -1)
                for i, v in ipairs(items) do
                    if v == member then
                        if ttl_secs > 0 then
                            redis.call('EXPIRE', list_key, ttl_secs)
                        end
                        return #items
                    end
                end
            end

            local len = redis.call('RPUSH', list_key, member)
            if ttl_secs > 0 then
                redis.call('EXPIRE', list_key, ttl_secs)
            end
            return len
        "#;

        self.with_retry(|mut conn| {
            let lk = list_key.clone();
            let m = member.clone();
            async move {
                redis::Script::new(script)
                    .key(&lk)
                    .arg(m)
                    .arg(unique_flag)
                    .arg(ttl_secs)
                    .invoke_async(&mut conn)
                    .await
            }
        })
        .await
    }

    async fn list_remove(&self, key: &str, member: &str) -> StorageResult<bool> {
        let list_key = self.list_key(key);
        let member = member.to_string();
        let removed: i64 = self
            .with_retry(|mut conn| {
                let lk = list_key.clone();
                let m = member.clone();
                async move { conn.lrem(lk, 0, m).await }
            })
            .await?;
        Ok(removed > 0)
    }

    async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> StorageResult<Vec<String>> {
        let list_key = self.list_key(key);
        let stop = match limit {
            Some(l) => {
                let end = start.saturating_add(l).saturating_sub(1);
                isize::try_from(end.min(isize::MAX as usize)).unwrap_or(isize::MAX)
            }
            None => -1,
        };

        self.with_retry(|mut conn| {
            let lk = list_key.clone();
            async move { conn.lrange(lk, start as isize, stop).await }
        })
        .await
    }

    async fn list_len(&self, key: &str) -> StorageResult<usize> {
        let list_key = self.list_key(key);
        let len: i64 = self
            .with_retry(|mut conn| {
                let lk = list_key.clone();
                async move { conn.llen(lk).await }
            })
            .await?;
        Ok(len.max(0) as usize)
    }

    async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> StorageResult<ScanPage> {
        let full_pattern = self.full_key(pattern);
        let count = limit.max(1);

        let (next, raw_keys): (u64, Vec<String>) = self
            .with_retry(|mut conn| {
                let p = full_pattern.clone();
                async move {
                    redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&p)
                        .arg("COUNT")
                        .arg(count)
                        .query_async(&mut conn)
                        .await
                }
            })
            .await?;

        let list_prefix = format!("{}list:", self.key_prefix);
        let keys: Vec<String> = raw_keys
            .into_iter()
            .filter(|k| !k.starts_with(&list_prefix))
            .filter_map(|k| self.strip_prefix(&k).map(str::to_string))
            .collect();

        Ok(ScanPage {
            keys,
            next_cursor: next,
        })
    }
}

/// `pool_size == 0` 按 1 条连接处理，避免空池。
fn pool_connection_count(pool_size: u32) -> usize {
    pool_size.max(1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_adapter::storage::SaStorage;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_logical_key_stripping_matches_manager_expectations() {
        let prefix = "phys:";
        let raw = vec!["phys:sa:token:a".to_string(), "phys:sa:token:b".to_string()];
        let n = prefix.len();
        let logical: Vec<String> = raw
            .into_iter()
            .map(|k| k.get(n..).map(str::to_string).unwrap_or(k))
            .collect();
        assert_eq!(logical, vec!["sa:token:a", "sa:token:b"]);
    }

    #[test]
    fn test_pool_size_max_one_when_zero() {
        assert_eq!(pool_connection_count(0), 1);
        assert_eq!(pool_connection_count(4), 4);
    }

    /// 真实 Redis：无 REDIS_URL 时 ignore；测 set/get/ttl/get_del。
    #[tokio::test]
    #[ignore = "requires REDIS_URL"]
    async fn test_redis_set_get_ttl_get_del() {
        let url = std::env::var("REDIS_URL").expect("REDIS_URL");
        let storage = RedisStorage::connect(&url).await.expect("connect");
        let storage: Arc<dyn SaStorage> = Arc::new(storage);
        let key = format!(
            "sa:test:gray:{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        );
        storage
            .set(&key, "v1", Some(Duration::from_secs(30)))
            .await
            .expect("set");
        assert_eq!(storage.get(&key).await.expect("get").as_deref(), Some("v1"));
        let ttl = storage.ttl(&key).await.expect("ttl");
        assert!(ttl.is_some());
        let secs = ttl.unwrap().as_secs();
        assert!(secs > 0 && secs <= 30);
        let taken = storage.get_del(&key).await.expect("get_del");
        assert_eq!(taken.as_deref(), Some("v1"));
        assert!(storage.get(&key).await.expect("gone").is_none());
    }

    // 需本机 Redis 时启用：验证 from_config 真正创建 N 个 manager
    #[tokio::test]
    #[ignore = "requires redis at localhost:6379"]
    async fn test_from_config_pool_len_matches_pool_size() {
        let config = RedisConfig {
            host: "127.0.0.1".to_string(),
            port: 6379,
            password: None,
            database: 0,
            pool_size: 4,
        };
        let storage = RedisStorage::from_config(config, "sa-test:")
            .await
            .expect("redis available");
        assert_eq!(storage.pool_len(), 4);

        storage
            .set("k1", "v1", Some(Duration::from_secs(30)))
            .await
            .unwrap();
        for _ in 0..8 {
            let v = storage.get("k1").await.unwrap();
            assert_eq!(v.as_deref(), Some("v1"));
        }
        storage.delete("k1").await.unwrap();
    }
}

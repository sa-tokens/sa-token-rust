# 分布式 Session 管理

## 中文

### 概述

分布式 Session 管理模块支持跨多个微服务共享 Session。它提供服务认证、跨服务 Session 访问和属性管理，并自动处理超时。

本模块专为微服务架构设计，允许多个服务无缝共享用户认证状态和会话数据。

### 架构

```text
┌────────────────────────────────────────────────────────────────────┐
│                   微服务架构                                       │
└────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  服务 A      │  │  服务 B      │  │  服务 C      │
    │  (用户 API)  │  │  (订单 API)  │  │  (支付 API)  │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                  │                  │
           └──────────────────┼──────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  分布式 Session     │
                    │  存储后端           │
                    │  (Redis/数据库)     │
                    └────────────────────┘

每个服务可以：
  - 为用户创建会话
  - 访问其他服务创建的会话
  - 共享用户认证状态
```

### 核心功能

- **跨服务 Session 共享** - 在微服务间共享 Session
- **服务认证** - 使用密钥验证服务凭证
- **Session 属性** - 存储自定义键值对用于用户上下文
- **多 Session 支持** - 一个用户可以有多个 Session（多设备）
- **自动清理** - 基于 TTL 的 Session 过期
- **可插拔存储** - 使用自定义存储后端（Redis、数据库、内存）
- **基于权限的访问** - 通过服务权限进行细粒度控制
- **会话监控** - 跟踪每个用户的所有活跃会话

### 快速开始

```rust
use sa_token_core::{
    DistributedSessionManager, InMemoryDistributedStorage, ServiceCredential
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建分布式 Session 管理器
    let storage = Arc::new(InMemoryDistributedStorage::new());
    let manager = DistributedSessionManager::new(
        storage,
        "service-main".to_string(),
        Duration::from_secs(3600), // 1 小时 TTL
    );
    
    // 注册服务
    let credential = ServiceCredential {
        service_id: "api-gateway".to_string(),
        service_name: "API Gateway".to_string(),
        secret_key: "secret123".to_string(),
        created_at: Utc::now(),
        permissions: vec!["read".to_string(), "write".to_string()],
    };
    manager.register_service(credential).await;
    
    // 验证服务
    let verified = manager.verify_service("api-gateway", "secret123").await?;
    
    // 创建 Session
    let session = manager.create_session(
        "user123".to_string(),
        "token456".to_string(),
    ).await?;
    
    // 设置 Session 属性
    manager.set_attribute(
        &session.session_id,
        "role".to_string(),
        "admin".to_string(),
    ).await?;
    
    Ok(())
}
```

### 服务认证流程

```text
服务 A                      管理器                     服务 B
   |                           |                           |
   |-- 注册服务 ------------->|                           |
   |<----- 已注册 ------------|                           |
   |                           |                           |
   |                           |<-- 验证服务(id, secret) --|
   |                           |--- 检查凭证 ------------->|
   |                           |<----- 已验证 ------------|
```

---


## 应用场景

### 1. 跨服务单点登录（SSO）
用户登录一次即可访问多个服务，无需重新认证：

```text
用户 → 服务 A：登录
  ├─ 创建 Session：session_id = "abc123"
  └─ 保存到分布式存储

用户 → 服务 B：携带 session_id = "abc123" 请求
  ├─ 服务 B 从存储中获取 Session
  ├─ 验证用户已认证
  └─ 处理请求 ✅（无需重新登录！）
```

### 2. 用户上下文 Session 共享
服务间共享用户上下文和状态：

```text
服务 A 存储：{ "user_role": "admin", "department": "IT" }
服务 B 读取：相同 Session 属性可用
服务 C 更新：{ "last_order": "order_123" }
→ 所有服务共享同一 Session 状态！
```

### 3. 多设备 Session 管理
同一用户可以有多个活跃 Session：

```text
用户：user_123
  ├─ Session 1：Web（服务 A）
  ├─ Session 2：Mobile（服务 B）
  └─ Session 3：Desktop（服务 C）

所有 Session 可以：
  - 列表查询：get_sessions_by_login_id()
  - 单独管理
  - 一键全部终止：delete_all_sessions()
```

### 4. 微服务架构
在 API 网关、用户服务、订单服务等之间共享用户 Session。

### 5. 多地域部署
使用共享存储在不同地理区域之间同步 Session。

### 6. 负载均衡
在多个服务器实例之间保持 Session 一致性。

## 存储后端

### Redis 实现（推荐）

```rust
use redis::AsyncCommands;

pub struct RedisDistributedStorage {
    client: redis::Client,
}

#[async_trait]
impl DistributedSessionStorage for RedisDistributedStorage {
    async fn save_session(&self, session: DistributedSession, ttl: Option<Duration>) 
        -> Result<(), SaTokenError> 
    {
        let mut conn = self.client.get_async_connection().await?;
        let key = format!("distributed:session:{}", session.session_id);
        let value = serde_json::to_string(&session)?;
        
        if let Some(ttl) = ttl {
            conn.set_ex(&key, value, ttl.as_secs() as usize).await?;
        } else {
            conn.set(&key, value).await?;
        }
        
        // 按 login_id 建立索引以便快速查找
        let index_key = format!("distributed:login:{}", session.login_id);
        conn.sadd(index_key, &session.session_id).await?;
        
        Ok(())
    }
    
    // ... 实现其他方法
}
```

### 数据库实现

```rust
use sqlx::PgPool;

pub struct PostgresDistributedStorage {
    pool: PgPool,
}

#[async_trait]
impl DistributedSessionStorage for PostgresDistributedStorage {
    async fn save_session(&self, session: DistributedSession, ttl: Option<Duration>) 
        -> Result<(), SaTokenError> 
    {
        let expires_at = ttl.map(|t| Utc::now() + chrono::Duration::from_std(t).unwrap());
        
        sqlx::query!(
            "INSERT INTO distributed_sessions 
             (session_id, login_id, token, service_id, attributes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (session_id) DO UPDATE 
             SET attributes = $5, last_access = NOW()",
            session.session_id,
            session.login_id,
            session.token,
            session.service_id,
            serde_json::to_value(&session.attributes)?,
            expires_at,
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    // ... 实现其他方法
}
```

## 最佳实践

### 1. 服务注册
使用加密安全的密钥生成服务凭证：

```rust
let credential = ServiceCredential {
    service_id: "user-service".to_string(),
    service_name: "用户管理服务".to_string(),
    secret_key: generate_secure_secret(), // 使用加密安全的方式生成
    created_at: Utc::now(),
    permissions: vec!["user.read".to_string(), "user.write".to_string()],
};
manager.register_service(credential).await;
```

### 2. 创建带上下文的 Session
创建 Session 后立即添加相关属性：

```rust
let session = manager.create_session(login_id, token).await?;

// 立即添加相关属性
manager.set_attribute(&session.session_id, "user_role".to_string(), "admin".to_string()).await?;
manager.set_attribute(&session.session_id, "department".to_string(), "IT".to_string()).await?;
manager.set_attribute(&session.session_id, "login_device".to_string(), "web".to_string()).await?;
```

### 3. 跨服务访问模式
始终验证服务身份并检查权限：

```rust
// 1. 验证服务身份
let service_cred = manager.verify_service("service-b", request.secret).await?;

// 2. 检查权限
if !service_cred.permissions.contains(&"session.read".to_string()) {
    return Err(SaTokenError::PermissionDenied);
}

// 3. 访问 Session
let session = manager.get_session(&request.session_id).await?;

// 4. 刷新以保持 Session 活跃
manager.refresh_session(&session.session_id).await?;
```

### 4. 多设备登出
支持单独和批量登出：

```rust
// 从所有设备登出
manager.delete_all_sessions(&login_id).await?;

// 或登出特定 Session
manager.delete_session(&session_id).await?;
```

### 5. Session 监控
监控用户的活跃 Session 以确保安全：

```rust
let sessions = manager.get_sessions_by_login_id(&login_id).await?;

for session in sessions {
    println!("Session: {} 来自服务: {}, 最后活跃: {}", 
        session.session_id,
        session.service_id,
        session.last_access
    );
    
    // 检查可疑活动
    if is_suspicious(&session) {
        manager.delete_session(&session.session_id).await?;
    }
}
```

### 6. 安全注意事项

- ✅ **服务认证**：每个服务有唯一的 secret_key
- ✅ **基于权限的访问**：服务有明确的权限
- ✅ **Session 超时**：配置适当的 TTL
- ✅ **数据加密**：加密敏感的 Session 属性
- ✅ **审计日志**：记录 Session 创建/删除和跨服务访问

### 7. 生产环境建议

1. **使用适当的 TTL** — 根据安全需求设置 Session 超时（通常 1-24 小时）
2. **使用持久化存储** — 生产环境使用 Redis/数据库存储（而非内存）
3. **保护服务凭证** — 使用强密钥并定期轮换
4. **监控 Session 数量** — 跟踪每个用户的活跃 Session 以检测异常
5. **实现清理机制** — 使用存储 TTL 特性进行自动清理
6. **启用加密** — 加密静态存储的敏感 Session 属性

## 相关文档

- [WebSocket 认证](/zh/guide/websocket-auth)
- [在线用户管理](/zh/guide/online-user-management)
- [事件监听指南](/zh/guide/event-listener)


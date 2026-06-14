# Distributed Session Management | 分布式 Session 管理

[English](#english) | [中文](#中文) | [ภาษาไทย](#ภาษาไทย) | [Tiếng Việt](#tiếng-việt) | [ភាសាខ្មែរ](#ភាសាខ្មែរ) | [Bahasa Melayu](#bahasa-melayu) | [မြန်မာဘာသာ](#မြန်မာဘာသာ)

---

## English

### Overview

The Distributed Session Management module enables session sharing across multiple microservices. It provides service authentication, cross-service session access, and attribute management with automatic timeout handling.

This module is designed for microservices architectures where multiple services need to share user authentication state and session data seamlessly.

### Architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│                   Microservices Architecture                       │
│                   微服务架构                                        │
└────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  Service A   │  │  Service B   │  │  Service C   │
    │  (User API)  │  │  (Order API) │  │  (Pay API)   │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                  │                  │
           └──────────────────┼──────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Distributed       │
                    │  Session Storage   │
                    │  (Redis/Database)  │
                    └────────────────────┘

Each service can:
  - Create sessions for users
  - Access sessions created by other services
  - Share user authentication state
```

### Key Features

- **Cross-Service Session Sharing** - Share sessions across microservices
- **Service Authentication** - Verify service credentials with secret keys
- **Session Attributes** - Store custom key-value pairs for user context
- **Multi-Session Support** - One user can have multiple sessions (multi-device)
- **Automatic Cleanup** - TTL-based session expiration
- **Pluggable Storage** - Use custom storage backends (Redis, Database, Memory)
- **Permission-Based Access** - Fine-grained control via service permissions
- **Session Monitoring** - Track all active sessions per user

### Quick Start

```rust
use sa_token_core::{
    DistributedSessionManager, InMemoryDistributedStorage, ServiceCredential
};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create distributed session manager
    let storage = Arc::new(InMemoryDistributedStorage::new());
    let manager = DistributedSessionManager::new(
        storage,
        "service-main".to_string(),
        Duration::from_secs(3600), // 1 hour TTL
    );
    
    // Register a service
    let credential = ServiceCredential {
        service_id: "api-gateway".to_string(),
        service_name: "API Gateway".to_string(),
        secret_key: "secret123".to_string(),
        created_at: Utc::now(),
        permissions: vec!["read".to_string(), "write".to_string()],
    };
    manager.register_service(credential).await?; // returns Result<(), SaTokenError> since 0.1.18
    
    // Verify service
    let verified = manager.verify_service("api-gateway", "secret123").await?;
    println!("Service verified: {}", verified.service_name);
    
    // Create session
    let session = manager.create_session(
        "user123".to_string(),
        "token456".to_string(),
    ).await?;
    
    // Set session attribute
    manager.set_attribute(
        &session.session_id,
        "role".to_string(),
        "admin".to_string(),
    ).await?;
    
    // Get session attribute
    if let Some(role) = manager.get_attribute(&session.session_id, "role").await? {
        println!("User role: {}", role);
    }
    
    // Get all sessions for user
    let sessions = manager.get_sessions_by_login_id("user123").await?;
    println!("User has {} active sessions", sessions.len());
    
    Ok(())
}
```

### Service Authentication Flow

```text
Service A                   Manager                    Service B
   |                           |                           |
   |-- register_service ------>|                           |
   |<----- registered ---------|                           |
   |                           |                           |
   |                           |<-- verify_service(id, secret)
   |                           |--- check credentials ---->|
   |                           |<----- verified ----------|
```

### Cross-Service Session Access

```text
Service A creates session:
  session_id: "uuid-123"
  login_id: "user123"
  attributes: {"role": "admin"}

Service B accesses session:
  get_session("uuid-123") -> Full session data
  Can read/modify attributes
  Updates last_access timestamp
```

### API Reference

#### DistributedSessionManager

**Methods:**
- `new(storage, service_id, timeout)` - Create manager
- `register_service(credential)` - Register a service. **Since 0.1.18 returns `Result<(), SaTokenError>`** (credentials are persisted to storage, no longer kept in an in-memory map)
- `verify_service(id, secret)` - Verify service credentials
- `create_session(login_id, token)` - Create new session
- `get_session(session_id)` - Get session by ID
- `update_session(session)` - Update existing session
- `delete_session(session_id)` - Delete session
- `set_attribute(id, key, value)` - Set session attribute
- `get_attribute(id, key)` - Get session attribute
- `remove_attribute(id, key)` - Remove session attribute
- `get_sessions_by_login_id(login_id)` - Get all user sessions
- `delete_all_sessions(login_id)` - Delete all user sessions

---

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
    manager.register_service(credential).await?; // 0.1.18 起返回 Result<(), SaTokenError>
    
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

## ภาษาไทย

### ภาพรวม

โมดูลการจัดการ Distributed Session ช่วยให้สามารถแชร์ session ข้ามไมโครเซอร์วิสหลายตัว มีการยืนยันตัวตนของเซอร์วิส การเข้าถึง session ข้ามเซอร์วิส และการจัดการแอตทริบิวต์พร้อมการจัดการหมดเวลาอัตโนมัติ

### คุณสมบัติหลัก

- **การแชร์ Session ข้ามเซอร์วิส** - แชร์ sessions ข้ามไมโครเซอร์วิส
- **การยืนยันตัวตนเซอร์วิส** - ตรวจสอบข้อมูลรับรองเซอร์วิส
- **แอตทริบิวต์ Session** - เก็บคู่คีย์-ค่าแบบกำหนดเอง
- **รองรับหลาย Session** - ผู้ใช้หนึ่งคนสามารถมีหลาย sessions

### เริ่มต้นอย่างรวดเร็ว

```rust
let manager = DistributedSessionManager::new(
    storage,
    "service-main".to_string(),
    Duration::from_secs(3600),
);

// สร้าง session
let session = manager.create_session(
    "user123".to_string(),
    "token456".to_string(),
).await?;

// ตั้งค่าแอตทริบิวต์
manager.set_attribute(&session.session_id, "role".to_string(), "admin".to_string()).await?;
```

---

## Tiếng Việt

### Tổng quan

Module quản lý Distributed Session cho phép chia sẻ session qua nhiều microservices. Nó cung cấp xác thực dịch vụ, truy cập session liên dịch vụ và quản lý thuộc tính với xử lý timeout tự động.

### Tính năng chính

- **Chia sẻ Session liên dịch vụ** - Chia sẻ sessions qua microservices
- **Xác thực dịch vụ** - Xác minh thông tin xác thực dịch vụ
- **Thuộc tính Session** - Lưu trữ các cặp key-value tùy chỉnh
- **Hỗ trợ nhiều Session** - Một người dùng có thể có nhiều sessions

### Bắt đầu nhanh

```rust
let manager = DistributedSessionManager::new(
    storage,
    "service-main".to_string(),
    Duration::from_secs(3600),
);

let session = manager.create_session("user123".to_string(), "token456".to_string()).await?;

manager.set_attribute(&session.session_id, "role".to_string(), "admin".to_string()).await?;
```

---

## ភាសាខ្មែរ

### ទិដ្ឋភាពទូទៅ

ម៉ូឌុលការគ្រប់គ្រង Distributed Session បើកឱ្យមានការចែករំលែក session ឆ្លងកាត់ microservices ជាច្រើន។ វាផ្តល់នូវការផ្ទៀងផ្ទាត់សេវាកម្ម ការចូលប្រើ session ឆ្លងកាត់សេវាកម្ម និងការគ្រប់គ្រងគុណលក្ខណៈជាមួយនឹងការ្រប់គ្រងការផុតកំណត់ដោយស្វ័យប្រវត្តិ។

```rust
let manager = DistributedSessionManager::new(
    storage,
    "service-main".to_string(),
    Duration::from_secs(3600),
);

let session = manager.create_session("user123".to_string(), "token456".to_string()).await?;
```

---

## Bahasa Melayu

### Gambaran Keseluruhan

Modul Pengurusan Distributed Session membolehkan perkongsian session merentasi pelbagai microservices. Ia menyediakan pengesahan perkhidmatan, akses session merentas perkhidmatan dan pengurusan atribut dengan pengendalian timeout automatik.

### Ciri Utama

- **Perkongsian Session Merentas Perkhidmatan** - Kongsi sessions merentasi microservices
- **Pengesahan Perkhidmatan** - Sahkan kelayakan perkhidmatan
- **Atribut Session** - Simpan pasangan key-value tersuai

### Permulaan Pantas

```rust
let manager = DistributedSessionManager::new(
    storage,
    "service-main".to_string(),
    Duration::from_secs(3600),
);

let session = manager.create_session("user123".to_string(), "token456".to_string()).await?;

manager.set_attribute(&session.session_id, "role".to_string(), "admin".to_string()).await?;
```

---

## မြန်မာဘာသာ

### အကျဉ်းချုပ်

Distributed Session Management module သည် microservices များစွာတွင် session sharing လုပ်နိုင်ပါသည်။ ၎င်းသည် service authentication၊ cross-service session access နှင့် attribute management တို့ကို automatic timeout handling ဖြင့် ပေးပါသည်။

### အဓိက လုပ်ဆောင်ချက်များ

- **Cross-Service Session Sharing** - microservices များတွင် sessions များ sharing လုပ်ရန်
- **Service Authentication** - service credentials များ verify လုပ်ရန်
- **Session Attributes** - custom key-value pairs များ သိမ်းဆည်းရန်

### လျင်မြန်စွာ စတင်ခြင်း

```rust
let manager = DistributedSessionManager::new(
    storage,
    "service-main".to_string(),
    Duration::from_secs(3600),
);

let session = manager.create_session("user123".to_string(), "token456".to_string()).await?;

manager.set_attribute(&session.session_id, "role".to_string(), "admin".to_string()).await?;
```

---

## Use Cases

### 1. Single Sign-On (SSO) Across Services
Users log in once and access multiple services without re-authentication:

```text
User → Service A: Login
  ├─ Create session: session_id = "abc123"
  └─ Save to distributed storage

User → Service B: Request with session_id = "abc123"
  ├─ Service B retrieves session from storage
  ├─ Validates user is authenticated
  └─ Processes request ✅ (No re-login needed!)
```

### 2. Session Sharing for User Context
Services share user context and state:

```text
Service A stores: { "user_role": "admin", "department": "IT" }
Service B reads: Same session attributes available
Service C updates: { "last_order": "order_123" }
→ All services share the same session state!
```

### 3. Multi-Device Session Management
One user can have multiple active sessions:

```text
User: user_123
  ├─ Session 1: Web (Service A)
  ├─ Session 2: Mobile (Service B)
  └─ Session 3: Desktop (Service C)

All sessions can be:
  - Listed: get_sessions_by_login_id()
  - Managed individually
  - Terminated all at once: delete_all_sessions()
```

### 4. Microservices Architecture
Share user sessions across API Gateway, User Service, Order Service, etc.

### 5. Multi-Region Deployment
Synchronize sessions across different geographic regions using shared storage.

### 6. Load Balancing
Maintain session consistency across multiple server instances.

## Storage Backends

### Built-in `SaStorageDistributedStorage` (Recommended, since 0.1.18)

Instead of hand-writing a backend, reuse the same `SaStorage` your `SaTokenManager` already uses.
`SaStorageDistributedStorage` persists distributed sessions, the per-user login index, and service
credentials, honoring the configured `storage_key_prefix`:

```rust
use std::sync::Arc;
use std::time::Duration;
use sa_token_core::{DistributedSessionManager, SaStorageDistributedStorage};

// `storage` is any Arc<dyn SaStorage> (memory, Redis, database, …);
// pass the same key prefix as your SaTokenConfig to keep keys consistent.
let dist_storage = Arc::new(SaStorageDistributedStorage::new(
    storage.clone(),
    config.storage_key_prefix.clone(), // e.g. "sa:"
));

let manager = DistributedSessionManager::new(
    dist_storage,
    "service-main".to_string(),
    Duration::from_secs(3600),
);
```

Key layout (with default prefix `sa:`): `sa:dsession:{session_id}`,
`sa:dsession:index:{login_id}`, `sa:dservice:{service_id}`.

### Implementing a custom backend

The `DistributedSessionStorage` trait has **six** methods (since 0.1.18 it also persists service
credentials): `save_session`, `get_session`, `delete_session`, `get_sessions_by_login_id`,
**`save_credential`**, and **`get_credential`**. Custom implementations must provide all six.

### Redis Implementation

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
        
        // Index by login_id for quick lookup
        let index_key = format!("distributed:login:{}", session.login_id);
        conn.sadd(index_key, &session.session_id).await?;
        
        Ok(())
    }
    
    // ... implement other methods
}
```

### Database Implementation

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
    
    // ... implement other methods
}
```

## Best Practices

### 1. Service Registration
Use crypto-secure secret generation for service credentials:

```rust
let credential = ServiceCredential {
    service_id: "user-service".to_string(),
    service_name: "User Management Service".to_string(),
    secret_key: generate_secure_secret(), // Use crypto-secure generation
    created_at: Utc::now(),
    permissions: vec!["user.read".to_string(), "user.write".to_string()],
};
manager.register_service(credential).await?; // returns Result since 0.1.18
```

### 2. Session Creation with Context
Add relevant attributes immediately after session creation:

```rust
let session = manager.create_session(login_id, token).await?;

// Add relevant attributes immediately
manager.set_attribute(&session.session_id, "user_role".to_string(), "admin".to_string()).await?;
manager.set_attribute(&session.session_id, "department".to_string(), "IT".to_string()).await?;
manager.set_attribute(&session.session_id, "login_device".to_string(), "web".to_string()).await?;
```

### 3. Cross-Service Access Pattern
Always verify service identity and check permissions:

```rust
// 1. Verify service identity
let service_cred = manager.verify_service("service-b", request.secret).await?;

// 2. Check permissions
if !service_cred.permissions.contains(&"session.read".to_string()) {
    return Err(SaTokenError::PermissionDenied);
}

// 3. Access session
let session = manager.get_session(&request.session_id).await?;

// 4. Refresh to keep session alive
manager.refresh_session(&session.session_id).await?;
```

### 4. Multi-Device Logout
Support both individual and bulk logout:

```rust
// Logout from all devices
manager.delete_all_sessions(&login_id).await?;

// Or logout specific session
manager.delete_session(&session_id).await?;
```

### 5. Session Monitoring
Monitor user's active sessions for security:

```rust
let sessions = manager.get_sessions_by_login_id(&login_id).await?;

for session in sessions {
    println!("Session: {} from service: {}, last active: {}", 
        session.session_id,
        session.service_id,
        session.last_access
    );
    
    // Check for suspicious activity
    if is_suspicious(&session) {
        manager.delete_session(&session.session_id).await?;
    }
}
```

### 6. Security Considerations

- ✅ **Service Authentication**: Each service has unique secret_key
- ✅ **Permission-Based Access**: Services have explicit permissions
- ✅ **Session Timeout**: Configure appropriate TTL
- ✅ **Data Encryption**: Encrypt sensitive session attributes
- ✅ **Audit Logging**: Log session creation/deletion and cross-service access

### 7. Production Recommendations

1. **Use appropriate TTL** - Set session timeout based on security requirements (typically 1-24 hours)
2. **Use persistent storage** - Implement Redis/Database storage for production (not in-memory)
3. **Secure service credentials** - Use strong secret keys and rotate periodically
4. **Monitor session count** - Track active sessions per user to detect anomalies
5. **Implement cleanup** - Use storage TTL features for automatic cleanup
6. **Enable encryption** - Encrypt sensitive session attributes at rest

## Related Documentation

- [WebSocket Authentication](./WEBSOCKET_AUTH.md)
- [Online User Management](./ONLINE_USER_MANAGEMENT.md)
- [Event Listener Guide](./EVENT_LISTENER.md)

## License

MIT OR Apache-2.0


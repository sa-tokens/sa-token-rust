# SSO 单点登录指南

## 🇨🇳 中文

### 概述

sa-token-rust 提供了基于票据认证的完整单点登录（SSO）解决方案。用户只需登录一次即可无缝访问多个应用程序。

### 核心特性

- 🎫 **票据认证**：安全的一次性使用票据
- 🔐 **统一登录**：一次登录，访问所有应用
- 🚪 **统一登出**：一次登出，退出所有应用
- 🌐 **跨域支持**：可配置的域名白名单
- ⏱️ **票据过期**：自动票据过期和清理
- 🛡️ **安全保护**：服务URL匹配、防重放攻击
- 🔄 **会话管理**：跟踪所有已登录应用

### 核心组件

#### 1. SsoServer - SSO 服务端

SSO 服务端是中央认证服务，负责：
- 管理用户认证
- 生成和验证票据
- 维护全局会话状态
- 处理统一登出
- 跟踪活跃客户端应用

#### 2. SsoClient - SSO 客户端

每个应用程序作为 SSO 客户端，负责：
- 检查本地登录状态
- 生成登录/登出 URL
- 验证来自 SSO 服务端的票据
- 创建本地会话
- 处理登出回调

#### 3. SsoTicket - 认证票据

票据是一个短期、一次性使用的认证令牌，包含：
- `ticket_id`：唯一票据标识符（UUID）
- `service`：目标应用 URL
- `login_id`：用户标识
- `create_time`：票据创建时间
- `expire_time`：票据过期时间
- `used`：使用状态标记

### 架构流程

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   用户      │         │ SSO 服务端  │         │   客户端    │
│  浏览器     │         │   (认证)    │         │   应用 1    │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │  1. 访问应用 1        │                       │
       ├───────────────────────┼──────────────────────>│
       │                       │                       │
       │  2. 重定向到 SSO      │                       │
       │<──────────────────────┼───────────────────────┤
       │                       │                       │
       │  3. 登录请求          │                       │
       ├──────────────────────>│                       │
       │                       │                       │
       │  4. 创建票据          │                       │
       │<──────────────────────┤                       │
       │                       │                       │
       │  6. 带票据回调                                │
       ├───────────────────────┼──────────────────────>│
       │                       │                       │
       │  7. 验证票据          │                       │
       │                       │<──────────────────────┤
       │                       │                       │
       │  8. 票据有效          │                       │
       │                       ├──────────────────────>│
       │                       │                       │
       │  9. 创建本地会话                              │
       │  10. 授予访问权限     │                       │
       │<──────────────────────┼───────────────────────┤
```

### 快速开始

#### 1. 基础设置

```rust
use std::sync::Arc;
use sa_token_core::{SaTokenConfig, SsoServer, SsoClient};
use sa_token_storage_memory::MemoryStorage;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .build();

let manager = Arc::new(manager);
```

#### 2. 创建 SSO 服务端

```rust
let sso_server = Arc::new(
    SsoServer::new(manager.clone())
        .with_ticket_timeout(300)  // 5 分钟
);
```

#### 3. 创建 SSO 客户端

```rust
let client1 = Arc::new(SsoClient::new(
    manager.clone(),
    "http://sso.example.com/auth".to_string(),
    "http://app1.example.com".to_string(),
));
```

### 完整登录流程

#### 步骤 1：用户在 SSO 服务端登录

```rust
let ticket = sso_server.login(
    "user_123".to_string(),
    "http://app1.example.com".to_string(),
).await?;
```

#### 步骤 2：验证票据

```rust
let login_id = sso_server.validate_ticket(
    &ticket.ticket_id,
    "http://app1.example.com",
).await?;
```

#### 步骤 3：创建本地会话

```rust
let token = client1.login_by_ticket(login_id).await?;
```

### 统一登出

```rust
let clients = sso_server.logout("user_123").await?;

for client_url in clients {
    // 通知每个客户端登出
}

client1.handle_logout("user_123").await?;
client2.handle_logout("user_123").await?;
```

### 安全特性

**1. 一次性票据使用**
```rust
// 第一次验证 - 成功
sso_server.validate_ticket(&ticket_id, service).await?;

// 第二次验证 - 失败（票据已使用）
sso_server.validate_ticket(&ticket_id, service).await?; // 错误！
```

**2. 服务 URL 匹配**
```rust
// 应用1的票据不能用于应用2
sso_server.validate_ticket(&ticket_id, "wrong_service").await?; // ServiceMismatch!
```

### 错误处理

```rust
use sa_token_core::SaTokenError;

match sso_server.validate_ticket(ticket_id, service).await {
    Ok(login_id) => println!("有效: {}", login_id),
    Err(SaTokenError::InvalidTicket) => println!("票据未找到"),
    Err(SaTokenError::TicketExpired) => println!("票据已过期"),
    Err(SaTokenError::ServiceMismatch) => println!("服务不匹配"),
    Err(e) => println!("其他错误: {}", e),
}
```

### API 参考

**SsoServer 方法：**
- `new(manager)` - 创建新的 SSO Server
- `with_ticket_timeout(seconds)` - 设置票据过期时间
- `login(login_id, service)` - 用户登录并生成票据
- `create_ticket(login_id, service)` - 为已登录用户创建票据
- `validate_ticket(ticket_id, service)` - 验证并消费票据
- `logout(login_id)` - 统一登出
- `is_logged_in(login_id)` - 检查用户是否已登录
- `get_session(login_id)` - 获取用户的 SSO 会话
- `get_active_clients(login_id)` - 获取活跃客户端列表
- `cleanup_expired_tickets()` - 清理过期票据

**SsoClient 方法：**
- `new(manager, server_url, service_url)` - 创建新的 SSO Client
- `with_logout_callback(callback)` - 设置登出回调
- `get_login_url()` - 生成登录 URL
- `get_logout_url()` - 生成登出 URL
- `check_local_login(login_id)` - 检查本地会话
- `login_by_ticket(login_id)` - 创建本地会话
- `handle_logout(login_id)` - 处理登出请求

### 完整示例

查看 [sso_example.rs](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/sso_example.rs) 获取完整的工作示例。

运行示例：
```bash
cargo run --example sso_example
```

### 相关文档

- [事件监听指南](/zh/guide/event-listener.md)
- [WebSocket 认证](/zh/guide/websocket-auth.md)
- [分布式 Session](/zh/guide/distributed-session.md)
- [错误参考](/zh/reference/error-reference.md)

---


## 📖 Additional Resources

- [Main Documentation](/zh/guide/quick-start.md)
- [Examples Directory](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/)
- [API Reference](/zh/guide/stp-util.md)

---

**Version**: 0.1.13  
**Last Updated**: 2025-01-15


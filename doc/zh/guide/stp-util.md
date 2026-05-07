# StpUtil API 参考

中文文档 | [English](/guide/stp-util.md)

`StpUtil` 是一个工具类，为常见的认证和授权操作提供简化的静态 API。它将 `SaTokenManager` 功能封装在易用的接口中。

## 目录

- [初始化](#初始化)
- [登录操作](#登录操作)
- [登出操作](#登出操作)
- [Token 验证](#token-验证)
- [Session 管理](#session-管理)
- [权限管理](#权限管理)
- [角色管理](#角色管理)
- [高级用法](#高级用法)

## 初始化

当您使用任何 Web 框架插件创建 `SaTokenState` 时，`StpUtil` 会自动初始化：

```rust
use sa_token_core::StpUtil;
use sa_token_plugin_axum::SaTokenState;  // 或其他框架插件
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

// 构建状态时 StpUtil 会自动初始化
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("Authorization")
    .timeout(86400)
    .build();

// StpUtil 已就绪，可以直接使用！
StpUtil::login("user_id").await?;
```

**注意**：初始化在 `SaTokenState::builder().build()` 中自动完成，所以您无需手动调用任何初始化方法。这适用于所有支持的 Web 框架（Axum、Actix-web、Poem、Rocket、Warp）。

## 登录操作

### 基本登录

```rust
use sa_token_core::StpUtil;

// 使用字符串 ID 登录
let token = StpUtil::login("user_10001").await?;
println!("生成的 token: {}", token.as_str());

// 使用数字 ID 登录
let token = StpUtil::login(10001).await?;  // 支持 i32, i64, u32, u64
```

### 链式构建登录

```rust
use sa_token_core::StpUtil;
use serde_json::json;

// 链式调用设置额外信息
let token = StpUtil::builder("user_123")
    .extra_data(json!({"ip": "192.168.1.1"}))
    .device("pc")
    .login_type("admin")
    .login(None) // None 表示使用构建器中的 login_id，Some("other_id") 可覆盖
    .await?;

let token = StpUtil::builder("user_123")
    .extra_data(json!({"ip": "192.168.1.1"}))
    .device("pc")
    .login_type("admin")
    .login(Some("new_user_456"))  // 或 Some(10001) 数字ID
    .await?;

```

### 带设备标识的登录

```rust
// 带设备信息登录（用于多设备管理）
let token = StpUtil::builder("user_10001")
    .device("mobile_ios")
    .login(None)
    .await?;
```

### 带登录类型的登录

```rust
// 指定登录类型（如 "admin"、"user"、"api"）
let token = StpUtil::login_with_type("user_10001", "admin").await?;
```

### 带额外数据的登录

```rust
use serde_json::json;

// 登录并附加额外数据（JWT 模式下会签入 JWT 声明）
let token = StpUtil::login_with_extra(
    "user_10001",
    json!({"ip": "192.168.1.1", "device": "mobile"})
).await?;
```

### 使用指定的 Manager 登录

```rust
// 使用特定的 SaTokenManager 实例登录（绕过全局 StpUtil）
let token = StpUtil::login_with_manager(&manager, "user_10001").await?;
```

## 登出操作

### 登出当前用户

```rust
// 通过 login_id 登出
StpUtil::logout_by_login_id("user_10001").await?;

// 通过 token 登出（接受 &TokenValue）
StpUtil::logout(&token).await?;

// 或使用别名
StpUtil::logout_by_token(&token).await?;
```

### 从特定设备登出

```rust
// 通过 login_id 登出（会移除该用户所有设备会话）
StpUtil::logout_by_login_id("user_10001").await?;
```

### 踢用户下线

```rust
// 强制登出（踢下线）— 移除用户所有会话
StpUtil::kick_out("user_10001").await?;

// 批量踢出多个用户
StpUtil::kick_out_batch(&["user_10001", "user_10002", "user_10003"]).await?;
```

### 上下文登出（请求处理器中）

```rust
// 登出当前请求的用户（从请求上下文中提取 token）
StpUtil::logout_current().await?;
```

## Token 验证

### 检查登录状态

```rust
use sa_token_core::token::TokenValue;

let token = TokenValue::new("your_token_string".to_string());

// 检查 token 是否有效（是否已登录）
let is_logged_in = StpUtil::is_login(&token).await;

// 通过 login_id 检查
let is_logged_in = StpUtil::is_login_by_login_id("user_10001").await;
```

### 要求登录（未登录则报错）

```rust
// token 无效时返回 Err(NotLogin)
StpUtil::check_login(&token).await?;
```

### 获取 Token 信息

```rust
// 获取完整的 token 元数据
let token_info = StpUtil::get_token_info(&token).await?;
println!("登录 ID: {}", token_info.login_id);
println!("设备: {:?}", token_info.device);
println!("过期时间: {:?}", token_info.expire_time);
```

### 从 Token 获取登录 ID

```rust
// 从 token 值获取 login_id
let login_id = StpUtil::get_login_id(&token).await?;

// 获取 login_id，失败时返回默认值
let login_id = StpUtil::get_login_id_or_default(&token, "anonymous").await;
```

### 通过登录 ID 获取 Token

```rust
// 获取用户当前的 token
let token = StpUtil::get_token_by_login_id("user_10001").await?;

// 获取所有活跃 token（多设备场景）
let tokens = StpUtil::get_all_tokens_by_login_id("user_10001").await?;
```

### Token 超时管理

```rust
// 获取 token 剩余有效时间
if let Some(remaining) = StpUtil::get_token_timeout(&token).await? {
    println!("Token 还有 {} 秒过期", remaining);
}

// 手动续期 token
StpUtil::renew_timeout(&token, 3600).await?; // 延长 1 小时
```

### Token 工具方法

```rust
// 创建原始 TokenValue（不执行登录）
let raw = StpUtil::create_token("custom_token_string");

// 检查 token 格式（长度 >= 16，非空）
if StpUtil::is_valid_token_format("my_token_string_16ch") {
    println!("Token 格式有效");
}
```

### 上下文 Token 方法（请求处理器中）

```rust
// 在请求处理器中（token 已由中间件注入）：
// 这些方法从请求作用域的 SaTokenContext 读取。

// 获取当前 token 值
let token = StpUtil::get_token_value()?;

// 获取当前 token 信息
let info = StpUtil::get_token_info_current()?;

// 检查当前请求是否已认证
if StpUtil::is_login_current() {
    println!("请求已认证");
}

// 要求当前请求已登录（未登录返回错误）
StpUtil::check_login_current()?;

// 获取当前登录 ID（String 类型）
let login_id = StpUtil::get_login_id_as_string().await?;

// 获取当前登录 ID（i64 类型）
let user_id = StpUtil::get_login_id_as_long().await?;
```

## Session 管理

### 获取 Session

```rust
// 获取用户 session（异步 — 从后端存储读取）
let session = StpUtil::get_session("user_10001").await?;

// 在 session 中存储数据（同步 — 操作内存中的 SaSession 对象）
session.set("username", "张三".to_string())?;
session.set("email", "zhangsan@example.com".to_string())?;

// 保存 session 以持久化到后端
StpUtil::save_session(&session).await?;

// 从 session 检索数据
let username: Option<String> = session.get("username");
println!("用户名: {:?}", username);
```

### Session 操作

```rust
// 检查键是否存在
let exists = session.has("email");

// 删除键
session.remove("email");

// 清除所有 session 数据
session.clear();

// 修改后保存
StpUtil::save_session(&session).await?;
```

### 删除 Session

```rust
// 删除用户 session
StpUtil::delete_session("user_10001").await?;
```

### Session 便捷方法

```rust
// 一步设置 session 值（get→set→save）
StpUtil::set_session_value("user_10001", "theme", "dark").await?;

// 一步获取 session 值
let theme: Option<String> = StpUtil::get_session_value("user_10001", "theme").await?;
```

### 直接访问 Session 数据

```rust
let session = StpUtil::get_session("user_10001").await?;

// session.data 是公开的 HashMap — 使用标准 HashMap 方法
let keys: Vec<&String> = session.data.keys().collect();
let values: Vec<&serde_json::Value> = session.data.values().collect();
let count = session.data.len();
```

## 权限管理

### 设置权限

```rust
// 设置用户权限
StpUtil::set_permissions(
    "user_10001",
    vec![
        "user:list".to_string(),
        "user:add".to_string(),
        "user:edit".to_string(),
        "user:delete".to_string(),
    ]
).await?;
```

### 检查权限

```rust
// 检查用户是否有某个权限
let has_permission = StpUtil::has_permission("user_10001", "user:delete").await;

if has_permission {
    println!("用户可以删除");
} else {
    println!("用户不能删除");
}
```

### 检查多个权限

```rust
// 主要方法名：
let has_all = StpUtil::has_all_permissions(
    "user_10001",
    &["user:list", "user:add"]
).await;

let has_any = StpUtil::has_any_permission(
    "user_10001",
    &["user:delete", "admin:all"]
).await;

// 别名（行为相同）：
let has_all = StpUtil::has_permissions_and("user_10001", &["user:list", "user:add"]).await;
let has_any = StpUtil::has_permissions_or("user_10001", &["user:delete", "admin:all"]).await;
```

### 添加 / 移除单个权限

```rust
// 添加单个权限
StpUtil::add_permission("user_10001", "user:export").await?;

// 移除单个权限
StpUtil::remove_permission("user_10001", "user:export").await?;
```

### 获取用户权限

```rust
// 获取用户的所有权限
let permissions = StpUtil::get_permissions("user_10001").await;
println!("用户权限: {:?}", permissions);
```

### 清除权限

```rust
// 清除用户的所有权限
StpUtil::clear_permissions("user_10001").await?;
```

## 角色管理

### 设置角色

```rust
// 设置用户角色
StpUtil::set_roles(
    "user_10001",
    vec![
        "user".to_string(),
        "vip".to_string(),
    ]
).await?;

// 设置管理员角色
StpUtil::set_roles(
    "admin_10001",
    vec!["admin".to_string()]
).await?;
```

### 检查角色

```rust
// 检查用户是否有某个角色
let is_admin = StpUtil::has_role("user_10001", "admin").await;

if is_admin {
    println!("用户是管理员");
}
```

### 检查多个角色

```rust
// 检查用户是否拥有所有角色（AND）
let has_all_roles = StpUtil::has_roles_and(
    "user_10001",
    &["user", "vip"]
).await;

// 检查用户是否拥有任一角色（OR）
let has_any_role = StpUtil::has_roles_or(
    "user_10001",
    &["admin", "moderator"]
).await;
```

### 获取用户角色

```rust
// 获取用户的所有角色
let roles = StpUtil::get_roles("user_10001").await;
println!("用户角色: {:?}", roles);
```

### 清除角色

```rust
// 清除用户的所有角色
StpUtil::clear_roles("user_10001").await?;
```

### 校验 / 添加 / 移除单个角色

```rust
// 要求拥有某个角色（无则返回错误）
StpUtil::check_role("user_10001", "admin").await?;

// 添加单个角色
StpUtil::add_role("user_10001", "moderator").await?;

// 移除单个角色
StpUtil::remove_role("user_10001", "moderator").await?;
```

## Token 额外数据

```rust
use serde_json::json;

// 在已有 token 上设置额外数据
StpUtil::set_extra_data(&token, json!({"plan": "premium", "quota": 100})).await?;

// 从 token 获取额外数据
let extra: Option<serde_json::Value> = StpUtil::get_extra_data(&token).await?;
if let Some(data) = extra {
    println!("Plan: {}", data["plan"]);
}
```

## 高级用法

### 完整登录流程示例

```rust
use sa_token_core::StpUtil;

// 1. 用户登录
let login_id = "user_10001";
let token = StpUtil::login(login_id).await?;

// 2. 设置用户权限
StpUtil::set_permissions(
    login_id,
    vec![
        "user:list".to_string(),
        "user:add".to_string(),
        "post:create".to_string(),
    ]
).await?;

// 3. 设置用户角色
StpUtil::set_roles(
    login_id,
    vec!["user".to_string(), "author".to_string()]
).await?;

// 4. 在 session 中存储额外数据
let mut session = StpUtil::get_session(login_id).await?;
session.set("username", "张三".to_string())?;
session.set("email", "zhangsan@example.com".to_string())?;
session.set("last_login", chrono::Utc::now().to_string())?;
StpUtil::save_session(&session).await?;

// 返回 token 给客户端
Ok(token.as_str().to_string())
```

### 中间件中的 Token 验证

```rust
use sa_token_core::StpUtil;
use sa_token_core::token::TokenValue;

async fn validate_request(token_string: &str) -> Result<String, String> {
    let token = TokenValue::new(token_string.to_string());
    
    // 验证 token（检查是否已登录）
    if !StpUtil::is_login(&token).await {
        return Err("无效的 token".to_string());
    }
    
    // 获取 login_id
    let login_id = StpUtil::get_login_id(&token).await
        .map_err(|_| "无法获取 login_id".to_string())?;
    
    // 检查用户是否仍然登录
    if !StpUtil::is_login_by_login_id(&login_id).await {
        return Err("用户未登录".to_string());
    }
    
    Ok(login_id)
}
```

### 基于权限的访问控制

```rust
use sa_token_core::StpUtil;

async fn delete_user(operator_id: &str, target_user_id: &str) -> Result<(), String> {
    // 检查操作者是否有删除权限
    if !StpUtil::has_permission(operator_id, "user:delete").await {
        return Err("无权删除用户".to_string());
    }
    
    // 额外检查：管理员可以删除任何人，普通用户只能删除自己
    let is_admin = StpUtil::has_role(operator_id, "admin").await;
    
    if !is_admin && operator_id != target_user_id {
        return Err("只能删除自己的账户".to_string());
    }
    
    // 执行删除
    // ... 你的删除逻辑
    
    Ok(())
}
```

### 多设备 Session 管理

```rust
use sa_token_core::StpUtil;

// 用户从不同设备登录（通过 builder 模式）
let token_web = StpUtil::builder("user_10001").device("web").login(None).await?;
let token_mobile = StpUtil::builder("user_10001").device("mobile_ios").login(None).await?;
let token_app = StpUtil::builder("user_10001").device("desktop_app").login(None).await?;

// 用户在其他设备上仍然登录（并发模式）
assert!(StpUtil::is_login_by_login_id("user_10001").await);

// 从所有设备登出
StpUtil::logout_by_login_id("user_10001").await?;
```

### 使用泛型类型

```rust
use sa_token_core::StpUtil;

// StpUtil 支持任何实现 Display 的类型
// 包括：String, &str, i32, i64, u32, u64 等

// String login_id
let token1 = StpUtil::login("user_string".to_string()).await?;

// &str login_id
let token2 = StpUtil::login("user_str").await?;

// 数字 login_id
let token3 = StpUtil::login(10001_i32).await?;
let token4 = StpUtil::login(20001_i64).await?;
let token5 = StpUtil::login(30001_u32).await?;

// 所有方法都接受泛型类型
StpUtil::set_permissions(10001, vec!["user:list".to_string()]).await?;
StpUtil::has_role(20001_i64, "admin").await;
let session = StpUtil::get_session(30001_u32).await?;
```

## 错误处理

所有 `StpUtil` 方法都返回 `Result` 类型。适当处理错误：

```rust
use sa_token_core::StpUtil;

match StpUtil::login("user_10001").await {
    Ok(token) => {
        println!("登录成功: {}", token.as_str());
    }
    Err(e) => {
        eprintln!("登录失败: {:?}", e);
    }
}

// 或使用 ? 操作符
let token = StpUtil::login("user_10001").await?;
```

## 最佳实践

1. **自动初始化**：`StpUtil` 在构建 `SaTokenState` 时自动初始化，无需手动初始化。

2. **错误处理**：始终适当处理 `StpUtil` 方法的错误。

3. **权限命名**：使用一致的权限命名规范（例如 `resource:action`）。

4. **角色层次**：设计清晰的角色层次结构（例如 admin > moderator > user）。

5. **Session 数据**：在 session 中存储最少的、非敏感的数据。

6. **安全事件时登出**：当发生安全敏感事件（密码更改等）时，始终调用 `logout` 或 `kick_out`。

7. **Token 验证**：在处理请求前始终验证 token。

8. **泛型类型**：利用泛型 `LoginId` 支持，使用不同 ID 类型编写更清晰的代码。

## 另见

- [首页](/zh/)
- [示例](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/)
- [Web 框架集成](/zh/guide/framework-integration)


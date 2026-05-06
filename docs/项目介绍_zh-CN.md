# sa-token-rust 项目介绍

## 📖 项目简介

**sa-token-rust** 是一个轻量级、高性能的 Rust 认证授权框架，灵感来源于 Java 生态中广受欢迎的 [sa-token](https://github.com/dromara/sa-token) 框架。

该框架专为 Rust Web 应用设计，提供了完整的认证（Authentication）和授权（Authorization）解决方案，帮助开发者快速构建安全的 Web 应用系统。

### 核心定位

- **轻量级**: 核心功能精简，不依赖重型库，快速编译
- **高性能**: 零拷贝设计，充分利用 Rust 的性能优势，支持异步/等待（async/await）
- **易用性**: 提供过程宏和工具类，简化集成流程，降低学习成本
- **灵活性**: 支持多种存储后端和 Web 框架，适配不同业务场景

## ✨ 特性

- 🚀 **多框架支持**: Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex（部分框架以 **门面 crate + feature** 固定大版本，参见 [主 README 快速开始](../README_zh-CN.md#-快速开始)）
- 🔐 **完整的认证**: 登录、登出、Token 验证、Session 管理
- 🛡️ **细粒度授权**: 基于权限和角色的访问控制
- 💾 **灵活存储**: 内存、Redis 和数据库存储后端
- 🎯 **易于使用**: 过程宏和工具类简化集成
- ⚡ **高性能**: 零拷贝设计，支持 async/await
- 🔧 **高度可配置**: Token 超时、Cookie 选项、自定义 Token 名称
- 🎧 **事件监听**: 监听登录、登出、踢出下线等认证事件
- 🔑 **JWT 支持**: 完整的 JWT (JSON Web Token) 实现，支持多种算法
- 🔒 **安全特性**: Nonce 防重放攻击、Refresh Token 刷新机制
- 🌐 **OAuth2 支持**: 完整的 OAuth2 授权码模式实现
- 🌐 **WebSocket 认证**: 安全的 WebSocket 连接认证，支持多种 Token 来源
- 👥 **在线用户管理**: 实时在线状态跟踪和消息推送
- 🔄 **分布式 Session**: 跨服务 Session 共享，适用于微服务架构
- 🎫 **SSO 单点登录**: 完整的 SSO 实现，支持票据认证和统一登出

### 项目结构

```
sa-token-rust/
├── sa-token-core/              # 核心库（Token、Session、Manager）
├── sa-token-adapter/           # 适配器接口（Storage、Request/Response）
├── sa-token-macro/             # 过程宏（#[sa_check_login] 等）
├── sa-token-storage-memory/    # 内存存储实现
├── sa-token-storage-redis/     # Redis 存储实现
├── sa-token-storage-database/  # 数据库存储实现
├── sa-token-plugin-axum/       # Axum（默认 axum-08）
├── sa-token-plugin-actix-web/  # Actix-web 门面（默认 v4；含 -core / -v4 / -v5）
├── sa-token-plugin-rocket/     # Rocket 门面（默认 v05）
├── sa-token-plugin-salvo/      # Salvo 门面（默认 v079）
├── sa-token-plugin-ntex/       # Ntex 门面（默认 v212）
├── sa-token-plugin-gotham/     # Gotham 门面（默认 v074）
├── sa-token-plugin-poem/ …     # Poem、Warp、Tide 等一体化插件
└── ...
```

## 🎯 解决的问题

### 1. **Web 框架集成复杂性**

**问题**: Rust 生态中有多个流行的 Web 框架（Axum、Actix-web、Poem、Rocket 等），每个框架的中间件和提取器（extractor）机制不同，开发者需要为每个框架重复实现认证逻辑。

**解决方案**: sa-token-rust 为 9 个主流 Web 框架提供了统一的插件接口（**0.1.13** 起 Actix / Rocket / Salvo / Gotham / Ntex 以门面 + 绑定 crate 对齐大版本），每个插件都提供：
- 统一的状态管理（Builder 模式）
- 双重中间件（基础 + 强制登录）
- 三种提取器（必须、可选、LoginId）
- 从 Header/Cookie/Query 自动提取 Token
- Bearer Token 支持

**使用示例**:

```rust
// Axum 框架
use sa_token_plugin_axum::*;
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Router::new()
    .route("/user/info", get(user_info))
    .layer(SaTokenMiddleware::new(state));
```

### 2. **认证授权代码重复**

**问题**: 在每个需要保护的路由处理函数中，都需要手动编写：
- Token 验证逻辑
- 用户身份提取
- 权限检查代码
- 错误处理

**解决方案**: 提供过程宏（Procedural Macros），通过注解式编程简化代码：

```rust
use sa_token_macro::*;

// 需要登录即可访问
#[sa_check_login]
async fn user_profile() -> Json<UserInfo> {
    // 代码简洁，自动处理认证
}

// 需要特定权限
#[sa_check_permission("user:delete")]
async fn delete_user(id: String) -> Json<ApiResponse> {
    // 自动检查权限，无权限自动返回 403
}

// 需要特定角色
#[sa_check_role("admin")]
async fn admin_panel() -> Json<AdminData> {
    // 自动检查角色
}
```

### 3. **Session 管理复杂性**

**问题**: 手动管理用户 Session 需要处理：
- Token 生成和存储
- Token 过期时间管理
- 多端登录控制
- Session 数据存储

**解决方案**: 提供 `StpUtil` 工具类，一行代码完成复杂操作：

```rust
use sa_token_core::StpUtil;

// 用户登录（自动生成 Token 和 Session）
let token = StpUtil::login("user_id_10001").await?;

// 检查登录状态
let is_login = StpUtil::is_login("user_id_10001").await;

// 登出
StpUtil::logout(&token).await?;

// 踢出下线（强制登出）
StpUtil::kick_out("user_id_10001").await?;
```

### 4. **权限和角色管理**

**问题**: 实现细粒度的权限控制需要：
- 权限数据存储
- 权限匹配规则（支持通配符）
- 角色继承关系
- 动态权限检查

**解决方案**: 内置权限和角色管理系统：

```rust
// 设置用户权限
StpUtil::set_permissions(
    "user_id_10001",
    vec!["user:list".to_string(), "user:add".to_string()]
).await?;

// 设置用户角色
StpUtil::set_roles(
    "user_id_10001",
    vec!["admin".to_string(), "user".to_string()]
).await?;

// 检查权限（支持通配符匹配，如 "user:*" 匹配 "user:list"）
let has_permission = StpUtil::has_permission("user_id_10001", "user:list").await;

// 检查角色
let has_role = StpUtil::has_role("user_id_10001", "admin").await;
```

### 5. **分布式系统 Session 共享**

**问题**: 在微服务架构中，用户在不同服务间跳转时需要：
- 跨服务身份验证
- Session 数据共享
- 统一登出机制

**解决方案**: 提供分布式 Session 和 SSO 单点登录支持：

```rust
use sa_token_core::{SsoServer, SsoClient};

// 创建 SSO Server
let sso_server = SsoServer::new(manager.clone())
    .with_ticket_timeout(300);  // 5 分钟

// 生成登录票据
let ticket = sso_server.login(
    "user_123".to_string(),
    "http://app1.example.com".to_string(),
).await?;

// 验证票据并创建本地会话
let login_id = sso_server.validate_ticket(
    &ticket.ticket_id,
    "http://app1.example.com",
).await?;

// 统一登出（所有应用）
sso_server.logout("user_123").await?;
```

### 6. **WebSocket 认证**

**问题**: WebSocket 连接无法直接使用 HTTP 中间件，需要特殊的认证机制。

**解决方案**: 提供 WebSocket 专用认证管理器，支持多种 Token 来源：

```rust
use sa_token_core::WsAuthManager;

let ws_auth = WsAuthManager::new(manager);

// 从 WebSocket 握手请求中提取 Token 并验证
let user_id = ws_auth.authenticate_connection(ws_request).await?;
```

### 7. **安全特性缺失**

**问题**: 标准 Token 机制缺少：
- 防重放攻击
- Token 刷新机制
- 自定义 Token 格式

**解决方案**: 提供完整的安全特性：

```rust
use sa_token_core::{NonceManager, RefreshTokenManager};

// Nonce 防重放攻击
let nonce_manager = NonceManager::new(storage, 300);  // 5 分钟有效期
let nonce = nonce_manager.generate();
nonce_manager.validate_and_consume(&nonce, "user_123").await?;  // 单次使用

// Refresh Token 刷新机制
let refresh_manager = RefreshTokenManager::new(storage, config);
let refresh_token = refresh_manager.generate("user_123");
let (new_access_token, user_id) = refresh_manager
    .refresh_access_token(&refresh_token)
    .await?;
```

### 8. **事件监听和扩展性**

**问题**: 需要在认证事件发生时执行自定义逻辑（如日志记录、通知发送等）。

**解决方案**: 提供事件监听系统：

```rust
use async_trait::async_trait;
use sa_token_core::SaTokenListener;

struct MyListener;

#[async_trait]
impl SaTokenListener for MyListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("用户 {} 登录了", login_id);
        // 记录到数据库、发送通知等
    }
    
    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("用户 {} 登出了", login_id);
    }
}

// 注册监听器
StpUtil::register_listener(Arc::new(MyListener)).await;
```

## 💻 代码示例

### 示例 1: 快速开始（Axum 框架）

```rust
use std::sync::Arc;
use axum::{Router, routing::{get, post}, Json};
use sa_token_plugin_axum::*;  // 一行导入所有功能
use sa_token_macro::*;
use serde::Serialize;

#[derive(Serialize)]
struct UserInfo {
    id: String,
    username: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化 sa-token（使用 Builder 模式）
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))  // 使用内存存储
        .token_name("Authorization")               // Token 名称
        .timeout(86400)                            // 24 小时超时
        .build();                                  // 自动初始化 StpUtil
    
    // 2. 创建路由
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/user/info", get(user_info))  // 需要登录
        .route("/api/admin", get(admin_panel))    // 需要管理员权限
        .layer(SaTokenMiddleware::new(state));    // 注册中间件
    
    // 3. 启动服务器
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

// 登录接口（公开）
#[sa_ignore]
async fn login(Json(req): Json<LoginRequest>) -> Json<LoginResponse> {
    // 验证用户名密码
    if req.username == "admin" && req.password == "admin123" {
        // 用户登录
        let token = StpUtil::login("admin").await.unwrap();
        
        // 设置权限和角色
        StpUtil::set_permissions(
            "admin",
            vec!["user:*".to_string(), "admin:*".to_string()]
        ).await.unwrap();
        
        StpUtil::set_roles("admin", vec!["admin".to_string()]).await.unwrap();
        
        Json(LoginResponse {
            token: token.to_string(),
            message: "登录成功".to_string(),
        })
    } else {
        Json(LoginResponse {
            token: String::new(),
            message: "用户名或密码错误".to_string(),
        })
    }
}

// 需要登录的接口
#[sa_check_login]
async fn user_info() -> Json<UserInfo> {
    // 获取当前登录用户 ID（从 Token 中提取）
    let login_id = StpUtil::get_login_id().await.unwrap();
    
    Json(UserInfo {
        id: login_id.clone(),
        username: login_id,
    })
}

// 需要管理员权限的接口
#[sa_check_role("admin")]
async fn admin_panel() -> &'static str {
    "管理员面板"
}
```

### 示例 2: 使用 Redis 存储（生产环境）

```rust
use std::sync::Arc;
use sa_token_plugin_axum::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 连接 Redis
    let storage = RedisStorage::new(
        "redis://:password@localhost:6379/0",  // Redis 连接字符串
        "sa-token:"                             // Key 前缀
    ).await?;
    
    // 初始化 sa-token
    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();
    
    // ... 其他代码
    Ok(())
}
```

### 示例 3: 使用过程宏进行权限控制

```rust
use sa_token_macro::*;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
struct ApiResponse<T> {
    code: i32,
    message: String,
    data: Option<T>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success".to_string(),
            data: Some(data),
        }
    }
}

// 公开接口（跳过认证）
#[sa_ignore]
async fn public_api() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("公开接口".to_string()))
}

// 需要登录
#[sa_check_login]
async fn protected_api() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("受保护接口".to_string()))
}

// 需要特定权限
#[sa_check_permission("user:list")]
async fn list_users() -> Json<ApiResponse<Vec<String>>> {
    Json(ApiResponse::success(vec!["user1".to_string(), "user2".to_string()]))
}

// 需要多个权限（AND 逻辑）
#[sa_check_permissions_and("user:read", "user:write")]
async fn manage_user() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("用户管理".to_string()))
}

// 需要多个权限（OR 逻辑）
#[sa_check_permissions_or("admin:panel", "super:admin")]
async fn admin_or_super() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("管理员或超级管理员".to_string()))
}

// 需要特定角色
#[sa_check_role("admin")]
async fn admin_only() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("仅管理员可见".to_string()))
}
```

### 示例 4: 事件监听

```rust
use async_trait::async_trait;
use sa_token_core::{SaTokenListener, StpUtil};
use std::sync::Arc;

// 自定义监听器
struct LoginAuditListener;

#[async_trait]
impl SaTokenListener for LoginAuditListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("[审计] 用户 {} 登录，Token: {}", login_id, token);
        // 可以在这里：
        // 1. 记录到数据库
        // 2. 发送通知
        // 3. 更新统计数据
    }
    
    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("[审计] 用户 {} 登出", login_id);
    }
    
    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        println!("[审计] 用户 {} 被踢出下线", login_id);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 注册监听器
    StpUtil::register_listener(Arc::new(LoginAuditListener)).await;
    
    // 现在所有认证事件都会触发监听器
    let token = StpUtil::login("user_123").await?;  // 触发 on_login
    StpUtil::logout(&token).await?;                 // 触发 on_logout
    StpUtil::kick_out("user_123").await?;          // 触发 on_kick_out
    
    Ok(())
}
```

### 示例 5: JWT Token

```rust
use sa_token_core::{SaTokenConfig, SaTokenManager, config::TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 配置 JWT Token
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)                    // 使用 JWT 风格
        .jwt_secret_key("your-secret-key-here")         // JWT 密钥
        .jwt_algorithm("HS256")                         // JWT 算法
        .timeout(3600)                                   // 1 小时超时
        .build_config();
    
    let storage = Arc::new(MemoryStorage::new());
    let manager = SaTokenManager::new(storage, config);
    
    // 登录（生成 JWT Token）
    let token = manager.login("user_123").await?;
    println!("JWT Token: {}", token);
    
    // 验证 Token
    let is_valid = manager.is_valid(&token).await?;
    println!("Token 是否有效: {}", is_valid);
    
    Ok(())
}
```

### 示例 6: 在线用户管理

```rust
use sa_token_core::{OnlineManager, StpUtil};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(MemoryStorage::new());
    let online_manager = OnlineManager::new(storage.clone());
    
    // 用户登录
    let token = StpUtil::login("user_123").await?;
    
    // 标记用户在线
    online_manager.add_online_user("user_123", "web").await?;
    
    // 获取在线用户列表
    let online_users = online_manager.get_online_users().await?;
    println!("在线用户: {:?}", online_users);
    
    // 向用户推送消息
    online_manager.push_message(
        "user_123",
        "system",
        serde_json::json!({"type": "notification", "content": "您有新的消息"}),
    ).await?;
    
    // 移除在线用户
    online_manager.remove_online_user("user_123").await?;
    
    Ok(())
}
```

### 示例 7: OAuth2 授权

```rust
use sa_token_core::{OAuth2Manager, OAuth2Client};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(MemoryStorage::new());
    let oauth2 = OAuth2Manager::new(storage);
    
    // 注册 OAuth2 客户端
    let client = OAuth2Client {
        client_id: "web_app_001".to_string(),
        client_secret: "secret_abc123xyz".to_string(),
        redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        scope: vec!["read".to_string(), "write".to_string()],
    };
    
    oauth2.register_client(&client).await?;
    
    // 生成授权码
    let auth_code = oauth2.generate_authorization_code(
        "web_app_001".to_string(),
        "user_123".to_string(),
        "http://localhost:3000/callback".to_string(),
        vec!["read".to_string()],
    );
    
    oauth2.store_authorization_code(&auth_code).await?;
    
    // 授权码换取访问令牌
    let token = oauth2.exchange_code_for_token(
        &auth_code.code,
        "web_app_001",
        "secret_abc123xyz",
        "http://localhost:3000/callback",
    ).await?;
    
    println!("访问令牌: {}", token.access_token);
    
    Ok(())
}
```

## 📚 更多资源

- **完整文档**: 查看 [README_zh-CN.md](../README_zh-CN.md)
- **API 参考**: 查看 [StpUtil 文档](StpUtil_zh-CN.md)
- **JWT 指南**: 查看 [JWT_GUIDE_zh-CN.md](JWT_GUIDE_zh-CN.md)
- **OAuth2 指南**: 查看 [OAUTH2_GUIDE_zh-CN.md](OAUTH2_GUIDE_zh-CN.md)
- **事件监听指南**: 查看 [EVENT_LISTENER_zh-CN.md](EVENT_LISTENER_zh-CN.md)
- **示例代码**: 查看 [examples](../examples/) 目录

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

## 📄 许可证

本项目采用 MIT 或 Apache-2.0 双许可证，由你选择。


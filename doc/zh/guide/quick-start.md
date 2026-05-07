# 快速入门指南

[English](/guide/quick-start.md) | 中文文档

几分钟内上手 sa-token-rust。本指南涵盖安装、初始化和基本用法。

## 简化使用方式（推荐）

只需添加一个依赖到你的 `Cargo.toml`：

```toml
[dependencies]
sa-token-plugin-axum = "0.1.14"  # 默认：内存存储
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

一行导入：

```rust
use sa_token_plugin_axum::*;  // 你需要的一切！

// 现在你可以直接使用：
// - SaTokenManager, StpUtil
// - MemoryStorage, RedisStorage（通过 features）
// - 所有宏：#[sa_check_login], #[sa_check_permission]
// - JWT, OAuth2, WebSocket, 在线用户等
```

### 选择存储后端

```toml
# Redis 存储
sa-token-plugin-axum = { version = "0.1.14", features = ["redis"] }

# 多个存储后端
sa-token-plugin-axum = { version = "0.1.14", features = ["memory", "redis"] }

# 所有存储后端
sa-token-plugin-axum = { version = "0.1.14", features = ["full"] }
```

**可用的 features：**
- `memory`（默认）：内存存储
- `redis`：Redis 存储
- `database`：数据库存储
- `full`：所有存储后端

**可用的插件（0.1.14）：**
- `sa-token-plugin-axum` — Axum（默认 `axum-08`）
- `sa-token-plugin-actix-web` — Actix-web 门面（默认 `v4`；`v5` 仅占位）
- `sa-token-plugin-poem` — Poem（默认 `poem-03`）
- `sa-token-plugin-rocket` — Rocket 门面（默认 `v05`）
- `sa-token-plugin-warp` — Warp（默认 `warp-03`）
- `sa-token-plugin-salvo` — Salvo 门面（默认 `v079`）
- `sa-token-plugin-tide` — Tide（默认 `tide-017`）
- `sa-token-plugin-gotham` — Gotham 门面（默认 `v074`）
- `sa-token-plugin-ntex` — Ntex 门面（默认 `v212`）

**如何选择 crate**
- **一体化（A 组）** — Axum、Warp、Poem、Tide：一个依赖，绑定 feature 默认开启。
- **门面（B 组）** — Actix-web、Rocket、Salvo、Gotham、Ntex：一个依赖，通过 Cargo features 默认选对应当前支持的大版本（`v4`、`v05` …）。生产环境 **勿** 单独依赖 Actix **`v5`**（HTTP 未接好）。

**更多 `Cargo.toml` 示例**

```toml
sa-token-plugin-actix-web = { version = "0.1.14", features = ["redis"] }
sa-token-plugin-rocket = "0.1.14"
sa-token-plugin-salvo = "0.1.14"
```

完整对照表见仓库根目录 [README.md](../../../README.md#-快速开始)。

---

## 传统使用方式（高级）

如果你喜欢细粒度控制：

```toml
[dependencies]
sa-token-core = "0.1.14"
sa-token-storage-memory = "0.1.14"
sa-token-plugin-axum = "0.1.14"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

---

## 初始化 sa-token

### 方式 A: 使用内存存储（开发环境）

```rust
use sa_token_plugin_axum::*;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // 创建状态（StpUtil 会自动初始化）
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .token_name("Authorization")
        .timeout(86400)  // 24 小时
        .build();

    // StpUtil 已就绪，可以直接使用！
}
```

### 方式 B: 使用 Redis 存储（生产环境）

**方法 1: 连接字符串**

```rust
use sa_token_plugin_axum::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = RedisStorage::new(
        "redis://:password@localhost:6379/0",
        "sa-token:"
    ).await?;

    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();

    Ok(())
}
```

**方法 2: RedisConfig 结构体（推荐配置文件读取）**

```rust
use sa_token_storage_redis::{RedisStorage, RedisConfig};
use sa_token_plugin_axum::SaTokenState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = RedisConfig {
        host: "localhost".to_string(),
        port: 6379,
        password: Some("password".to_string()),
        database: 0,
        pool_size: 10,
    };

    let storage = RedisStorage::from_config(config, "sa-token:").await?;

    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();

    Ok(())
}
```

**方法 3: Builder 构建器（最灵活）**

```rust
use sa_token_storage_redis::RedisStorage;
use sa_token_plugin_axum::SaTokenState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = RedisStorage::builder()
        .host("localhost")
        .port(6379)
        .password("password")
        .database(0)
        .key_prefix("sa-token:")
        .build()
        .await?;

    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();

    Ok(())
}
```

---

## 用户登录

```rust
use sa_token_core::StpUtil;

// 用户登录
let token = StpUtil::login("user_id_10001").await?;
println!("Token: {}", token.as_str());

// 设置权限和角色
StpUtil::set_permissions(
    "user_id_10001",
    vec!["user:list".to_string(), "user:add".to_string()]
).await?;

StpUtil::set_roles(
    "user_id_10001",
    vec!["admin".to_string()]
).await?;
```

---

## 检查认证（Axum 示例）

```rust
use axum::{Router, routing::get};
use sa_token_plugin_axum::{SaTokenMiddleware, LoginIdExtractor};

async fn user_info(LoginIdExtractor(login_id): LoginIdExtractor) -> String {
    format!("当前用户: {}", login_id)
}

async fn admin_panel(login_id: LoginIdExtractor) -> String {
    if !StpUtil::has_permission(&login_id.0, "admin:panel").await {
        return "无权限".to_string();
    }
    format!("欢迎管理员: {}", login_id.0)
}

let app = Router::new()
    .route("/user/info", get(user_info))
    .route("/admin/panel", get(admin_panel))
    .layer(SaTokenMiddleware::new(state));
```

---

## 使用过程宏

```rust
use sa_token_macro::*;

#[sa_check_login]
async fn protected_route() -> &'static str {
    "此路由需要登录"
}

#[sa_check_permission("user:delete")]
async fn delete_user(user_id: String) -> &'static str {
    "用户已删除"
}

#[sa_check_role("admin")]
async fn admin_only() -> &'static str {
    "仅管理员可见内容"
}
```

---

## Token 配置

```rust
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("X-Token")           // 自定义 Token 名称
    .timeout(7200)                    // Token 超时（秒）
    .active_timeout(1800)             // 活动超时（秒）
    .auto_renew(true)                 // 访问时自动续签 Token
    .enable_nonce(true)               // 启用防重放攻击保护
    .nonce_timeout(300)               // Nonce 有效期（秒）
    .enable_refresh_token(true)       // 启用 Refresh Token
    .refresh_token_timeout(604800)    // Refresh Token 有效期（默认 7 天）
    .jwt_secret_key("your-secret")    // JWT 签名密钥（仅 JWT 风格）
    .jwt_algorithm("HS256")           // JWT 算法
    .jwt_issuer("my-app")             // JWT 签发者声明
    .jwt_audience("web-users")        // JWT 受众声明
    .build();
```
**auto_renew**：启用后，每次访问（如中间件验证）时 Token 自动续签。续签时长由 `active_timeout`（> 0 时）或 `timeout` 决定。

---

## 架构概览

```
sa-token-rust/
├── sa-token-core/                    # 核心库（Token、Session、Manager）
│   ├── token/                        # Token 管理
│   │   ├── generator.rs              # Token 生成（UUID、Random、JWT、Hash、Timestamp、Tik）
│   │   ├── validator.rs              # Token 验证
│   │   ├── jwt.rs                    # JWT 实现（HS256/384/512、RS256/384/512、ES256/384）
│   │   └── mod.rs                    # Token 类型（TokenValue、TokenInfo）
│   ├── session/                      # Session 管理
│   ├── permission/                   # 权限和角色检查
│   ├── event/                        # 事件监听系统
│   ├── nonce.rs                      # Nonce 管理器（防重放攻击）
│   ├── refresh.rs                    # Refresh Token 管理器
│   ├── oauth2.rs                     # OAuth2 授权码模式
│   ├── ws.rs                         # WebSocket 认证
│   ├── online.rs                     # 在线用户管理和实时推送
│   ├── distributed.rs                # 分布式 Session 管理
│   ├── sso.rs                        # SSO 单点登录（Server、Client、Ticket）
│   ├── router.rs                     # 路径鉴权路由器
│   ├── manager.rs                    # SaTokenManager（核心管理器）
│   ├── config.rs                     # 配置和构建器
│   └── util.rs                       # StpUtil（工具类）
├── sa-token-adapter/                 # 适配器接口（Storage、Request/Response）
├── sa-token-macro/                   # 过程宏（#[sa_check_login] 等）
├── sa-token-storage-memory/          # 内存存储实现
├── sa-token-storage-redis/           # Redis 存储实现
├── sa-token-storage-database/        # 数据库存储实现
├── sa-token-plugin-axum/             # Axum 框架集成（v08 绑定）
├── sa-token-plugin-actix-web/        # Actix-web 门面 → v4/v5 绑定
│   ├── sa-token-plugin-actix-web-core/   # 共享 Actix-web 核心（状态、适配器、错误）
│   ├── sa-token-plugin-actix-web-v4/     # Actix-web 4.x 绑定
│   └── sa-token-plugin-actix-web-v5/     # Actix-web 5.x 绑定（占位）
├── sa-token-plugin-poem/             # Poem 框架集成
├── sa-token-plugin-rocket/           # Rocket 门面 → v05 绑定
│   ├── sa-token-plugin-rocket-core/  # 共享 Rocket 核心
│   └── sa-token-plugin-rocket-v05/   # Rocket 0.5.x 绑定
├── sa-token-plugin-warp/             # Warp 框架集成
├── sa-token-plugin-salvo/            # Salvo 门面 → v079 绑定
│   ├── sa-token-plugin-salvo-core/   # 共享 Salvo 核心
│   └── sa-token-plugin-salvo-v079/   # Salvo 0.79.x 绑定
├── sa-token-plugin-tide/             # Tide 框架集成
├── sa-token-plugin-gotham/           # Gotham 门面 → v074 绑定
│   ├── sa-token-plugin-gotham-core/  # 共享 Gotham 核心
│   └── sa-token-plugin-gotham-v074/  # Gotham 0.7.x 绑定
├── sa-token-plugin-ntex/             # Ntex 门面 → v212 绑定
│   ├── sa-token-plugin-ntex-core/    # 共享 Ntex 核心
│   └── sa-token-plugin-ntex-v212/    # Ntex 2.x 绑定
└── examples/                         # 示例项目
```

---

## 下一步

- [StpUtil API 参考](/zh/guide/stp-util.md) — 完整 API 指南
- [Token 风格](/zh/guide/token-styles.md) — 所有 Token 生成风格
- [事件监听](/zh/guide/event-listener.md) — 监听认证事件
- [权限匹配](/zh/guide/permission-matching.md) — 授权规则
- [JWT 指南](/zh/guide/jwt.md) — JSON Web Token 实现
- [框架集成](/zh/guide/framework-integration.md) — 所有框架示例

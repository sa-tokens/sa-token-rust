# 框架集成

[English](/guide/framework-integration.md) | 中文文档

sa-token-rust 通过专用插件包支持 9 个 Web 框架。每个插件提供中间件、提取器和状态管理，具有一致的 API。

## 支持的框架

| 框架 | 插件包 | 说明（0.1.13） |
|-----------|---------------|--------|
| **Axum** | `sa-token-plugin-axum` | 默认绑定 `axum-08` |
| **Actix-web** | `sa-token-plugin-actix-web` | 门面；默认 **`v4`**；`v5` 占位 |
| **Poem** | `sa-token-plugin-poem` | 默认 `poem-03` |
| **Rocket** | `sa-token-plugin-rocket` | 门面；默认 **`v05`** |
| **Warp** | `sa-token-plugin-warp` | 默认 `warp-03` |
| **Salvo** | `sa-token-plugin-salvo` | 门面；默认 **`v079`** |
| **Tide** | `sa-token-plugin-tide` | 默认 `tide-017` |
| **Gotham** | `sa-token-plugin-gotham` | 门面；默认 **`v074`** |
| **Ntex** | `sa-token-plugin-ntex` | 门面；默认 **`v212`** |

速查：[快速入门](./quick-start.md)。

所有插件都提供：
- 使用 Builder 模式的状态管理
- 双重中间件（基础 + 强制登录）
- 三种提取器（必须、可选、LoginId）
- 请求/响应适配器
- 从 Header/Cookie/Query 提取 Token
- Bearer Token 支持

---

## Axum

```toml
[dependencies]
sa-token-plugin-axum = "0.1.13"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

```rust
use axum::{Router, routing::{get, post}};
use sa_token_plugin_axum::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Router::new()
    .route("/user/info", get(user_info))
    .layer(SaTokenMiddleware::new(state));
```

---

## Actix-web

```rust
use actix_web::{App, HttpServer, web};
use sa_token_plugin_actix_web::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

// 初始化 Sa-Token
let sa_token_manager = conf::init_sa_token(None)
    .await
    .expect("Sa-Token 初始化失败");

// 创建 Sa-Token 状态
let sa_token_state = SaTokenState {
    manager: sa_token_manager.clone(),
};

// 创建应用状态数据
let sa_token_data = web::Data::new(sa_token_state.clone());

HttpServer::new(move || {
    App::new()
        // 注册中间件
        .wrap(Logger::default())
        .app_data(sa_token_data.clone()) // 注入 Sa-Token 到应用状态
        .wrap(SaTokenMiddleware::new(sa_token_state.clone()))

        // 路由
        .route("/api/login", web::post().to(login))
        .route("/api/user/info", web::get().to(user_info))
})
.bind("0.0.0.0:3000")?
.run()
.await

// 完整示例请参考 examples/actix-web-example/
```

---

## Poem

```rust
use poem::{Route, Server};
use sa_token_plugin_poem::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Route::new()
    .at("/user/info", poem::get(user_info))
    .with(SaTokenMiddleware::new(state));

Server::new(TcpListener::bind("127.0.0.1:8080"))
    .run(app)
    .await
```

---

## Rocket

```rust
use rocket::{launch, get, routes};
use sa_token_plugin_rocket::{SaTokenState, SaTokenFairing, LoginIdGuard};

#[get("/user/info")]
fn user_info(login_id: LoginIdGuard) -> String {
    format!("用户: {}", login_id.0)
}

#[launch]
fn rocket() -> _ {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .build();

    rocket::build()
        .attach(SaTokenFairing::new(state))
        .mount("/", routes![user_info])
}
```

---

## Warp

```rust
use warp::Filter;
use sa_token_plugin_warp::{SaTokenState, sa_token_filter};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let routes = warp::path("user")
    .and(warp::path("info"))
    .and(sa_token_filter(state))
    .map(|token_data| {
        format!("用户信息")
    });

warp::serve(routes)
    .run(([127, 0, 0, 1], 8080))
    .await;
```

---

## 通用模式

### 中间件类型

所有插件支持两种中间件级别：

1. **基础中间件** (`SaTokenMiddleware`)：验证 Token 并将登录 ID 注入到请求上下文中，但不会阻止未认证的请求。适用于需要同时支持公开和受保护路由的场景。

2. **强制登录中间件** (`SaTokenLoginMiddleware`)：阻止没有有效 Token 的请求。适用于完全受保护的路由组。

### 提取器

每个插件提供三种提取器类型：

1. **LoginIdExtractor**（必须）：提取登录 ID，如果未认证则返回 401
2. **OptionalLoginIdExtractor**（可选）：如果存在则提取登录 ID，否则返回 `None`
3. **TokenValueExtractor**：提取原始 Token 值用于自定义处理

### Token 来源

Token 按优先级从多个来源自动提取：

1. **Authorization 头**：`Authorization: Bearer <token>` 或 `Authorization: <token>`
2. **Cookie**：可配置的 Cookie 名称
3. **Query 参数**：可配置的查询参数名称

### 自定义 Token 名称

```rust
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("X-Auth-Token")  // 自定义 header/cookie/query 名称
    .build();
```

# 路径鉴权指南

[English](./PATH_AUTH_GUIDE.md) | 中文

---

## 概述

路径鉴权允许您配置哪些路由需要认证，哪些被排除，提供细粒度的访问控制，而无需修改单个路由处理器。

## 目录

- [快速开始](#快速开始)
- [配置](#配置)
- [模式匹配](#模式匹配)
- [示例](#示例)
- [框架集成](#框架集成)

## 快速开始

**依赖（0.1.18）：** Actix-web 使用门面 crate **`sa-token-plugin-actix-web`**（默认 **`v4`** + **`memory`**）。存储切换方式见 [主 README](../README_zh-CN.md#-快速开始)。

### 基本用法

```rust
use sa_token_core::router::PathAuthConfig;
use sa_token_plugin_actix_web::{SaTokenMiddleware, SaTokenState, MemoryStorage};
use std::sync::Arc;

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string(), "/api/health".to_string()]);

App::new()
    .wrap(SaTokenMiddleware::with_path_auth(state, config))
```

## 配置

### PathAuthConfig

`PathAuthConfig` 结构体提供了构建器模式来配置路径鉴权：

```rust
let config = PathAuthConfig::new()
    .include(vec![
        "/api/**".to_string(),
        "/admin/**".to_string(),
    ])
    .exclude(vec![
        "/api/public/**".to_string(),
        "/api/login".to_string(),
    ])
    .validator(|login_id| {
        // 自定义验证逻辑
        login_id.starts_with("user_")
    });
```

### 方法

- `include(patterns)`: 设置需要鉴权的路径
- `exclude(patterns)`: 设置排除鉴权的路径
- `validator(fn)`: 设置自定义登录ID验证函数

## 模式匹配

### 支持的模式

| 模式 | 说明 | 示例 |
|------|------|------|
| `/**` | 匹配所有路径 | 匹配所有 |
| `/api/**` | 多级前缀匹配 | 匹配 `/api/user`、`/api/user/profile` |
| `/api/*` | 单级前缀匹配 | 匹配 `/api/user`，不匹配 `/api/user/profile` |
| `*.html` | 后缀匹配 | 匹配 `/page.html` |
| `/exact` | 精确匹配 | 仅匹配 `/exact` |

### 匹配规则

1. 首先检查包含模式 - 如果路径匹配，则需要鉴权
2. 排除模式覆盖包含模式 - 如果路径匹配排除模式，则不需要鉴权
3. 如果未设置包含模式，则没有路径需要鉴权
4. 如果路径既不匹配包含也不匹配排除，则不需要鉴权

## 示例

### 示例 1: 保护 API 路由

```rust
let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

// /api/user -> 需要鉴权
// /api/public/info -> 不需要鉴权
// /web/page -> 不需要鉴权
```

### 示例 2: 多个包含模式

```rust
let config = PathAuthConfig::new()
    .include(vec![
        "/api/**".to_string(),
        "/admin/**".to_string(),
    ])
    .exclude(vec![
        "/api/login".to_string(),
        "/api/register".to_string(),
    ]);
```

### 示例 3: 自定义验证器

```rust
let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .validator(|login_id| {
        // 只允许以 "user_" 开头的登录ID
        login_id.starts_with("user_")
    });
```

## 框架集成

下文展示了 Actix-web、Axum、Poem、Salvo、Tide 中内置的 **`with_path_auth`**。**Rocket / Gotham / Warp** 当前主要提供 **`SaTokenLayer::new`** 等形式的全局流水线，路径规则需在处理器中组合 **`PathAuthConfig::need_auth`** 等 `sa_token_core::router` 工具，或通过过程宏（如 `#[sa_check_login]`）控制。

### Actix-web

```rust
use sa_token_plugin_actix_web::{SaTokenMiddleware, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

App::new()
    .wrap(SaTokenMiddleware::with_path_auth(state, config))
```

### Axum

```rust
use sa_token_plugin_axum::{SaTokenLayer, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

Router::new()
    .layer(SaTokenLayer::with_path_auth(state, config))
```

### Poem

```rust
use sa_token_plugin_poem::{SaTokenLayer, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

Route::new()
    .with(SaTokenLayer::with_path_auth(state, config))
```

### Salvo

```rust
use sa_token_plugin_salvo::{SaTokenLayer, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

Router::new()
    .hoop(SaTokenLayer::with_path_auth(state, config))
```

### Ntex

```rust
use sa_token_plugin_ntex::{SaTokenLayer, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

App::new()
    .wrap(SaTokenLayer::with_path_auth(state, config))
    // ...路由
```

### Tide

```rust
use sa_token_plugin_tide::{SaTokenLayer, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

app.with(SaTokenLayer::with_path_auth(state, config))
```

## 最佳实践

1. **使用特定模式**: 尽可能使用 `/api/user/*` 而不是 `/api/**`
2. **排除公共路由**: 始终排除登录、注册和公共 API 路由
3. **测试模式**: 验证您的模式是否匹配预期路径
4. **使用验证器**: 添加自定义验证以增强安全性
5. **记录模式**: 保留受保护和公共路由的列表

## API 参考

### PathAuthConfig

```rust
impl PathAuthConfig {
    pub fn new() -> Self;
    pub fn include(self, patterns: Vec<String>) -> Self;
    pub fn exclude(self, patterns: Vec<String>) -> Self;
    pub fn validator<F>(self, f: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static;
    pub fn check(&self, path: &str) -> bool;
    pub fn validate_login_id(&self, login_id: &str) -> bool;
}
```

### 辅助函数

```rust
pub fn match_path(path: &str, pattern: &str) -> bool;
pub fn match_any(path: &str, patterns: &[&str]) -> bool;
pub fn need_auth(path: &str, include: &[&str], exclude: &[&str]) -> bool;
```


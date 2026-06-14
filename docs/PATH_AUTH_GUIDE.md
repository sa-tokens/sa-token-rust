# Path-Based Authentication Guide

[中文](./PATH_AUTH_GUIDE_zh-CN.md) | English

---

## Overview

Path-based authentication allows you to configure which routes require authentication and which are excluded, providing fine-grained control over access without modifying individual route handlers.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Pattern Matching](#pattern-matching)
- [Examples](#examples)
- [Framework Integration](#framework-integration)

## Quick Start

**Dependencies (0.1.18):** Actix-web needs the façade crate **`sa-token-plugin-actix-web`** (default **`v4`** + **`memory`**). Adjust storage with `redis` / `database` features as in the [main README](../README.md#-quick-start).

### Basic Usage

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

## Configuration

### PathAuthConfig

The `PathAuthConfig` struct provides a builder pattern for configuring path authentication:

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
        // Custom validation logic
        login_id.starts_with("user_")
    });
```

### Methods

- `include(patterns)`: Set paths that require authentication
- `exclude(patterns)`: Set paths excluded from authentication
- `validator(fn)`: Set custom login ID validator function

## Pattern Matching

### Supported Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| `/**` | Match all paths | Matches everything |
| `/api/**` | Multi-level prefix match | Matches `/api/user`, `/api/user/profile` |
| `/api/*` | Single-level prefix match | Matches `/api/user`, not `/api/user/profile` |
| `*.html` | Suffix match | Matches `/page.html` |
| `/exact` | Exact match | Only matches `/exact` |

### Matching Rules

1. Include patterns are checked first - if path matches, authentication is required
2. Exclude patterns override include patterns - if path matches exclude, authentication is not required
3. If no include patterns are set, no paths require authentication
4. If path matches neither include nor exclude, authentication is not required

## Examples

### Example 1: Protect API Routes

```rust
let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

// /api/user -> requires auth
// /api/public/info -> no auth required
// /web/page -> no auth required
```

### Example 2: Multiple Include Patterns

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

### Example 3: Custom Validator

```rust
let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .validator(|login_id| {
        // Only allow login IDs starting with "user_"
        login_id.starts_with("user_")
    });
```

## Framework Integration

Built-in **`with_path_auth` helpers** are shown below for Actix-web, Axum, Poem, Salvo, and Tide. Rocket, Gotham, and Warp integrations currently expose **`SaTokenLayer::new` / Fairing-style** pipelines without path decorators — combine **`PathAuthConfig::need_auth`** or other `sa_token_core::router` helpers in your handlers, or rely on procedural macros (`#[sa_check_login]`, etc.) where appropriate.

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
    // ...routes
```

### Tide

```rust
use sa_token_plugin_tide::{SaTokenLayer, PathAuthConfig};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

app.with(SaTokenLayer::with_path_auth(state, config))
```

## Best Practices

1. **Use specific patterns**: Prefer `/api/user/*` over `/api/**` when possible
2. **Exclude public routes**: Always exclude login, register, and public API routes
3. **Test patterns**: Verify your patterns match expected paths
4. **Use validators**: Add custom validation for additional security
5. **Document patterns**: Keep a list of protected and public routes

## API Reference

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

### Helper Functions

```rust
pub fn match_path(path: &str, pattern: &str) -> bool;
pub fn match_any(path: &str, patterns: &[&str]) -> bool;
pub fn need_auth(path: &str, include: &[&str], exclude: &[&str]) -> bool;
```


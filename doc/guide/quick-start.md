# Quick Start Guide

[中文文档](/zh/guide/quick-start.md) | English

Get started with sa-token-rust in minutes. This guide covers installation, initialization, and basic usage.

## Simplified Usage (Recommended)

Add a single dependency to your `Cargo.toml`:

```toml
[dependencies]
sa-token-plugin-axum = "0.1.14"  # Default: memory storage
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

One-line import:

```rust
use sa_token_plugin_axum::*;  // Everything you need!

// Now you can use:
// - SaTokenManager, StpUtil
// - MemoryStorage, RedisStorage (with features)
// - All macros: #[sa_check_login], #[sa_check_permission]
// - JWT, OAuth2, WebSocket, Online users, etc.
```

### Choose Your Storage Backend

```toml
# Redis storage
sa-token-plugin-axum = { version = "0.1.14", features = ["redis"] }

# Multiple storage backends
sa-token-plugin-axum = { version = "0.1.14", features = ["memory", "redis"] }

# All storage backends
sa-token-plugin-axum = { version = "0.1.14", features = ["full"] }
```

**Available features:**
- `memory` (default): In-memory storage
- `redis`: Redis storage
- `database`: Database storage
- `full`: All storage backends

**Available plugins (0.1.14):**
- `sa-token-plugin-axum` — Axum (`axum-08` default)
- `sa-token-plugin-actix-web` — Actix-web façade (`v4` default; `v5` placeholder-only)
- `sa-token-plugin-poem` — Poem (`poem-03` default)
- `sa-token-plugin-rocket` — Rocket façade (`v05` default)
- `sa-token-plugin-warp` — Warp (`warp-03` default)
- `sa-token-plugin-salvo` — Salvo façade (`v079` default)
- `sa-token-plugin-tide` — Tide (`tide-017` default)
- `sa-token-plugin-gotham` — Gotham façade (`v074` default)
- `sa-token-plugin-ntex` — Ntex façade (`v212` default)

**Choosing a crate**
- **Integrated (Group A)** — Axum, Warp, Poem, Tide: one dependency; binding feature is enabled by default.
- **Façade (Group B)** — Actix-web, Rocket, Salvo, Gotham, Ntex: one dependency; defaults select the supported major via Cargo features (`v4`, `v05`, …). Do **not** use Actix **`v5`** for production HTTP yet.

**More `Cargo.toml` examples**

```toml
sa-token-plugin-actix-web = { version = "0.1.14", features = ["redis"] }
sa-token-plugin-rocket = "0.1.14"
sa-token-plugin-salvo = "0.1.14"
```

Full framework matrix: [README.md](../../README.md#-quick-start) in the repository root.

---

## Traditional Usage (Advanced)

If you prefer fine-grained control:

```toml
[dependencies]
sa-token-core = "0.1.14"
sa-token-storage-memory = "0.1.14"
sa-token-plugin-axum = "0.1.14"
tokio = { version = "1", features = ["full"] }
axum = "0.8"
```

---

## Initialize sa-token

### Option A: Using Memory Storage (Development)

```rust
use sa_token_plugin_axum::*;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Create state (StpUtil is automatically initialized)
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .token_name("Authorization")
        .timeout(86400)  // 24 hours
        .build();

    // StpUtil is ready to use!
}
```

### Option B: Using Redis Storage (Production)

**Method 1: Connection String**

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

**Method 2: RedisConfig Structure (Recommended for config files)**

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

**Method 3: Builder Pattern (Most flexible)**

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

## User Login

```rust
use sa_token_core::StpUtil;

// User login
let token = StpUtil::login("user_id_10001").await?;
println!("Token: {}", token.as_str());

// Set permissions and roles
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

## Check Authentication (Axum Example)

```rust
use axum::{Router, routing::get};
use sa_token_plugin_axum::{SaTokenMiddleware, LoginIdExtractor};

async fn user_info(LoginIdExtractor(login_id): LoginIdExtractor) -> String {
    format!("Current user: {}", login_id)
}

async fn admin_panel(login_id: LoginIdExtractor) -> String {
    if !StpUtil::has_permission(&login_id.0, "admin:panel").await {
        return "No permission".to_string();
    }
    format!("Welcome admin: {}", login_id.0)
}

let app = Router::new()
    .route("/user/info", get(user_info))
    .route("/admin/panel", get(admin_panel))
    .layer(SaTokenMiddleware::new(state));
```

---

## Using Procedural Macros

```rust
use sa_token_macro::*;

#[sa_check_login]
async fn protected_route() -> &'static str {
    "This route requires login"
}

#[sa_check_permission("user:delete")]
async fn delete_user(user_id: String) -> &'static str {
    "User deleted"
}

#[sa_check_role("admin")]
async fn admin_only() -> &'static str {
    "Admin only content"
}
```

---

## Token Configuration

```rust
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("X-Token")           // Custom token name
    .timeout(7200)                    // Token timeout (seconds)
    .active_timeout(1800)             // Activity timeout (seconds)
    .auto_renew(true)                 // Auto-renew token on access
    .enable_nonce(true)               // Enable replay attack protection
    .nonce_timeout(300)               // Nonce validity period (seconds)
    .enable_refresh_token(true)       // Enable refresh token
    .refresh_token_timeout(604800)    // Refresh token timeout (default 7 days)
    .jwt_secret_key("your-secret")    // JWT signing key (JWT style only)
    .jwt_algorithm("HS256")           // JWT algorithm
    .jwt_issuer("my-app")             // JWT issuer claim
    .jwt_audience("web-users")        // JWT audience claim
    .build();
```
**auto_renew**: When enabled, tokens are automatically renewed on every access (e.g., middleware validation). The renewal duration is `active_timeout` (if > 0) or `timeout` otherwise.

---

## Architecture Overview

```
sa-token-rust/
├── sa-token-core/                   # Core library (Token, Session, Manager)
│   ├── token/                       # Token management
│   │   ├── generator.rs             # Token generation (UUID, Random, JWT, Hash, Timestamp, Tik)
│   │   ├── validator.rs             # Token validation
│   │   ├── jwt.rs                   # JWT implementation (HS256/384/512, RS256/384/512, ES256/384)
│   │   └── mod.rs                   # Token types (TokenValue, TokenInfo)
│   ├── session/                     # Session management
│   ├── permission/                  # Permission and role checking
│   ├── event/                       # Event listener system
│   ├── nonce.rs                     # Nonce manager (replay attack prevention)
│   ├── refresh.rs                   # Refresh token manager
│   ├── oauth2.rs                    # OAuth2 authorization code flow
│   ├── ws.rs                        # WebSocket authentication
│   ├── online.rs                    # Online user management and real-time push
│   ├── distributed.rs               # Distributed session management
│   ├── sso.rs                       # SSO single sign-on (Server, Client, Ticket)
│   ├── router.rs                    # Path-based authentication router
│   ├── manager.rs                   # SaTokenManager (core manager)
│   ├── config.rs                    # Configuration and builder
│   └── util.rs                      # StpUtil (utility class)
├── sa-token-adapter/                # Adapter interfaces (Storage, Request/Response)
├── sa-token-macro/                  # Procedural macros (#[sa_check_login], etc.)
├── sa-token-storage-memory/         # Memory storage implementation
├── sa-token-storage-redis/          # Redis storage implementation
├── sa-token-storage-database/       # Database storage implementation
├── sa-token-plugin-axum/            # Axum framework integration (v08 binding)
├── sa-token-plugin-actix-web/       # Actix-web facade → v4/v5 bindings
│   ├── sa-token-plugin-actix-web-core/  # Shared Actix-web core (state, adapter, errors)
│   ├── sa-token-plugin-actix-web-v4/    # Actix-web 4.x binding
│   └── sa-token-plugin-actix-web-v5/    # Actix-web 5.x binding (placeholder)
├── sa-token-plugin-poem/            # Poem framework integration
├── sa-token-plugin-rocket/          # Rocket facade → v05 binding
│   ├── sa-token-plugin-rocket-core/ # Shared Rocket core
│   └── sa-token-plugin-rocket-v05/  # Rocket 0.5.x binding
├── sa-token-plugin-warp/            # Warp framework integration
├── sa-token-plugin-salvo/           # Salvo facade → v079 binding
│   ├── sa-token-plugin-salvo-core/  # Shared Salvo core
│   └── sa-token-plugin-salvo-v079/  # Salvo 0.79.x binding
├── sa-token-plugin-tide/            # Tide framework integration
├── sa-token-plugin-gotham/          # Gotham facade → v074 binding
│   ├── sa-token-plugin-gotham-core/ # Shared Gotham core
│   └── sa-token-plugin-gotham-v074/ # Gotham 0.7.x binding
├── sa-token-plugin-ntex/            # Ntex facade → v212 binding
│   ├── sa-token-plugin-ntex-core/   # Shared Ntex core
│   └── sa-token-plugin-ntex-v212/   # Ntex 2.x binding
└── examples/                        # Example projects
```

---

## Next Steps

- [StpUtil API Reference](/guide/stp-util.md) — Complete API guide
- [Token Styles](/guide/token-styles.md) — All token generation styles
- [Event Listeners](/guide/event-listener.md) — Monitor authentication events
- [Permission Matching](/guide/permission-matching.md) — Authorization rules
- [JWT Guide](/guide/jwt.md) — JSON Web Token implementation
- [Framework Integration](/guide/framework-integration.md) — All framework examples

# sa-token-rust Project Introduction

[中文文档](/zh/guide/project-intro) | English

## 📖 Overview

**sa-token-rust** is a lightweight, high-performance Rust authentication and authorization framework, inspired by the widely popular [sa-token](https://github.com/dromara/sa-token) framework from the Java ecosystem.

Designed specifically for Rust web applications, it provides a complete authentication and authorization solution to help developers quickly build secure web application systems.

### Core Principles

- **Lightweight**: Minimal core functionality, no heavy dependencies, fast compilation
- **High Performance**: Zero-copy design, fully leveraging Rust's performance advantages with async/await support
- **Ease of Use**: Procedural macros and utility classes simplify integration and reduce the learning curve
- **Flexibility**: Multiple storage backends and web framework support, adaptable to different business scenarios

## ✨ Features

- 🚀 **Multi-Framework Support**: Axum, Actix-web, Poem, Rocket, Warp, Salvo, Tide, Gotham, Ntex
- 🔐 **Complete Authentication**: Login, logout, token validation, session management
- 🛡️ **Fine-grained Authorization**: Permission and role-based access control
- 💾 **Flexible Storage**: Memory, Redis, and database storage backends
- 🎯 **Easy to Use**: Procedural macros and utility classes for simple integration
- ⚡ **High Performance**: Zero-copy design with async/await support
- 🔧 **Highly Configurable**: Token timeout, cookie options, custom token names
- 🎧 **Event Listeners**: Monitor login, logout, kick-out, and other authentication events
- 🔑 **JWT Support**: Complete JWT (JSON Web Token) implementation with multiple algorithms
- 🔒 **Security Features**: Nonce replay attack prevention and Refresh Token mechanism
- 🌐 **OAuth2 Support**: Complete OAuth2 authorization code flow implementation
- 🌐 **WebSocket Authentication**: Secure WebSocket connection auth with multiple token sources
- 👥 **Online User Management**: Real-time online status tracking and message push
- 🔄 **Distributed Session**: Cross-service session sharing for microservices
- 🎫 **SSO Single Sign-On**: Complete SSO with ticket-based authentication and unified logout

### Project Structure

```
sa-token-rust/
├── sa-token-core/                     # Core library (Token, Session, Manager)
│   ├── router.rs                      # Path-based authentication router
│   └── token/generator.rs             # Token generator
├── sa-token-adapter/                  # Adapter interfaces (Storage, Request/Response)
├── sa-token-macro/                    # Procedural macros (#[sa_check_login], etc.)
├── sa-token-storage-memory/           # Memory storage implementation
├── sa-token-storage-redis/            # Redis storage implementation
├── sa-token-storage-database/         # Database storage implementation
├── sa-token-plugin-axum/              # Axum framework integration (v08 binding)
├── sa-token-plugin-actix-web/         # Actix-web facade (v4 default)
│   ├── sa-token-plugin-actix-web-core/   # Shared core
│   ├── sa-token-plugin-actix-web-v4/     # v4 binding
│   └── sa-token-plugin-actix-web-v5/     # v5 placeholder
├── sa-token-plugin-rocket/            # Rocket facade (v05 default)
│   ├── sa-token-plugin-rocket-core/      # Shared core
│   └── sa-token-plugin-rocket-v05/       # v05 binding
├── sa-token-plugin-salvo/             # Salvo facade (v079 default)
├── sa-token-plugin-gotham/            # Gotham facade (v074 default)
├── sa-token-plugin-ntex/              # Ntex facade (v212 default)
├── sa-token-plugin-poem/              # Poem framework integration
├── sa-token-plugin-warp/              # Warp framework integration
├── sa-token-plugin-tide/              # Tide framework integration
└── examples/                          # Example projects
```

> **Version-Split Architecture**: Facade crates use Cargo features to select the framework major version at compile time (e.g., `v4`/`v5`, `v05`, `v079`, etc.). Each facade shares a `*-core` crate for common logic.

## 🎯 Problems Solved

### 1. **Web Framework Integration Complexity**

**Problem**: The Rust ecosystem has multiple popular web frameworks (Axum, Actix-web, Poem, Rocket, etc.), each with different middleware and extractor mechanisms. Developers need to re-implement authentication logic for each framework.

**Solution**: sa-token-rust provides unified plugin interfaces for 9 mainstream web frameworks. Each plugin offers:
- Unified state management (Builder pattern)
- Dual middleware (basic + login-required)
- Three extractors (required, optional, LoginId)
- Automatic token extraction from Header/Cookie/Query
- Bearer token support

**Example**:

```rust
// Axum framework
use sa_token_plugin_axum::*;
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Router::new()
    .route("/user/info", get(user_info))
    .layer(SaTokenMiddleware::new(state));
```

### 2. **Authentication Code Duplication**

**Problem**: In every protected route handler, developers manually write:
- Token validation logic
- User identity extraction
- Permission checking code
- Error handling

**Solution**: Procedural macros enable annotation-driven programming:

```rust
use sa_token_macro::*;

// Login required
#[sa_check_login]
async fn user_profile() -> Json<UserInfo> {
    // Code is clean — authentication is handled automatically
}

// Specific permission required
#[sa_check_permission("user:delete")]
async fn delete_user(id: String) -> Json<ApiResponse> {
    // Permission is checked automatically — returns 403 if denied
}

// Specific role required
#[sa_check_role("admin")]
async fn admin_panel() -> Json<AdminData> {
    // Role is checked automatically
}
```

### 3. **Session Management Complexity**

**Problem**: Manual user session management requires handling:
- Token generation and storage
- Token expiration management
- Multi-device login control
- Session data storage

**Solution**: The `StpUtil` utility class completes complex operations in a single line:

```rust
use sa_token_core::StpUtil;

// User login (auto-generates Token and Session)
let token = StpUtil::login("user_id_10001").await?;

// Check login status
let is_login = StpUtil::is_login_by_login_id("user_id_10001").await;

// Logout
StpUtil::logout(&token).await?;

// Force logout (kick offline)
StpUtil::kick_out("user_id_10001").await?;
```

### 4. **Permission and Role Management**

**Problem**: Implementing fine-grained permission control requires:
- Permission data storage
- Permission matching rules (including wildcards)
- Role inheritance
- Dynamic permission checking

**Solution**: Built-in permission and role management system:

```rust
// Set user permissions
StpUtil::set_permissions(
    "user_id_10001",
    vec!["user:list".to_string(), "user:add".to_string()]
).await?;

// Set user roles
StpUtil::set_roles(
    "user_id_10001",
    vec!["admin".to_string(), "user".to_string()]
).await?;

// Check permission (supports wildcard matching, e.g. "user:*" matches "user:list")
let has_permission = StpUtil::has_permission("user_id_10001", "user:list").await;

// Check role
let has_role = StpUtil::has_role("user_id_10001", "admin").await;
```

### 5. **Distributed System Session Sharing**

**Problem**: In microservices architectures, users moving between services need:
- Cross-service identity verification
- Session data sharing
- Unified logout mechanism

**Solution**: Distributed session and SSO single sign-on support:

```rust
use sa_token_core::{SsoServer, SsoClient};

// Create SSO Server
let sso_server = SsoServer::new(manager.clone())
    .with_ticket_timeout(300);  // 5 minutes

// Generate login ticket
let ticket = sso_server.login(
    "user_123".to_string(),
    "http://app1.example.com".to_string(),
).await?;

// Validate ticket and create local session
let login_id = sso_server.validate_ticket(
    &ticket.ticket_id,
    "http://app1.example.com",
).await?;

// Unified logout (all applications)
sso_server.logout("user_123").await?;
```

### 6. **WebSocket Authentication**

**Problem**: WebSocket connections cannot use HTTP middleware directly and require a special authentication mechanism.

**Solution**: Dedicated WebSocket authentication manager with multiple token sources:

```rust
use sa_token_core::WsAuthManager;

let ws_auth = WsAuthManager::new(manager);

// Extract token from WebSocket handshake and verify
let user_id = ws_auth.authenticate(&headers, &query).await?;
```

### 7. **Missing Security Features**

**Problem**: Standard token mechanisms lack:
- Replay attack prevention
- Token refresh mechanism
- Custom token formats

**Solution**: Complete security features:

```rust
use sa_token_core::{NonceManager, RefreshTokenManager};

// Nonce replay attack prevention
let nonce_manager = NonceManager::new(storage, 300);  // 5-minute TTL
let nonce = nonce_manager.generate();
nonce_manager.validate_and_consume(&nonce, "user_123").await?;  // Single use

// Refresh Token mechanism
let refresh_manager = RefreshTokenManager::new(storage, config);
let refresh_token = refresh_manager.generate("user_123");
let (new_access_token, user_id) = refresh_manager
    .refresh_access_token(&refresh_token)
    .await?;
```

### 8. **Event Listening and Extensibility**

**Problem**: Custom logic needs to execute when authentication events occur (logging, notifications, etc.).

**Solution**: Event listener system:

```rust
use async_trait::async_trait;
use sa_token_core::SaTokenListener;

struct MyListener;

#[async_trait]
impl SaTokenListener for MyListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} logged in", login_id);
        // Log to database, send notifications, etc.
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} logged out", login_id);
    }
}

// Register listener (synchronous method)
StpUtil::register_listener(Arc::new(MyListener));
```

## 💻 Code Examples

### Example 1: Quick Start (Axum Framework)

```rust
use std::sync::Arc;
use axum::{Router, routing::{get, post}, Json};
use sa_token_plugin_axum::*;  // One-line import for all functionality
use sa_token_macro::*;
use serde::Serialize;

#[derive(Serialize)]
struct UserInfo {
    id: String,
    username: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize sa-token (Builder pattern)
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))  // Memory storage
        .token_name("Authorization")               // Token name
        .timeout(86400)                            // 24-hour timeout
        .build();                                  // Auto-initializes StpUtil

    // 2. Create routes
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/user/info", get(user_info))  // Requires login
        .route("/api/admin", get(admin_panel))    // Requires admin role
        .layer(SaTokenMiddleware::new(state));    // Register middleware

    // 3. Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// Login endpoint (public)
#[sa_ignore]
async fn login(Json(req): Json<LoginRequest>) -> Json<LoginResponse> {
    // Validate credentials
    if req.username == "admin" && req.password == "admin123" {
        // User login
        let token = StpUtil::login("admin").await.unwrap();

        // Set permissions and roles
        StpUtil::set_permissions(
            "admin",
            vec!["user:*".to_string(), "admin:*".to_string()]
        ).await.unwrap();

        StpUtil::set_roles("admin", vec!["admin".to_string()]).await.unwrap();

        Json(LoginResponse {
            token: token.to_string(),
            message: "Login successful".to_string(),
        })
    } else {
        Json(LoginResponse {
            token: String::new(),
            message: "Invalid username or password".to_string(),
        })
    }
}

// Login-required endpoint
#[sa_check_login]
async fn user_info() -> Json<UserInfo> {
    // Get current user ID (from request context)
    let login_id = StpUtil::get_login_id_as_string().await.unwrap();

    Json(UserInfo {
        id: login_id.clone(),
        username: login_id,
    })
}

// Admin-only endpoint
#[sa_check_role("admin")]
async fn admin_panel() -> &'static str {
    "Admin panel"
}
```

### Example 2: Redis Storage (Production)

```rust
use std::sync::Arc;
use sa_token_plugin_axum::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Redis
    let storage = RedisStorage::new(
        "redis://:password@localhost:6379/0",  // Redis connection string
        "sa-token:"                             // Key prefix
    ).await?;

    // Initialize sa-token
    let state = SaTokenState::builder()
        .storage(Arc::new(storage))
        .timeout(86400)
        .build();

    // ... rest of the code
    Ok(())
}
```

### Example 3: Procedural Macros for Permission Control

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

// Public endpoint (skip authentication)
#[sa_ignore]
async fn public_api() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Public API".to_string()))
}

// Login required
#[sa_check_login]
async fn protected_api() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Protected API".to_string()))
}

// Specific permission required
#[sa_check_permission("user:list")]
async fn list_users() -> Json<ApiResponse<Vec<String>>> {
    Json(ApiResponse::success(vec!["user1".to_string(), "user2".to_string()]))
}

// Multiple permissions (AND logic)
#[sa_check_permissions_and("user:read", "user:write")]
async fn manage_user() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("User management".to_string()))
}

// Multiple permissions (OR logic)
#[sa_check_permissions_or("admin:panel", "super:admin")]
async fn admin_or_super() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Admin or Super Admin".to_string()))
}

// Specific role required
#[sa_check_role("admin")]
async fn admin_only() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Admin only".to_string()))
}
```

### Example 4: Event Listeners

```rust
use async_trait::async_trait;
use sa_token_core::{SaTokenListener, StpUtil};
use std::sync::Arc;

// Custom listener
struct LoginAuditListener;

#[async_trait]
impl SaTokenListener for LoginAuditListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("[Audit] User {} logged in, Token: {}", login_id, token);
        // Possible actions:
        // 1. Log to database
        // 2. Send notifications
        // 3. Update statistics
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("[Audit] User {} logged out", login_id);
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        println!("[Audit] User {} was kicked out", login_id);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Register listener (synchronous method)
    StpUtil::register_listener(Arc::new(LoginAuditListener));

    // All authentication events now trigger the listener
    let token = StpUtil::login("user_123").await?;  // Triggers on_login
    StpUtil::logout(&token).await?;                 // Triggers on_logout
    StpUtil::kick_out("user_123").await?;           // Triggers on_kick_out

    Ok(())
}
```

### Example 5: JWT Token

```rust
use sa_token_core::{SaTokenConfig, SaTokenManager, config::TokenStyle};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure JWT tokens
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Jwt)                    // JWT style
        .jwt_secret_key("your-secret-key-here")         // JWT secret
        .jwt_algorithm("HS256")                         // JWT algorithm
        .timeout(3600)                                   // 1-hour timeout
        .build_config();

    let storage = Arc::new(MemoryStorage::new());
    let manager = SaTokenManager::new(storage, config);

    // Login (generates JWT token)
    let token = manager.login("user_123").await?;
    println!("JWT Token: {}", token);

    // Validate token
    let is_valid = manager.is_valid(&token).await;
    println!("Token valid: {}", is_valid);

    Ok(())
}
```

### Example 6: Online User Management

```rust
use sa_token_core::{OnlineManager, OnlineUser, StpUtil};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let online_manager = OnlineManager::new();

    // User login
    let token = StpUtil::login("user_123").await?;

    // Mark user online
    let user = OnlineUser {
        login_id: "user_123".to_string(),
        token: token.as_str().to_string(),
        device: "web".to_string(),
        connect_time: chrono::Utc::now(),
        last_activity: chrono::Utc::now(),
        metadata: HashMap::new(),
    };
    online_manager.mark_online(user).await;

    // Get online users
    let online_users = online_manager.get_online_users().await;
    println!("Online users: {:?}", online_users);

    // Check if user is online
    if online_manager.is_online("user_123").await {
        println!("User is online");
    }

    // Push message to user
    online_manager.push_to_user("user_123", "You have a new message".to_string()).await?;

    // Remove online user
    online_manager.mark_offline_all("user_123").await;

    Ok(())
}
```

### Example 7: OAuth2 Authorization

```rust
use sa_token_core::{OAuth2Manager, OAuth2Client};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(MemoryStorage::new());
    let oauth2 = OAuth2Manager::new(storage);

    // Register OAuth2 client
    let client = OAuth2Client {
        client_id: "web_app_001".to_string(),
        client_secret: "secret_abc123xyz".to_string(),
        redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        scope: vec!["read".to_string(), "write".to_string()],
    };

    oauth2.register_client(&client).await?;

    // Generate authorization code
    let auth_code = oauth2.generate_authorization_code(
        "web_app_001".to_string(),
        "user_123".to_string(),
        "http://localhost:3000/callback".to_string(),
        vec!["read".to_string()],
    );

    oauth2.store_authorization_code(&auth_code).await?;

    // Exchange code for access token
    let token = oauth2.exchange_code_for_token(
        &auth_code.code,
        "web_app_001",
        "secret_abc123xyz",
        "http://localhost:3000/callback",
    ).await?;

    println!("Access token: {}", token.access_token);

    Ok(())
}
```

## 📚 More Resources

- **Full Documentation**: See [Home](/)
- **API Reference**: See [StpUtil Documentation](/guide/stp-util)
- **JWT Guide**: See [JWT Guide](/guide/jwt)
- **OAuth2 Guide**: See [OAuth2 Guide](/guide/oauth2)
- **Event Listener Guide**: See [Event Listener Guide](/guide/event-listener)
- **Examples**: See [examples](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/) directory

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome!

## 📄 License

This project is dual-licensed under MIT or Apache-2.0, at your option.

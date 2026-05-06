# sa-token-core

Core authentication and authorization library for sa-token-rust.

## Features

- 🔐 **Token Management**: Generate, validate, and refresh tokens
- 🎨 **Multiple Token Styles**: UUID, Random, JWT, Hash, Timestamp, Tik
- 👤 **Session Management**: User session storage and management
- 🛡️ **Permission Control**: Role and permission-based access control
- ⏰ **Timeout Control**: Flexible token and session timeout configuration
- 🔑 **JWT Support**: Full JWT implementation with 8 algorithms (HS256/384/512, RS256/384/512, ES256/384)
- 🎧 **Event System**: Listen to login, logout, kick-out, and other authentication events
- 🔒 **Security Features**: Nonce for replay attack prevention, Refresh Token mechanism
- 🌐 **OAuth2**: Complete OAuth2 authorization code flow implementation
- 🌍 **Multi-language Error Docs**: Error documentation in 7 languages

## Installation

```toml
[dependencies]
sa-token-core = "0.1.13"
sa-token-adapter = "0.1.13"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### Basic Authentication

```rust
use sa_token_core::{SaTokenManager, SaTokenConfig};
use std::sync::Arc;

// Create configuration
let config = SaTokenConfig::default()
    .with_timeout(7200)  // 2 hours
    .with_token_name("satoken");

    // Create manager
    let manager = SaTokenManager::new(storage, config);
    
// Login
let token = manager.login("user_123").await?;

// Validate token
let is_valid = manager.is_valid(&token).await?;

// Logout
manager.logout(&token).await?;
```

### JWT Authentication

```rust
use sa_token_core::{SaTokenConfig, TokenStyle, JwtManager, JwtAlgorithm};

// Configure JWT
let config = SaTokenConfig::default()
    .with_token_style(TokenStyle::Jwt)
    .with_jwt_secret_key("your-secret-key")
    .with_jwt_algorithm("HS256");

// Or use JWT directly
let jwt = JwtManager::new("secret", JwtAlgorithm::HS256);
let token = jwt.generate("user_123", 3600)?;
let claims = jwt.validate(&token)?;
```

### Event Listeners

```rust
use sa_token_core::{SaTokenListener, SaTokenEvent};
use async_trait::async_trait;

struct MyListener;

#[async_trait]
impl SaTokenListener for SaTokenListener {
    async fn on_login(&self, event: &SaTokenEvent) {
        println!("User logged in: {}", event.login_id);
    }
}

// Register listener
manager.event_bus().register(Arc::new(MyListener)).await;
```

### OAuth2 Authorization

```rust
use sa_token_core::{OAuth2Manager, OAuth2Client};

let oauth2 = OAuth2Manager::new(storage);

// Register client
let client = OAuth2Client {
    client_id: "app_001".to_string(),
    client_secret: "secret".to_string(),
    redirect_uris: vec!["http://localhost/callback".to_string()],
    grant_types: vec!["authorization_code".to_string()],
    scope: vec!["read".to_string(), "write".to_string()],
};

oauth2.register_client(&client).await?;

// Authorization flow
let auth_code = oauth2.generate_authorization_code(...);
let token = oauth2.exchange_code_for_token(&auth_code.code, ...).await?;
```

### Security Features

```rust
use sa_token_core::{NonceManager, RefreshTokenManager};

// Nonce for replay attack prevention
let nonce_mgr = NonceManager::new(storage, 300);
let nonce = nonce_mgr.generate();
nonce_mgr.validate_and_consume(&nonce, "user_123").await?;

// Refresh token
let refresh_mgr = RefreshTokenManager::new(storage, config);
let refresh_token = refresh_mgr.generate("user_123");
let (new_token, _) = refresh_mgr.refresh_access_token(&refresh_token).await?;
```

## Core Components

### SaTokenManager

Main manager for token and session operations with event support.

```rust
// Create token
let token = manager.login("user_id").await?;

// Check login status
let is_login = manager.is_login(&token).await?;

// Get login ID
let login_id = manager.get_login_id(&token).await?;

// Access event bus
let event_bus = manager.event_bus();
event_bus.register(Arc::new(MyListener)).await;

// Logout (triggers event)
manager.logout(&token).await?;
```

### Token Styles

Support for 7 different token generation styles:

```rust
use sa_token_core::TokenStyle;

// UUID (default)
config.with_token_style(TokenStyle::Uuid);
// Output: 550e8400-e29b-41d4-a716-446655440000

// Simple UUID (no hyphens)
config.with_token_style(TokenStyle::SimpleUuid);
// Output: 550e8400e29b41d4a716446655440000

// Random (32, 64, or 128 chars)
config.with_token_style(TokenStyle::Random64);
// Output: a1b2c3d4e5f6...

// JWT
config.with_token_style(TokenStyle::Jwt);
// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

// Hash (SHA256 of login_id + timestamp)
config.with_token_style(TokenStyle::Hash);
// Output: 5f4dcc3b5aa765d61d8327deb882cf99

// Timestamp
config.with_token_style(TokenStyle::Timestamp);
// Output: 1728876543_a1b2c3d4

// Tik (short alphanumeric)
config.with_token_style(TokenStyle::Tik);
// Output: aB3dE9fG2h
```

### JWT Manager

Full JWT implementation with multiple algorithms:

```rust
use sa_token_core::{JwtManager, JwtAlgorithm, JwtClaims};

let jwt = JwtManager::new("your-secret-key", JwtAlgorithm::HS256);

// Generate JWT
let token = jwt.generate("user_123", 3600)?; // 1 hour

// Validate JWT
let claims = jwt.validate(&token)?;
println!("User: {}", claims.sub);

// Refresh JWT
let new_token = jwt.refresh(&token, 3600)?;

// Custom claims
let mut custom_claims = JwtClaims::new("user_123");
custom_claims.add_custom("role", "admin");
let token = jwt.generate_with_claims(custom_claims)?;
```

### Event System

Monitor authentication events:

```rust
use sa_token_core::{SaTokenListener, SaTokenEvent, SaTokenEventType};
use async_trait::async_trait;

#[derive(Clone)]
struct AuditLogger;

#[async_trait]
impl SaTokenListener for SaTokenListener {
    async fn on_login(&self, event: &SaTokenEvent) {
        log::info!("Login: user={}, token={}", event.login_id, event.token_value);
    }
    
    async fn on_logout(&self, event: &SaTokenEvent) {
        log::info!("Logout: user={}", event.login_id);
    }
    
    async fn on_kick_out(&self, event: &SaTokenEvent) {
        log::warn!("Kicked out: user={}", event.login_id);
    }
}

// Register listener
manager.event_bus().register(Arc::new(AuditLogger)).await;
```

### Nonce Manager

Prevent replay attacks:

```rust
use sa_token_core::NonceManager;

let nonce_mgr = NonceManager::new(storage, 300); // 5 minutes

// Generate unique nonce
let nonce = nonce_mgr.generate();
// Output: nonce_1728876543000_a1b2c3d4e5f6

// Validate and consume (one-time use)
nonce_mgr.validate_and_consume(&nonce, "user_123").await?;

// Second use fails (replay attack detected)
match nonce_mgr.validate_and_consume(&nonce, "user_123").await {
    Err(SaTokenError::NonceAlreadyUsed) => {
        println!("Replay attack prevented!");
    }
    _ => {}
}
```

### Refresh Token Manager

Token refresh mechanism:

```rust
use sa_token_core::RefreshTokenManager;

let refresh_mgr = RefreshTokenManager::new(storage, config);

// Generate refresh token
let refresh_token = refresh_mgr.generate("user_123");
refresh_mgr.store(&refresh_token, &access_token, "user_123").await?;

// Refresh access token when expired
let (new_access_token, user_id) = refresh_mgr
    .refresh_access_token(&refresh_token)
    .await?;

// Validate refresh token
let login_id = refresh_mgr.validate(&refresh_token).await?;

// Delete refresh token
refresh_mgr.delete(&refresh_token).await?;
```

### OAuth2 Manager

Complete OAuth2 authorization code flow:

```rust
use sa_token_core::{OAuth2Manager, OAuth2Client, AccessToken};

let oauth2 = OAuth2Manager::new(storage)
    .with_ttl(600, 3600, 2592000); // code, access, refresh TTL

// Register OAuth2 client
let client = OAuth2Client {
    client_id: "web_app_001".to_string(),
    client_secret: "secret_abc123xyz".to_string(),
    redirect_uris: vec!["http://localhost:3000/callback".to_string()],
    grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
    scope: vec!["read".to_string(), "write".to_string(), "profile".to_string()],
};

oauth2.register_client(&client).await?;

// Authorization code flow
let auth_code = oauth2.generate_authorization_code(
    "web_app_001".to_string(),
    "user_123".to_string(),
    "http://localhost:3000/callback".to_string(),
    vec!["read".to_string(), "profile".to_string()],
);

oauth2.store_authorization_code(&auth_code).await?;

// Exchange code for tokens
let token = oauth2.exchange_code_for_token(
    &auth_code.code,
    "web_app_001",
    "secret_abc123xyz",
    "http://localhost:3000/callback",
).await?;

// Verify access token
let token_info = oauth2.verify_access_token(&token.access_token).await?;

// Refresh token
let new_token = oauth2.refresh_access_token(
    token.refresh_token.as_ref().unwrap(),
    "web_app_001",
    "secret_abc123xyz",
).await?;

// Revoke token
oauth2.revoke_token(&token.access_token).await?;
```

## Configuration

### Basic Configuration

```rust
use sa_token_core::{SaTokenConfig, TokenStyle};

let config = SaTokenConfig::default()
    .with_token_name("Authorization")
    .with_timeout(7200)           // 2 hours
    .with_is_concurrent(false)    // Single device login
    .with_is_share(false)         // No session sharing
    .with_token_style(TokenStyle::Uuid)
    .with_is_log(true);           // Enable logging
```

### JWT Configuration

```rust
let config = SaTokenConfig::default()
    .with_token_style(TokenStyle::Jwt)
    .with_jwt_secret_key("your-256-bit-secret-key")
    .with_jwt_algorithm("HS256")
    .with_jwt_issuer("sa-token-rust")
    .with_jwt_audience("your-app");
```

### Security Configuration

```rust
let config = SaTokenConfig::default()
    // Enable Nonce
    .with_enable_nonce(true)
    .with_nonce_timeout(300)  // 5 minutes
    
    // Enable Refresh Token
    .with_enable_refresh_token(true)
    .with_refresh_token_timeout(2592000);  // 30 days
```

## Architecture

```
sa-token-core/
├── config.rs         # Configuration and builder
├── manager.rs        # SaTokenManager (core manager with event support)
├── util.rs           # StpUtil (utility class for simplified API)
├── error.rs          # Error definitions (32 types in 10 categories)
├── session/          # Session management
├── permission/       # Permission and role control
├── event/            # Event system (bus, listeners, event types)
├── token/            # Token management
│   ├── generator.rs  # Token generation (7 styles)
│   ├── validator.rs  # Token validation
│   ├── jwt.rs        # JWT implementation (8 algorithms)
│   └── mod.rs        # Token types
├── nonce.rs          # Nonce manager (replay attack prevention)
├── refresh.rs        # Refresh token manager
└── oauth2.rs         # OAuth2 authorization code flow
```

## Error Handling

All errors are defined in `error.rs` with 32 types across 10 categories:

```rust
use sa_token_core::SaTokenError;

match manager.login("user_123").await {
    Ok(token) => println!("Login successful"),
    Err(SaTokenError::NotLogin) => println!("Not logged in"),
    Err(SaTokenError::TokenExpired) => println!("Token expired"),
    Err(SaTokenError::PermissionDenied(perm)) => println!("Missing permission: {}", perm),
    Err(SaTokenError::NonceAlreadyUsed) => println!("Replay attack detected"),
    Err(SaTokenError::OAuth2InvalidCredentials) => println!("Invalid OAuth2 credentials"),
    Err(e) => println!("Error: {}", e),
}
```

See [Error Reference](../docs/ERROR_REFERENCE.md) for complete error documentation in 7 languages:
- English
- 中文 (Chinese)
- ภาษาไทย (Thai)
- Tiếng Việt (Vietnamese)
- ភាសាខ្មែរ (Khmer)
- Bahasa Melayu (Malay)
- မြန်မာဘာသာ (Burmese)

## Examples

Run the examples to see features in action:

```bash
# Event listeners
cargo run --example event_listener_example

# JWT authentication
cargo run --example jwt_example

# Token styles (all 7 styles)
cargo run --example token_styles_example

# Security features (Nonce + Refresh Token)
cargo run --example security_features_example

# OAuth2 authorization flow
cargo run --example oauth2_example
```

## Token Styles Reference

| Style | Format | Use Case | Example |
|-------|--------|----------|---------|
| **Uuid** | Standard UUID | Default, widely compatible | `550e8400-e29b-41d4-a716-446655440000` |
| **SimpleUuid** | UUID without hyphens | Compact format | `550e8400e29b41d4a716446655440000` |
| **Random32** | 32 random chars | Short tokens | `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6` |
| **Random64** | 64 random chars | Medium tokens | `a1b2c3d4...` (64 chars) |
| **Random128** | 128 random chars | Long tokens | `a1b2c3d4...` (128 chars) |
| **Jwt** | JSON Web Token | Self-contained | `eyJhbGciOiJIUzI1NiIsInR5cCI...` |
| **Hash** | SHA256 hash | Traceable to user | `5f4dcc3b5aa765d61d8327deb882cf99` |
| **Timestamp** | Timestamp + random | Time-aware | `1728876543_a1b2c3d4` |
| **Tik** | Short alphanumeric | URL/QR friendly | `aB3dE9fG2h` |

## Security Features

### Nonce (Replay Attack Prevention)

Prevents duplicate requests and replay attacks:
- One-time use nonces
- Timestamp-based validation
- Configurable time window
- Automatic expiration

```rust
let nonce_mgr = NonceManager::new(storage, 300);
let nonce = nonce_mgr.generate();
nonce_mgr.validate_and_consume(&nonce, "user_123").await?;
```

### Refresh Token

Long-lived tokens for refreshing access tokens:
- Separate refresh token lifecycle
- Secure refresh flow
- Automatic cleanup
- Configurable TTL (default 30 days)

```rust
let refresh_mgr = RefreshTokenManager::new(storage, config);
let refresh_token = refresh_mgr.generate("user_123");
let (new_access_token, user_id) = refresh_mgr
    .refresh_access_token(&refresh_token).await?;
```

### OAuth2 Authorization

Complete OAuth2 authorization code flow:
- Client registration and verification
- Authorization code generation (10 min TTL)
- Access token issuance (1 hour TTL)
- Refresh token support (30 days TTL)
- Redirect URI validation
- Scope permission control
- Token revocation

```rust
let oauth2 = OAuth2Manager::new(storage);
oauth2.register_client(&client).await?;
let auth_code = oauth2.generate_authorization_code(...);
let token = oauth2.exchange_code_for_token(...).await?;
```

## Performance

- **Async/await**: Non-blocking I/O operations
- **Zero-copy**: Minimal memory allocations
- **Concurrent**: Thread-safe with Arc and RwLock
- **Efficient**: Storage-level TTL for automatic cleanup

## Testing

Run all tests:

```bash
cargo test --package sa-token-core
```

Run specific test module:

```bash
cargo test --package sa-token-core jwt
cargo test --package sa-token-core oauth2
cargo test --package sa-token-core nonce
cargo test --package sa-token-core event
```

## Documentation

### Core Guides
- [Architecture](../docs/ARCHITECTURE.md)
- [Quick Start](../docs/QUICK_START.md)
- [Error Reference](../docs/ERROR_REFERENCE.md) - 7 languages

### Feature Guides
- [JWT Guide](../docs/JWT_GUIDE.md) | [中文](../docs/JWT_GUIDE_zh-CN.md)
- [OAuth2 Guide](../docs/OAUTH2_GUIDE.md) | [中文](../docs/OAUTH2_GUIDE_zh-CN.md)
- [Event Listener](../docs/EVENT_LISTENER.md) | [中文](../docs/EVENT_LISTENER_zh-CN.md)
- [StpUtil API](../docs/StpUtil.md)

## Author

**金书记**

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

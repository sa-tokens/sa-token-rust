# JWT (JSON Web Token) Complete Guide

[中文](/zh/guide/jwt.md) | English

---

## Overview

sa-token-rust provides complete JWT (JSON Web Token) functionality, supporting token generation, validation, refresh, and custom claims.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [JWT Manager](#jwt-manager)
- [JWT Claims](#jwt-claims)
- [Integration with sa-token](#integration-with-sa-token)
- [Algorithms](#algorithms)
- [Advanced Usage](#advanced-usage)
- [API Reference](#api-reference)

## Features

- ✅ Multiple algorithm support (HS256, HS384, HS512, RS256, etc.)
- ✅ Custom claims
- ✅ Token validation
- ✅ Token refresh
- ✅ Expiration time management
- ✅ Issuer and audience verification
- ✅ Seamless integration with sa-token
- ✅ Fast user identification

## Quick Start

### 1. Standalone JWT Manager

```rust
use sa_token_core::{JwtManager, JwtClaims};

// Create JWT manager
let jwt_manager = JwtManager::new("your-secret-key");

// Create claims
let mut claims = JwtClaims::new("user_123");
claims.set_expiration(3600); // 1 hour

// Generate token
let token = jwt_manager.generate(&claims)?;

// Validate token
let decoded_claims = jwt_manager.validate(&token)?;
println!("User ID: {}", decoded_claims.login_id);
```

### 2. Using JWT with sa-token

```rust
use sa_token_core::{SaTokenConfig, SaTokenManager, StpUtil};
use sa_token_core::config::TokenStyle;
use std::sync::Arc;

// Configure to use JWT tokens
let config = SaTokenConfig::builder()
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("my-secret-key")
    .jwt_algorithm("HS256")
    .timeout(7200)
    .build_config();

let manager = SaTokenManager::new(storage, config);
StpUtil::init_manager(manager);

// Login generates JWT token
let token = StpUtil::login("user_123").await?;
```

## JWT Manager

### Creating JWT Manager

```rust
use sa_token_core::{JwtManager, JwtAlgorithm};

// Default (HS256)
let manager = JwtManager::new("secret-key");

// With custom algorithm
let manager = JwtManager::with_algorithm("secret-key", JwtAlgorithm::HS512);

// With issuer and audience
let manager = JwtManager::new("secret-key")
    .set_issuer("my-app")
    .set_audience("web-users");
```

### Generating Tokens

```rust
let mut claims = JwtClaims::new("user_123");
claims.set_expiration(3600);

let token = jwt_manager.generate(&claims)?;
```

### Validating Tokens

```rust
// Full validation (signature + expiration)
let claims = jwt_manager.validate(&token)?;

// Decode without validation (unsafe - for debugging only)
let claims = jwt_manager.decode_without_validation(&token)?;
```

### Refreshing Tokens

```rust
// Extend token validity by 2 hours
let new_token = jwt_manager.refresh(&token, 7200)?;
```

## JWT Claims

### Standard Claims

```rust
let mut claims = JwtClaims::new("user_123");

// Set expiration (seconds from now)
claims.set_expiration(3600);

// Set specific expiration time
claims.set_expiration_at(datetime);

// Set issuer
claims.set_issuer("my-application");

// Set audience
claims.set_audience("web-app");

// Set JWT ID
claims.set_jti("unique-id-123");
```

### sa-token Extensions

```rust
// Set login type
claims.set_login_type("admin");

// Set device identifier
claims.set_device("mobile-ios");
```

### Custom Claims

```rust
use serde_json::json;

// Add custom claims
claims.add_claim("role", json!("admin"));
claims.add_claim("permissions", json!(["read", "write"]));
claims.add_claim("metadata", json!({
    "department": "IT",
    "level": 5
}));

// Retrieve custom claims
let role = claims.get_claim("role");
```

### JWT with Extra Data at Login Time

```rust
use sa_token_core::StpUtil;
use serde_json::json;

// Login with extra data signed into JWT claims
let token = StpUtil::builder("user_123")
    .extra_data(json!({
        "role": "admin",
        "tenant_id": 42,
        "permissions": ["read", "write"]
    }))
    .login(None)
    .await?;

// The extra data is embedded in the JWT token itself (not just stored in session)
// JWT 模式下 extra_data 直接签入 JWT 声明中
```

### Checking Expiration

```rust
// Check if expired
if claims.is_expired() {
    println!("Token has expired");
}

// Get remaining time
if let Some(seconds) = claims.remaining_time() {
    println!("Token valid for {} seconds", seconds);
}
```

## Integration with sa-token

### Configuration

```rust
use sa_token_core::SaTokenConfig;
use sa_token_core::config::TokenStyle;

let config = SaTokenConfig::builder()
    // Set token style to JWT
    .token_style(TokenStyle::Jwt)
    
    // Required: JWT secret key
    .jwt_secret_key("your-secret-key-min-32-chars")
    
    // Optional: Algorithm (default: HS256)
    .jwt_algorithm("HS256")
    
    // Optional: Issuer
    .jwt_issuer("my-application")
    
    // Optional: Audience
    .jwt_audience("web-users")
    
    // Token timeout
    .timeout(7200)
    
    .build_config();
```

### Usage

Once configured, all sa-token operations automatically use JWT:

```rust
// Login - generates JWT token
let token = StpUtil::login("user_123").await?;

// Logout
StpUtil::logout(&token).await?;

// Validate
let is_valid = StpUtil::is_login(&token).await;
```

## Algorithms

Supported JWT algorithms:

| Algorithm | Description | Key Type |
|-----------|-------------|----------|
| HS256 | HMAC using SHA-256 | Symmetric (Secret) |
| HS384 | HMAC using SHA-384 | Symmetric (Secret) |
| HS512 | HMAC using SHA-512 | Symmetric (Secret) |
| RS256 | RSA using SHA-256 | Asymmetric (Public/Private) |
| RS384 | RSA using SHA-384 | Asymmetric (Public/Private) |
| RS512 | RSA using SHA-512 | Asymmetric (Public/Private) |
| ES256 | ECDSA using SHA-256 | Asymmetric (Public/Private) |
| ES384 | ECDSA using SHA-384 | Asymmetric (Public/Private) |

### Choosing an Algorithm

- **HS256/384/512**: Best for most applications, fast and simple
- **RS256/384/512**: When you need to distribute public keys for verification
- **ES256/384**: Modern alternative to RSA, smaller keys

## Advanced Usage

### 1. Token Validation with Custom Validation

```rust
let jwt_manager = JwtManager::new("secret")
    .set_issuer("expected-issuer")
    .set_audience("expected-audience");

// Validation will check issuer and audience
let claims = jwt_manager.validate(&token)?;
```

### 2. Quick User Identification

```rust
// Extract user ID without full validation (for logging, analytics)
let user_id = jwt_manager.extract_login_id(&token)?;
```

### 3. Multiple Algorithms

```rust
// Different managers for different purposes
let user_manager = JwtManager::with_algorithm("user-secret", JwtAlgorithm::HS256);
let admin_manager = JwtManager::with_algorithm("admin-secret", JwtAlgorithm::HS512);
```

### 4. Custom Token Lifetime

```rust
let mut claims = JwtClaims::new("user_123");

// Short-lived token (5 minutes)
claims.set_expiration(300);

// Long-lived token (30 days)
claims.set_expiration(2592000);

// Never expires (not recommended for production)
// Don't set expiration
```

## API Reference

### JwtManager

```rust
impl JwtManager {
    // Create new manager
    pub fn new(secret: impl Into<String>) -> Self;
    pub fn with_algorithm(secret: impl Into<String>, algorithm: JwtAlgorithm) -> Self;
    
    // Configure
    pub fn set_issuer(self, issuer: impl Into<String>) -> Self;
    pub fn set_audience(self, audience: impl Into<String>) -> Self;
    
    // Operations
    pub fn generate(&self, claims: &JwtClaims) -> SaTokenResult<String>;
    pub fn validate(&self, token: &str) -> SaTokenResult<JwtClaims>;
    pub fn refresh(&self, token: &str, extend_seconds: i64) -> SaTokenResult<String>;
    pub fn extract_login_id(&self, token: &str) -> SaTokenResult<String>;
    pub fn decode_without_validation(&self, token: &str) -> SaTokenResult<JwtClaims>;
}
```

### JwtClaims

```rust
impl JwtClaims {
    // Create
    pub fn new(login_id: impl Into<String>) -> Self;
    
    // Standard claims
    pub fn set_expiration(&mut self, seconds: i64) -> &mut Self;
    pub fn set_expiration_at(&mut self, datetime: DateTime<Utc>) -> &mut Self;
    pub fn set_issuer(&mut self, issuer: impl Into<String>) -> &mut Self;
    pub fn set_audience(&mut self, audience: impl Into<String>) -> &mut Self;
    pub fn set_jti(&mut self, jti: impl Into<String>) -> &mut Self;
    
    // sa-token extensions
    pub fn set_login_type(&mut self, login_type: impl Into<String>) -> &mut Self;
    pub fn set_device(&mut self, device: impl Into<String>) -> &mut Self;
    
    // Custom claims
    pub fn add_claim(&mut self, key: impl Into<String>, value: Value) -> &mut Self;
    pub fn get_claim(&self, key: &str) -> Option<&Value>;
    
    // Utilities
    pub fn is_expired(&self) -> bool;
    pub fn remaining_time(&self) -> Option<i64>;
}
```

## Security Best Practices

1. **Use Strong Secrets**: Minimum 32 characters for HMAC algorithms
2. **Rotate Keys**: Periodically change your secret keys
3. **Set Expiration**: Always set reasonable expiration times
4. **Validate Everything**: Use full validation, not just decoding
5. **HTTPS Only**: Always transmit JWTs over HTTPS
6. **Store Securely**: Never expose secrets in code or logs
7. **Handle Errors**: Properly handle validation errors
8. **Avoid Sensitive Data**: Don't store sensitive information in claims (they're just base64-encoded)

## Error Handling

```rust
use sa_token_core::SaTokenError;

match jwt_manager.validate(&token) {
    Ok(claims) => {
        // Token is valid
        println!("User: {}", claims.login_id);
    }
    Err(SaTokenError::TokenExpired) => {
        // Token has expired
        println!("Please login again");
    }
    Err(SaTokenError::InvalidToken(msg)) => {
        // Invalid token (signature, format, etc.)
        println!("Invalid token: {}", msg);
    }
    Err(e) => {
        // Other errors
        println!("Error: {:?}", e);
    }
}
```

## Examples

Run the JWT example:

```bash
cargo run --example jwt_example
```

See `examples/jwt_example.rs` for comprehensive examples covering:
- Standalone JWT usage
- Integration with sa-token
- Token refresh
- Multiple algorithms
- Custom claims
- Quick user identification

## References

- [JWT.io](https://jwt.io/) - JWT introduction and debugger
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT specification
- [jsonwebtoken crate](https://docs.rs/jsonwebtoken/) - Underlying library

## Next Steps

- [StpUtil API Reference](/guide/stp-util.md)
- [Event Listeners](/guide/event-listener.md)
- [Permission Matching](/guide/permission-matching.md)


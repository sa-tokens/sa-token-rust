# Security Features

[中文文档](/zh/guide/security-features.md) | English

sa-token-rust provides built-in security mechanisms to protect against common attack vectors.

## Nonce (Replay Attack Prevention)

A nonce is a one-time-use random value that prevents replay attacks. Each nonce can only be validated and consumed once.

```rust
use sa_token_core::NonceManager;

let nonce_manager = NonceManager::new(storage, 300); // 5 minutes TTL

// Generate nonce
let nonce = nonce_manager.generate();

// Validate and consume (one-time use)
nonce_manager.validate_and_consume(&nonce, "user_123").await?;

// Second use will fail (replay attack detected)
match nonce_manager.validate_and_consume(&nonce, "user_123").await {
    Err(_) => println!("Replay attack prevented!"),
    _ => {}
}
```

### How It Works

1. The server generates a unique nonce value and sends it to the client
2. The client includes the nonce in its request
3. The server validates the nonce and marks it as "consumed"
4. Any subsequent request with the same nonce is rejected

This ensures that even if an attacker captures a valid request, they cannot replay it because the nonce has already been used.

### Configuration

- **TTL (Time To Live)**: Controls how long a nonce remains valid before it expires. Default: 300 seconds (5 minutes).
- **Storage**: Nonces are stored in the configured storage backend (memory, Redis, or database).

---

## Automatic Token Renewal (auto_renew)

When enabled, tokens are automatically renewed on every access. Configure via `SaTokenConfig`:

```rust
let config = SaTokenConfig::builder()
    .auto_renew(true)           // Enable auto-renewal
    .active_timeout(1800)       // Renew by this amount (if > 0)
    .timeout(86400)             // Or fall back to this
    .build_config();

// Token auto-renewal happens on:
// - get_token_info() calls
// - Middleware token validation
// - Parameterless StpUtil methods
```

**Behavior**: If `active_timeout > 0`, the token is renewed by `active_timeout` seconds on each access. Otherwise, it uses `timeout` as the renewal duration.

---

## Refresh Token

Refresh tokens allow clients to obtain new access tokens without requiring the user to re-authenticate.

```rust
use sa_token_core::RefreshTokenManager;

let refresh_manager = RefreshTokenManager::new(storage, config);

// Generate refresh token
let refresh_token = refresh_manager.generate("user_123");
refresh_manager.store(&refresh_token, &access_token, "user_123").await?;

// Refresh access token when expired
let (new_access_token, user_id) = refresh_manager
    .refresh_access_token(&refresh_token)
    .await?;
```

### Token Lifecycle

```
User Login
    │
    ├──► Access Token (short-lived, e.g., 2 hours)
    │
    └──► Refresh Token (long-lived, e.g., 30 days)
              │
              │  Access token expires
              │
              └──► Use Refresh Token to get new Access Token
                        │
                        │  Refresh token expires or revoked
                        │
                        └──► User must re-authenticate
```

### Security Considerations

- **Access tokens** should be short-lived (minutes to hours)
- **Refresh tokens** should be long-lived but revocable (days to weeks)
- Always store refresh tokens securely
- Rotate refresh tokens on each use for enhanced security
- Implement refresh token rotation to detect token theft

---

## Best Practices

### Token Security

1. **Use HTTPS**: Always use TLS in production to protect tokens in transit
2. **Set appropriate timeouts**: Balance security and user experience
3. **Rotate secrets**: Regularly rotate JWT signing keys and other secrets
4. **Validate all inputs**: Never trust client-provided tokens without validation

### Storage Security

1. **Redis**: Use password authentication and TLS for Redis connections in production
2. **Memory**: Only use memory storage for development and testing
3. **Database**: Implement proper indexing and cleanup for expired tokens

### Defense in Depth

- Combine multiple security features: Nonce + Refresh Token + Permission checking
- Use event listeners to log security-relevant events (login, logout, kick-out)
- Monitor for suspicious patterns (rapid login failures, token reuse attempts)

## Run Security Examples

```bash
cargo run --example security_features_example
```

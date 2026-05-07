# StpUtil API Reference

[中文文档](/zh/guide/stp-util.md) | English

`StpUtil` is a utility class that provides a simplified, static API for common authentication and authorization operations. It wraps `SaTokenManager` functionality in an easy-to-use interface.

## Table of Contents

- [Initialization](#initialization)
- [Login Operations](#login-operations)
- [Logout Operations](#logout-operations)
- [Token Validation](#token-validation)
- [Session Management](#session-management)
- [Permission Management](#permission-management)
- [Role Management](#role-management)
- [Advanced Usage](#advanced-usage)

## Initialization

`StpUtil` is automatically initialized when you create `SaTokenState` using any web framework plugin:

```rust
use sa_token_core::StpUtil;
use sa_token_plugin_axum::SaTokenState;  // or any other framework plugin
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

// StpUtil is automatically initialized when building state
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("Authorization")
    .timeout(86400)
    .build();

// StpUtil is ready to use!
StpUtil::login("user_id").await?;
```

**Note**: The initialization happens automatically in `SaTokenState::builder().build()`, so you don't need to call any initialization method manually. This works for all supported web frameworks (Axum, Actix-web, Poem, Rocket, Warp).

## Login Operations

### Basic Login

```rust
use sa_token_core::StpUtil;

// Login with string ID
let token = StpUtil::login("user_10001").await?;
println!("Generated token: {}", token.as_str());

// Login with numeric ID
let token = StpUtil::login(10001).await?;  // i32, i64, u32, u64 supported
```

### Fluent Login Builder

```rust
use sa_token_core::StpUtil;
use serde_json::json;

// Chainable builder-style login with extra metadata
let token = StpUtil::builder("user_123")
    .extra_data(json!({"ip": "192.168.1.1"}))
    .device("pc")
    .login_type("admin")
    .login(None) // None => use builder login_id; Some("other_id") overrides
    .await?;
let token = StpUtil::builder("user_123")
    .extra_data(json!({"ip": "192.168.1.1"}))
    .device("pc")
    .login_type("admin")
    .login(Some("new_user_456"))  // 或 Some(10001) 数字ID
    .await?;    
```

### Login with Device Identification

```rust
// Login with device info (for multi-device management)
let token = StpUtil::builder("user_10001")
    .device("mobile_ios")
    .login(None)
    .await?;
```

### Login with Type

```rust
// Login with a specific login type (e.g., "admin", "user", "api")
let token = StpUtil::login_with_type("user_10001", "admin").await?;
```

### Login with Extra Data

```rust
use serde_json::json;

// Login and attach extra data (signed into JWT claims when using JWT style)
let token = StpUtil::login_with_extra(
    "user_10001",
    json!({"ip": "192.168.1.1", "device": "mobile"})
).await?;
```

### Login with Explicit Manager

```rust
// Login using a specific SaTokenManager instance (bypassing global StpUtil)
let token = StpUtil::login_with_manager(&manager, "user_10001").await?;
```

## Logout Operations

### Logout Current User

```rust
// Logout by login_id
StpUtil::logout_by_login_id("user_10001").await?;

// Logout by token (takes &TokenValue)
StpUtil::logout(&token).await?;

// Or use the alias
StpUtil::logout_by_token(&token).await?;
```

### Logout from Specific Device

```rust
// Logout from a specific device (logout by login_id removes all device sessions)
StpUtil::logout_by_login_id("user_10001").await?;
```

### Kick User Offline

```rust
// Force logout (kick offline) — removes all sessions for a user
StpUtil::kick_out("user_10001").await?;

// Kick multiple users at once
StpUtil::kick_out_batch(&["user_10001", "user_10002", "user_10003"]).await?;
```

### Context-Aware Logout (Request Handler)

```rust
// Logout the current request's user (extracts token from request context)
StpUtil::logout_current().await?;
```

## Token Validation

### Check Login Status

```rust
use sa_token_core::token::TokenValue;

let token = TokenValue::new("your_token_string".to_string());

// Check if token is valid (logged in)
let is_logged_in = StpUtil::is_login(&token).await;

// Check by login_id
let is_logged_in = StpUtil::is_login_by_login_id("user_10001").await;
```

### Require Login (Error if Not)

```rust
// Returns Err(NotLogin) if token is invalid
StpUtil::check_login(&token).await?;
```

### Get Token Info

```rust
// Get full token metadata
let token_info = StpUtil::get_token_info(&token).await?;
println!("Login ID: {}", token_info.login_id);
println!("Device: {:?}", token_info.device);
println!("Expires: {:?}", token_info.expire_time);
```

### Get Login ID from Token

```rust
// Get login_id from token value
let login_id = StpUtil::get_login_id(&token).await?;

// Get login_id with default fallback
let login_id = StpUtil::get_login_id_or_default(&token, "anonymous").await;
```

### Get Token by Login ID

```rust
// Retrieve the current token for a user
let token = StpUtil::get_token_by_login_id("user_10001").await?;

// Get all active tokens (multi-device)
let tokens = StpUtil::get_all_tokens_by_login_id("user_10001").await?;
```

### Token Timeout Management

```rust
// Get remaining timeout for a token
if let Some(remaining) = StpUtil::get_token_timeout(&token).await? {
    println!("Token expires in {} seconds", remaining);
}

// Manually renew token timeout
StpUtil::renew_timeout(&token, 3600).await?; // extend by 1 hour
```

### Token Utilities

```rust
// Create a raw TokenValue (does not login)
let raw = StpUtil::create_token("custom_token_string");

// Check token format (length >= 16, non-empty)
if StpUtil::is_valid_token_format("my_token_string_16ch") {
    println!("Token format is valid");
}
```

### Context-Aware Token Methods (Request Handler)

```rust
// In a request handler (token already injected by middleware):
// These methods read from the request-scoped SaTokenContext.

// Get current token value
let token = StpUtil::get_token_value()?;

// Get current token info
let info = StpUtil::get_token_info_current()?;

// Check if current request is authenticated
if StpUtil::is_login_current() {
    println!("Request is authenticated");
}

// Require login for current request (returns error if not)
StpUtil::check_login_current()?;

// Get current login_id as String
let login_id = StpUtil::get_login_id_as_string().await?;

// Get current login_id as i64
let user_id = StpUtil::get_login_id_as_long().await?;
```

## Session Management

### Get Session

```rust
// Get user session (async — stored in backend)
let session = StpUtil::get_session("user_10001").await?;

// Store data in session (sync — operates on in-memory SaSession object)
session.set("username", "John Doe".to_string())?;
session.set("email", "john@example.com".to_string())?;

// Save session to persist changes to backend
StpUtil::save_session(&session).await?;

// Retrieve data from session
let username: Option<String> = session.get("username");
println!("Username: {:?}", username);
```

### Session Operations

```rust
// Check if key exists
let exists = session.has("email");

// Remove a key
session.remove("email");

// Clear all session data
session.clear();

// Save after modifications
StpUtil::save_session(&session).await?;
```

### Delete Session

```rust
// Delete user session
StpUtil::delete_session("user_10001").await?;
```

### Session Convenience Methods

```rust
// Set a single session value (get→set→save in one call)
StpUtil::set_session_value("user_10001", "theme", "dark").await?;

// Get a single session value
let theme: Option<String> = StpUtil::get_session_value("user_10001", "theme").await?;
```

### Access Session Data Directly

```rust
let session = StpUtil::get_session("user_10001").await?;

// session.data is a public HashMap — use standard HashMap methods
let keys: Vec<&String> = session.data.keys().collect();
let values: Vec<&serde_json::Value> = session.data.values().collect();
let count = session.data.len();
```

## Permission Management

### Set Permissions

```rust
// Set user permissions
StpUtil::set_permissions(
    "user_10001",
    vec![
        "user:list".to_string(),
        "user:add".to_string(),
        "user:edit".to_string(),
        "user:delete".to_string(),
    ]
).await?;
```

### Check Permissions

```rust
// Check if user has a permission
let has_permission = StpUtil::has_permission("user_10001", "user:delete").await;

if has_permission {
    println!("User can delete");
} else {
    println!("User cannot delete");
}
```

### Check Multiple Permissions

```rust
// Primary method names:
let has_all = StpUtil::has_all_permissions(
    "user_10001",
    &["user:list", "user:add"]
).await;

let has_any = StpUtil::has_any_permission(
    "user_10001",
    &["user:delete", "admin:all"]
).await;

// Aliases (same behavior):
let has_all = StpUtil::has_permissions_and("user_10001", &["user:list", "user:add"]).await;
let has_any = StpUtil::has_permissions_or("user_10001", &["user:delete", "admin:all"]).await;
```

### Add / Remove Single Permission

```rust
// Add a single permission
StpUtil::add_permission("user_10001", "user:export").await?;

// Remove a single permission
StpUtil::remove_permission("user_10001", "user:export").await?;
```

### Get User Permissions

```rust
// Get all permissions for a user
let permissions = StpUtil::get_permissions("user_10001").await;
println!("User permissions: {:?}", permissions);
```

### Clear Permissions

```rust
// Clear all permissions for a user
StpUtil::clear_permissions("user_10001").await?;
```

## Role Management

### Set Roles

```rust
// Set user roles
StpUtil::set_roles(
    "user_10001",
    vec![
        "user".to_string(),
        "vip".to_string(),
    ]
).await?;

// Set admin role
StpUtil::set_roles(
    "admin_10001",
    vec!["admin".to_string()]
).await?;
```

### Check Roles

```rust
// Check if user has a role
let is_admin = StpUtil::has_role("user_10001", "admin").await;

if is_admin {
    println!("User is admin");
}
```

### Check Multiple Roles

```rust
// Check if user has all roles (AND)
let has_all_roles = StpUtil::has_roles_and(
    "user_10001",
    &["user", "vip"]
).await;

// Check if user has any role (OR)
let has_any_role = StpUtil::has_roles_or(
    "user_10001",
    &["admin", "moderator"]
).await;
```

### Get User Roles

```rust
// Get all roles for a user
let roles = StpUtil::get_roles("user_10001").await;
println!("User roles: {:?}", roles);
```

### Clear Roles

```rust
// Clear all roles for a user
StpUtil::clear_roles("user_10001").await?;
```

### Check / Add / Remove Single Role

```rust
// Require a role (returns error if missing)
StpUtil::check_role("user_10001", "admin").await?;

// Add a single role
StpUtil::add_role("user_10001", "moderator").await?;

// Remove a single role
StpUtil::remove_role("user_10001", "moderator").await?;
```

## Token Extra Data

```rust
use serde_json::json;

// Set extra data on an existing token
StpUtil::set_extra_data(&token, json!({"plan": "premium", "quota": 100})).await?;

// Get extra data from a token
let extra: Option<serde_json::Value> = StpUtil::get_extra_data(&token).await?;
if let Some(data) = extra {
    println!("Plan: {}", data["plan"]);
}
```

## Advanced Usage

### Complete Login Flow Example

```rust
use sa_token_core::StpUtil;

// 1. User login
let login_id = "user_10001";
let token = StpUtil::login(login_id).await?;

// 2. Set user permissions
StpUtil::set_permissions(
    login_id,
    vec![
        "user:list".to_string(),
        "user:add".to_string(),
        "post:create".to_string(),
    ]
).await?;

// 3. Set user roles
StpUtil::set_roles(
    login_id,
    vec!["user".to_string(), "author".to_string()]
).await?;

// 4. Store additional data in session
let mut session = StpUtil::get_session(login_id).await?;
session.set("username", "John Doe".to_string())?;
session.set("email", "john@example.com".to_string())?;
session.set("last_login", chrono::Utc::now().to_string())?;
StpUtil::save_session(&session).await?;

// Return token to client
Ok(token.as_str().to_string())
```

### Token Validation in Middleware

```rust
use sa_token_core::StpUtil;
use sa_token_core::token::TokenValue;

async fn validate_request(token_string: &str) -> Result<String, String> {
    let token = TokenValue::new(token_string.to_string());
    
    // Validate token (check if logged in)
    if !StpUtil::is_login(&token).await {
        return Err("Invalid token".to_string());
    }
    
    // Get login_id
    let login_id = StpUtil::get_login_id(&token).await
        .map_err(|_| "Cannot get login_id".to_string())?;
    
    // Check if user is still logged in
    if !StpUtil::is_login_by_login_id(&login_id).await {
        return Err("User not logged in".to_string());
    }
    
    Ok(login_id)
}
```

### Permission-based Access Control

```rust
use sa_token_core::StpUtil;

async fn delete_user(operator_id: &str, target_user_id: &str) -> Result<(), String> {
    // Check if operator has delete permission
    if !StpUtil::has_permission(operator_id, "user:delete").await {
        return Err("No permission to delete users".to_string());
    }
    
    // Additional check: admin can delete anyone, user can only delete self
    let is_admin = StpUtil::has_role(operator_id, "admin").await;
    
    if !is_admin && operator_id != target_user_id {
        return Err("Can only delete your own account".to_string());
    }
    
    // Proceed with deletion
    // ... your deletion logic
    
    Ok(())
}
```

### Multi-device Session Management

```rust
use sa_token_core::StpUtil;

// User logs in from different devices via builder
let token_web = StpUtil::builder("user_10001").device("web").login(None).await?;
let token_mobile = StpUtil::builder("user_10001").device("mobile_ios").login(None).await?;
let token_app = StpUtil::builder("user_10001").device("desktop_app").login(None).await?;

// Kick out a specific device (logout all sessions for that login_id via manager)
// Note: StpUtil::kick_out removes all sessions for a user.

// User is still logged in on other devices (concurrent mode)
assert!(StpUtil::is_login_by_login_id("user_10001").await);

// Logout from all devices
StpUtil::logout_by_login_id("user_10001").await?;
```

### Working with Generic Types

```rust
use sa_token_core::StpUtil;

// StpUtil supports any type that implements Display
// This includes: String, &str, i32, i64, u32, u64, etc.

// String login_id
let token1 = StpUtil::login("user_string".to_string()).await?;

// &str login_id
let token2 = StpUtil::login("user_str").await?;

// Numeric login_id
let token3 = StpUtil::login(10001_i32).await?;
let token4 = StpUtil::login(20001_i64).await?;
let token5 = StpUtil::login(30001_u32).await?;

// All methods accept generic types
StpUtil::set_permissions(10001, vec!["user:list".to_string()]).await?;
StpUtil::has_role(20001_i64, "admin").await;
let session = StpUtil::get_session(30001_u32).await?;
```

## Error Handling

All `StpUtil` methods return `Result` types. Handle errors appropriately:

```rust
use sa_token_core::StpUtil;

match StpUtil::login("user_10001").await {
    Ok(token) => {
        println!("Login successful: {}", token.as_str());
    }
    Err(e) => {
        eprintln!("Login failed: {:?}", e);
    }
}

// Or use the ? operator
let token = StpUtil::login("user_10001").await?;
```

## Best Practices

1. **Automatic Initialization**: `StpUtil` is automatically initialized when you build `SaTokenState`, no manual initialization needed.

2. **Error Handling**: Always handle errors from `StpUtil` methods appropriately.

3. **Permission Naming**: Use consistent naming conventions for permissions (e.g., `resource:action`).

4. **Role Hierarchy**: Design a clear role hierarchy (e.g., admin > moderator > user).

5. **Session Data**: Store minimal, non-sensitive data in sessions.

6. **Logout on Security Events**: Always call `logout` or `kick_out` when security-sensitive events occur (password change, etc.).

7. **Token Validation**: Always validate tokens before processing requests.

8. **Generic Types**: Leverage generic `LoginId` support for cleaner code with different ID types.

## See Also

- [Main Documentation](https://github.com/sa-tokens/sa-token-rust)
- [Examples](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/)
- [Web Framework Integration](/guide/framework-integration)


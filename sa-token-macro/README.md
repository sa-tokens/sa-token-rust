# sa-token-macro

Procedural macros for sa-token-rust.

## Features

- 🎯 **Annotation Style**: Java-like annotation syntax
- ✅ **Compile-time Checking**: Catch errors before runtime
- 🔧 **Easy to Use**: Decorator-style authentication
- 📝 **Comprehensive**: All authentication scenarios covered

## Installation

```toml
[dependencies]
sa-token-macro = "0.1.13"
sa-token-core = "0.1.13"
```

## Macros

### Login Check

```rust
use sa_token_macro::sa_check_login;

#[sa_check_login]
async fn protected_route() -> &'static str {
    "This route requires login"
}
```

### Permission Check

```rust
use sa_token_macro::sa_check_permission;

#[sa_check_permission("user:list")]
async fn list_users() -> &'static str {
    "User list"
}
```

### Role Check

```rust
use sa_token_macro::sa_check_role;

#[sa_check_role("admin")]
async fn admin_panel() -> &'static str {
    "Admin panel"
}
```

### Multiple Permissions (AND)

```rust
use sa_token_macro::sa_check_permissions_and;

#[sa_check_permissions_and("user:list", "user:edit")]
async fn manage_users() -> &'static str {
    "Manage users"
}
```

### Multiple Permissions (OR)

```rust
use sa_token_macro::sa_check_permissions_or;

#[sa_check_permissions_or("user:view", "user:list")]
async fn view_users() -> &'static str {
    "View users"
}
```

### Ignore Authentication

```rust
use sa_token_macro::sa_ignore;

#[sa_ignore]
async fn public_route() -> &'static str {
    "Public access"
}
```

## Permission Matching Rules

See [Permission Matching Documentation](../docs/PermissionMatching.md) for detailed rules.

## Author

**金书记**

## License

Licensed under either of Apache-2.0 or MIT.

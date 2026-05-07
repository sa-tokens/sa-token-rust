# SSO Single Sign-On Guide

## 🇬🇧 English

### Overview

sa-token-rust provides a complete Single Sign-On (SSO) solution based on ticket authentication. Users only need to log in once to access multiple applications seamlessly.

### Key Features

- 🎫 **Ticket-based Authentication**: Secure, one-time use tickets
- 🔐 **Unified Login**: Log in once, access all applications
- 🚪 **Unified Logout**: Log out from all applications at once
- 🌐 **Cross-domain Support**: Configurable origin whitelist
- ⏱️ **Ticket Expiration**: Automatic ticket expiration and cleanup
- 🛡️ **Security Protection**: Service URL matching, replay attack prevention
- 🔄 **Session Management**: Track all logged-in applications
- 🔑 **Token Type Isolation**: SSO server and client tokens are isolated by `login_type`
- 📊 **Enhanced Token Info**: SSO context stored in token `extra_data` for traceability

### Core Components

#### 1. SsoServer - SSO Server

The SSO Server is the central authentication service that:
- Manages user authentication
- Generates and validates tickets
- Maintains global session state
- Handles unified logout
- Tracks active client applications

#### 2. SsoClient - SSO Client

Each application acts as an SSO Client that:
- Checks local login status
- Generates login/logout URLs
- Validates tickets from SSO Server
- Creates local sessions
- Handles logout callbacks

#### 3. SsoTicket - Authentication Ticket

A ticket is a short-lived, one-time use authentication token that contains:
- `ticket_id`: Unique ticket identifier (UUID)
- `service`: Target application URL
- `login_id`: User identifier
- `create_time`: Ticket creation time
- `expire_time`: Ticket expiration time
- `used`: Usage status flag

### Architecture Flow

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   User      │         │ SSO Server  │         │   Client    │
│  Browser    │         │   (Auth)    │         │   App 1     │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │  1. Access App 1      │                       │
       ├───────────────────────┼──────────────────────>│
       │                       │                       │
       │  2. Redirect to SSO   │                       │
       │<──────────────────────┼───────────────────────┤
       │                       │                       │
       │  3. Login Request     │                       │
       ├──────────────────────>│                       │
       │                       │                       │
       │  4. Create Ticket     │                       │
       │<──────────────────────┤                       │
       │                       │                       │
       │  6. Callback with Ticket                      │
       ├───────────────────────┼──────────────────────>│
       │                       │                       │
       │  7. Validate Ticket   │                       │
       │                       │<──────────────────────┤
       │                       │                       │
       │  8. Ticket Valid      │                       │
       │                       ├──────────────────────>│
       │                       │                       │
       │  9. Create Local Session                      │
       │  10. Access Granted   │                       │
       │<──────────────────────┼───────────────────────┤
```

### Quick Start

#### 1. Basic Setup

```rust
use std::sync::Arc;
use sa_token_core::{SaTokenConfig, SsoServer, SsoClient};
use sa_token_storage_memory::MemoryStorage;

let manager = SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .build();

let manager = Arc::new(manager);
```

#### 2. Create SSO Server

```rust
let sso_server = Arc::new(
    SsoServer::new(manager.clone())
        .with_ticket_timeout(300)  // 5 minutes
);
```

#### 3. Create SSO Clients

```rust
let client1 = Arc::new(SsoClient::new(
    manager.clone(),
    "http://sso.example.com/auth".to_string(),
    "http://app1.example.com".to_string(),
));
```

### Complete Login Flow

#### Step 1: User Logs in at SSO Server

```rust
let ticket = sso_server.login(
    "user_123".to_string(),
    "http://app1.example.com".to_string(),
).await?;
```

#### Step 2: Validate Ticket

```rust
let login_id = sso_server.validate_ticket(
    &ticket.ticket_id,
    "http://app1.example.com",
).await?;
```

#### Step 3: Create Local Session

```rust
let token = client1.login_by_ticket(login_id).await?;
```

### Unified Logout

```rust
let clients = sso_server.logout("user_123").await?;

for client_url in clients {
    // Notify each client to logout
}

client1.handle_logout("user_123").await?;
client2.handle_logout("user_123").await?;
```

### Security Features

**1. One-time Ticket Usage**
```rust
// First validation - succeeds
sso_server.validate_ticket(&ticket_id, service).await?;

// Second validation - fails (ticket already used)
sso_server.validate_ticket(&ticket_id, service).await?; // Error!
```

**2. Service URL Matching**
```rust
// Ticket for App1 cannot be used for App2
sso_server.validate_ticket(&ticket_id, "wrong_service").await?; // ServiceMismatch!
```

### Error Handling

```rust
use sa_token_core::SaTokenError;

match sso_server.validate_ticket(ticket_id, service).await {
    Ok(login_id) => println!("Valid: {}", login_id),
    Err(SaTokenError::InvalidTicket) => println!("Ticket not found"),
    Err(SaTokenError::TicketExpired) => println!("Ticket expired"),
    Err(SaTokenError::ServiceMismatch) => println!("Service mismatch"),
    Err(e) => println!("Other error: {}", e),
}
```

### API Reference

**SsoServer Methods:**
- `new(manager)` - Create new SSO Server
- `with_ticket_timeout(seconds)` - Set ticket expiration time
- `login(login_id, service)` - User login and generate ticket
- `create_ticket(login_id, service)` - Create ticket for logged-in user
- `validate_ticket(ticket_id, service)` - Validate and consume ticket
- `logout(login_id)` - Unified logout
- `is_logged_in(login_id)` - Check if user is logged in
- `get_session(login_id)` - Get user's SSO session
- `get_active_clients(login_id)` - Get list of active clients
- `cleanup_expired_tickets()` - Clean up expired tickets

**SsoClient Methods:**
- `new(manager, server_url, service_url)` - Create new SSO Client
- `with_logout_callback(callback)` - Set logout callback
- `get_login_url()` - Generate login URL
- `get_logout_url()` - Generate logout URL
- `check_local_login(login_id)` - Check local session
- `login_by_ticket(login_id)` - Create local session
- `handle_logout(login_id)` - Handle logout request

### Complete Example

See [sso_example.rs](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/sso_example.rs) for a complete working example.

Run the example:
```bash
cargo run --example sso_example
```

### Related Documentation

- [Event Listener Guide](/guide/event-listener.md)
- [WebSocket Authentication](/guide/websocket-auth.md)
- [Distributed Session](/guide/distributed-session.md)
- [Error Reference](/reference/error-reference.md)

---

<a name="中文"></a>
## 📖 Additional Resources

- [Main Documentation](/guide/quick-start.md)
- [Examples Directory](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/)
- [API Reference](/guide/stp-util.md)

---

**Version**: 0.1.14  
**Last Updated**: 2026-05-07


# sa-token Event Listeners

English | [中文](/zh/guide/event-listener.md)

---

sa-token-rust provides a complete event listening mechanism that allows you to monitor and respond to various authentication-related events.

## Table of Contents

- [Overview](#overview)
- [Event Types](#event-types)
- [Basic Usage](#basic-usage)
- [Custom Listeners](#custom-listeners)
- [Built-in Listeners](#built-in-listeners)
- [Real-world Scenarios](#real-world-scenarios)
- [API Reference](#api-reference)

## Overview

The event listening system is implemented based on the observer pattern, allowing you to execute custom logic when authentication operations (login, logout, kick-out, etc.) occur.

### Core Components

- **SaTokenEvent**: Event data structure
- **SaTokenEventType**: Event type enumeration
- **SaTokenListener**: Listener trait
- **SaTokenEventBus**: Event bus for managing and dispatching events

## Event Types

sa-token supports the following event types:

| Event Type | Description | Trigger Time |
|---------|------|---------|
| `Login` | Login event | When user successfully logs in |
| `Logout` | Logout event | When user actively logs out |
| `KickOut` | Kick-out event | When admin forcibly kicks out a user |
| `RenewTimeout` | Token renewal event | When token expiration time is updated |
| `Replaced` | Replaced event | When user is logged out due to login from another device |
| `Banned` | Banned event | When user account is banned |

## Basic Usage

### 1. Register Listeners

There are three ways to register listeners:

#### ⭐ Method 1: Builder Pattern (Recommended)

```rust
use sa_token_core::SaTokenConfig;
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;

// One-line initialization: create manager + register listeners + initialize StpUtil!
SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .timeout(7200)
    .register_listener(Arc::new(LoggingListener))  // Register here!
    .register_listener(Arc::new(MyListener))  // Support multiple listeners!
    .build();  // Auto-complete all initialization!

// StpUtil is ready to use immediately!
```

#### Method 2: Through SaTokenManager

```rust
use sa_token_core::{SaTokenManager, LoggingListener};
use std::sync::Arc;

// Create manager
let manager = SaTokenManager::new(storage, config);

// Register listener (synchronous, no .await needed!)
manager.event_bus()
    .register(Arc::new(LoggingListener));
```

#### Method 3: Through StpUtil

```rust
use sa_token_core::{StpUtil, LoggingListener};
use std::sync::Arc;

// Register listener (synchronous, no .await needed!)
StpUtil::register_listener(Arc::new(LoggingListener));
```

### 2. Automatic Event Triggering

Once listeners are registered, events are automatically triggered for relevant operations:

```rust
// Login - triggers Login event
let token = StpUtil::login("user_123").await?;

// Logout - triggers Logout event
StpUtil::logout(&token).await?;

// Kick out - triggers KickOut event
StpUtil::kick_out("user_123").await?;
```

## Custom Listeners

### Implement Listener Trait

```rust
use async_trait::async_trait;
use sa_token_core::SaTokenListener;

struct MyListener;

#[async_trait]
impl SaTokenListener for MyListener {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} logged in, token: {}", login_id, token);
        
        // Add your business logic here
        // For example:
        // - Log login to database
        // - Update user's last login time
        // - Send login notification
        // - Update login statistics
    }

    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} logged out", login_id);
    }

    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {
        println!("User {} was kicked out", login_id);
    }

    // Other event methods are optional
    // async fn on_renew_timeout(...) {}
    // async fn on_replaced(...) {}
    // async fn on_banned(...) {}
}
```

### Register and Use

#### Recommended: Builder Pattern

```rust
// Register listener during initialization
SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .register_listener(Arc::new(MyListener))
    .build();

// Use sa-token normally, events will be triggered automatically
let token = StpUtil::login("user_123").await?;
```

#### Alternative: Manual Registration

```rust
// Register listener after initialization (synchronous)
StpUtil::register_listener(Arc::new(MyListener));

// Use sa-token normally, events will be triggered automatically
let token = StpUtil::login("user_123").await?;
```

## Built-in Listeners

### LoggingListener

Built-in logging listener that uses tracing to log all events:

```rust
use sa_token_core::LoggingListener;
use std::sync::Arc;

// Via Builder (Recommended)
SaTokenConfig::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .register_listener(Arc::new(LoggingListener))
    .build();

// Or register manually (synchronous)
StpUtil::register_listener(Arc::new(LoggingListener));
```

Sample output:
```
INFO  User logged in login_id="user_123" token="abc..." login_type="default"
INFO  User logged out login_id="user_123" token="abc..." login_type="default"
WARN  User kicked out login_id="user_123" token="abc..." login_type="default"
```

## Real-world Scenarios

### Scenario 1: Login Log Recording

```rust
struct LoginLogListener {
    db_pool: Arc<DbPool>,
}

#[async_trait]
impl SaTokenListener for LoginLogListener {
    async fn on_login(&self, login_id: &str, token: &str, _login_type: &str) {
        // Record to database
        let log = LoginLog {
            user_id: login_id.to_string(),
            token: token.to_string(),
            login_time: Utc::now(),
            ip_address: get_client_ip(),
        };
        
        if let Err(e) = self.db_pool.insert_login_log(log).await {
            eprintln!("Failed to record login log: {}", e);
        }
    }
}
```

### Scenario 2: Security Monitoring

```rust
struct SecurityMonitorListener {
    alert_service: Arc<AlertService>,
}

#[async_trait]
impl SaTokenListener for SecurityMonitorListener {
    async fn on_login(&self, login_id: &str, _token: &str, _login_type: &str) {
        // Check for suspicious login
        if self.is_suspicious_login(login_id).await {
            self.alert_service.send_alert(
                format!("Suspicious login detected for user: {}", login_id)
            ).await;
        }
    }

    async fn on_kick_out(&self, login_id: &str, _token: &str, _login_type: &str) {
        // Log security event
        self.alert_service.log_security_event(
            "User kicked out",
            login_id,
        ).await;
    }
}

impl SecurityMonitorListener {
    async fn is_suspicious_login(&self, login_id: &str) -> bool {
        // Implement anomaly detection logic
        // For example: check login frequency, IP geolocation, device fingerprint, etc.
        false
    }
}
```

### Scenario 3: Real-time Statistics

```rust
struct StatisticsListener {
    redis: Arc<RedisClient>,
}

#[async_trait]
impl SaTokenListener for StatisticsListener {
    async fn on_login(&self, _login_id: &str, _token: &str, _login_type: &str) {
        // Increment online user count
        let _ = self.redis.incr("online_users").await;
        
        // Increment today's login count
        let key = format!("login_count:{}", today());
        let _ = self.redis.incr(&key).await;
    }

    async fn on_logout(&self, _login_id: &str, _token: &str, _login_type: &str) {
        // Decrement online user count
        let _ = self.redis.decr("online_users").await;
    }
}
```

### Scenario 4: WebSocket Push Notifications

```rust
struct WebSocketNotifyListener {
    ws_manager: Arc<WebSocketManager>,
}

#[async_trait]
impl SaTokenListener for WebSocketNotifyListener {
    async fn on_kick_out(&self, login_id: &str, _token: &str, _login_type: &str) {
        // Notify user via WebSocket
        let message = json!({
            "type": "kicked_out",
            "message": "Your account has been logged in from another device",
            "timestamp": Utc::now()
        });
        
        let _ = self.ws_manager
            .send_to_user(login_id, message)
            .await;
    }
}
```

### Scenario 5: Multiple Listeners Cooperation

```rust
// Method 1: Register via Builder (Recommended)
fn setup_listeners_builder() -> SaTokenManager {
    SaTokenConfig::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .register_listener(Arc::new(LoggingListener))
        .register_listener(Arc::new(LoginLogListener { 
            db_pool: Arc::clone(&db_pool) 
        }))
        .register_listener(Arc::new(SecurityMonitorListener { 
            alert_service: Arc::clone(&alert_service) 
        }))
        .register_listener(Arc::new(StatisticsListener { 
            redis: Arc::clone(&redis_client) 
        }))
        .register_listener(Arc::new(WebSocketNotifyListener { 
            ws_manager: Arc::clone(&ws_manager) 
        }))
        .build()  // Returns fully initialized manager!
}

// Method 2: Register manually (synchronous, no async needed!)
fn setup_listeners_manual(manager: &SaTokenManager) {
    // Logging
    manager.event_bus()
        .register(Arc::new(LoggingListener));
    
    // Database recording
    let db_listener = LoginLogListener {
        db_pool: Arc::clone(&db_pool),
    };
    manager.event_bus()
        .register(Arc::new(db_listener));
    
    // Security monitoring
    let security_listener = SecurityMonitorListener {
        alert_service: Arc::clone(&alert_service),
    };
    manager.event_bus()
        .register(Arc::new(security_listener));
    
    // Real-time statistics
    let stats_listener = StatisticsListener {
        redis: Arc::clone(&redis_client),
    };
    manager.event_bus()
        .register(Arc::new(stats_listener));
    
    // WebSocket notifications
    let ws_listener = WebSocketNotifyListener {
        ws_manager: Arc::clone(&ws_manager),
    };
    manager.event_bus()
        .register(Arc::new(ws_listener));
}
```

## API Reference

### SaTokenEvent

Event data structure:

```rust
pub struct SaTokenEvent {
    /// Event type
    pub event_type: SaTokenEventType,
    /// Login ID
    pub login_id: String,
    /// Token value
    pub token: String,
    /// Login type
    pub login_type: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Extra data
    pub extra: Option<serde_json::Value>,
}
```

Convenient methods for creating events:

```rust
// Create login event
let event = SaTokenEvent::login("user_123", "token_abc");

// Create logout event
let event = SaTokenEvent::logout("user_123", "token_abc");

// Create kick-out event
let event = SaTokenEvent::kick_out("user_123", "token_abc");

// Set extra data
let event = SaTokenEvent::login("user_123", "token_abc")
    .with_login_type("admin")
    .with_extra(json!({"ip": "192.168.1.1"}));
```

### SaTokenListener

All methods in the listener trait are optional:

```rust
#[async_trait]
pub trait SaTokenListener: Send + Sync {
    async fn on_login(&self, login_id: &str, token: &str, login_type: &str) {}
    async fn on_logout(&self, login_id: &str, token: &str, login_type: &str) {}
    async fn on_kick_out(&self, login_id: &str, token: &str, login_type: &str) {}
    async fn on_renew_timeout(&self, login_id: &str, token: &str, login_type: &str) {}
    async fn on_replaced(&self, login_id: &str, token: &str, login_type: &str) {}
    async fn on_banned(&self, login_id: &str, login_type: &str) {}
    async fn on_event(&self, event: &SaTokenEvent) {}
}
```

### SaTokenEventBus

Event bus methods:

```rust
// Create event bus
let bus = SaTokenEventBus::new();

// Register listener (synchronous)
bus.register(Arc::new(MyListener));

// Publish event (asynchronous)
let event = SaTokenEvent::login("user_123", "token_abc");
bus.publish(event).await;

// Clear all listeners (synchronous)
bus.clear();

// Get listener count (synchronous)
let count = bus.listener_count();
```

### StpUtil Event Methods

```rust
// Get event bus
let bus = StpUtil::event_bus();

// Register listener (synchronous, no .await needed!)
StpUtil::register_listener(Arc::new(MyListener));

// Register multiple listeners
StpUtil::register_listener(Arc::new(LoggingListener));
StpUtil::register_listener(Arc::new(DatabaseListener));
```

### Using with Builder Pattern

```rust
// Create state with listeners
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .listener(Arc::new(MyListener))           // Add single listener
    .listeners(vec![                          // Add multiple listeners
        Arc::new(LoggingListener),
        Arc::new(DatabaseListener),
    ])
    .timeout(86400)
    .build();

// StpUtil is automatically initialized and listeners are registered
```

## Notes

1. **Async Execution**: All listener methods are asynchronous and execute sequentially in registration order
2. **Error Handling**: Errors in listeners don't affect the main business flow; handle errors within listeners
3. **Performance Considerations**: Avoid long-running operations in listeners; consider using message queues for async processing
4. **Thread Safety**: Listeners must implement `Send + Sync`
5. **Lifecycle**: Listeners are wrapped in `Arc` and can be shared across multiple event buses

## Complete Example

See `examples/event_listener_example.rs` for a complete runnable example.

Run the example:

```bash
cargo run --example event_listener_example
```

## References

- [Quick Start](/guide/event-listener-quickstart.md)
- [Chinese Documentation](/zh/guide/event-listener.md)
- [API Documentation](https://docs.rs/sa-token-core)

# sa-token-adapter

Adapter layer for sa-token-rust framework integration.

## Features

- 🔌 **Storage Interface**: Abstract storage operations
- 🌐 **Request/Response Abstraction**: Framework-agnostic interfaces
- 🎯 **Trait-based Design**: Easy to implement custom adapters

## Installation

```toml
[dependencies]
sa-token-adapter = "0.1.13"
async-trait = "0.1"
```

## Traits

### SaStorage

Storage interface for tokens and sessions:

```rust
#[async_trait]
pub trait SaStorage: Send + Sync {
    async fn get(&self, key: &str) -> StorageResult<Option<String>>;
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()>;
    async fn delete(&self, key: &str) -> StorageResult<()>;
    // ... more methods
}
```

### SaRequest / SaResponse

HTTP request/response abstraction:

```rust
pub trait SaRequest {
    fn get_header(&self, name: &str) -> Option<String>;
    fn get_cookie(&self, name: &str) -> Option<String>;
    fn get_param(&self, name: &str) -> Option<String>;
}

pub trait SaResponse {
    fn set_header(&mut self, name: &str, value: &str);
    fn set_cookie(&mut self, cookie: SaCookie);
    fn set_status(&mut self, status: u16);
}
```

## Implementing Custom Storage

```rust
use sa_token_adapter::storage::{SaStorage, StorageResult};
use async_trait::async_trait;

pub struct MyStorage {
    // Your storage fields
}

#[async_trait]
impl SaStorage for MyStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        // Your implementation
    }
    
    // Implement other required methods...
}
```

## Author

**金书记**

## License

Licensed under either of:
- Apache License, Version 2.0
- MIT License

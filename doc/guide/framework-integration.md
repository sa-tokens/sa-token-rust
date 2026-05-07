# Framework Integration

[中文文档](/zh/guide/framework-integration.md) | English

sa-token-rust supports 9 web frameworks through dedicated plugin packages. Each plugin provides middleware, extractors, and state management with a consistent API.

## Supported Frameworks

| Framework | Plugin Package | Feature (default) | Binding Crate |
|-----------|---------------|-------------------|---------------|
| **Axum** | `sa-token-plugin-axum` | `axum-08` | (internal `v08`) |
| **Actix-web** | `sa-token-plugin-actix-web` | `v4` | `sa-token-plugin-actix-web-v4` |
| **Poem** | `sa-token-plugin-poem` | (none) | (direct) |
| **Rocket** | `sa-token-plugin-rocket` | `v05` | `sa-token-plugin-rocket-v05` |
| **Warp** | `sa-token-plugin-warp` | (none) | (direct) |
| **Salvo** | `sa-token-plugin-salvo` | `v079` | `sa-token-plugin-salvo-v079` |
| **Tide** | `sa-token-plugin-tide` | (none) | (direct) |
| **Gotham** | `sa-token-plugin-gotham` | `v074` | `sa-token-plugin-gotham-v074` |
| **Ntex** | `sa-token-plugin-ntex` | `v212` | `sa-token-plugin-ntex-v212` |

Quick reference: [Quick Start](./quick-start.md).

### Version-Split Architecture

Facade crates (Actix-web, Rocket, Salvo, Gotham, Ntex) use Cargo features to select the framework major version at compile time. Each facade re-exports from a version-specific binding crate (`*-v4`, `*-v05`, etc.) and shares a `*-core` crate for common logic (state, adapter, error responses).

```toml
# Default: v4 (production-ready)
sa-token-plugin-actix-web = "0.1.14"

# Explicit feature selection
sa-token-plugin-actix-web = { version = "0.1.14", default-features = false, features = ["v4", "redis"] }
```

All plugins provide:
- State management with Builder pattern
- Dual middleware (basic + login-required)
- Three extractors (required, optional, LoginId)
- Request/Response adapters
- Token extraction from Header/Cookie/Query
- Bearer token support
- `SaTokenLayer` for fine-grained route control
- `with_path_auth(state, config)` for path-based auth rules

---

## Axum

```toml
[dependencies]
sa-token-plugin-axum = "0.1.14"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

```rust
use axum::{Router, routing::{get, post}};
use sa_token_plugin_axum::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Router::new()
    .route("/user/info", get(user_info))
    .layer(SaTokenMiddleware::new(state));
```

---

## Actix-web

```rust
use actix_web::{App, HttpServer, web};
use sa_token_plugin_actix_web::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

// Initialize Sa-Token
let sa_token_manager = conf::init_sa_token(None)
    .await
    .expect("Sa-Token initialization failed");

// Create Sa-Token state
let sa_token_state = SaTokenState {
    manager: sa_token_manager.clone(),
};

// Create data for application state
let sa_token_data = web::Data::new(sa_token_state.clone());

HttpServer::new(move || {
    App::new()
        // Register middleware
        .wrap(Logger::default())
        .app_data(sa_token_data.clone()) // Inject Sa-Token into application state
        .wrap(SaTokenMiddleware::new(sa_token_state.clone()))

        // Routes
        .route("/api/login", web::post().to(login))
        .route("/api/user/info", web::get().to(user_info))
})
.bind("0.0.0.0:3000")?
.run()
.await

// For a complete example, see examples/actix-web-example/
```

---

## Poem

```rust
use poem::{Route, Server};
use sa_token_plugin_poem::{SaTokenState, SaTokenMiddleware, LoginIdExtractor};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Route::new()
    .at("/user/info", poem::get(user_info))
    .with(SaTokenMiddleware::new(state));

Server::new(TcpListener::bind("127.0.0.1:8080"))
    .run(app)
    .await
```

---

## Rocket

```rust
use rocket::{launch, get, routes};
use sa_token_plugin_rocket::{SaTokenState, SaTokenFairing, LoginIdGuard};

#[get("/user/info")]
fn user_info(login_id: LoginIdGuard) -> String {
    format!("User: {}", login_id.0)
}

#[launch]
fn rocket() -> _ {
    let state = SaTokenState::builder()
        .storage(Arc::new(MemoryStorage::new()))
        .build();

    rocket::build()
        .attach(SaTokenFairing::new(state))
        .mount("/", routes![user_info])
}
```

---

## Warp

```rust
use warp::Filter;
use sa_token_plugin_warp::{SaTokenState, sa_token_filter};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let routes = warp::path("user")
    .and(warp::path("info"))
    .and(sa_token_filter(state))
    .map(|token_data| {
        format!("User info")
    });

warp::serve(routes)
    .run(([127, 0, 0, 1], 8080))
    .await;
```

---

## Common Patterns

### Middleware Types

All plugins support two middleware levels:

1. **Basic Middleware** (Axum: `SaTokenMiddleware` / Actix: `SaTokenMiddleware` / Rocket: `SaTokenFairing`): Validates tokens and injects login ID into request context, but does NOT block unauthenticated requests. Use when you want to support both public and protected routes.

2. **Login-Required Middleware** (Axum/Actix: `SaCheckLoginMiddleware` / Rocket: `SaCheckLoginFairing`): Blocks requests without valid tokens. Use for fully protected route groups.

### Extractors

Each plugin provides three extractor types:

1. **LoginIdExtractor** (required): Extracts login ID, returns 401 if not authenticated
2. **OptionalLoginIdExtractor** (optional): Extracts login ID if present, returns `None` if not
3. **TokenValueExtractor**: Extracts the raw token value for custom processing

### Token Sources

Tokens are automatically extracted from multiple sources in priority order:

1. **Authorization Header**: `Authorization: Bearer <token>` or `Authorization: <token>`
2. **Cookie**: Configurable cookie name
3. **Query Parameter**: Configurable query parameter name

### Custom Token Name

```rust
let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .token_name("X-Auth-Token")  // Custom header/cookie/query name
    .build();
```

### Layered Middleware (Axum)

```rust
use sa_token_plugin_axum::{SaTokenLayer, SaCheckLoginLayer, SaCheckPermissionLayer};

let state = SaTokenState::builder()
    .storage(Arc::new(MemoryStorage::new()))
    .build();

let app = Router::new()
    // Global: validate token, inject context (does not block unauthenticated)
    .layer(SaTokenLayer::new(state.clone()))
    // Per-route: require login
    .route("/user/info", get(user_info))
    .route_layer(SaCheckLoginLayer::new(state.clone()))
    // Per-route: require specific permission
    .route("/user/delete", post(delete_user))
    .route_layer(SaCheckPermissionLayer::new(state.clone(), "user:delete"));
```

### Path-based Auth Router

```rust
use sa_token_core::router::{PathAuthConfig, run_auth_flow, extract_token};

let config = PathAuthConfig::new()
    .include(vec!["/api/**".to_string()])
    .exclude(vec!["/api/public/**".to_string()]);

// In middleware / layer:
let token_str = extract_token(&req, token_name);
let flow = run_auth_flow(&req, &manager, Some(&config)).await;
if flow.should_reject() {
    return StatusCode::UNAUTHORIZED;
}
flow.run(service.call(req)).await
```

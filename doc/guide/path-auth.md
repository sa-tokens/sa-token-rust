# Path auth

English | [中文](/zh/guide/path-auth.md)

HTTP / gRPC middleware uses `PathAuthConfig` to decide which paths require login. Allow anonymous routes with `exclude` — **do not** rely on `#[sa_ignore]` (it only skips macro checks).

## When to use

- Default auth for the whole app, with a few public paths (`/login`, `/health`).
- Split duties: middleware answers “logged in?”, macros answer “has permission / role?”.

## PathAuthConfig

```rust
use sa_token_core::router::PathAuthConfig;

let config = PathAuthConfig::new()
    .include(vec!["/**".into()])           // paths that require auth (Ant-style)
    .exclude(vec![
        "/api/login".into(),
        "/health".into(),
        "/public/**".into(),
    ])
    // Public routes: skip storage entirely even if the client sends a token
    .check_token_on_exclude(false)
    .validator(|login_id| {                 // optional extra login_id check
        !login_id.is_empty()
    });
```

`check_token_on_exclude` defaults to `true` (soft-login on exclude paths). Set `false` for pure public endpoints so a stray Authorization header never hits Redis.

Rule: `need_auth = matches include AND does not match exclude`.

| Pattern | Meaning |
|---------|---------|
| `/**` | All paths |
| `/api/**` | Prefix `/api` |
| `/api/*` | One segment under `/api` (`/api/user` yes, `/api/a/b` no) |
| `*.html` | Ends with `.html` |
| `/exact` | Exact match |

## run_auth_flow

Framework layers share one pipeline:

```text
extract_token_from(req, config)
  → process_auth(path, token, PathAuthConfig?, manager)
  → create_context → AuthFlowResult
```

```rust
use sa_token_core::router::run_auth_flow;

// Some(config): include/exclude may produce 401 or 503
// None: validate token if present; never reject by path
let flow = run_auth_flow(&adapter, &manager, Some(&config)).await;
if flow.should_service_unavailable() {
    // binding returns 503 — storage blip, not "logged out"
}
if flow.should_reject() {
    // binding returns 401 — missing / invalid / expired token
}
```

| Outcome | HTTP | Meaning |
|---------|------|---------|
| `should_reject` | 401 | Real auth failure |
| `should_service_unavailable` | 503 | Storage temporarily unavailable |
| neither | continue | Logged in or public path |

Bindings (Actix / Axum / Poem / Tide / Salvo / Ntex / Warp / Tonic) check **503 before 401**.

`AuthFlowResult::run(fut)` runs the handler inside `SaTokenContext::scope` so `StpUtil` parameterless APIs work.

## Layer: `with_path_auth` vs macros

**Axum:**

```rust
use sa_token_plugin_axum::{SaTokenLayer, SaTokenState};
use sa_token_core::PathAuthConfig;

let state = SaTokenState::builder()
    .storage(storage)
    .build();

let path = PathAuthConfig::new()
    .include(vec!["/**".into()])
    .exclude(vec!["/api/login".into()]);

let app = axum::Router::new()
    .route("/api/login", /* ... */)
    .route("/api/user", /* ... */)
    .layer(SaTokenLayer::with_path_auth(state.clone(), path));
```

**Actix:**

```rust
use sa_token_plugin_actix_web::{PathAuthConfig, SaTokenMiddleware};

App::new().wrap(SaTokenMiddleware::with_path_auth(
    state.clone(),
    PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec!["/api/login".into()]),
))
```

| Mechanism | Does | Does not |
|-----------|------|----------|
| `SaTokenLayer::with_path_auth` / `SaTokenMiddleware::with_path_auth` | Path-level login gate; fills context | Check permission strings |
| `#[sa_check_login]` / `#[sa_check_permission]` | Fine-grained checks in the handler | Bypass middleware |
| `#[sa_ignore]` | Skip inserting macro checks | Skip the Layer |

`SaTokenLayer::new(state)` without path config only validates a present token and fills context — anonymous requests pass. Use that when routes protect themselves with macros.

## Pitfalls

1. Forgetting to `exclude` login → clients always get 401.
2. Only `#[sa_ignore]` without `exclude` → middleware still rejects.
3. Empty `include` → no path ever `need_auth` (path enforcement off).
4. Soft-login on exclude (`check_token_on_exclude=true`) still hits storage; Redis jitter can leave `login_id` empty while HTTP stays 200 — use `check_token_on_exclude(false)` or treat missing login as anonymous defaults.
5. Frontends must **not** clear the session on 503; retry silently. Clear login state only on real 401.

## Related

- Example: `cargo run --example path_auth_example` ([`examples/path_auth_example.rs`](https://github.com/sa-tokens/sa-token-rust/blob/main/examples/path_auth_example.rs))
- [StpUtil](./stp-util.md)
- [Permissions and macros](./permission-matching.md)
- [Framework integration](./framework-integration.md)

# Multi-Account & Multi-Device Terminal Guide

[English](#english) | [中文](#中文)

---

## English

This guide covers two related capabilities aligned with Java Sa-Token:

1. **Multi-Account System** (`SaLogic`): multiple `login_type` account systems (e.g. `admin`, `user`) isolated on the same `SaTokenManager`.
2. **Multi-Device Terminal Info** (`SaTerminalInfo`): record every logged-in device on the Account-Session, queryable by device type and reverse-lookup by token.

### 1. Concepts

#### Account namespace (`account_ns`)

Every login-id-related storage key is namespaced by `login_type`:

- `default` / `""` / `login` → the key uses `login_id` directly (fully backward compatible).
- Any other type (e.g. `admin`) → the key uses `{login_type}:{login_id}`.

| Operation | default account | `admin` account |
|-----------|-----------------|-----------------|
| session | `sa:session:10001` | `sa:session:admin:10001` |
| login token map | `sa:login:token:10001` | `sa:login:token:admin:10001` |
| token list | `sa:login:tokens:10001` | `sa:login:tokens:admin:10001` |
| permission | `sa:permission:10001` | `sa:permission:admin:10001` |
| role | `sa:role:10001` | `sa:role:admin:10001` |

Token-related keys (`sa:token:{token}`, `sa:token-id:{token}`, `sa:token-session:{token}`) are globally unique and not affected by `login_type`.

#### Terminal info (`SaTerminalInfo`)

Each successful login appends a terminal entry to the Account-Session:

| Field | Type | Description |
|-------|------|-------------|
| `index` | `i32` | Login sequence index, starts at 1, auto-assigned |
| `token_value` | `String` | Token held by this terminal |
| `device_type` | `String` | Device type, e.g. `PC` / `APP` / `WEB`; empty if unspecified |
| `device_id` | `Option<String>` | Optional unique device identifier |
| `extra_data` | `Option<serde_json::Value>` | Extra data attached at login time |
| `create_time` | `i64` | Creation time (Unix millis) |

The `index` is derived from `history_terminal_count`, which only ever increases — re-login after logout produces a higher index, never reusing old ones.

### 2. Multi-Account System (`SaLogic`)

```rust
use sa_token_core::{SaLogic, StpUtil};

// Obtain (or create) a SaLogic for a given login_type from the global registry
let admin = StpUtil::stp_logic("admin");
let user = StpUtil::stp_logic("user");

// Login under each account system — same login_id, different isolated tokens
let admin_token = admin.login("10001").await?;
let user_token = user.login("10001").await?;
assert_ne!(admin_token.as_str(), user_token.as_str());

// Permissions / roles are isolated per login_type
admin.set_permissions("10001", vec!["admin:read".to_string()]).await?;
user.set_permissions("10001", vec!["user:read".to_string()]).await?;

// Query
let id = admin.get_login_id(&admin_token).await?;
let ok = admin.is_valid(&admin_token).await;

// Logout / kick-out by login_id within this account system only
admin.logout_by_login_id("10001").await?;
admin.kick_out("10001").await?;

// Account ban (disable) within this account system
admin.disable("10001", 3600).await?;   // 1 hour
admin.check_disable("10001").await?;     // Err if banned
```

#### `SaLogic` methods

| Method | Description |
|--------|-------------|
| `login(login_id)` | Login under this login_type |
| `login_with_device(login_id, device, extra)` | Login with device type + extra data |
| `logout(token)` | Logout a single token |
| `logout_by_login_id(login_id)` | Logout all tokens of the account (terminal-list driven) |
| `kick_out(login_id)` | Kick out all tokens and remove the session |
| `get_login_id(token)` | Resolve login_id from a token |
| `is_valid(token)` | Whether the token is valid |
| `get_session(login_id)` | Get the Account-Session |
| `get_terminal_list(login_id, device_type)` | List terminals, optionally filtered by device type |
| `get_terminal_info_by_token(token)` | Reverse-lookup the terminal by token |
| `get_permissions / set_permissions` | Permissions within this namespace |
| `get_roles / set_roles` | Roles within this namespace |
| `disable(login_id, time)` / `check_disable(login_id)` | Account ban within this namespace |
| `manager()` | Access the underlying `SaTokenManager` |

#### Global registry

```rust
use std::sync::Arc;
use sa_token_core::{SaLogic, StpUtil};

// Register a custom-configured SaLogic
let logic = Arc::new(SaLogic::new("shop", manager.clone()));
StpUtil::put_stp_logic(logic);

// Fetch (returns None if absent)
let found = sa_token_core::stp_logic::try_get_stp_logic("shop");

// Remove
StpUtil::remove_stp_logic("shop");
```

`StpUtil::stp_logic(login_type)` lazily creates and caches a `SaLogic` bound to the global manager.

### 3. Multi-Device Terminal

```rust
use sa_token_core::StpUtil;

// For the default account system
let pc = StpUtil::login_with_type("10001", "default").await?; // or any login
// List all terminals
let all = StpUtil::get_terminal_list("10001", None).await?;
// Filter by device type
let pcs = StpUtil::get_terminal_list("10001", Some("PC")).await?;
// All token values held by this account
let tokens = StpUtil::get_token_value_list_by_login_id("10001", None).await?;
// Reverse lookup by token
let terminal = StpUtil::get_terminal_info_by_token(&pc).await?;
```

When logging in with a device type, prefer `SaLogic::login_with_device` or `SaTokenManager::login_with_options`:

```rust
let admin = StpUtil::stp_logic("admin");
let pc_token  = admin.login_with_device("10001", Some("PC".to_string()), None).await?;
let app_token = admin.login_with_device("10001", Some("APP".to_string()), None).await?;

assert_eq!(admin.get_terminal_list("10001", Some("PC")).await?.len(), 1);
assert_eq!(admin.get_terminal_list("10001", None).await?.len(), 2);

// Logout removes the matching terminal; when the last terminal is removed,
// the Account-Session is deleted (except in Replaced mode).
admin.logout(&pc_token).await?;
assert_eq!(admin.get_terminal_list("10001", None).await?.len(), 1);
```

#### `SaTokenManager` terminal APIs

| Method | Description |
|--------|-------------|
| `get_terminal_list(login_type, login_id, device_type)` | List terminals |
| `get_token_value_list_by_login_id(login_type, login_id, device_type)` | List token values |
| `get_terminal_info_by_token(token)` | Reverse-lookup terminal by token |

### 4. Backward Compatibility

- The `default` / `login` account system keeps byte-identical storage keys; existing data and tests are unaffected.
- `SaSession.terminal_list` / `history_terminal_count` use `#[serde(default)]`, so legacy sessions deserialize into an empty terminal list.
- The terminal list and the lightweight `login:tokens:` index are kept dual-track: the former powers external device queries, the latter powers fast internal logout / max-login-count paths.

---

## 中文

本指南介绍两个对齐 Java Sa-Token 的能力：

1. **多账号体系**（`SaLogic`）：在同一个 `SaTokenManager` 上隔离多个 `login_type` 账号体系（如 `admin`、`user`）。
2. **多设备终端信息**（`SaTerminalInfo`）：将"某账号在哪些设备登录"记录到 Account-Session，支持按设备类型查询、按 token 反查。

### 1. 概念

#### 账号命名空间（`account_ns`）

所有与 login_id 相关的存储键都会按 `login_type` 做命名空间隔离：

- `default` / `""` / `login` → 键直接使用 `login_id`（完全向后兼容）。
- 其它类型（如 `admin`）→ 键使用 `{login_type}:{login_id}`。

| 操作 | default 账号 | `admin` 账号 |
|------|-------------|-------------|
| session | `sa:session:10001` | `sa:session:admin:10001` |
| login token 映射 | `sa:login:token:10001` | `sa:login:token:admin:10001` |
| token 列表 | `sa:login:tokens:10001` | `sa:login:tokens:admin:10001` |
| 权限 | `sa:permission:10001` | `sa:permission:admin:10001` |
| 角色 | `sa:role:10001` | `sa:role:admin:10001` |

与 token 相关的键（`sa:token:{token}`、`sa:token-id:{token}`、`sa:token-session:{token}`）全局唯一，不受 `login_type` 影响。

#### 终端信息（`SaTerminalInfo`）

每次登录成功都会向 Account-Session 追加一条终端记录：

| 字段 | 类型 | 说明 |
|------|------|------|
| `index` | `i32` | 登录序号，从 1 开始，自动分配 |
| `token_value` | `String` | 该终端持有的 token |
| `device_type` | `String` | 设备类型，如 `PC` / `APP` / `WEB`；未指定时为空串 |
| `device_id` | `Option<String>` | 可选的设备唯一标识 |
| `extra_data` | `Option<serde_json::Value>` | 登录时挂载的扩展数据 |
| `create_time` | `i64` | 创建时间（Unix 毫秒） |

`index` 由 `history_terminal_count` 派生，该计数只增不减——登出后再登录会得到更大的 index，不会复用旧值。

### 2. 多账号体系（`SaLogic`）

```rust
use sa_token_core::{SaLogic, StpUtil};

// 从全局注册表获取（或创建）指定 login_type 的 SaLogic
let admin = StpUtil::stp_logic("admin");
let user = StpUtil::stp_logic("user");

// 在各自账号体系下登录——同一 login_id，得到互相隔离的不同 token
let admin_token = admin.login("10001").await?;
let user_token = user.login("10001").await?;
assert_ne!(admin_token.as_str(), user_token.as_str());

// 权限/角色按 login_type 隔离
admin.set_permissions("10001", vec!["admin:read".to_string()]).await?;
user.set_permissions("10001", vec!["user:read".to_string()]).await?;

// 查询
let id = admin.get_login_id(&admin_token).await?;
let ok = admin.is_valid(&admin_token).await;

// 仅在本账号体系内按 login_id 登出/踢人
admin.logout_by_login_id("10001").await?;
admin.kick_out("10001").await?;

// 本账号体系内的封禁
admin.disable("10001", 3600).await?;   // 1 小时
admin.check_disable("10001").await?;     // 已封禁则返回 Err
```

#### `SaLogic` 方法

| 方法 | 说明 |
|------|------|
| `login(login_id)` | 在本 login_type 下登录 |
| `login_with_device(login_id, device, extra)` | 带设备类型 + 扩展数据登录 |
| `logout(token)` | 登出单个 token |
| `logout_by_login_id(login_id)` | 登出该账号全部 token（终端列表驱动） |
| `kick_out(login_id)` | 踢出全部 token 并删除 session |
| `get_login_id(token)` | 由 token 解析 login_id |
| `is_valid(token)` | token 是否有效 |
| `get_session(login_id)` | 获取 Account-Session |
| `get_terminal_list(login_id, device_type)` | 列出终端，可按设备类型筛选 |
| `get_terminal_info_by_token(token)` | 按 token 反查终端 |
| `get_permissions / set_permissions` | 本命名空间下的权限 |
| `get_roles / set_roles` | 本命名空间下的角色 |
| `disable(login_id, time)` / `check_disable(login_id)` | 本命名空间下的封禁 |
| `manager()` | 访问底层 `SaTokenManager` |

#### 全局注册表

```rust
use std::sync::Arc;
use sa_token_core::{SaLogic, StpUtil};

// 注册一个自定义配置的 SaLogic
let logic = Arc::new(SaLogic::new("shop", manager.clone()));
StpUtil::put_stp_logic(logic);

// 获取（不存在返回 None）
let found = sa_token_core::stp_logic::try_get_stp_logic("shop");

// 移除
StpUtil::remove_stp_logic("shop");
```

`StpUtil::stp_logic(login_type)` 会惰性创建并缓存一个绑定全局 manager 的 `SaLogic`。

### 3. 多设备终端

```rust
use sa_token_core::StpUtil;

// 默认账号体系
let pc = StpUtil::login_with_type("10001", "default").await?;
// 列出所有终端
let all = StpUtil::get_terminal_list("10001", None).await?;
// 按设备类型筛选
let pcs = StpUtil::get_terminal_list("10001", Some("PC")).await?;
// 该账号持有的所有 token
let tokens = StpUtil::get_token_value_list_by_login_id("10001", None).await?;
// 按 token 反查终端
let terminal = StpUtil::get_terminal_info_by_token(&pc).await?;
```

需要带设备类型登录时，推荐使用 `SaLogic::login_with_device` 或 `SaTokenManager::login_with_options`：

```rust
let admin = StpUtil::stp_logic("admin");
let pc_token  = admin.login_with_device("10001", Some("PC".to_string()), None).await?;
let app_token = admin.login_with_device("10001", Some("APP".to_string()), None).await?;

assert_eq!(admin.get_terminal_list("10001", Some("PC")).await?.len(), 1);
assert_eq!(admin.get_terminal_list("10001", None).await?.len(), 2);

// 登出会移除对应终端；当最后一个终端被移除时，Account-Session 会被删除
// （Replaced 顶号模式除外）。
admin.logout(&pc_token).await?;
assert_eq!(admin.get_terminal_list("10001", None).await?.len(), 1);
```

#### `SaTokenManager` 终端 API

| 方法 | 说明 |
|------|------|
| `get_terminal_list(login_type, login_id, device_type)` | 列出终端 |
| `get_token_value_list_by_login_id(login_type, login_id, device_type)` | 列出 token 值 |
| `get_terminal_info_by_token(token)` | 按 token 反查终端 |

### 4. 向后兼容

- `default` / `login` 账号体系的存储键逐字节保持不变；既有数据和测试不受影响。
- `SaSession.terminal_list` / `history_terminal_count` 使用 `#[serde(default)]`，旧 session 反序列化为空终端列表。
- 终端列表与轻量级 `login:tokens:` 索引采用双轨保留：前者用于对外的设备详情查询，后者用于内部快速登出 / 最大登录数限制路径。

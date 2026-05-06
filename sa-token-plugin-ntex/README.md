# sa-token-plugin-ntex

Ntex integration for **sa-token-rust**（facade）。

## 版本选择

| Feature（默认） | 绑定 crate | ntex |
|------------------|------------|------|
| `v212` | `sa-token-plugin-ntex-v212` | 2.12（Cargo 可解析同 major 的兼容版本） |

共享逻辑：**`sa-token-plugin-ntex-core`**。路径鉴权使用 **`SaTokenLayer::with_path_auth`** + **`PathAuthConfig`**。

```toml
sa-token-plugin-ntex = { version = "0.1.13", features = ["memory"] }
ntex = "2.12"
```

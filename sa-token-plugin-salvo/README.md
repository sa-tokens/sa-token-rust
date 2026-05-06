# sa-token-plugin-salvo

Salvo integration for **sa-token-rust**（facade）。

## 版本选择

| Feature（默认） | 绑定 crate | Salvo |
|------------------|------------|-------|
| `v079` | `sa-token-plugin-salvo-v079` | 0.79.x |

共享逻辑（无 Salvo 依赖）：**`sa-token-plugin-salvo-core`**（`SaTokenState`、`router::run_auth_flow` 等）。

```toml
sa-token-plugin-salvo = { version = "0.1.13", features = ["memory"] }
salvo = "0.79"
```

# sa-token-plugin-gotham

Gotham integration for **sa-token-rust**（facade）。

## 版本选择

| Feature（默认） | 绑定 crate | Gotham |
|------------------|------------|--------|
| `v074` | `sa-token-plugin-gotham-v074` | 0.7.x |

共享逻辑：**`sa-token-plugin-gotham-core`**。`TokenValueWrapper` / `LoginIdWrapper` 在 **`sa-token-plugin-gotham-v074`** 的 **`wrapper.rs`**。

```toml
sa-token-plugin-gotham = { version = "0.1.13", features = ["memory"] }
gotham = "0.7"
```

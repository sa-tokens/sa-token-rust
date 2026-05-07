# 安全特性

[English](/guide/security-features.md) | 中文文档

sa-token-rust 提供内置的安全机制，防范常见的攻击手段。

## Nonce 防重放攻击

Nonce 是一次性使用的随机值，可防止重放攻击。每个 nonce 只能验证和消费一次。

```rust
use sa_token_core::NonceManager;

let nonce_manager = NonceManager::new(storage, 300); // 5 分钟有效期

// 生成 nonce
let nonce = nonce_manager.generate();

// 验证并消费（单次使用）
nonce_manager.validate_and_consume(&nonce, "user_123").await?;

// 第二次使用将失败（检测到重放攻击）
match nonce_manager.validate_and_consume(&nonce, "user_123").await {
    Err(_) => println!("重放攻击已阻止！"),
    _ => {}
}
```

### 工作原理

1. 服务器生成唯一的 nonce 值并发送给客户端
2. 客户端在请求中包含此 nonce
3. 服务器验证 nonce 并将其标记为"已消费"
4. 任何使用相同 nonce 的后续请求都将被拒绝

这确保了即使攻击者捕获了有效的请求，也无法重放它，因为 nonce 已被使用。

### 配置

- **TTL（有效期）**：控制 nonce 在过期前保持有效的时间。默认：300 秒（5 分钟）。
- **存储**：Nonce 存储在配置的存储后端中（内存、Redis 或数据库）。

---

## 自动续签（auto_renew）

启用后，每次访问时 Token 自动续签。通过 `SaTokenConfig` 配置：

```rust
let config = SaTokenConfig::builder()
    .auto_renew(true)           // 启用自动续签
    .active_timeout(1800)       // 续签时长（> 0 时使用）
    .timeout(86400)             // 否则回退使用
    .build_config();

// Token 自动续签发生在：
// - get_token_info() 调用时
// - 中间件 token 验证时
// - 无参数的 StpUtil 方法调用时
```

**行为**：如果 `active_timeout > 0`，每次访问 Token 续签 `active_timeout` 秒。否则使用 `timeout` 作为续签时长。

---

## Refresh Token 刷新机制

Refresh Token 允许客户端获取新的访问令牌，而无需用户重新认证。

```rust
use sa_token_core::RefreshTokenManager;

let refresh_manager = RefreshTokenManager::new(storage, config);

// 生成 refresh token
let refresh_token = refresh_manager.generate("user_123");
refresh_manager.store(&refresh_token, &access_token, "user_123").await?;

// 访问令牌过期时刷新
let (new_access_token, user_id) = refresh_manager
    .refresh_access_token(&refresh_token)
    .await?;
```

### Token 生命周期

```
用户登录
    │
    ├──► 访问令牌（短期有效，如 2 小时）
    │
    └──► 刷新令牌（长期有效，如 30 天）
              │
              │  访问令牌过期
              │
              └──► 使用刷新令牌获取新的访问令牌
                        │
                        │  刷新令牌过期或被撤销
                        │
                        └──► 用户必须重新认证
```

### 安全注意事项

- **访问令牌**应为短期有效（数分钟到数小时）
- **刷新令牌**应为长期有效但可撤销（数天到数周）
- 始终安全存储刷新令牌
- 每次使用时轮换刷新令牌以增强安全性
- 实现刷新令牌轮换以检测令牌被盗

---

## 最佳实践

### Token 安全

1. **使用 HTTPS**：生产环境始终使用 TLS 保护传输中的令牌
2. **设置适当的超时时间**：在安全性和用户体验之间取得平衡
3. **定期轮换密钥**：定期轮换 JWT 签名密钥和其他机密
4. **验证所有输入**：永远不要信任未经验证的客户端提供的令牌

### 存储安全

1. **Redis**：生产环境中为 Redis 连接使用密码认证和 TLS
2. **Memory**：仅将内存存储用于开发和测试
3. **Database**：为过期的令牌实现适当的索引和清理机制

### 纵深防御

- 组合多种安全特性：Nonce + Refresh Token + 权限检查
- 使用事件监听器记录安全相关事件（登录、登出、踢出下线）
- 监控可疑模式（快速登录失败、令牌重用尝试）

## 运行安全示例

```bash
cargo run --example security_features_example
```

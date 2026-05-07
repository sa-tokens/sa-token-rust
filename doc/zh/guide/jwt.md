# JWT (JSON Web Token) 完整功能指南

中文 | [English](/guide/jwt.md)

---

## 概述

sa-token-rust 提供完整的 JWT (JSON Web Token) 功能，支持令牌生成、验证、刷新和自定义声明。

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [JWT 管理器](#jwt-管理器)
- [JWT 声明](#jwt-声明)
- [与 sa-token 集成](#与-sa-token-集成)
- [算法](#算法)
- [高级用法](#高级用法)
- [API 参考](#api-参考)

## 功能特性

- ✅ 支持多种算法（HS256, HS384, HS512, RS256 等）
- ✅ 自定义声明
- ✅ Token 验证
- ✅ Token 刷新
- ✅ 过期时间管理
- ✅ 签发者和受众验证
- ✅ 与 sa-token 无缝集成
- ✅ 快速用户识别

## 快速开始

### 1. 独立使用 JWT 管理器

```rust
use sa_token_core::{JwtManager, JwtClaims};

// 创建 JWT 管理器
let jwt_manager = JwtManager::new("your-secret-key");

// 创建声明
let mut claims = JwtClaims::new("user_123");
claims.set_expiration(3600); // 1 小时

// 生成令牌
let token = jwt_manager.generate(&claims)?;

// 验证令牌
let decoded_claims = jwt_manager.validate(&token)?;
println!("用户ID: {}", decoded_claims.login_id);
```

### 2. 与 sa-token 集成使用

```rust
use sa_token_core::{SaTokenConfig, SaTokenManager, StpUtil};
use sa_token_core::config::TokenStyle;
use std::sync::Arc;

// 配置使用 JWT 令牌
let config = SaTokenConfig::builder()
    .token_style(TokenStyle::Jwt)
    .jwt_secret_key("my-secret-key")
    .jwt_algorithm("HS256")
    .timeout(7200)
    .build_config();

let manager = SaTokenManager::new(storage, config);
StpUtil::init_manager(manager);

// 登录生成 JWT 令牌
let token = StpUtil::login("user_123").await?;
```

## JWT 管理器

### 创建 JWT 管理器

```rust
use sa_token_core::{JwtManager, JwtAlgorithm};

// 默认（HS256）
let manager = JwtManager::new("secret-key");

// 使用自定义算法
let manager = JwtManager::with_algorithm("secret-key", JwtAlgorithm::HS512);

// 设置签发者和受众
let manager = JwtManager::new("secret-key")
    .set_issuer("my-app")
    .set_audience("web-users");
```

### 生成令牌

```rust
let mut claims = JwtClaims::new("user_123");
claims.set_expiration(3600);

let token = jwt_manager.generate(&claims)?;
```

### 验证令牌

```rust
// 完整验证（签名 + 过期）
let claims = jwt_manager.validate(&token)?;

// 不验证解码（不安全 - 仅用于调试）
let claims = jwt_manager.decode_without_validation(&token)?;
```

### 刷新令牌

```rust
// 延长令牌有效期 2 小时
let new_token = jwt_manager.refresh(&token, 7200)?;
```

## JWT 声明

### 标准声明

```rust
let mut claims = JwtClaims::new("user_123");

// 设置过期时间（从现在开始的秒数）
claims.set_expiration(3600);

// 设置特定的过期时间
claims.set_expiration_at(datetime);

// 设置签发者
claims.set_issuer("my-application");

// 设置受众
claims.set_audience("web-app");

// 设置 JWT ID
claims.set_jti("unique-id-123");
```

### sa-token 扩展

```rust
// 设置登录类型
claims.set_login_type("admin");

// 设置设备标识
claims.set_device("mobile-ios");
```

### 自定义声明

```rust
use serde_json::json;

// 添加自定义声明
claims.add_claim("role", json!("admin"));
claims.add_claim("permissions", json!(["read", "write"]));
claims.add_claim("metadata", json!({
    "department": "IT",
    "level": 5
}));

// 获取自定义声明
let role = claims.get_claim("role");
```

### 登录时携带额外数据签入 JWT

```rust
use sa_token_core::StpUtil;
use serde_json::json;

// 登录时签名额外数据到 JWT 声明中
let token = StpUtil::builder("user_123")
    .extra_data(json!({
        "role": "admin",
        "tenant_id": 42,
        "permissions": ["read", "write"]
    }))
    .login(None)
    .await?;

// extra_data 直接签入 JWT token 中（而非仅存储于 session）
```

### 检查过期

```rust
// 检查是否过期
if claims.is_expired() {
    println!("令牌已过期");
}

// 获取剩余时间
if let Some(seconds) = claims.remaining_time() {
    println!("令牌还有 {} 秒有效", seconds);
}
```

## 与 sa-token 集成

### 配置

```rust
use sa_token_core::SaTokenConfig;
use sa_token_core::config::TokenStyle;

let config = SaTokenConfig::builder()
    // 设置令牌风格为 JWT
    .token_style(TokenStyle::Jwt)
    
    // 必需：JWT 密钥
    .jwt_secret_key("your-secret-key-min-32-chars")
    
    // 可选：算法（默认：HS256）
    .jwt_algorithm("HS256")
    
    // 可选：签发者
    .jwt_issuer("my-application")
    
    // 可选：受众
    .jwt_audience("web-users")
    
    // 令牌超时
    .timeout(7200)
    
    .build_config();
```

### 使用

配置完成后，所有 sa-token 操作都会自动使用 JWT：

```rust
// 登录 - 生成 JWT 令牌
let token = StpUtil::login("user_123").await?;

// 登出
StpUtil::logout(&token).await?;

// 验证
let is_valid = StpUtil::is_login(&token).await;
```

## 算法

支持的 JWT 算法：

| 算法 | 描述 | 密钥类型 |
|------|------|----------|
| HS256 | HMAC 使用 SHA-256 | 对称（密钥） |
| HS384 | HMAC 使用 SHA-384 | 对称（密钥） |
| HS512 | HMAC 使用 SHA-512 | 对称（密钥） |
| RS256 | RSA 使用 SHA-256 | 非对称（公钥/私钥） |
| RS384 | RSA 使用 SHA-384 | 非对称（公钥/私钥） |
| RS512 | RSA 使用 SHA-512 | 非对称（公钥/私钥） |
| ES256 | ECDSA 使用 SHA-256 | 非对称（公钥/私钥） |
| ES384 | ECDSA 使用 SHA-384 | 非对称（公钥/私钥） |

### 选择算法

- **HS256/384/512**：适合大多数应用，快速且简单
- **RS256/384/512**：需要分发公钥进行验证时
- **ES256/384**：RSA 的现代替代方案，密钥更小

## 高级用法

### 1. 带自定义验证的令牌验证

```rust
let jwt_manager = JwtManager::new("secret")
    .set_issuer("expected-issuer")
    .set_audience("expected-audience");

// 验证将检查签发者和受众
let claims = jwt_manager.validate(&token)?;
```

### 2. 快速用户识别

```rust
// 提取用户ID而无需完整验证（用于日志记录、分析）
let user_id = jwt_manager.extract_login_id(&token)?;
```

### 3. 多算法

```rust
// 不同目的使用不同管理器
let user_manager = JwtManager::with_algorithm("user-secret", JwtAlgorithm::HS256);
let admin_manager = JwtManager::with_algorithm("admin-secret", JwtAlgorithm::HS512);
```

### 4. 自定义令牌生命周期

```rust
let mut claims = JwtClaims::new("user_123");

// 短期令牌（5 分钟）
claims.set_expiration(300);

// 长期令牌（30 天）
claims.set_expiration(2592000);

// 永不过期（生产环境不推荐）
// 不设置过期时间
```

## API 参考

### JwtManager

```rust
impl JwtManager {
    // 创建新管理器
    pub fn new(secret: impl Into<String>) -> Self;
    pub fn with_algorithm(secret: impl Into<String>, algorithm: JwtAlgorithm) -> Self;
    
    // 配置
    pub fn set_issuer(self, issuer: impl Into<String>) -> Self;
    pub fn set_audience(self, audience: impl Into<String>) -> Self;
    
    // 操作
    pub fn generate(&self, claims: &JwtClaims) -> SaTokenResult<String>;
    pub fn validate(&self, token: &str) -> SaTokenResult<JwtClaims>;
    pub fn refresh(&self, token: &str, extend_seconds: i64) -> SaTokenResult<String>;
    pub fn extract_login_id(&self, token: &str) -> SaTokenResult<String>;
    pub fn decode_without_validation(&self, token: &str) -> SaTokenResult<JwtClaims>;
}
```

### JwtClaims

```rust
impl JwtClaims {
    // 创建
    pub fn new(login_id: impl Into<String>) -> Self;
    
    // 标准声明
    pub fn set_expiration(&mut self, seconds: i64) -> &mut Self;
    pub fn set_expiration_at(&mut self, datetime: DateTime<Utc>) -> &mut Self;
    pub fn set_issuer(&mut self, issuer: impl Into<String>) -> &mut Self;
    pub fn set_audience(&mut self, audience: impl Into<String>) -> &mut Self;
    pub fn set_jti(&mut self, jti: impl Into<String>) -> &mut Self;
    
    // sa-token 扩展
    pub fn set_login_type(&mut self, login_type: impl Into<String>) -> &mut Self;
    pub fn set_device(&mut self, device: impl Into<String>) -> &mut Self;
    
    // 自定义声明
    pub fn add_claim(&mut self, key: impl Into<String>, value: Value) -> &mut Self;
    pub fn get_claim(&self, key: &str) -> Option<&Value>;
    
    // 工具方法
    pub fn is_expired(&self) -> bool;
    pub fn remaining_time(&self) -> Option<i64>;
}
```

## 安全最佳实践

1. **使用强密钥**：HMAC 算法至少 32 个字符
2. **定期轮换密钥**：定期更换密钥
3. **设置过期时间**：始终设置合理的过期时间
4. **验证所有内容**：使用完整验证，而不仅仅是解码
5. **仅 HTTPS**：始终通过 HTTPS 传输 JWT
6. **安全存储**：不要在代码或日志中暴露密钥
7. **处理错误**：正确处理验证错误
8. **避免敏感数据**：不要在声明中存储敏感信息（它们只是 base64 编码的）

## 错误处理

```rust
use sa_token_core::SaTokenError;

match jwt_manager.validate(&token) {
    Ok(claims) => {
        // 令牌有效
        println!("用户: {}", claims.login_id);
    }
    Err(SaTokenError::TokenExpired) => {
        // 令牌已过期
        println!("请重新登录");
    }
    Err(SaTokenError::InvalidToken(msg)) => {
        // 无效的令牌（签名、格式等）
        println!("无效的令牌: {}", msg);
    }
    Err(e) => {
        // 其他错误
        println!("错误: {:?}", e);
    }
}
```

## 示例

运行 JWT 示例：

```bash
cargo run --example jwt_example
```

查看 `examples/jwt_example.rs` 获取全面的示例，包括：
- 独立 JWT 使用
- 与 sa-token 集成
- 令牌刷新
- 多种算法
- 自定义声明
- 快速用户识别

## 参考资料

- [JWT.io](https://jwt.io/) - JWT 介绍和调试器
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT 规范
- [jsonwebtoken crate](https://docs.rs/jsonwebtoken/) - 底层库

## 下一步

- [StpUtil API 参考](/zh/guide/stp-util.md)
- [事件监听](/zh/guide/event-listener.md)
- [权限匹配](/zh/guide/permission-matching.md)


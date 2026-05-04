// Author: 金书记
//
//! Token Generator | Token 生成器
//!
//! Supports multiple token styles including UUID, Random, and JWT
//! 支持多种 Token 风格，包括 UUID、随机字符串和 JWT

use uuid::Uuid;
use crate::config::{TokenStyle, SaTokenConfig};
use crate::token::TokenValue;
use crate::token::jwt::{JwtManager, JwtClaims, JwtAlgorithm};
use chrono::Utc;
use sha2::{Sha256, Digest};

pub struct TokenGenerator;

impl TokenGenerator {
    /// Generate token based on configuration | 根据配置生成 token
    ///
    /// # Arguments | 参数
    ///
    /// * `config` - Sa-token configuration | Sa-token 配置
    /// * `login_id` - User login ID (required for JWT) | 用户登录ID（JWT 必需）
    pub fn generate_with_login_id(config: &SaTokenConfig, login_id: &str) -> TokenValue {
        match config.token_style {
            TokenStyle::Uuid => Self::generate_uuid(),
            TokenStyle::SimpleUuid => Self::generate_simple_uuid(),
            TokenStyle::Random32 => Self::generate_random(32),
            TokenStyle::Random64 => Self::generate_random(64),
            TokenStyle::Random128 => Self::generate_random(128),
            TokenStyle::Jwt => Self::generate_jwt(config, login_id),
            TokenStyle::Hash => Self::generate_hash(login_id),
            TokenStyle::Timestamp => Self::generate_timestamp(),
            TokenStyle::Tik => Self::generate_tik(),
        }
    }
    
    /// Generate token with login_id and extra data | 根据配置生成带有额外数据的 token
    ///
    /// 当 token_style 为 JWT 时，extra_data 会被签名到 JWT Claims 中。
    /// 其他风格不支持在 token 本身携带数据，extra_data 仅存储在 storage 中。
    ///
    /// # Arguments | 参数
    ///
    /// * `config` - Sa-token configuration | Sa-token 配置
    /// * `login_id` - User login ID | 用户登录ID
    /// * `extra_data` - Extra data to sign into JWT | 要签名到 JWT 中的额外数据
    pub fn generate_with_login_id_and_extra(
        config: &SaTokenConfig,
        login_id: &str,
        extra_data: &serde_json::Value,
    ) -> TokenValue {
        match config.token_style {
            TokenStyle::Jwt => Self::generate_jwt_with_extra(config, login_id, extra_data),
            // 非 JWT 风格无法在 token 中携带 extra 数据，走原有生成逻辑
            _ => Self::generate_with_login_id(config, login_id),
        }
    }
    
    /// Generate token (backward compatible) | 根据配置生成 token（向后兼容）
    pub fn generate(config: &SaTokenConfig) -> TokenValue {
        Self::generate_with_login_id(config, "")
    }
    
    /// 生成 UUID 风格的 token
    pub fn generate_uuid() -> TokenValue {
        TokenValue::new(Uuid::new_v4().to_string())
    }
    
    /// 生成简化的 UUID（去掉横杠）
    pub fn generate_simple_uuid() -> TokenValue {
        TokenValue::new(Uuid::new_v4().simple().to_string())
    }
    
    /// 生成随机字符串
    pub fn generate_random(length: usize) -> TokenValue {
        use sha2::{Sha256, Digest};
        let uuid = Uuid::new_v4();
        let random_bytes = uuid.as_bytes();
        let hash = Sha256::digest(random_bytes);
        let hex_string = hex::encode(hash);
        TokenValue::new(hex_string[..length.min(hex_string.len())].to_string())
    }
    
    /// Generate JWT token | 生成 JWT token
    ///
    /// # Arguments | 参数
    ///
    /// * `config` - Sa-token configuration | Sa-token 配置
    /// * `login_id` - User login ID | 用户登录ID
    pub fn generate_jwt(config: &SaTokenConfig, login_id: &str) -> TokenValue {
        // 如果 login_id 为空，则使用时间戳作为 login_id
        let effective_login_id = if login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            login_id.to_string()
        };
        
        // Get JWT secret key | 获取 JWT 密钥
        let secret = config.jwt_secret_key.as_ref()
            .expect("JWT secret key is required when using JWT token style");
        
        // Parse algorithm | 解析算法
        let algorithm = config.jwt_algorithm.as_ref()
            .and_then(|alg| Self::parse_jwt_algorithm(alg))
            .unwrap_or(JwtAlgorithm::HS256);
        
        // Create JWT manager | 创建 JWT 管理器
        let mut jwt_manager = JwtManager::with_algorithm(secret, algorithm);
        
        if let Some(ref issuer) = config.jwt_issuer {
            jwt_manager = jwt_manager.set_issuer(issuer);
        }
        
        if let Some(ref audience) = config.jwt_audience {
            jwt_manager = jwt_manager.set_audience(audience);
        }
        
        // Create claims | 创建声明
        let mut claims = JwtClaims::new(effective_login_id);
        
        // Set expiration | 设置过期时间
        if config.timeout > 0 {
            claims.set_expiration(config.timeout);
        }
        
        // Generate JWT token | 生成 JWT token
        match jwt_manager.generate(&claims) {
            Ok(token) => TokenValue::new(token),
            Err(e) => {
                eprintln!("Failed to generate JWT token: {:?}", e);
                // Fallback to UUID | 回退到 UUID
                Self::generate_uuid()
            }
        }
    }
    
    /// Generate JWT token with extra data signed into claims | 生成带有额外数据签名的 JWT token
    ///
    /// 与 `generate_jwt` 类似，但会将 `extra_data` 写入 JWT Claims 中，
    /// 使得 extra 数据成为 token 签名的一部分。
    ///
    /// # Arguments | 参数
    ///
    /// * `config` - Sa-token configuration | Sa-token 配置
    /// * `login_id` - User login ID | 用户登录ID
    /// * `extra_data` - Extra data to embed in JWT claims | 要签入 JWT 声明的额外数据
    pub fn generate_jwt_with_extra(
        config: &SaTokenConfig,
        login_id: &str,
        extra_data: &serde_json::Value,
    ) -> TokenValue {
        let effective_login_id = if login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            login_id.to_string()
        };
        
        let secret = config.jwt_secret_key.as_ref()
            .expect("JWT secret key is required when using JWT token style");
        
        let algorithm = config.jwt_algorithm.as_ref()
            .and_then(|alg| Self::parse_jwt_algorithm(alg))
            .unwrap_or(JwtAlgorithm::HS256);
        
        let mut jwt_manager = JwtManager::with_algorithm(secret, algorithm);
        
        if let Some(ref issuer) = config.jwt_issuer {
            jwt_manager = jwt_manager.set_issuer(issuer);
        }
        
        if let Some(ref audience) = config.jwt_audience {
            jwt_manager = jwt_manager.set_audience(audience);
        }
        
        let mut claims = JwtClaims::new(effective_login_id);
        
        if config.timeout > 0 {
            claims.set_expiration(config.timeout);
        }
        
        // 将 extra_data 写入 JWT claims
        // If extra_data is an Object, flatten each key-value into claims.extra
        // Otherwise, store the entire value under "extra" key
        match extra_data {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    claims.add_claim(key.clone(), value.clone());
                }
            }
            serde_json::Value::Null => {
                // Null 值不写入
            }
            other => {
                claims.add_claim("extra", other.clone());
            }
        }
        
        match jwt_manager.generate(&claims) {
            Ok(token) => TokenValue::new(token),
            Err(e) => {
                eprintln!("Failed to generate JWT token with extra: {:?}", e);
                Self::generate_uuid()
            }
        }
    }
    
    /// Parse JWT algorithm from string | 从字符串解析 JWT 算法
    fn parse_jwt_algorithm(alg: &str) -> Option<JwtAlgorithm> {
        match alg.to_uppercase().as_str() {
            "HS256" => Some(JwtAlgorithm::HS256),
            "HS384" => Some(JwtAlgorithm::HS384),
            "HS512" => Some(JwtAlgorithm::HS512),
            "RS256" => Some(JwtAlgorithm::RS256),
            "RS384" => Some(JwtAlgorithm::RS384),
            "RS512" => Some(JwtAlgorithm::RS512),
            "ES256" => Some(JwtAlgorithm::ES256),
            "ES384" => Some(JwtAlgorithm::ES384),
            _ => None,
        }
    }
    
    /// Generate Hash style token | 生成 Hash 风格 token
    ///
    /// Uses SHA256 hash of login_id + timestamp + random UUID
    /// 使用 SHA256 哈希：login_id + 时间戳 + 随机 UUID
    ///
    /// # Arguments | 参数
    ///
    /// * `login_id` - User login ID | 用户登录ID
    pub fn generate_hash(login_id: &str) -> TokenValue {
        // 如果 login_id 为空，使用时间戳代替
        let login_id_value = if login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            login_id.to_string()
        };
        
        let timestamp = Utc::now().timestamp_millis();
        let uuid = Uuid::new_v4();
        let data = format!("{}{}{}", login_id_value, timestamp, uuid);
        
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        let hash = hex::encode(result);
        
        TokenValue::new(hash)
    }
    
    /// Generate Timestamp style token | 生成时间戳风格 token
    ///
    /// Format: timestamp_milliseconds + 16-char random suffix
    /// 格式：毫秒级时间戳 + 16位随机后缀
    ///
    /// Example: 1760403556789_a3b2c1d4e5f6g7h8
    /// 示例：1760403556789_a3b2c1d4e5f6g7h8
    pub fn generate_timestamp() -> TokenValue {
        use chrono::Utc;
        use sha2::{Sha256, Digest};
        
        let timestamp = Utc::now().timestamp_millis();
        let uuid = Uuid::new_v4();
        
        // Generate random suffix | 生成随机后缀
        let mut hasher = Sha256::new();
        hasher.update(uuid.as_bytes());
        let result = hasher.finalize();
        let suffix = hex::encode(&result[..8]); // 16 characters
        
        TokenValue::new(format!("{}_{}", timestamp, suffix))
    }
    
    /// Generate Tik style token | 生成 Tik 风格 token
    ///
    /// Short 8-character alphanumeric token (URL-safe)
    /// 短小精悍的8位字母数字 token（URL安全）
    ///
    /// Character set: A-Z, a-z, 0-9 (62 characters)
    /// 字符集：A-Z, a-z, 0-9（62个字符）
    ///
    /// Example: aB3dE9fG
    /// 示例：aB3dE9fG
    pub fn generate_tik() -> TokenValue {
        use sha2::{Sha256, Digest};
        
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const TOKEN_LENGTH: usize = 8;
        
        let uuid = Uuid::new_v4();
        let mut hasher = Sha256::new();
        hasher.update(uuid.as_bytes());
        let hash = hasher.finalize();
        
        let mut token = String::with_capacity(TOKEN_LENGTH);
        for i in 0..TOKEN_LENGTH {
            let idx = (hash[i] as usize) % CHARSET.len();
            token.push(CHARSET[idx] as char);
        }
        
        TokenValue::new(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SaTokenConfig, TokenStyle};
    use crate::token::jwt::JwtManager;

    fn jwt_config() -> SaTokenConfig {
        let mut config = SaTokenConfig::default();
        config.token_style = TokenStyle::Jwt;
        config.jwt_secret_key = Some("test-secret-key-for-jwt".to_string());
        config.timeout = 3600;
        config
    }

    #[test]
    fn test_generate_jwt_with_extra_object() {
        let config = jwt_config();
        let extra = serde_json::json!({
            "role": "admin",
            "tenant_id": 42,
            "permissions": ["read", "write"]
        });

        let token = TokenGenerator::generate_jwt_with_extra(&config, "user_123", &extra);
        assert!(!token.as_str().is_empty());

        // 解析 JWT 验证 extra 数据已签入
        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();

        assert_eq!(claims.login_id, "user_123");
        assert_eq!(claims.get_claim("role"), Some(&serde_json::json!("admin")));
        assert_eq!(claims.get_claim("tenant_id"), Some(&serde_json::json!(42)));
        assert_eq!(
            claims.get_claim("permissions"),
            Some(&serde_json::json!(["read", "write"]))
        );
    }

    #[test]
    fn test_generate_jwt_with_extra_non_object() {
        let config = jwt_config();
        let extra = serde_json::json!("simple_string_value");

        let token = TokenGenerator::generate_jwt_with_extra(&config, "user_456", &extra);

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();

        assert_eq!(claims.login_id, "user_456");
        assert_eq!(
            claims.get_claim("extra"),
            Some(&serde_json::json!("simple_string_value"))
        );
    }

    #[test]
    fn test_generate_jwt_with_extra_null() {
        let config = jwt_config();
        let extra = serde_json::Value::Null;

        let token = TokenGenerator::generate_jwt_with_extra(&config, "user_789", &extra);

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();

        assert_eq!(claims.login_id, "user_789");
        assert!(claims.extra.is_empty());
    }

    #[test]
    fn test_generate_with_login_id_and_extra_jwt_style() {
        let config = jwt_config();
        let extra = serde_json::json!({"key": "value"});

        let token = TokenGenerator::generate_with_login_id_and_extra(&config, "user_jwt", &extra);

        // JWT token 包含两个 '.' 分隔符
        assert!(token.as_str().contains('.'));

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();
        assert_eq!(claims.get_claim("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn test_generate_with_login_id_and_extra_non_jwt_style() {
        let mut config = SaTokenConfig::default();
        config.token_style = TokenStyle::Uuid;
        let extra = serde_json::json!({"key": "value"});

        // 非 JWT 风格应该走正常生成逻辑，不 panic
        let token = TokenGenerator::generate_with_login_id_and_extra(&config, "user_uuid", &extra);
        assert!(!token.as_str().is_empty());
        // UUID 格式不包含 '.'
        assert!(!token.as_str().contains('.'));
    }
}

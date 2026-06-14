// Author: 金书记
//
//! Error type definitions | 错误类型定义

use thiserror::Error;

pub type SaTokenResult<T> = Result<T, SaTokenError>;

#[derive(Debug, Error)]
pub enum SaTokenError {
    // ============ Basic Token Errors | 基础 Token 错误 ============
    #[error("Token not found or expired")]
    TokenNotFound,
    
    #[error("Token is invalid: {0}")]
    InvalidToken(String),
    
    #[error("Token has expired")]
    TokenExpired,
    
    // ============ Authentication Errors | 认证错误 ============
    #[error("User not logged in")]
    NotLogin,
    
    #[error("Token is inactive")]
    TokenInactive,
    
    // ============ Authorization Errors | 授权错误 ============
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Permission denied: missing permission '{0}'")]
    PermissionDeniedDetail(String),
    
    #[error("Role denied: missing role '{0}'")]
    RoleDenied(String),
    
    // ============ Account Status Errors | 账户状态错误 ============
    #[error("Account is banned until {0}")]
    AccountBanned(String),
    
    #[error("Account is kicked out")]
    AccountKickedOut,

    #[error("Account login has been replaced on another device")]
    AccountReplaced,

    #[error("Secondary authentication required for service '{0}'")]
    NotSafe(String),

    #[error("Account is disabled for service '{service}' at level {level}")]
    DisableService { service: String, level: i32 },
    
    // ============ Session Errors | Session 错误 ============
    #[error("Session not found")]
    SessionNotFound,
    
    // ============ Nonce Errors | Nonce 错误 ============
    #[error("Nonce has been used, possible replay attack detected")]
    NonceAlreadyUsed,
    
    #[error("Invalid nonce format")]
    InvalidNonceFormat,
    
    #[error("Nonce timestamp is invalid or expired")]
    InvalidNonceTimestamp,
    
    // ============ Refresh Token Errors | 刷新令牌错误 ============
    #[error("Refresh token not found or expired")]
    RefreshTokenNotFound,
    
    #[error("Invalid refresh token data")]
    RefreshTokenInvalidData,
    
    #[error("Missing login_id in refresh token")]
    RefreshTokenMissingLoginId,
    
    #[error("Invalid expire time format in refresh token")]
    RefreshTokenInvalidExpireTime,
    
    // ============ Token Validation Errors | Token 验证错误 ============
    #[error("Token is empty")]
    TokenEmpty,
    
    #[error("Token is too short")]
    TokenTooShort,
    
    #[error("Login ID is not a valid number")]
    LoginIdNotNumber,
    
    // ============ OAuth2 Errors | OAuth2 错误 ============
    #[error("OAuth2 client not found")]
    OAuth2ClientNotFound,
    
    #[error("Invalid client credentials")]
    OAuth2InvalidCredentials,
    
    #[error("Client ID mismatch")]
    OAuth2ClientIdMismatch,
    
    #[error("Redirect URI mismatch")]
    OAuth2RedirectUriMismatch,
    
    #[error("Authorization code not found or expired")]
    OAuth2CodeNotFound,
    
    #[error("Access token not found or expired")]
    OAuth2AccessTokenNotFound,
    
    #[error("Refresh token not found or expired")]
    OAuth2RefreshTokenNotFound,
    
    #[error("Invalid refresh token data")]
    OAuth2InvalidRefreshToken,
    
    #[error("Invalid scope data")]
    OAuth2InvalidScope,
    
    // ============ SSO Errors | SSO 单点登录错误 ============
    #[error("SSO ticket not found or invalid")]
    InvalidTicket,
    
    #[error("SSO ticket has expired")]
    TicketExpired,
    
    #[error("Service URL mismatch")]
    ServiceMismatch,
    
    #[error("SSO session not found")]
    SsoSessionNotFound,
    
    // ============ System Errors | 系统错误 ============
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl SaTokenError {
    /// Get the error message as a string
    /// 
    /// This method returns the English error message for the error.
    /// The error messages are defined using the `#[error(...)]` attribute.
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let err = SaTokenError::NotLogin;
    /// assert_eq!(err.message(), "User not logged in");
    /// ```
    pub fn message(&self) -> String {
        self.to_string()
    }
    
    /// Check if the error is an authentication error
    /// 
    /// Returns `true` for errors related to authentication (login/token validity)
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::NotLogin 
            | Self::TokenNotFound 
            | Self::TokenExpired 
            | Self::TokenInactive 
            | Self::InvalidToken(_)
            | Self::AccountKickedOut
            | Self::AccountReplaced
        )
    }
    
    /// Check if the error is an authorization error
    /// 
    /// Returns `true` for errors related to permissions or roles
    pub fn is_authz_error(&self) -> bool {
        matches!(
            self,
            Self::PermissionDenied 
            | Self::PermissionDeniedDetail(_) 
            | Self::RoleDenied(_)
        )
    }
}

/// Application-level error messages
/// 
/// These constants provide standard error messages for application-specific errors
/// that are not part of SaTokenError.
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use sa_token_core::error::messages;
/// 
/// let err_msg = messages::INVALID_CREDENTIALS;
/// return Err(ApiError::Unauthorized(err_msg.to_string()));
/// ```
pub mod messages {
    /// Invalid username or password
    pub const INVALID_CREDENTIALS: &str = "Invalid username or password";
    
    /// Login failed
    pub const LOGIN_FAILED: &str = "Login failed";
    
    /// Authentication error
    pub const AUTH_ERROR: &str = "Authentication error";
    
    /// Permission required
    pub const PERMISSION_REQUIRED: &str = "Permission required";
    
    /// Role required
    pub const ROLE_REQUIRED: &str = "Role required";
}

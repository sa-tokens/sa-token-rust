use gotham::state::StateData;
use sa_token_core::token::TokenValue;

/// 中文 | English
/// TokenValue 包装器 - 实现 StateData trait | TokenValue wrapper - implements StateData trait
#[derive(Clone, StateData)]
pub struct TokenValueWrapper(pub TokenValue);

impl From<TokenValue> for TokenValueWrapper {
    fn from(token: TokenValue) -> Self {
        Self(token)
    }
}

/// 中文 | English
/// LoginId 包装器 - 实现 StateData trait | LoginId wrapper - implements StateData trait
#[derive(Clone, StateData)]
pub struct LoginIdWrapper(pub String);

impl From<String> for LoginIdWrapper {
    fn from(login_id: String) -> Self {
        Self(login_id)
    }
}

// Author: 金书记
//
//! Token → login_id 映射标记（对齐 Java NotLoginException）

/// 被踢下线标记
pub const TOKEN_MAP_KICK_OUT: &str = "-5";

/// 被顶下线标记
pub const TOKEN_MAP_BE_REPLACED: &str = "-4";

pub fn is_kick_out_marker(value: &str) -> bool {
    value == TOKEN_MAP_KICK_OUT
}

pub fn is_replaced_marker(value: &str) -> bool {
    value == TOKEN_MAP_BE_REPLACED
}

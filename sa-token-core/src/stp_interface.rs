// Author: 金书记
//
//! 权限/角色/封禁数据源回调（对齐 Java StpInterface）

use async_trait::async_trait;

use crate::error::SaTokenResult;

/// 权限、角色、封禁数据回调
#[async_trait]
pub trait StpInterface: Send + Sync {
    async fn get_permission_list(
        &self,
        login_id: &str,
        login_type: &str,
    ) -> SaTokenResult<Vec<String>>;

    async fn get_role_list(
        &self,
        login_id: &str,
        login_type: &str,
    ) -> SaTokenResult<Vec<String>>;

    /// 返回封禁等级；`None` 表示未封禁
    async fn is_disabled(&self, login_id: &str, service: &str) -> SaTokenResult<Option<i32>> {
        let _ = (login_id, service);
        Ok(None)
    }
}

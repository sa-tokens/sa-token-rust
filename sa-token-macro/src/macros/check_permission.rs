// Author: 金书记
//
//! 权限检查宏
//! 
//! 提供细粒度的权限控制，支持通配符和精确匹配

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, ItemFn, LitStr, Error};

/// 检查权限的宏
/// 
/// 使用此宏标注的函数会在执行前检查用户是否拥有指定权限。
/// 
/// # 参数
/// 
/// - `permission` - 权限标识符，支持以下格式：
///   - 精确匹配: `"user:delete"`
///   - 通配符: `"admin:*"` (表示 admin 模块的所有权限)
///   - 全局通配符: `"*"` (表示所有权限)
/// 
/// # 工作原理
/// 
/// 1. 编译时：验证权限格式并添加元数据标记
/// 2. 运行时：中间件读取权限标识并验证
/// 3. 验证失败：返回 403 Forbidden
/// 
/// # 示例
/// 
/// ```rust,ignore
/// use axum::Json;
/// use sa_token_macro::sa_check_permission;
/// 
/// // 检查单个权限
/// #[sa_check_permission("user:delete")]
/// async fn delete_user(id: u64) -> &'static str {
///     "User deleted"
/// }
/// 
/// // 使用通配符
/// #[sa_check_permission("admin:*")]
/// async fn admin_panel() -> &'static str {
///     "Admin panel"
/// }
/// 
/// // 全局权限
/// #[sa_check_permission("*")]
/// async fn super_admin() -> &'static str {
///     "Super admin area"
/// }
/// ```
/// 
/// # 权限命名规范
/// 
/// 推荐使用 `模块:操作` 的格式：
/// - `user:list` - 查看用户列表
/// - `user:create` - 创建用户
/// - `user:update` - 更新用户
/// - `user:delete` - 删除用户
/// - `order:*` - 订单模块所有权限
pub fn sa_check_permission_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let permission = parse_macro_input!(attr as LitStr);
    let perm_value = permission.value();
    
    // 编译时验证：权限标识符不能为空
    if perm_value.trim().is_empty() {
        let err = Error::new_spanned(&permission, "Permission identifier cannot be empty");
        return TokenStream::from(err.to_compile_error());
    }
    
    let input = parse_macro_input!(item as ItemFn);
    
    let fn_name = &input.sig.ident;
    let fn_inputs = &input.sig.inputs;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_attrs = &input.attrs;
    let fn_vis = &input.vis;
    let fn_asyncness = &input.sig.asyncness;
    let fn_generics = &input.sig.generics;
    let fn_where_clause = &input.sig.generics.where_clause;
    
    if fn_asyncness.is_none() {
        return syn::Error::new_spanned(fn_name, "Macro requires async function")
            .to_compile_error().into();
    }
    
    let check_code = quote! {
        let __login_id = sa_token_core::StpUtil::get_login_id_as_string().await?;
        sa_token_core::StpUtil::check_permission(&__login_id, #perm_value).await?;
    };
    
    let expanded: TokenStream2 = quote! {
        #(#fn_attrs)*
        #[doc(hidden)]
        #fn_vis #fn_asyncness fn #fn_name #fn_generics(#fn_inputs) #fn_output #fn_where_clause {
            #check_code
            #fn_body
        }
    };
    
    expanded.into()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 📖 代码流程说明 - 权限检查
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 问题：为什么宏中没有看到实际的权限检查逻辑？
// 答案：权限检查逻辑在业务代码或中间件中，宏只负责标记所需权限。
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 完整权限检查流程
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 1】编译时 - 宏展开（本文件）
// ─────────────────────────────────────────────────────────────────────────
//
// 用户代码：
// ```rust
// #[sa_check_permission("user:delete")]
// async fn delete_user(id: u64) -> &'static str {
//     "User deleted"
// }
// ```
//
// 宏展开后：
// ```rust
// #[cfg_attr(feature = "sa-token-metadata", sa_token_check = "permission")]
// #[cfg_attr(feature = "sa-token-metadata", sa_token_permission = "user:delete")]
// async fn delete_user(id: u64) -> &'static str {
//     "User deleted"
// }
// ```
//
// 关键点：
// - 编译时验证：权限标识符不能为空
// - 添加元数据：记录所需权限 "user:delete"
// - 函数体不变：不插入任何权限检查代码
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 2】应用启动 - 权限配置（业务代码）
// ─────────────────────────────────────────────────────────────────────────
//
// 位置：main.rs 或初始化代码
//
// ```rust
// // 初始化权限数据（通常从数据库加载）
// async fn init_permissions() {
//     // 为用户设置权限
//     StpUtil::set_permissions("user_123", vec![
//         "user:list".to_string(),
//         "user:create".to_string(),
//         "user:update".to_string(),
//         "user:delete".to_string(),  // ⬅️ 这个用户有删除权限
//     ]).await?;
//     
//     // 为管理员设置权限（使用通配符）
//     StpUtil::set_permissions("admin_001", vec![
//         "user:*".to_string(),    // ⬅️ user 模块的所有权限
//         "order:*".to_string(),
//     ]).await?;
// }
// ```
//
// 关键点：
// - 权限存储在内存或 Redis 中
// - 支持精确匹配和通配符
// - 每个用户可以有多个权限
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 3】运行时 - 请求处理
// ─────────────────────────────────────────────────────────────────────────
//
// 3.1 中间件提取 token 和 login_id
// ─────────────────────────────────────────────────────────────────────────
//
// 位置：sa-token-plugin-axum/src/layer.rs
//
// ```rust
// impl<S> Service<Request<ReqBody>> for SaTokenMiddleware<S> {
//     fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
//         Box::pin(async move {
//             // ⬇️ 提取并验证 token
//             if let Some(token_str) = extract_token_from_request(&request) {
//                 let token = TokenValue::new(token_str);
//                 if state.manager.is_valid(&token).await {
//                     if let Ok(token_info) = state.manager.get_token_info(&token).await {
//                         // ⬇️ 存储 login_id 到上下文
//                         request.extensions_mut().insert(token_info.login_id.clone());
//                         ctx.login_id = Some(token_info.login_id);
//                     }
//                 }
//             }
//             
//             // ⬇️ 继续处理请求
//             inner.call(request).await
//         })
//     }
// }
// ```
//
// 3.2 路由处理函数 - 权限检查（两种方式）
// ─────────────────────────────────────────────────────────────────────────
//
// 方式 A：在函数内手动检查（推荐）
// ```rust
// #[sa_check_permission("user:delete")]  // ⬅️ 宏标记所需权限
// async fn delete_user(id: u64) -> Result<&'static str, StatusCode> {
//     // ⬇️ 手动检查权限
//     let login_id = StpUtil::get_login_id_as_string()
//         .map_err(|_| StatusCode::UNAUTHORIZED)?;
//     
//     // ⬇️ 验证是否有权限
//     if !StpUtil::has_permission(&login_id, "user:delete").await {
//         return Err(StatusCode::FORBIDDEN);
//     }
//     
//     // ⬇️ 执行业务逻辑
//     // ... 删除用户代码 ...
//     Ok("User deleted")
// }
// ```
//
// 方式 B：使用 check_permission（抛异常）
// ```rust
// #[sa_check_permission("user:delete")]
// async fn delete_user(id: u64) -> Result<&'static str, StatusCode> {
//     let login_id = StpUtil::get_login_id_as_string()?;
//     
//     // ⬇️ 检查权限，失败会抛出异常
//     StpUtil::check_permission(&login_id, "user:delete").await?;
//     
//     Ok("User deleted")
// }
// ```
//
// 关键点：
// - 宏只标记所需权限，不执行检查
// - 实际检查需要手动调用 StpUtil 方法
// - has_permission() 返回 bool
// - check_permission() 失败会返回 Err
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 4】权限匹配逻辑
// ─────────────────────────────────────────────────────────────────────────
//
// 位置：sa-token-core/src/util.rs
//
// ```rust
// pub async fn has_permission(login_id: impl LoginId, permission: &str) -> bool {
//     let manager = Self::get_manager();
//     let map = manager.user_permissions.read().await;
//     
//     if let Some(permissions) = map.get(&login_id.to_login_id()) {
//         // ⬇️ 1. 精确匹配
//         if permissions.contains(&permission.to_string()) {
//             return true;
//         }
//         
//         // ⬇️ 2. 通配符匹配
//         for perm in permissions {
//             if perm.ends_with(":*") {
//                 let prefix = &perm[..perm.len() - 2];
//                 if permission.starts_with(prefix) {
//                     return true;
//                 }
//             }
//         }
//     }
//     
//     false
// }
// ```
//
// 匹配规则：
// ┌──────────────────┬──────────────────┬──────────┐
// │ 用户权限         │ 请求权限         │ 是否匹配 │
// ├──────────────────┼──────────────────┼──────────┤
// │ user:delete      │ user:delete      │ ✅ 精确  │
// │ user:*           │ user:delete      │ ✅ 通配  │
// │ user:*           │ user:list        │ ✅ 通配  │
// │ admin:*          │ user:delete      │ ❌ 不匹配│
// │ user:read        │ user:delete      │ ❌ 不匹配│
// └──────────────────┴──────────────────┴──────────┘
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【总结】权限检查的职责分离
// ─────────────────────────────────────────────────────────────────────────
//
// ┌─────────────────┬──────────────────────┬──────────────────────────────┐
// │  组件           │  职责                │  执行时机                    │
// ├─────────────────┼──────────────────────┼──────────────────────────────┤
// │ 宏 (本文件)     │ 标记所需权限         │ 编译时                       │
// │ 初始化代码      │ 配置用户权限         │ 应用启动时                   │
// │ 中间件          │ 提取 token/login_id（宜 core `router::run_auth_flow`） │ 运行时 - 请求到达时 │
// │ 业务代码        │ 调用权限检查         │ 运行时 - 函数内部            │
// │ StpUtil         │ 执行权限匹配         │ 运行时 - 被调用时            │
// └─────────────────┴──────────────────────┴──────────────────────────────┘
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【为什么需要手动调用权限检查？】
// ─────────────────────────────────────────────────────────────────────────
//
// ✅ 优点：
// 1. 灵活性 - 可以在检查前后执行自定义逻辑
// 2. 错误处理 - 可以自定义权限不足时的响应
// 3. 动态权限 - 可以根据业务逻辑动态决定检查哪些权限
// 4. 性能优化 - 只在需要时才检查，避免不必要的数据库查询
//
// 示例：
// ```rust
// #[sa_check_permission("order:refund")]
// async fn refund_order(order_id: u64, amount: f64) -> Result<String, StatusCode> {
//     let login_id = StpUtil::get_login_id_as_string()?;
//     
//     // ⬇️ 动态权限：金额超过 1000 需要额外的高级权限
//     let required_permission = if amount > 1000.0 {
//         "order:refund:advanced"
//     } else {
//         "order:refund"
//     };
//     
//     if !StpUtil::has_permission(&login_id, required_permission).await {
//         // ⬇️ 自定义错误响应
//         return Err(StatusCode::FORBIDDEN);
//     }
//     
//     Ok(format!("Refunded ${}", amount))
// }
// ```
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【未来可能的增强】自动权限检查中间件
// ─────────────────────────────────────────────────────────────────────────
//
// 可以开发一个专门的权限检查中间件，自动读取函数的权限标记并验证：
//
// ```rust
// // 未来可能的实现（需要反射或代码生成）
// pub struct SaPermissionMiddleware;
//
// impl<S> Service<Request> for SaPermissionMiddleware<S> {
//     fn call(&mut self, request: Request) -> Self::Future {
//         // 1. 从路由元数据中读取所需权限
//         // 2. 自动调用 StpUtil::has_permission()
//         // 3. 如果没有权限，直接返回 403
//         // 4. 有权限则继续执行
//     }
// }
// ```
//
// 注意：当前版本需要手动调用，因为：
// - Rust 缺少运行时反射
// - cfg_attr 的元数据在运行时不可访问
// - 需要额外的工具或框架支持
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

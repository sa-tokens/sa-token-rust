// Author: 金书记
//
//! Login check macro
//! 
//! Provides compile-time login check that automatically inserts authentication verification

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Login check macro
/// 
/// Functions annotated with this macro will check if the user is logged in before execution.
/// 
/// # Requirements
/// 
/// - Function must be async (`async fn`)
/// - Function must return `Result<T, E>` where `E` implements `From<sa_token_core::SaTokenError>`
/// - Must be used with framework middleware (e.g., Axum's SaTokenLayer) which extracts and validates tokens
/// 
/// # How it works
/// 
/// 1. Compile time: Inserts `StpUtil::check_login_current()?;` at the beginning of function body
/// 2. Runtime: Executes login check, returns `SaTokenError::NotLogin` if not logged in
/// 3. On failure: Error is propagated via `?` operator, framework converts to HTTP status code (typically 401)
/// 
/// # Examples
/// 
/// ```rust,ignore
/// use axum::{response::Json, http::StatusCode};
/// use sa_token_macro::sa_check_login;
/// 
/// #[sa_check_login]
/// async fn user_dashboard() -> Result<Json<serde_json::Value>, StatusCode> {
///     // If not logged in, check_login_current()? will return error
///     // Only logged in users can reach here
///     Ok(Json(serde_json::json!({
///         "message": "Welcome!"
///     })))
/// }
/// ```
/// 
/// # Notes
/// 
/// - Must be used with framework middleware (e.g., Axum's SaTokenLayer) which sets up context
/// - Only supports async functions
/// - Function must return Result type for `?` operator to work
/// - Supports generic parameters and lifetime annotations
pub fn sa_check_login_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    
    // Extract function signature components
    let fn_name = &input.sig.ident;
    let fn_inputs = &input.sig.inputs;
    let fn_output = &input.sig.output;
    let fn_body = &input.block;
    let fn_attrs = &input.attrs;
    let fn_vis = &input.vis;
    let fn_asyncness = &input.sig.asyncness;
    let fn_generics = &input.sig.generics;
    let fn_where_clause = &input.sig.generics.where_clause;
    
    // Check if function is async
    if fn_asyncness.is_none() {
        return syn::Error::new_spanned(
            fn_name,
            "sa_check_login macro requires function to be async (async fn)"
        ).to_compile_error().into();
    }
    
    // Generate authentication check code
    // Insert login check at the beginning of function body
    let auth_check = quote! {
        // Login check - automatically inserted by sa_check_login macro
        // Returns SaTokenError::NotLogin if not logged in, error is propagated via ? operator
        if !sa_token_core::StpUtil::is_login_current() {
            return Err(sa_token_core::SaTokenError::NotLogin.into());
        }
    };
    
    // Generate expanded function
    let expanded: TokenStream2 = quote! {
        // Preserve original attributes
        #(#fn_attrs)*
        // Add metadata marker (for middleware recognition)
        #[doc(hidden)]
        #fn_vis #fn_asyncness fn #fn_name #fn_generics(#fn_inputs) #fn_output #fn_where_clause {
            // Insert authentication check at beginning of function body
            #auth_check
            
            // Original function body
            #fn_body
        }
    };
    
    expanded.into()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 📖 代码流程说明
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 问题：为什么宏中没有看到实际的认证逻辑？
// 答案：这是一个**声明式**的设计模式，认证逻辑在运行时由中间件执行。
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 完整认证流程（从编译时到运行时）
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 1】编译时 - 宏展开（本文件）
// ─────────────────────────────────────────────────────────────────────────
//
// 用户代码：
// ```rust
// #[sa_check_login]
// async fn user_info() -> Json<Value> {
//     Json(json!({"name": "Alice"}))
// }
// ```
//
// 宏展开后：
// ```rust
// #[cfg_attr(feature = "sa-token-metadata", sa_token_check = "login")]
// async fn user_info() -> Json<Value> {
//     Json(json!({"name": "Alice"}))
// }
// ```
//
// 关键点：
// - 只添加了元数据属性标记
// - 函数体保持不变
// - 没有插入任何认证代码
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 2】运行时 - 请求到达（框架插件）
// ─────────────────────────────────────────────────────────────────────────
//
// 位置：sa-token-plugin-axum/src/layer.rs (或其他框架插件)
//
// ```rust
// // 中间件拦截所有请求
// impl<S> Service<Request<ReqBody>> for SaTokenMiddleware<S> {
//     fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
//         Box::pin(async move {
//             // ⬇️ 从请求中提取 token
//             if let Some(token_str) = extract_token_from_request(&request, &state) {
//                 let token = TokenValue::new(token_str);
//                 
//                 // ⬇️ 验证 token 是否有效
//                 if state.manager.is_valid(&token).await {
//                     // ⬇️ 获取 token 信息
//                     if let Ok(token_info) = state.manager.get_token_info(&token).await {
//                         // ⬇️ 存储到请求扩展中
//                         request.extensions_mut().insert(token.clone());
//                         request.extensions_mut().insert(token_info.login_id.clone());
//                         
//                         // ⬇️ 设置上下文（供无参数方法使用）
//                         ctx.token = Some(token.clone());
//                         ctx.login_id = Some(token_info.login_id);
//                     }
//                 }
//             }
//             
//             // ⬇️ 继续处理请求（调用实际的路由处理函数）
//             inner.call(request).await
//         })
//     }
// }
// ```
//
// 关键点：
// - 中间件在路由处理函数之前执行
// - 自动从 Header/Cookie/Query 中提取 token
// - 验证 token 并存储到请求上下文
// - 如果验证失败，token 不会被存储
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【步骤 3】运行时 - 路由处理函数执行
// ─────────────────────────────────────────────────────────────────────────
//
// 用户的路由处理函数：
// ```rust
// #[sa_check_login]  // ⬅️ 这个宏标记的函数
// async fn user_info() -> Json<Value> {
//     // ⬇️ 如果执行到这里，说明：
//     //    1. 中间件已经验证了 token
//     //    2. token 和 login_id 已存储到上下文
//     //    3. 可以安全地使用无参数 StpUtil 方法
//     
//     let login_id = StpUtil::get_login_id_as_string()?;
//     Json(json!({
//         "name": "Alice",
//         "login_id": login_id
//     }))
// }
// ```
//
// 关键点：
// - 宏本身不做验证，只是标记
// - 实际验证已在中间件完成
// - 函数内可以放心使用用户数据
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【可选】高级用法 - 手动验证（未来扩展）
// ─────────────────────────────────────────────────────────────────────────
//
// 如果需要更细粒度的控制，可以在函数内手动验证：
//
// ```rust
// #[sa_check_login]
// async fn user_info() -> Result<Json<Value>, StatusCode> {
//     // 方式 1: 使用无参数方法（从上下文获取）
//     if !StpUtil::is_login_current() {
//         return Err(StatusCode::UNAUTHORIZED);
//     }
//     
//     // 方式 2: 手动检查
//     StpUtil::check_login_current()?;
//     
//     Ok(Json(json!({"name": "Alice"})))
// }
// ```
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【总结】认证流程的职责分离
// ─────────────────────────────────────────────────────────────────────────
//
// ┌─────────────────┬──────────────────────┬──────────────────────────────┐
// │  组件           │  职责                │  执行时机                    │
// ├─────────────────┼──────────────────────┼──────────────────────────────┤
// │ 宏 (本文件)     │ 添加元数据标记       │ 编译时                       │
// │ 中间件          │ 提取和验证 token（宜调用 core `router::run_auth_flow`） │ 运行时 - 请求到达时 │
// │ 路由处理函数    │ 业务逻辑             │ 运行时 - 中间件之后          │
// │ StpUtil         │ 便捷的认证操作       │ 运行时 - 函数内部            │
// └─────────────────┴──────────────────────┴──────────────────────────────┘
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【为什么这样设计？】
// ─────────────────────────────────────────────────────────────────────────
//
// ✅ 优点：
// 1. 关注点分离 - 宏只负责声明，中间件负责执行
// 2. 灵活性高 - 可以根据不同框架实现不同的中间件
// 3. 性能好 - 编译时只做标记，不生成额外代码
// 4. 可维护性强 - 认证逻辑集中在中间件，易于修改和测试
// 5. 符合 Rust 习惯 - 类似于 Axum 的 Extension、Actix 的 HttpMessage
//
// ❌ 注意事项：
// 1. 必须配合中间件使用 - 单独的宏标记不会执行任何验证
// 2. 依赖框架特性 - 需要框架支持请求扩展（Extension）
// 3. 元数据功能有限 - cfg_attr 仅用于文档和工具，不影响运行时
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// 【完整示例】从配置到使用
// ─────────────────────────────────────────────────────────────────────────
//
// ```rust
// use axum::{Router, routing::get};
// use sa_token_plugin_axum::{SaTokenState, SaTokenLayer};
// use sa_token_storage_memory::MemoryStorage;
// use sa_token_macro::sa_check_login;
//
// // 1️⃣ 配置和初始化
// let state = SaTokenState::builder()
//     .storage(Arc::new(MemoryStorage::new()))
//     .build();
//
// // 2️⃣ 添加中间件
// let app = Router::new()
//     .route("/user/info", get(user_info))
//     .layer(SaTokenLayer::new(state.clone()));  // ⬅️ 中间件在这里
//
// // 3️⃣ 定义路由（使用宏标记）
// #[sa_check_login]  // ⬅️ 宏标记
// async fn user_info() -> Json<Value> {
//     let login_id = StpUtil::get_login_id_as_string()?;
//     Json(json!({"login_id": login_id}))
// }
//
// // 4️⃣ 请求流程
// // 客户端请求 → 中间件提取并验证 token → 路由处理函数执行 → 返回响应
// ```
//
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

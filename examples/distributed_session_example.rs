//! 分布式 Session 与服务间认证示例
//!
//! 演示微服务架构下的 Session 共享和服务认证
//!
//! ## 导入方式
//!
//! ### 方式1: 独立使用核心库（本示例）
//! ```ignore
//! use sa_token_core::{DistributedSessionManager, ServiceCredential, ...};
//! ```
//!
//! ### 方式2: 使用 Web 框架插件（推荐）
//! ```toml
//! [dependencies]
//! sa-token-plugin-axum = "0.1.3"
//! ```
//! ```ignore
//! use sa_token_plugin_axum::*;  // 分布式 Session 功能已重新导出！
//! ```

use sa_token_core::{
    SaTokenManager, SaTokenConfig, DistributedSessionManager, 
    InMemoryDistributedStorage, ServiceCredential,
};
use sa_token_storage_memory::MemoryStorage;
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("分布式 Session 与服务间认证示例 | Distributed Session & Service Authentication Example");
    println!("========================================\n");

    let config = SaTokenConfig::default();
    let storage = Arc::new(MemoryStorage::new());
    
    let dist_storage = Arc::new(InMemoryDistributedStorage::new());
    let dist_manager = Arc::new(DistributedSessionManager::new(
        dist_storage,
        "service-main".to_string(),
        Duration::from_secs(3600),
    ));
    
    let manager_with_dist = SaTokenManager::new(
        storage,
        config,
    ).with_distributed_manager(dist_manager.clone());

    println!("1. Register Multiple Services");
    
    let service1 = ServiceCredential {
        service_id: "api-gateway".to_string(),
        service_name: "API Gateway".to_string(),
        secret_key: "gateway-secret-key-123".to_string(),
        created_at: Utc::now(),
        permissions: vec!["read".to_string(), "write".to_string()],
    };
    dist_manager.register_service(service1.clone()).await;
    println!("   Registered: {} ({})", service1.service_name, service1.service_id);
    
    let service2 = ServiceCredential {
        service_id: "user-service".to_string(),
        service_name: "User Service".to_string(),
        secret_key: "user-secret-key-456".to_string(),
        created_at: Utc::now(),
        permissions: vec!["read".to_string()],
    };
    dist_manager.register_service(service2.clone()).await;
    println!("   Registered: {} ({})\n", service2.service_name, service2.service_id);

    println!("2. Service Authentication");
    match dist_manager.verify_service("api-gateway", "gateway-secret-key-123").await {
        Ok(cred) => {
            println!("   ✓ Service verified: {}", cred.service_name);
            println!("   Permissions: {:?}", cred.permissions);
        }
        Err(e) => println!("   ✗ Verification failed: {}", e),
    }
    
    match dist_manager.verify_service("api-gateway", "wrong-secret").await {
        Ok(_) => println!("   ✗ Should have failed!"),
        Err(_) => println!("   ✓ Correctly rejected invalid secret\n"),
    }

    println!("3. Create Distributed Session");
    let token1 = manager_with_dist.login("user123").await?;
    let session1 = dist_manager.create_session(
        "user123".to_string(),
        token1.as_str().to_string(),
    ).await?;
    
    println!("   Session created:");
    println!("   - ID: {}", session1.session_id);
    println!("   - Login ID: {}", session1.login_id);
    println!("   - Service: {}", session1.service_id);
    println!("   - Created: {}\n", session1.create_time);

    println!("4. Set Session Attributes");
    dist_manager.set_attribute(
        &session1.session_id,
        "user_role".to_string(),
        "admin".to_string(),
    ).await?;
    
    dist_manager.set_attribute(
        &session1.session_id,
        "department".to_string(),
        "Engineering".to_string(),
    ).await?;
    
    println!("   Set attributes: user_role=admin, department=Engineering\n");

    println!("5. Retrieve Session Attributes");
    if let Some(role) = dist_manager.get_attribute(&session1.session_id, "user_role").await? {
        println!("   user_role: {}", role);
    }
    if let Some(dept) = dist_manager.get_attribute(&session1.session_id, "department").await? {
        println!("   department: {}\n", dept);
    }

    println!("6. Refresh Session");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    dist_manager.refresh_session(&session1.session_id).await?;
    
    let refreshed = dist_manager.get_session(&session1.session_id).await?;
    println!("   Session refreshed");
    println!("   Last access: {}\n", refreshed.last_access);

    println!("7. Create Multiple Sessions for Same User");
    let token2 = manager_with_dist.login("user123").await?;
    let session2 = dist_manager.create_session(
        "user123".to_string(),
        token2.as_str().to_string(),
    ).await?;
    
    println!("   Created second session for user123");
    
    let sessions = dist_manager.get_sessions_by_login_id("user123").await?;
    println!("   Total sessions for user123: {}", sessions.len());
    for (i, session) in sessions.iter().enumerate() {
        println!("   Session {}: {}", i + 1, session.session_id);
    }
    println!();

    println!("8. Cross-Service Session Sharing");
    println!("   Scenario: User-Service accessing session created by API-Gateway");
    
    let session_from_gateway = dist_manager.get_session(&session1.session_id).await?;
    println!("   Retrieved session:");
    println!("   - Original service: {}", session_from_gateway.service_id);
    println!("   - Login ID: {}", session_from_gateway.login_id);
    println!("   - Attributes: {} items\n", session_from_gateway.attributes.len());

    println!("9. Remove Session Attribute");
    dist_manager.remove_attribute(&session1.session_id, "department").await?;
    println!("   Removed 'department' attribute");
    
    let dept_after = dist_manager.get_attribute(&session1.session_id, "department").await?;
    println!("   Department after removal: {:?}\n", dept_after);

    println!("10. Delete Single Session");
    dist_manager.delete_session(&session2.session_id).await?;
    println!("   Deleted session: {}", session2.session_id);
    
    let sessions_after = dist_manager.get_sessions_by_login_id("user123").await?;
    println!("   Remaining sessions: {}\n", sessions_after.len());

    println!("11. Delete All Sessions for User");
    let token3 = manager_with_dist.login("user456").await?;
    let _session3 = dist_manager.create_session("user456".to_string(), token3.as_str().to_string()).await?;
    let token4 = manager_with_dist.login("user456").await?;
    let _session4 = dist_manager.create_session("user456".to_string(), token4.as_str().to_string()).await?;
    
    println!("   Created 2 sessions for user456");
    
    dist_manager.delete_all_sessions("user456").await?;
    println!("   Deleted all sessions for user456");
    
    let sessions_456 = dist_manager.get_sessions_by_login_id("user456").await?;
    println!("   Remaining sessions: {}\n", sessions_456.len());

    println!("12. Session Timeout Simulation");
    println!("   Session timeout configured: 3600 seconds");
    println!("   In production, sessions would expire automatically");
    println!("   Storage backend handles TTL enforcement\n");

    println!("=== Example Completed Successfully ===");
    
    Ok(())
}


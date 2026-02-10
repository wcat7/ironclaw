//! Integration tests for Store with SQLite backend.
//!
//! Uses in-memory SQLite (no Postgres required). Verifies conversation, job,
//! and workspace operations on the SQLite store.

//! Run with: cargo test --features test-utils store_sqlite

use std::sync::Arc;

use ironclaw::config::DatabaseConfig;
use ironclaw::context::{JobContext, JobState};
use ironclaw::history::Store;

#[tokio::test]
async fn test_sqlite_store_conversation_and_job() {
    let config = DatabaseConfig::for_test("sqlite://");
    let store = Store::new(&config).await.expect("Store::new");
    store.run_migrations().await.expect("run_migrations");

    let conv_id = store
        .create_conversation("test", "user1", None)
        .await
        .expect("create_conversation");
    store.touch_conversation(conv_id).await.expect("touch_conversation");
    let msg_id = store
        .add_conversation_message(conv_id, "user", "hello")
        .await
        .expect("add_conversation_message");
    assert_ne!(msg_id, conv_id);

    let mut ctx = JobContext::with_user("user1", "Test job", "Description");
    ctx.conversation_id = Some(conv_id);
    store.save_job(&ctx).await.expect("save_job");

    let loaded = store.get_job(ctx.job_id).await.expect("get_job");
    let loaded = loaded.expect("job found");
    assert_eq!(loaded.title, "Test job");
    assert_eq!(loaded.conversation_id, Some(conv_id));

    store
        .update_job_status(ctx.job_id, JobState::Completed, None)
        .await
        .expect("update_job_status");
    let loaded2 = store.get_job(ctx.job_id).await.expect("get_job");
    assert_eq!(loaded2.unwrap().state, JobState::Completed);
}

#[tokio::test]
async fn test_sqlite_store_new_workspace_write_read() {
    let config = DatabaseConfig::for_test("sqlite://");
    let store = Store::new(&config).await.expect("Store::new");
    store.run_migrations().await.expect("run_migrations");

    let workspace = store.new_workspace("test_user");
    let workspace = Arc::new(workspace);

    workspace
        .write("MEMORY.md", "# Test content\n\nLine 2.")
        .await
        .expect("write");

    let doc = workspace.read("MEMORY.md").await.expect("read");
    assert!(doc.content.contains("Test content"));
    assert!(doc.content.contains("Line 2."));

    workspace.append("MEMORY.md", "\nAppended.").await.expect("append");
    let doc2 = workspace.read("MEMORY.md").await.expect("read");
    assert!(doc2.content.contains("Appended."));
}

#[tokio::test]
async fn test_sqlite_store_temp_file_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("ironclaw.db");
    // Use bare path so absolute path is preserved (sqlite:// strips leading slash on Unix)
    let url = path.to_string_lossy().to_string();
    let config = DatabaseConfig::for_test(&url);
    let store = Store::new(&config).await.expect("Store::new");
    store.run_migrations().await.expect("run_migrations");

    let conv_id = store
        .create_conversation("test", "file_user", None)
        .await
        .expect("create_conversation");
    assert!(conv_id != uuid::Uuid::nil());

    let workspace = store.new_workspace("file_user");
    workspace
        .write("notes.md", "Persisted to file")
        .await
        .expect("write");
    let doc = workspace.read("notes.md").await.expect("read");
    assert_eq!(doc.content, "Persisted to file");
}

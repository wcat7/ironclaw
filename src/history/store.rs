//! Unified store: dispatches to Postgres or SQLite based on DATABASE_URL.

use std::sync::Arc;

use deadpool_postgres::Pool;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::config::{DatabaseConfig, DbKind};
use crate::context::{ActionRecord, JobContext, JobState};
use crate::error::DatabaseError;
use crate::history::postgres::PostgresStore;
use crate::history::sqlite::SqliteStore;
use crate::workspace::{SqliteWorkspaceRepo, Workspace};

/// Record for an LLM call to be persisted.
#[derive(Debug, Clone)]
pub struct LlmCallRecord<'a> {
    pub job_id: Option<Uuid>,
    pub conversation_id: Option<Uuid>,
    pub provider: &'a str,
    pub model: &'a str,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cost: Decimal,
    pub purpose: Option<&'a str>,
}

/// Database store for the agent (Postgres or SQLite).
pub enum Store {
    Postgres(PostgresStore),
    Sqlite(SqliteStore),
}

impl Store {
    /// Create a new store from config. Backend is chosen by DATABASE_URL scheme.
    pub async fn new(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let kind = config.kind().map_err(|e| DatabaseError::Pool(e.to_string()))?;
        match kind {
            DbKind::Postgres => {
                let inner = PostgresStore::new(config).await?;
                Ok(Store::Postgres(inner))
            }
            DbKind::Sqlite => {
                let inner = SqliteStore::new(config).await?;
                Ok(Store::Sqlite(inner))
            }
        }
    }

    /// Run database migrations.
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.run_migrations().await,
            Store::Sqlite(s) => s.run_migrations().await,
        }
    }

    /// Get a connection from the pool (Postgres only).
    pub async fn conn(&self) -> Result<deadpool_postgres::Object, DatabaseError> {
        match self {
            Store::Postgres(s) => s.conn().await,
            Store::Sqlite(_) => Err(DatabaseError::Pool(
                "conn() is not available for SQLite backend".to_string(),
            )),
        }
    }

    /// Get the Postgres pool, if this store is Postgres. Used by SecretsStore (Postgres only).
    pub fn pool(&self) -> Pool {
        match self {
            Store::Postgres(s) => s.pool(),
            Store::Sqlite(_) => {
                panic!("pool() called on SQLite store; use store.new_workspace() for Workspace")
            }
        }
    }

    /// Create a workspace for the given user. Uses Postgres or SQLite backend based on store.
    pub fn new_workspace(&self, user_id: &str) -> Workspace {
        match self {
            Store::Postgres(s) => Workspace::new(user_id, s.pool()),
            Store::Sqlite(s) => Workspace::new_with_repo(
                user_id,
                Arc::new(SqliteWorkspaceRepo::new(s.pool_sqlite().clone())),
            ),
        }
    }

    // ==================== Conversations ====================

    pub async fn create_conversation(
        &self,
        channel: &str,
        user_id: &str,
        thread_id: Option<&str>,
    ) -> Result<Uuid, DatabaseError> {
        match self {
            Store::Postgres(s) => s.create_conversation(channel, user_id, thread_id).await,
            Store::Sqlite(s) => s.create_conversation(channel, user_id, thread_id).await,
        }
    }

    pub async fn touch_conversation(&self, id: Uuid) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.touch_conversation(id).await,
            Store::Sqlite(s) => s.touch_conversation(id).await,
        }
    }

    pub async fn add_conversation_message(
        &self,
        conversation_id: Uuid,
        role: &str,
        content: &str,
    ) -> Result<Uuid, DatabaseError> {
        match self {
            Store::Postgres(s) => s.add_conversation_message(conversation_id, role, content).await,
            Store::Sqlite(s) => s.add_conversation_message(conversation_id, role, content).await,
        }
    }

    /// Get conversation by channel, user_id, and thread_id. Returns None if not found (read-only).
    pub async fn get_conversation_by_thread(
        &self,
        channel: &str,
        user_id: &str,
        thread_id: &str,
    ) -> Result<Option<Uuid>, DatabaseError> {
        match self {
            Store::Postgres(s) => s.get_conversation_by_thread(channel, user_id, thread_id).await,
            Store::Sqlite(s) => s.get_conversation_by_thread(channel, user_id, thread_id).await,
        }
    }

    /// Get or create a conversation by channel, user_id, and thread_id.
    /// Returns the conversation UUID (existing or newly created).
    pub async fn get_or_create_conversation_by_thread(
        &self,
        channel: &str,
        user_id: &str,
        thread_id: &str,
    ) -> Result<Uuid, DatabaseError> {
        match self {
            Store::Postgres(s) => {
                if let Some(id) = s.get_conversation_by_thread(channel, user_id, thread_id).await? {
                    return Ok(id);
                }
                s.create_conversation(channel, user_id, Some(thread_id)).await
            }
            Store::Sqlite(s) => {
                if let Some(id) = s.get_conversation_by_thread(channel, user_id, thread_id).await? {
                    return Ok(id);
                }
                s.create_conversation(channel, user_id, Some(thread_id)).await
            }
        }
    }

    /// Get messages for a conversation: (role, content, created_at). Limit 0 = no limit.
    pub async fn get_conversation_messages(
        &self,
        conversation_id: Uuid,
        limit: usize,
    ) -> Result<Vec<(String, String, String)>, DatabaseError> {
        match self {
            Store::Postgres(s) => s.get_conversation_messages(conversation_id, limit).await,
            Store::Sqlite(s) => s.get_conversation_messages(conversation_id, limit).await,
        }
    }

    // ==================== Jobs ====================

    pub async fn save_job(&self, ctx: &JobContext) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.save_job(ctx).await,
            Store::Sqlite(s) => s.save_job(ctx).await,
        }
    }

    pub async fn get_job(&self, id: Uuid) -> Result<Option<JobContext>, DatabaseError> {
        match self {
            Store::Postgres(s) => s.get_job(id).await,
            Store::Sqlite(s) => s.get_job(id).await,
        }
    }

    pub async fn update_job_status(
        &self,
        id: Uuid,
        status: JobState,
        failure_reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.update_job_status(id, status, failure_reason).await,
            Store::Sqlite(s) => s.update_job_status(id, status, failure_reason).await,
        }
    }

    pub async fn mark_job_stuck(&self, id: Uuid) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.mark_job_stuck(id).await,
            Store::Sqlite(s) => s.mark_job_stuck(id).await,
        }
    }

    pub async fn get_stuck_jobs(&self) -> Result<Vec<Uuid>, DatabaseError> {
        match self {
            Store::Postgres(s) => s.get_stuck_jobs().await,
            Store::Sqlite(s) => s.get_stuck_jobs().await,
        }
    }

    // ==================== Actions ====================

    pub async fn save_action(
        &self,
        job_id: Uuid,
        action: &ActionRecord,
    ) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.save_action(job_id, action).await,
            Store::Sqlite(s) => s.save_action(job_id, action).await,
        }
    }

    pub async fn get_job_actions(&self, job_id: Uuid) -> Result<Vec<ActionRecord>, DatabaseError> {
        match self {
            Store::Postgres(s) => s.get_job_actions(job_id).await,
            Store::Sqlite(s) => s.get_job_actions(job_id).await,
        }
    }

    // ==================== LLM Calls ====================

    pub async fn record_llm_call(&self, record: &LlmCallRecord<'_>) -> Result<Uuid, DatabaseError> {
        match self {
            Store::Postgres(s) => s.record_llm_call(record).await,
            Store::Sqlite(s) => s.record_llm_call(record).await,
        }
    }

    // ==================== Estimation Snapshots ====================

    pub async fn save_estimation_snapshot(
        &self,
        job_id: Uuid,
        category: &str,
        tool_names: &[String],
        estimated_cost: Decimal,
        estimated_time_secs: i32,
        estimated_value: Decimal,
    ) -> Result<Uuid, DatabaseError> {
        match self {
            Store::Postgres(s) => {
                s.save_estimation_snapshot(
                    job_id,
                    category,
                    tool_names,
                    estimated_cost,
                    estimated_time_secs,
                    estimated_value,
                )
                .await
            }
            Store::Sqlite(s) => {
                s.save_estimation_snapshot(
                    job_id,
                    category,
                    tool_names,
                    estimated_cost,
                    estimated_time_secs,
                    estimated_value,
                )
                .await
            }
        }
    }

    pub async fn update_estimation_actuals(
        &self,
        id: Uuid,
        actual_cost: Decimal,
        actual_time_secs: i32,
        actual_value: Option<Decimal>,
    ) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.update_estimation_actuals(id, actual_cost, actual_time_secs, actual_value).await,
            Store::Sqlite(s) => s.update_estimation_actuals(id, actual_cost, actual_time_secs, actual_value).await,
        }
    }
}

// ==================== Tool Failures (from agent) ====================

use crate::agent::BrokenTool;

impl Store {
    pub async fn record_tool_failure(
        &self,
        tool_name: &str,
        error_message: &str,
    ) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.record_tool_failure(tool_name, error_message).await,
            Store::Sqlite(s) => s.record_tool_failure(tool_name, error_message).await,
        }
    }

    pub async fn get_broken_tools(&self, threshold: i32) -> Result<Vec<BrokenTool>, DatabaseError> {
        match self {
            Store::Postgres(s) => s.get_broken_tools(threshold).await,
            Store::Sqlite(s) => s.get_broken_tools(threshold).await,
        }
    }

    pub async fn mark_tool_repaired(&self, tool_name: &str) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.mark_tool_repaired(tool_name).await,
            Store::Sqlite(s) => s.mark_tool_repaired(tool_name).await,
        }
    }

    pub async fn increment_repair_attempts(&self, tool_name: &str) -> Result<(), DatabaseError> {
        match self {
            Store::Postgres(s) => s.increment_repair_attempts(tool_name).await,
            Store::Sqlite(s) => s.increment_repair_attempts(tool_name).await,
        }
    }
}


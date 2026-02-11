//! SQLite backend for history store.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::FromRow;
use uuid::Uuid;

use crate::agent::BrokenTool;
use crate::config::DatabaseConfig;
use crate::context::{ActionRecord, JobContext, JobState};
use crate::error::DatabaseError;
use crate::history::store::LlmCallRecord;

/// SQLite-backed store.
pub struct SqliteStore {
    pool: SqlitePool,
}

fn sqlite_path_from_url(url: &str) -> String {
    let url = url.trim();
    if url.starts_with("sqlite://") {
        url.strip_prefix("sqlite://").unwrap_or(url).trim_start_matches('/').to_string()
    } else {
        url.to_string()
    }
}

impl SqliteStore {
    /// Create a new SQLite store and run migrations.
    pub async fn new(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let url = config.url();
        let path = sqlite_path_from_url(url);
        let path = if path.is_empty() || path == "memory" || path == ":memory:" {
            "file::memory:?cache=shared".to_string()
        } else {
            format!("file:{}?mode=rwc", path)
        };

        let opts = SqliteConnectOptions::from_str(&path)
            .map_err(|e| DatabaseError::Pool(format!("Invalid SQLite path: {}", e)))?
            .create_if_missing(true);

        let pool = SqlitePool::connect_with(opts)
            .await
            .map_err(|e| DatabaseError::Pool(e.to_string()))?;

        let store = Self { pool };
        store.run_migrations().await?;
        Ok(store)
    }

    /// Run schema creation (CREATE TABLE IF NOT EXISTS).
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        let stmts = [
            "CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                channel TEXT NOT NULL,
                user_id TEXT NOT NULL,
                thread_id TEXT,
                started_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_activity TEXT NOT NULL DEFAULT (datetime('now')),
                metadata TEXT NOT NULL DEFAULT '{}'
            )",
            "CREATE TABLE IF NOT EXISTS conversation_messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            "CREATE TABLE IF NOT EXISTS agent_jobs (
                id TEXT PRIMARY KEY,
                conversation_id TEXT REFERENCES conversations(id),
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT,
                status TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'direct',
                budget_amount TEXT,
                budget_token TEXT,
                bid_amount TEXT,
                estimated_cost TEXT,
                estimated_time_secs INTEGER,
                actual_cost TEXT,
                repair_attempts INTEGER NOT NULL DEFAULT 0,
                failure_reason TEXT,
                stuck_since TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                started_at TEXT,
                completed_at TEXT
            )",
            "CREATE TABLE IF NOT EXISTS job_actions (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES agent_jobs(id) ON DELETE CASCADE,
                sequence_num INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                input TEXT NOT NULL,
                output_raw TEXT,
                output_sanitized TEXT,
                sanitization_warnings TEXT,
                cost TEXT,
                duration_ms INTEGER,
                success INTEGER NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(job_id, sequence_num)
            )",
            "CREATE TABLE IF NOT EXISTS llm_calls (
                id TEXT PRIMARY KEY,
                job_id TEXT REFERENCES agent_jobs(id),
                conversation_id TEXT REFERENCES conversations(id),
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cost TEXT NOT NULL,
                purpose TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            "CREATE TABLE IF NOT EXISTS estimation_snapshots (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES agent_jobs(id) ON DELETE CASCADE,
                category TEXT NOT NULL,
                tool_names TEXT NOT NULL,
                estimated_cost TEXT NOT NULL,
                actual_cost TEXT,
                estimated_time_secs INTEGER NOT NULL,
                actual_time_secs INTEGER,
                estimated_value TEXT NOT NULL,
                actual_value TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            "CREATE TABLE IF NOT EXISTS tool_failures (
                id TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL UNIQUE,
                error_message TEXT,
                error_count INTEGER DEFAULT 1,
                first_failure TEXT DEFAULT (datetime('now')),
                last_failure TEXT DEFAULT (datetime('now')),
                last_build_result TEXT,
                repaired_at TEXT,
                repair_attempts INTEGER DEFAULT 0
            )",
            // Workspace tables (shared with workspace SQLite repo)
            "CREATE TABLE IF NOT EXISTS memory_documents (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                agent_id TEXT,
                path TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                metadata TEXT NOT NULL DEFAULT '{}',
                UNIQUE(user_id, agent_id, path)
            )",
            "CREATE TABLE IF NOT EXISTS memory_chunks (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES memory_documents(id) ON DELETE CASCADE,
                chunk_index INTEGER NOT NULL,
                content TEXT NOT NULL,
                embedding TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        ];
        for stmt in stmts {
            sqlx::query(stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| DatabaseError::Migration(e.to_string()))?;
        }
        Ok(())
    }

    pub fn pool_pg(&self) -> Option<deadpool_postgres::Pool> {
        None
    }

    pub fn pool_sqlite(&self) -> &SqlitePool {
        &self.pool
    }

    fn dec_to_str(d: &Decimal) -> String {
        d.to_string()
    }

    fn str_to_dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap_or_default()
    }

    pub async fn create_conversation(
        &self,
        channel: &str,
        user_id: &str,
        thread_id: Option<&str>,
    ) -> Result<Uuid, DatabaseError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO conversations (id, channel, user_id, thread_id) VALUES (?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(channel)
        .bind(user_id)
        .bind(thread_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(id)
    }

    pub async fn touch_conversation(&self, id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE conversations SET last_activity = datetime('now') WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn add_conversation_message(
        &self,
        conversation_id: Uuid,
        role: &str,
        content: &str,
    ) -> Result<Uuid, DatabaseError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO conversation_messages (id, conversation_id, role, content) VALUES (?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(conversation_id.to_string())
        .bind(role)
        .bind(content)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        self.touch_conversation(conversation_id).await?;
        Ok(id)
    }

    /// Look up conversation by channel, user_id, and thread_id. Returns None if not found.
    pub async fn get_conversation_by_thread(
        &self,
        channel: &str,
        user_id: &str,
        thread_id: &str,
    ) -> Result<Option<Uuid>, DatabaseError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM conversations WHERE channel = ? AND user_id = ? AND thread_id = ?",
        )
        .bind(channel)
        .bind(user_id)
        .bind(thread_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(row.and_then(|(id,)| Uuid::parse_str(&id).ok()))
    }

    /// Get messages for a conversation, ordered by created_at ascending. Limit 0 = no limit.
    pub async fn get_conversation_messages(
        &self,
        conversation_id: Uuid,
        limit: usize,
    ) -> Result<Vec<(String, String, String)>, DatabaseError> {
        let rows = if limit > 0 {
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT role, content, created_at FROM conversation_messages \
                 WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?",
            )
            .bind(conversation_id.to_string())
            .bind(limit as i64)
            .fetch_all(&self.pool)
        } else {
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT role, content, created_at FROM conversation_messages \
                 WHERE conversation_id = ? ORDER BY created_at ASC",
            )
            .bind(conversation_id.to_string())
            .fetch_all(&self.pool)
        }
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(rows)
    }

    pub async fn save_job(&self, ctx: &JobContext) -> Result<(), DatabaseError> {
        let status = ctx.state.to_string();
        let estimated_time_secs = ctx.estimated_duration.map(|d| d.as_secs() as i32);

        sqlx::query(
            r#"
            INSERT INTO agent_jobs (
                id, conversation_id, title, description, category, status, source,
                budget_amount, budget_token, bid_amount, estimated_cost, estimated_time_secs,
                actual_cost, repair_attempts, created_at, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                actual_cost = excluded.actual_cost,
                repair_attempts = excluded.repair_attempts,
                started_at = excluded.started_at,
                completed_at = excluded.completed_at
            "#,
        )
        .bind(ctx.job_id.to_string())
        .bind(ctx.conversation_id.map(|u| u.to_string()))
        .bind(&ctx.title)
        .bind(&ctx.description)
        .bind(&ctx.category)
        .bind(&status)
        .bind("direct")
        .bind(ctx.budget.as_ref().map(Self::dec_to_str))
        .bind(&ctx.budget_token)
        .bind(ctx.bid_amount.as_ref().map(Self::dec_to_str))
        .bind(ctx.estimated_cost.as_ref().map(Self::dec_to_str))
        .bind(estimated_time_secs)
        .bind(Self::dec_to_str(&ctx.actual_cost))
        .bind(ctx.repair_attempts as i32)
        .bind(ctx.created_at)
        .bind(ctx.started_at)
        .bind(ctx.completed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn get_job(&self, id: Uuid) -> Result<Option<JobContext>, DatabaseError> {
        let row: Option<JobRow> = sqlx::query_as(
            r#"
            SELECT id, conversation_id, title, description, category, status,
                   budget_amount, budget_token, bid_amount, estimated_cost, estimated_time_secs,
                   actual_cost, repair_attempts, created_at, started_at, completed_at
            FROM agent_jobs WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(row.map(|r| r.to_job_context()))
    }

    pub async fn update_job_status(
        &self,
        id: Uuid,
        status: JobState,
        failure_reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let status_str = status.to_string();
        sqlx::query("UPDATE agent_jobs SET status = ?, failure_reason = ? WHERE id = ?")
            .bind(&status_str)
            .bind(failure_reason)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn mark_job_stuck(&self, id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE agent_jobs SET status = 'stuck', stuck_since = datetime('now') WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn get_stuck_jobs(&self) -> Result<Vec<Uuid>, DatabaseError> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT id FROM agent_jobs WHERE status = 'stuck'")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(rows
            .into_iter()
            .filter_map(|(s,)| Uuid::parse_str(&s).ok())
            .collect())
    }

    pub async fn save_action(
        &self,
        job_id: Uuid,
        action: &ActionRecord,
    ) -> Result<(), DatabaseError> {
        let duration_ms = action.duration.as_millis() as i32;
        let warnings_json = serde_json::to_string(&action.sanitization_warnings)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let input_json = serde_json::to_string(&action.input)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let output_sanitized_json = action
            .output_sanitized
            .as_ref()
            .map(|v| serde_json::to_string(v))
            .transpose()
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO job_actions (
                id, job_id, sequence_num, tool_name, input, output_raw, output_sanitized,
                sanitization_warnings, cost, duration_ms, success, error_message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(action.id.to_string())
        .bind(job_id.to_string())
        .bind(action.sequence as i32)
        .bind(&action.tool_name)
        .bind(&input_json)
        .bind(&action.output_raw)
        .bind(output_sanitized_json)
        .bind(&warnings_json)
        .bind(action.cost.as_ref().map(Self::dec_to_str))
        .bind(duration_ms)
        .bind(action.success)
        .bind(&action.error)
        .bind(action.executed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn get_job_actions(&self, job_id: Uuid) -> Result<Vec<ActionRecord>, DatabaseError> {
        let rows: Vec<ActionActionRow> = sqlx::query_as(
            r#"
            SELECT id, sequence_num, tool_name, input, output_raw, output_sanitized,
                   sanitization_warnings, cost, duration_ms, success, error_message, created_at
            FROM job_actions WHERE job_id = ? ORDER BY sequence_num
            "#,
        )
        .bind(job_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let mut actions = Vec::new();
        for r in rows {
            let input: serde_json::Value = serde_json::from_str(&r.input).unwrap_or(serde_json::Value::Null);
            let output_sanitized = r
                .output_sanitized
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());
            actions.push(ActionRecord {
                id: Uuid::parse_str(&r.id).unwrap_or_default(),
                sequence: r.sequence_num as u32,
                tool_name: r.tool_name,
                input,
                output_raw: r.output_raw,
                output_sanitized,
                sanitization_warnings: serde_json::from_str(&r.sanitization_warnings).unwrap_or_default(),
                cost: r.cost.as_deref().map(Self::str_to_dec),
                duration: std::time::Duration::from_millis(r.duration_ms as u64),
                success: r.success,
                error: r.error_message,
                executed_at: r.created_at,
            });
        }
        Ok(actions)
    }

    pub async fn record_llm_call(&self, record: &LlmCallRecord<'_>) -> Result<Uuid, DatabaseError> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO llm_calls (id, job_id, conversation_id, provider, model, input_tokens, output_tokens, cost, purpose)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(record.job_id.map(|u| u.to_string()))
        .bind(record.conversation_id.map(|u| u.to_string()))
        .bind(record.provider)
        .bind(record.model)
        .bind(record.input_tokens as i32)
        .bind(record.output_tokens as i32)
        .bind(Self::dec_to_str(&record.cost))
        .bind(record.purpose)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(id)
    }

    pub async fn save_estimation_snapshot(
        &self,
        job_id: Uuid,
        category: &str,
        tool_names: &[String],
        estimated_cost: Decimal,
        estimated_time_secs: i32,
        estimated_value: Decimal,
    ) -> Result<Uuid, DatabaseError> {
        let id = Uuid::new_v4();
        let tool_names_json = serde_json::to_string(tool_names)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        sqlx::query(
            r#"
            INSERT INTO estimation_snapshots (id, job_id, category, tool_names, estimated_cost, estimated_time_secs, estimated_value)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(job_id.to_string())
        .bind(category)
        .bind(&tool_names_json)
        .bind(Self::dec_to_str(&estimated_cost))
        .bind(estimated_time_secs)
        .bind(Self::dec_to_str(&estimated_value))
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(id)
    }

    pub async fn update_estimation_actuals(
        &self,
        id: Uuid,
        actual_cost: Decimal,
        actual_time_secs: i32,
        actual_value: Option<Decimal>,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            "UPDATE estimation_snapshots SET actual_cost = ?, actual_time_secs = ?, actual_value = ? WHERE id = ?",
        )
        .bind(Self::dec_to_str(&actual_cost))
        .bind(actual_time_secs)
        .bind(actual_value.as_ref().map(Self::dec_to_str))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn record_tool_failure(
        &self,
        tool_name: &str,
        error_message: &str,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO tool_failures (id, tool_name, error_message, error_count, last_failure)
            VALUES (?, ?, ?, 1, datetime('now'))
            ON CONFLICT(tool_name) DO UPDATE SET
                error_message = excluded.error_message,
                error_count = error_count + 1,
                last_failure = datetime('now')
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(tool_name)
        .bind(error_message)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn get_broken_tools(&self, threshold: i32) -> Result<Vec<BrokenTool>, DatabaseError> {
        let rows: Vec<ToolFailureRow> = sqlx::query_as(
            r#"
            SELECT tool_name, error_message, error_count, first_failure, last_failure,
                   last_build_result, repair_attempts
            FROM tool_failures
            WHERE error_count >= ? AND repaired_at IS NULL
            ORDER BY error_count DESC
            "#,
        )
        .bind(threshold)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| BrokenTool {
                name: r.tool_name,
                last_error: r.error_message,
                failure_count: r.error_count as u32,
                first_failure: r.first_failure.unwrap_or_else(Utc::now),
                last_failure: r.last_failure.unwrap_or_else(Utc::now),
                last_build_result: r
                    .last_build_result
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok()),
                repair_attempts: r.repair_attempts as u32,
            })
            .collect())
    }

    pub async fn mark_tool_repaired(&self, tool_name: &str) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE tool_failures SET repaired_at = datetime('now'), error_count = 0 WHERE tool_name = ?")
            .bind(tool_name)
            .execute(&self.pool)
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

    pub async fn increment_repair_attempts(&self, tool_name: &str) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE tool_failures SET repair_attempts = repair_attempts + 1 WHERE tool_name = ?")
            .bind(tool_name)
            .execute(&self.pool)
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }
}

#[derive(FromRow)]
struct JobRow {
    id: String,
    conversation_id: String,
    title: String,
    description: String,
    category: Option<String>,
    status: String,
    budget_amount: Option<String>,
    budget_token: Option<String>,
    bid_amount: Option<String>,
    estimated_cost: Option<String>,
    estimated_time_secs: Option<i32>,
    actual_cost: Option<String>,
    repair_attempts: i32,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
}

impl JobRow {
    fn to_job_context(self) -> JobContext {
        let state = parse_job_state(&self.status);
        JobContext {
            job_id: Uuid::parse_str(&self.id).unwrap_or_default(),
            state,
            user_id: "default".to_string(),
            conversation_id: Uuid::parse_str(&self.conversation_id).ok(),
            title: self.title,
            description: self.description,
            category: self.category,
            budget: self.budget_amount.as_deref().map(SqliteStore::str_to_dec),
            budget_token: self.budget_token,
            bid_amount: self.bid_amount.as_deref().map(SqliteStore::str_to_dec),
            estimated_cost: self.estimated_cost.as_deref().map(SqliteStore::str_to_dec),
            estimated_duration: self.estimated_time_secs.map(|s| std::time::Duration::from_secs(s as u64)),
            actual_cost: self.actual_cost.as_deref().map(SqliteStore::str_to_dec).unwrap_or_default(),
            repair_attempts: self.repair_attempts as u32,
            created_at: self.created_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
            transitions: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }
}

#[derive(FromRow)]
struct ActionActionRow {
    id: String,
    sequence_num: i32,
    tool_name: String,
    input: String,
    output_raw: Option<String>,
    output_sanitized: Option<String>,
    sanitization_warnings: String,
    cost: Option<String>,
    duration_ms: i32,
    success: bool,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ToolFailureRow {
    tool_name: String,
    error_message: Option<String>,
    error_count: i32,
    first_failure: Option<DateTime<Utc>>,
    last_failure: Option<DateTime<Utc>>,
    last_build_result: Option<String>,
    repair_attempts: i32,
}

fn parse_job_state(s: &str) -> JobState {
    match s {
        "pending" => JobState::Pending,
        "in_progress" => JobState::InProgress,
        "completed" => JobState::Completed,
        "submitted" => JobState::Submitted,
        "accepted" => JobState::Accepted,
        "failed" => JobState::Failed,
        "stuck" => JobState::Stuck,
        "cancelled" => JobState::Cancelled,
        _ => JobState::Pending,
    }
}

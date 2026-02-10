//! SQLite backend for workspace repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use crate::error::WorkspaceError;
use crate::workspace::document::{MemoryChunk, MemoryDocument, WorkspaceEntry};
use crate::workspace::repo_backend::WorkspaceRepoBackend;
use crate::workspace::search::{RankedResult, SearchConfig, SearchResult};

/// SQLite-backed workspace repository.
pub struct SqliteWorkspaceRepo {
    pool: SqlitePool,
}

impl SqliteWorkspaceRepo {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceRepoBackend for SqliteWorkspaceRepo {
    async fn repo_get_document_by_path(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        path: &str,
    ) -> Result<MemoryDocument, WorkspaceError> {
        let agent_id_str = agent_id.map(|u| u.to_string());
        let row: Option<DocRow> = sqlx::query_as(
            "SELECT id, user_id, agent_id, path, content, created_at, updated_at, metadata FROM memory_documents WHERE user_id = ? AND ((agent_id IS NULL AND ? IS NULL) OR (agent_id = ?)) AND path = ?",
        )
        .bind(user_id)
        .bind(agent_id_str.as_deref())
        .bind(agent_id_str.as_deref())
        .bind(path)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;

        row.map(|r| r.to_doc())
            .ok_or_else(|| WorkspaceError::DocumentNotFound {
                doc_type: path.to_string(),
                user_id: user_id.to_string(),
            })
    }

    async fn repo_get_document_by_id(&self, id: Uuid) -> Result<MemoryDocument, WorkspaceError> {
        let row: Option<DocRow> = sqlx::query_as(
            "SELECT id, user_id, agent_id, path, content, created_at, updated_at, metadata FROM memory_documents WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;

        row.map(|r| r.to_doc())
            .ok_or_else(|| WorkspaceError::DocumentNotFound {
                doc_type: "unknown".to_string(),
                user_id: "unknown".to_string(),
            })
    }

    async fn repo_get_or_create_document_by_path(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        path: &str,
    ) -> Result<MemoryDocument, WorkspaceError> {
        if let Ok(doc) = self.repo_get_document_by_path(user_id, agent_id, path).await {
            return Ok(doc);
        }

        let id = Uuid::new_v4();
        let now = Utc::now();
        let agent_id_str = agent_id.map(|u| u.to_string());

        sqlx::query(
            "INSERT OR IGNORE INTO memory_documents (id, user_id, agent_id, path, content, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, '', '{}', ?, ?)",
        )
        .bind(id.to_string())
        .bind(user_id)
        .bind(agent_id_str.as_deref())
        .bind(path)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;

        self.repo_get_document_by_path(user_id, agent_id, path).await
    }

    async fn repo_update_document(&self, id: Uuid, content: &str) -> Result<(), WorkspaceError> {
        sqlx::query("UPDATE memory_documents SET content = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(content)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| WorkspaceError::SearchFailed {
                reason: e.to_string(),
            })?;
        Ok(())
    }

    async fn repo_delete_document_by_path(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        path: &str,
    ) -> Result<(), WorkspaceError> {
        let doc = self.repo_get_document_by_path(user_id, agent_id, path).await?;
        self.repo_delete_chunks(doc.id).await?;
        let agent_id_str = agent_id.map(|u| u.to_string());
        sqlx::query("DELETE FROM memory_documents WHERE user_id = ? AND (agent_id IS NULL AND ? IS NULL OR agent_id = ?) AND path = ?")
            .bind(user_id)
            .bind(agent_id_str.as_deref())
            .bind(agent_id_str.as_deref())
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(|e| WorkspaceError::SearchFailed {
                reason: e.to_string(),
            })?;
        Ok(())
    }

    async fn repo_list_directory(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        directory: &str,
    ) -> Result<Vec<WorkspaceEntry>, WorkspaceError> {
        let agent_id_str = agent_id.map(|u| u.to_string());
        let dir = directory.trim_end_matches('/');

        let rows: Vec<(String, Option<DateTime<Utc>>, String)> = if dir.is_empty() {
            sqlx::query_as(
                r#"
                SELECT path, updated_at, substr(content, 1, 200) as content_preview
                FROM memory_documents
                WHERE user_id = ? AND (agent_id IS NULL AND ? IS NULL OR agent_id = ?)
                ORDER BY path
                "#,
            )
            .bind(user_id)
            .bind(agent_id_str.as_deref())
            .bind(agent_id_str.as_deref())
        } else {
            sqlx::query_as(
                r#"
                SELECT path, updated_at, substr(content, 1, 200) as content_preview
                FROM memory_documents
                WHERE user_id = ? AND (agent_id IS NULL AND ? IS NULL OR agent_id = ?)
                AND (path LIKE ? OR path = ?)
                ORDER BY path
                "#,
            )
            .bind(user_id)
            .bind(agent_id_str.as_deref())
            .bind(agent_id_str.as_deref())
            .bind(format!("{}/%", dir))
            .bind(dir)
        }
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;

        let mut seen = std::collections::HashSet::new();
        let mut entries = Vec::new();
        for (path, updated_at, content_preview) in rows {
            let rel = if dir.is_empty() {
                path.clone()
            } else if let Some(rest) = path.strip_prefix(&format!("{}/", dir)) {
                rest.to_string()
            } else if path == dir {
                continue;
            } else {
                continue;
            };
            let name = rel.split('/').next().unwrap_or(&rel);
            let key = if rel.contains('/') {
                format!("{}/", name)
            } else {
                name.to_string()
            };
            if !seen.insert(key.clone()) {
                continue;
            }
            let is_directory = rel.contains('/');
            entries.push(WorkspaceEntry {
                path: key,
                is_directory,
                updated_at: if is_directory { None } else { updated_at },
                content_preview: if is_directory {
                    None
                } else {
                    Some(content_preview)
                },
            });
        }
        Ok(entries)
    }

    async fn repo_list_all_paths(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<String>, WorkspaceError> {
        let agent_id_str = agent_id.map(|u| u.to_string());
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT path FROM memory_documents WHERE user_id = ? AND (agent_id IS NULL AND ? IS NULL OR agent_id = ?) ORDER BY path",
        )
        .bind(user_id)
        .bind(agent_id_str.as_deref())
        .bind(agent_id_str.as_deref())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn repo_list_documents(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<MemoryDocument>, WorkspaceError> {
        let agent_id_str = agent_id.map(|u| u.to_string());
        let rows: Vec<DocRow> = sqlx::query_as(
            "SELECT id, user_id, agent_id, path, content, created_at, updated_at, metadata FROM memory_documents WHERE user_id = ? AND (agent_id IS NULL AND ? IS NULL OR agent_id = ?) ORDER BY updated_at DESC",
        )
        .bind(user_id)
        .bind(agent_id_str.as_deref())
        .bind(agent_id_str.as_deref())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;
        Ok(rows.into_iter().map(|r| r.to_doc()).collect())
    }

    async fn repo_delete_chunks(&self, document_id: Uuid) -> Result<(), WorkspaceError> {
        sqlx::query("DELETE FROM memory_chunks WHERE document_id = ?")
            .bind(document_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| WorkspaceError::ChunkingFailed {
                reason: e.to_string(),
            })?;
        Ok(())
    }

    async fn repo_insert_chunk(
        &self,
        document_id: Uuid,
        chunk_index: i32,
        content: &str,
        embedding: Option<&[f32]>,
    ) -> Result<Uuid, WorkspaceError> {
        let id = Uuid::new_v4();
        let embedding_json = embedding.map(|v| serde_json::to_string(&v).unwrap_or_default());
        sqlx::query(
            "INSERT INTO memory_chunks (id, document_id, chunk_index, content, embedding) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(document_id.to_string())
        .bind(chunk_index)
        .bind(content)
        .bind(embedding_json)
        .execute(&self.pool)
        .await
        .map_err(|e| WorkspaceError::ChunkingFailed {
            reason: e.to_string(),
        })?;
        Ok(id)
    }

    async fn repo_update_chunk_embedding(
        &self,
        chunk_id: Uuid,
        embedding: &[f32],
    ) -> Result<(), WorkspaceError> {
        let embedding_json = serde_json::to_string(embedding).unwrap_or_default();
        sqlx::query("UPDATE memory_chunks SET embedding = ? WHERE id = ?")
            .bind(&embedding_json)
            .bind(chunk_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| WorkspaceError::EmbeddingFailed {
                reason: e.to_string(),
            })?;
        Ok(())
    }

    async fn repo_get_chunks_without_embeddings(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<MemoryChunk>, WorkspaceError> {
        let agent_id_str = agent_id.map(|u| u.to_string());
        let rows: Vec<ChunkRow> = sqlx::query_as(
            r#"
            SELECT c.id, c.document_id, c.chunk_index, c.content, c.created_at
            FROM memory_chunks c
            JOIN memory_documents d ON d.id = c.document_id
            WHERE d.user_id = ? AND (d.agent_id IS NULL AND ? IS NULL OR d.agent_id = ?)
            AND c.embedding IS NULL
            LIMIT ?
            "#,
        )
        .bind(user_id)
        .bind(agent_id_str.as_deref())
        .bind(agent_id_str.as_deref())
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;

        Ok(rows
            .into_iter()
            .map(|r| MemoryChunk {
                id: Uuid::parse_str(&r.id).unwrap_or_default(),
                document_id: Uuid::parse_str(&r.document_id).unwrap_or_default(),
                chunk_index: r.chunk_index,
                content: r.content,
                embedding: None,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn repo_hybrid_search(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        query: &str,
        _embedding: Option<&[f32]>,
        config: &SearchConfig,
    ) -> Result<Vec<SearchResult>, WorkspaceError> {
        let agent_id_str = agent_id.map(|u| u.to_string());
        let like = format!("%{}%", query);

        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT c.id, c.document_id, c.content
            FROM memory_chunks c
            JOIN memory_documents d ON d.id = c.document_id
            WHERE d.user_id = ? AND (d.agent_id IS NULL AND ? IS NULL OR d.agent_id = ?)
            AND c.content LIKE ?
            ORDER BY c.content
            LIMIT ?
            "#,
        )
        .bind(user_id)
        .bind(agent_id_str.as_deref())
        .bind(agent_id_str.as_deref())
        .bind(&like)
        .bind(config.pre_fusion_limit as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WorkspaceError::SearchFailed {
            reason: e.to_string(),
        })?;

        let fts_results: Vec<RankedResult> = rows
            .into_iter()
            .enumerate()
            .map(|(i, (chunk_id, document_id, content))| RankedResult {
                chunk_id: Uuid::parse_str(&chunk_id).unwrap_or_default(),
                document_id: Uuid::parse_str(&document_id).unwrap_or_default(),
                content,
                rank: (i + 1) as u32,
            })
            .collect();

        let vector_results: Vec<RankedResult> = Vec::new();

        Ok(crate::workspace::search::reciprocal_rank_fusion(
            fts_results,
            vector_results,
            config,
        ))
    }
}

#[derive(sqlx::FromRow)]
struct DocRow {
    id: String,
    user_id: String,
    agent_id: Option<String>,
    path: String,
    content: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    metadata: String,
}

impl DocRow {
    fn to_doc(self) -> MemoryDocument {
        MemoryDocument {
            id: Uuid::parse_str(&self.id).unwrap_or_default(),
            user_id: self.user_id,
            agent_id: self.agent_id.and_then(|s| Uuid::parse_str(&s).ok()),
            path: self.path,
            content: self.content,
            created_at: self.created_at,
            updated_at: self.updated_at,
            metadata: serde_json::from_str(&self.metadata).unwrap_or(serde_json::Value::Null),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ChunkRow {
    id: String,
    document_id: String,
    chunk_index: i32,
    content: String,
    created_at: DateTime<Utc>,
}

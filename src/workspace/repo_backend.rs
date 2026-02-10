//! Trait for workspace repository backends (Postgres or SQLite).

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::WorkspaceError;
use crate::workspace::document::{MemoryChunk, MemoryDocument, WorkspaceEntry};
use crate::workspace::search::{SearchConfig, SearchResult};

/// Backend for workspace persistence (Postgres or SQLite).
/// Method names are prefixed to avoid conflict with Repository's inherent methods.
#[async_trait]
pub trait WorkspaceRepoBackend: Send + Sync {
    async fn repo_get_document_by_path(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        path: &str,
    ) -> Result<MemoryDocument, WorkspaceError>;

    async fn repo_get_document_by_id(&self, id: Uuid) -> Result<MemoryDocument, WorkspaceError>;

    async fn repo_get_or_create_document_by_path(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        path: &str,
    ) -> Result<MemoryDocument, WorkspaceError>;

    async fn repo_update_document(&self, id: Uuid, content: &str) -> Result<(), WorkspaceError>;

    async fn repo_delete_document_by_path(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        path: &str,
    ) -> Result<(), WorkspaceError>;

    async fn repo_list_directory(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        directory: &str,
    ) -> Result<Vec<WorkspaceEntry>, WorkspaceError>;

    async fn repo_list_all_paths(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<String>, WorkspaceError>;

    async fn repo_list_documents(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<MemoryDocument>, WorkspaceError>;

    async fn repo_delete_chunks(&self, document_id: Uuid) -> Result<(), WorkspaceError>;

    async fn repo_insert_chunk(
        &self,
        document_id: Uuid,
        chunk_index: i32,
        content: &str,
        embedding: Option<&[f32]>,
    ) -> Result<Uuid, WorkspaceError>;

    async fn repo_update_chunk_embedding(
        &self,
        chunk_id: Uuid,
        embedding: &[f32],
    ) -> Result<(), WorkspaceError>;

    async fn repo_get_chunks_without_embeddings(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<MemoryChunk>, WorkspaceError>;

    async fn repo_hybrid_search(
        &self,
        user_id: &str,
        agent_id: Option<Uuid>,
        query: &str,
        embedding: Option<&[f32]>,
        config: &SearchConfig,
    ) -> Result<Vec<SearchResult>, WorkspaceError>;
}

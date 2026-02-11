//! Session manager for multi-user, multi-thread conversation handling.
//!
//! Maps external channel thread IDs to internal UUIDs and manages undo state
//! for each thread. Optionally persists sessions to disk under a configurable path.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::agent::session::{Session, Thread};
use crate::agent::undo::UndoManager;

/// Key for mapping external thread IDs to internal ones.
#[derive(Clone, Hash, Eq, PartialEq)]
struct ThreadKey {
    user_id: String,
    channel: String,
    external_thread_id: Option<String>,
}

/// Persisted session metadata (meta.json per user).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMeta {
    session_id: Uuid,
    active_thread_id: Option<Uuid>,
    threads: Vec<ThreadMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreadMapEntry {
    channel: String,
    external_thread_id: Option<String>,
    thread_id: Uuid,
}

/// Manages sessions, threads, and undo state for all users.
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<Mutex<Session>>>>,
    thread_map: RwLock<HashMap<ThreadKey, Uuid>>,
    undo_managers: RwLock<HashMap<Uuid, Arc<Mutex<UndoManager>>>>,
    /// When set, sessions are persisted under this path.
    persist_path: Option<PathBuf>,
}

impl SessionManager {
    /// Create a new session manager (no persistence).
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            thread_map: RwLock::new(HashMap::new()),
            undo_managers: RwLock::new(HashMap::new()),
            persist_path: None,
        }
    }

    /// Create a session manager that persists to the given path.
    /// Loads existing sessions from disk if present.
    pub async fn new_with_persistence(path: PathBuf) -> Self {
        let manager = Self {
            sessions: RwLock::new(HashMap::new()),
            thread_map: RwLock::new(HashMap::new()),
            undo_managers: RwLock::new(HashMap::new()),
            persist_path: Some(path.clone()),
        };
        if let Err(e) = manager.load_from_disk().await {
            tracing::warn!("Session load from disk failed: {}", e);
        }
        manager
    }

    /// Load sessions and thread map from disk. No-op if persist_path is None.
    async fn load_from_disk(&self) -> Result<(), std::io::Error> {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };
        let sessions_dir = path.join("sessions");
        if !sessions_dir.is_dir() {
            return Ok(());
        }
        let mut read_dir = tokio::fs::read_dir(&sessions_dir).await?;
        while let Some(entry) = read_dir.next_entry().await? {
            let user_dir = entry.path();
            if !user_dir.is_dir() {
                continue;
            }
            let user_id = match entry.file_name().to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let meta_path = user_dir.join("meta.json");
            if !meta_path.exists() {
                continue;
            }
            let meta_bytes = match tokio::fs::read(&meta_path).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Failed to read {}: {}", meta_path.display(), e);
                    continue;
                }
            };
            let meta: SessionMeta = match serde_json::from_slice(&meta_bytes) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Invalid meta.json for {}: {}", user_id, e);
                    continue;
                }
            };
            let mut threads = HashMap::new();
            let threads_dir = user_dir.join("threads");
            for entry in &meta.threads {
                let thread_path = threads_dir.join(format!("{}.json", entry.thread_id));
                if !thread_path.exists() {
                    continue;
                }
                let thread_bytes = match tokio::fs::read(&thread_path).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("Failed to read thread {}: {}", thread_path.display(), e);
                        continue;
                    }
                };
                let thread: Thread = match serde_json::from_slice(&thread_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("Invalid thread {}: {}", entry.thread_id, e);
                        continue;
                    }
                };
                threads.insert(thread.id, thread);
            }
            let last_active_at = threads
                .values()
                .map(|t| t.updated_at)
                .max()
                .unwrap_or_else(chrono::Utc::now);
            let session = Session::from_loaded(
                meta.session_id,
                &user_id,
                meta.active_thread_id,
                threads,
                last_active_at,
            );
            let session = Arc::new(Mutex::new(session));
            {
                let mut sessions = self.sessions.write().await;
                sessions.insert(user_id.clone(), Arc::clone(&session));
            }
            for entry in &meta.threads {
                let key = ThreadKey {
                    user_id: user_id.clone(),
                    channel: entry.channel.clone(),
                    external_thread_id: entry.external_thread_id.clone(),
                };
                let mut thread_map = self.thread_map.write().await;
                thread_map.insert(key, entry.thread_id);
            }
            for thread_id in meta.threads.iter().map(|e| e.thread_id) {
                let mut undo_managers = self.undo_managers.write().await;
                undo_managers.insert(thread_id, Arc::new(Mutex::new(UndoManager::new())));
            }
        }
        Ok(())
    }

    /// Persist session meta after creating a new thread or when thread map / active thread changes.
    pub async fn save_session_meta(&self, user_id: &str, session: &Session) {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return,
        };
        let user_dir = path.join("sessions").join(sanitize_user_dir(user_id));
        if let Err(e) = tokio::fs::create_dir_all(&user_dir).await {
            tracing::warn!("Failed to create session dir {}: {}", user_dir.display(), e);
            return;
        }
        let thread_map = self.thread_map.read().await;
        let threads: Vec<ThreadMapEntry> = thread_map
            .iter()
            .filter(|(k, _)| k.user_id == user_id)
            .map(|(k, &thread_id)| ThreadMapEntry {
                channel: k.channel.clone(),
                external_thread_id: k.external_thread_id.clone(),
                thread_id,
            })
            .collect();
        drop(thread_map);
        let meta = SessionMeta {
            session_id: session.id,
            active_thread_id: session.active_thread,
            threads,
        };
        let meta_path = user_dir.join("meta.json");
        let json = match serde_json::to_string_pretty(&meta) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("Failed to serialize session meta: {}", e);
                return;
            }
        };
        if let Err(e) = tokio::fs::write(&meta_path, json).await {
            tracing::warn!("Failed to write {}: {}", meta_path.display(), e);
        }
    }

    /// Persist a single thread to disk. Call after any thread update.
    pub async fn save_thread(
        &self,
        user_id: &str,
        session: &Arc<Mutex<Session>>,
        thread_id: Uuid,
    ) {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return,
        };
        let sess = session.lock().await;
        let thread = match sess.threads.get(&thread_id) {
            Some(t) => t.clone(),
            None => return,
        };
        drop(sess);
        let user_dir = path.join("sessions").join(sanitize_user_dir(user_id));
        let threads_dir = user_dir.join("threads");
        if let Err(e) = tokio::fs::create_dir_all(&threads_dir).await {
            tracing::warn!("Failed to create threads dir {}: {}", threads_dir.display(), e);
            return;
        }
        let thread_path = threads_dir.join(format!("{}.json", thread_id));
        let json = match serde_json::to_string_pretty(&thread) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("Failed to serialize thread {}: {}", thread_id, e);
                return;
            }
        };
        if let Err(e) = tokio::fs::write(&thread_path, json).await {
            tracing::warn!("Failed to write {}: {}", thread_path.display(), e);
        }
    }

    /// Get or create a session for a user.
    pub async fn get_or_create_session(&self, user_id: &str) -> Arc<Mutex<Session>> {
        // Fast path: check if session exists
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(user_id) {
                return Arc::clone(session);
            }
        }

        // Slow path: create new session
        let mut sessions = self.sessions.write().await;
        // Double-check after acquiring write lock
        if let Some(session) = sessions.get(user_id) {
            return Arc::clone(session);
        }

        let session = Arc::new(Mutex::new(Session::new(user_id)));
        sessions.insert(user_id.to_string(), Arc::clone(&session));
        session
    }

    /// Resolve an external thread ID to an internal thread.
    ///
    /// Returns the session and thread ID. Creates both if they don't exist.
    pub async fn resolve_thread(
        &self,
        user_id: &str,
        channel: &str,
        external_thread_id: Option<&str>,
    ) -> (Arc<Mutex<Session>>, Uuid) {
        let session = self.get_or_create_session(user_id).await;

        let key = ThreadKey {
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            external_thread_id: external_thread_id.map(String::from),
        };

        // Check if we have a mapping
        {
            let thread_map = self.thread_map.read().await;
            if let Some(&thread_id) = thread_map.get(&key) {
                // Verify thread still exists in session
                let sess = session.lock().await;
                if sess.threads.contains_key(&thread_id) {
                    return (Arc::clone(&session), thread_id);
                }
            }
        }

        // Create new thread (always create a new one for a new key)
        let thread_id = {
            let mut sess = session.lock().await;
            let thread = sess.create_thread();
            thread.id
        };

        // Store mapping so this key resolves to the new thread
        {
            let mut thread_map = self.thread_map.write().await;
            thread_map.insert(key.clone(), thread_id);
            // Always register (user, channel, Some(thread_id)) so the next request with the
            // returned thread_id resolves to this same thread (whether or not client sent one).
            let key_with_id = ThreadKey {
                external_thread_id: Some(thread_id.to_string()),
                ..key.clone()
            };
            thread_map.insert(key_with_id, thread_id);
        }

        // Create undo manager for thread
        {
            let mut undo_managers = self.undo_managers.write().await;
            undo_managers.insert(thread_id, Arc::new(Mutex::new(UndoManager::new())));
        }

        // Persist session meta when using persistence (new thread + mapping)
        if self.persist_path.is_some() {
            let sess = session.lock().await;
            self.save_session_meta(user_id, &sess).await;
        }
        (session, thread_id)
    }

    /// Register an existing thread (e.g. created via /thread new) so it can be resolved by external_thread_id.
    /// Call after creating a thread outside resolve_thread (e.g. process_new_thread).
    pub async fn register_thread(
        &self,
        user_id: &str,
        channel: &str,
        external_thread_id: Option<String>,
        thread_id: Uuid,
        session: &Session,
    ) {
        let key = ThreadKey {
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            external_thread_id,
        };
        {
            let mut thread_map = self.thread_map.write().await;
            thread_map.insert(key, thread_id);
        }
        {
            let mut undo_managers = self.undo_managers.write().await;
            undo_managers.insert(thread_id, Arc::new(Mutex::new(UndoManager::new())));
        }
        if self.persist_path.is_some() {
            self.save_session_meta(user_id, session).await;
        }
    }

    /// Get undo manager for a thread.
    pub async fn get_undo_manager(&self, thread_id: Uuid) -> Arc<Mutex<UndoManager>> {
        // Fast path
        {
            let managers = self.undo_managers.read().await;
            if let Some(mgr) = managers.get(&thread_id) {
                return Arc::clone(mgr);
            }
        }

        // Create if missing
        let mut managers = self.undo_managers.write().await;
        // Double-check
        if let Some(mgr) = managers.get(&thread_id) {
            return Arc::clone(mgr);
        }

        let mgr = Arc::new(Mutex::new(UndoManager::new()));
        managers.insert(thread_id, Arc::clone(&mgr));
        mgr
    }

    /// Remove sessions that have been idle for longer than the given duration.
    ///
    /// Returns the number of sessions pruned.
    pub async fn prune_stale_sessions(&self, max_idle: std::time::Duration) -> usize {
        let cutoff = chrono::Utc::now() - chrono::TimeDelta::seconds(max_idle.as_secs() as i64);

        // Find stale session user_ids
        let stale_users: Vec<String> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter_map(|(user_id, session)| {
                    // Try to lock; skip if contended (someone is actively using it)
                    let sess = session.try_lock().ok()?;
                    if sess.last_active_at < cutoff {
                        Some(user_id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if stale_users.is_empty() {
            return 0;
        }

        // Collect thread IDs from stale sessions for cleanup
        let mut stale_thread_ids: Vec<Uuid> = Vec::new();
        {
            let sessions = self.sessions.read().await;
            for user_id in &stale_users {
                if let Some(session) = sessions.get(user_id) {
                    if let Ok(sess) = session.try_lock() {
                        stale_thread_ids.extend(sess.threads.keys());
                    }
                }
            }
        }

        // Remove sessions
        let count = {
            let mut sessions = self.sessions.write().await;
            let before = sessions.len();
            for user_id in &stale_users {
                sessions.remove(user_id);
            }
            before - sessions.len()
        };

        // Clean up thread mappings that point to stale sessions
        {
            let mut thread_map = self.thread_map.write().await;
            thread_map.retain(|key, _| !stale_users.contains(&key.user_id));
        }

        // Clean up undo managers for stale threads
        {
            let mut undo_managers = self.undo_managers.write().await;
            for thread_id in &stale_thread_ids {
                undo_managers.remove(thread_id);
            }
        }

        if count > 0 {
            tracing::info!(
                "Pruned {} stale session(s) (idle > {}s)",
                count,
                max_idle.as_secs()
            );
        }

        count
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitize user_id for use as a directory name (no path separators or invalid chars).
fn sanitize_user_dir(user_id: &str) -> String {
    user_id
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => '_',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_or_create_session() {
        let manager = SessionManager::new();

        let session1 = manager.get_or_create_session("user-1").await;
        let session2 = manager.get_or_create_session("user-1").await;

        // Same user should get same session
        assert!(Arc::ptr_eq(&session1, &session2));

        let session3 = manager.get_or_create_session("user-2").await;
        assert!(!Arc::ptr_eq(&session1, &session3));
    }

    #[tokio::test]
    async fn test_resolve_thread() {
        let manager = SessionManager::new();

        let (session1, thread1) = manager.resolve_thread("user-1", "cli", None).await;
        let (session2, thread2) = manager.resolve_thread("user-1", "cli", None).await;

        // Same channel+user should get same thread
        assert!(Arc::ptr_eq(&session1, &session2));
        assert_eq!(thread1, thread2);

        // Different channel should get different thread
        let (_, thread3) = manager.resolve_thread("user-1", "http", None).await;
        assert_ne!(thread1, thread3);
    }

    #[tokio::test]
    async fn test_undo_manager() {
        let manager = SessionManager::new();
        let (_, thread_id) = manager.resolve_thread("user-1", "cli", None).await;

        let undo1 = manager.get_undo_manager(thread_id).await;
        let undo2 = manager.get_undo_manager(thread_id).await;

        assert!(Arc::ptr_eq(&undo1, &undo2));
    }

    #[tokio::test]
    async fn test_prune_stale_sessions() {
        let manager = SessionManager::new();

        // Create two sessions and resolve threads (which updates last_active_at)
        let (_, _thread_id) = manager.resolve_thread("user-active", "cli", None).await;
        let (s2, _thread_id) = manager.resolve_thread("user-stale", "cli", None).await;

        // Backdate the stale session's last_active_at AFTER thread creation
        {
            let mut sess = s2.lock().await;
            sess.last_active_at = chrono::Utc::now() - chrono::TimeDelta::seconds(86400 * 10); // 10 days ago
        }

        // Prune with 7-day timeout
        let pruned = manager
            .prune_stale_sessions(std::time::Duration::from_secs(86400 * 7))
            .await;
        assert_eq!(pruned, 1);

        // Active session should still exist
        let sessions = manager.sessions.read().await;
        assert!(sessions.contains_key("user-active"));
        assert!(!sessions.contains_key("user-stale"));
    }

    #[tokio::test]
    async fn test_prune_no_stale_sessions() {
        let manager = SessionManager::new();
        let _s1 = manager.get_or_create_session("user-1").await;

        // Nothing should be pruned when timeout is long
        let pruned = manager
            .prune_stale_sessions(std::time::Duration::from_secs(86400 * 365))
            .await;
        assert_eq!(pruned, 0);
    }
}

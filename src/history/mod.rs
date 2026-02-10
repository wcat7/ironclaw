//! History and persistence layer.
//!
//! Stores job history, conversations, and actions in Postgres or SQLite for:
//! - Audit trail
//! - Learning from past executions
//! - Analytics and metrics

mod analytics;
mod postgres;
mod store;
mod sqlite;

pub use analytics::{JobStats, ToolStats};
pub use store::{LlmCallRecord, Store};

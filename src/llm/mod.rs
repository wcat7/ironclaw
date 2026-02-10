//! LLM integration for the agent.
//!
//! Supports:
//! - **NEAR AI**: Responses API (session) or Chat Completions API (API key)
//! - **OpenAI-compatible**: Any base URL + optional API key (e.g. OpenAI, Groq, local system model server)

mod nearai;
mod nearai_chat;
mod openai_compatible;
mod provider;
mod reasoning;
pub mod session;

pub use nearai::{ModelInfo, NearAiProvider};
pub use nearai_chat::NearAiChatProvider;
pub use openai_compatible::OpenAiCompatibleProvider;
pub use provider::{
    ChatMessage, CompletionRequest, CompletionResponse, FinishReason, LlmProvider, Role,
    ToolCall, ToolCompletionRequest, ToolCompletionResponse, ToolDefinition, ToolResult,
};
pub use reasoning::{ActionPlan, Reasoning, ReasoningContext, RespondResult, ToolSelection};
pub use session::{SessionConfig, SessionManager, create_session_manager};

use std::sync::Arc;

use crate::config::{LlmConfig, NearAiApiMode, LLM_PROVIDER_OPENAI_COMPATIBLE};
use crate::error::LlmError;

/// Create an LLM provider based on configuration.
///
/// - For `openai_compatible`: Uses OPENAI_COMPATIBLE_* config; session is not used (can be None).
/// - For `nearai` Responses mode: Requires session for authentication.
/// - For `nearai` ChatCompletions mode: Uses API key from config (session not used but may be passed).
pub fn create_llm_provider(
    config: &LlmConfig,
    session: Option<Arc<SessionManager>>,
) -> Result<Arc<dyn LlmProvider>, LlmError> {
    if config.provider == LLM_PROVIDER_OPENAI_COMPATIBLE {
        let openai_config = config.openai_compatible.as_ref().ok_or_else(|| {
            LlmError::RequestFailed {
                provider: "openai_compatible".to_string(),
                reason: "OPENAI_COMPATIBLE_* config missing".to_string(),
            }
        })?;
        tracing::info!(
            "Using OpenAI-compatible API: {} (model: {})",
            openai_config.base_url,
            openai_config.model
        );
        return Ok(Arc::new(OpenAiCompatibleProvider::new(openai_config.clone())?));
    }

    // NEAR AI
    let session = session.ok_or_else(|| LlmError::AuthFailed {
        provider: "nearai".to_string(),
    })?;
    match config.nearai.api_mode {
        NearAiApiMode::Responses => {
            tracing::info!("Using NEAR AI Responses API (chat-api) with session auth");
            Ok(Arc::new(NearAiProvider::new(
                config.nearai.clone(),
                session,
            )))
        }
        NearAiApiMode::ChatCompletions => {
            tracing::info!("Using NEAR AI Chat Completions API (cloud-api) with API key auth");
            Ok(Arc::new(NearAiChatProvider::new(config.nearai.clone())?))
        }
    }
}

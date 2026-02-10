//! Extensible tool system.
//!
//! Tools are the agent's interface to the outside world. They can:
//! - Call external APIs
//! - Interact with the marketplace
//! - Execute sandboxed code (via WASM sandbox)
//! - Delegate tasks to other services
//! - Build new software and tools

pub mod builder;
pub mod builtin;
pub mod mcp;
#[cfg(feature = "wasm")]
pub mod wasm;

mod registry;
mod sandbox;
mod tool;

pub use builder::{
    BuildPhase, BuildRequirement, BuildResult, BuildSoftwareTool, BuilderConfig, Language,
    LlmSoftwareBuilder, SoftwareBuilder, SoftwareType, Template, TemplateEngine, TemplateType,
    ValidationError, ValidationResult, WasmValidator,
};
#[cfg(feature = "wasm")]
pub use builder::{TestCase, TestHarness, TestResult, TestSuite};
pub use registry::ToolRegistry;
pub use sandbox::ToolSandbox;
pub use tool::{Tool, ToolError, ToolOutput};

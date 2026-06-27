//! MCP response contracts and redacted domain report shapes.
//!
//! Reports in this module are intentionally aggregate and redacted. They
//! distinguish source evidence from unproven readiness gates so an agent cannot
//! confuse list/campaign readback or queue cancellation with send
//! authorization.

mod audience;
mod common;
mod forms;
mod queue;

pub use audience::*;
pub use common::*;
pub use forms::*;
pub use queue::*;

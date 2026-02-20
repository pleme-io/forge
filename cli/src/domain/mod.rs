//! Domain layer - pure business logic
//!
//! This module contains business logic with no external I/O.
//! Types and functions here can be unit tested without mocking.

pub mod migration;
pub mod release;
pub mod service;

// Re-export commonly used types
pub use migration::{DatabaseType, MigrationConfig};
pub use release::{ReleaseConfig, ReleasePhase, ReleaseStep};
pub use service::{ServiceDefinition, ServiceType};

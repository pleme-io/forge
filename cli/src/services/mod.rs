//! Services layer - orchestration logic
//!
//! This module coordinates between domain logic and infrastructure.
//! Services use infrastructure adapters to perform I/O operations.

pub mod migration_service;
pub mod release_service;

// Re-export commonly used types
pub use migration_service::MigrationService;
pub use release_service::ReleaseService;

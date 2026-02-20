//! Infrastructure layer - external I/O adapters
//!
//! This module contains all code that interacts with external systems:
//! - Container registries (GHCR via skopeo)
//! - Git operations
//! - Nix builds
//! - Kubernetes API
//! - Attic cache
//! - Flux CD
//! - Release Tracker

pub mod attic;
pub mod git;
pub mod registry;
pub mod release_tracker;

// Re-export commonly used types
pub use attic::AtticClient;
pub use git::GitClient;
pub use registry::{RegistryClient, RegistryCredentials};
pub use release_tracker::{ReleaseTracker, ReleaseTrackerClient};

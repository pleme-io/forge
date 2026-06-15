//! Runtime tool path resolution
//!
//! This module provides a centralized, generalized way to resolve paths to external tools
//! using the derivation-to-environment-variable pattern.
//!
//! ## Pattern
//!
//! For each tool (e.g., `skopeo`), we:
//! 1. Check for an environment variable `{TOOL}_BIN` (e.g., `SKOPEO_BIN`)
//! 2. Fall back to PATH-based invocation if the envvar is not set
//!
//! This allows Nix to provide explicit derivation paths via environment variables,
//! ensuring reproducible builds while maintaining flexibility for non-Nix environments.
//!
//! ## Benefits
//!
//! - **Explicit dependencies**: Nix flake apps export tool paths from derivations
//! - **Reproducible**: Always uses exact version specified in nixpkgs
//! - **Flexible**: Falls back to PATH for development/testing
//! - **Easy to add tools**: Just call `get_tool_path("toolname")`
//! - **Easy to mock**: Override envvar in tests
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::tools::get_tool_path;
//! use tokio::process::Command;
//!
//! // Get skopeo path (reads SKOPEO_BIN envvar, falls back to "skopeo")
//! let skopeo = get_tool_path("skopeo");
//! Command::new(&skopeo)
//!     .args(&["copy", source, dest])
//!     .status()
//!     .await?;
//!
//! // Get kubectl path (reads KUBECTL_BIN envvar, falls back to "kubectl")
//! let kubectl = get_tool_path("kubectl");
//! Command::new(&kubectl)
//!     .args(&["get", "pods"])
//!     .status()
//!     .await?;
//! ```
//!
//! ## Adding New Tools
//!
//! 1. Add tool to `runtimeTools` in substrate
//! 2. Call `get_tool_path("toolname")` in Rust code
//! 3. Nix apps automatically export the envvar via `mkRuntimeToolsEnv`
//!
//! No other changes needed - the pattern is fully generalized.

use std::env;

/// Get the path to an external tool
///
/// Checks for an environment variable `{TOOL}_BIN` (uppercase tool name with
/// any `-` canonicalized to `_`, then `_BIN` appended). Falls back to the
/// tool name itself if the envvar is not set, which relies on PATH.
///
/// # Arguments
///
/// * `tool` - The tool name (e.g., "skopeo", "kubectl", "attic", "git",
///   "postgres-bootstrap")
///
/// # Returns
///
/// The tool path as a String. Either:
/// - The value of the derived env var (e.g., `SKOPEO_BIN` for "skopeo",
///   `POSTGRES_BOOTSTRAP_BIN` for "postgres-bootstrap")
/// - The tool name itself if envvar not set
///
/// # Env-var name is shell-safe by construction
///
/// POSIX environment variable names are restricted to `[A-Z0-9_]` — a dash
/// is not legal. Tool names in forge follow the Nix derivation convention
/// of dash-separated kebab-case (`postgres-bootstrap`, `openbao-bootstrap`,
/// `kanidm-bootstrap`); the derivation that exports the bin path lifts to
/// `{POSTGRES_BOOTSTRAP_BIN, OPENBAO_BOOTSTRAP_BIN, KANIDM_BOOTSTRAP_BIN}`.
/// Without the `-` → `_` canonicalization, a dash-bearing tool name would
/// produce an env-var lookup (e.g. `POSTGRES-BOOTSTRAP_BIN`) that no
/// shell-emitted environment ever sets — silently downgrading every
/// Nix-derivation-provided path back to PATH-based invocation. The
/// canonicalization is the load-bearing bridge between the derivation
/// surface (dashes legal) and the env-var surface (underscores only).
///
/// # Examples
///
/// ```rust,ignore
/// // With SKOPEO_BIN="/nix/store/abc123-skopeo-1.14.0/bin/skopeo"
/// assert_eq!(get_tool_path("skopeo"), "/nix/store/abc123-skopeo-1.14.0/bin/skopeo");
///
/// // Dash-bearing tool name -> underscore env var
/// // With POSTGRES_BOOTSTRAP_BIN="/nix/store/.../bin/postgres-bootstrap"
/// assert_eq!(
///     get_tool_path("postgres-bootstrap"),
///     "/nix/store/.../bin/postgres-bootstrap",
/// );
///
/// // Without SKOPEO_BIN set
/// assert_eq!(get_tool_path("skopeo"), "skopeo");
/// ```
pub fn get_tool_path(tool: &str) -> String {
    let env_var = format!("{}_BIN", tool.to_uppercase().replace("-", "_"));
    env::var(&env_var).unwrap_or_else(|_| tool.to_string())
}

/// Get the path to a tool with a custom environment variable name
///
/// Like `get_tool_path`, but allows specifying a custom environment variable name
/// instead of deriving it from the tool name.
///
/// # Arguments
///
/// * `tool` - The tool name (fallback if envvar not set)
/// * `env_var` - The environment variable name to check
///
/// # Returns
///
/// The tool path as a String
///
/// # Examples
///
/// ```rust,ignore
/// // Check CUSTOM_SKOPEO_PATH, fall back to "skopeo"
/// let path = get_tool_path_custom("skopeo", "CUSTOM_SKOPEO_PATH");
/// ```
pub fn get_tool_path_custom(tool: &str, env_var: &str) -> String {
    env::var(env_var).unwrap_or_else(|_| tool.to_string())
}

/// Common tool names (for documentation and IDE autocomplete)
///
/// This module doesn't enforce these names - you can pass any string to `get_tool_path`.
/// These constants are provided for convenience and discoverability.
pub mod tools {
    pub const SKOPEO: &str = "skopeo";
    pub const ATTIC: &str = "attic";
    pub const KUBECTL: &str = "kubectl";
    pub const GIT: &str = "git";
    pub const NIX: &str = "nix";
    pub const FLUX: &str = "flux";
    pub const DOCKER: &str = "docker";
    pub const CRATE2NIX: &str = "crate2nix";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_get_tool_path_from_env() {
        env::set_var("TEST_TOOL_BIN", "/custom/path/to/test-tool");
        assert_eq!(get_tool_path("test-tool"), "/custom/path/to/test-tool");
        env::remove_var("TEST_TOOL_BIN");
    }

    #[test]
    fn test_get_tool_path_fallback() {
        env::remove_var("MISSING_TOOL_BIN");
        assert_eq!(get_tool_path("missing-tool"), "missing-tool");
    }

    #[test]
    fn test_get_tool_path_custom() {
        env::set_var("CUSTOM_VAR", "/custom/path");
        assert_eq!(get_tool_path_custom("tool", "CUSTOM_VAR"), "/custom/path");
        env::remove_var("CUSTOM_VAR");
    }

    #[test]
    fn test_uppercase_conversion() {
        env::set_var("SKOPEO_BIN", "/nix/store/abc/bin/skopeo");
        assert_eq!(get_tool_path("skopeo"), "/nix/store/abc/bin/skopeo");
        env::remove_var("SKOPEO_BIN");
    }

    /// Pins the dash-to-underscore canonicalization: a tool name with one
    /// dash routes to the shell-safe underscore env var, not to the
    /// dash-bearing form (which POSIX shells cannot export).
    ///
    /// Regression coverage for the silent-PATH-fallback bug a single-`-`
    /// canonicalization regression would re-introduce: the derived env
    /// var `POSTGRES-BOOTSTRAP_BIN` is unsettable from shells, so a
    /// regression would always fall through to the PATH-based "tool name"
    /// fallback, defeating every Nix-derivation-provided absolute path
    /// at the bootstrap-binary surface (`commands/bootstrap.rs`).
    #[test]
    fn test_get_tool_path_canonicalizes_single_dash_to_underscore() {
        env::set_var(
            "POSTGRES_BOOTSTRAP_BIN",
            "/nix/store/abc/bin/postgres-bootstrap",
        );
        assert_eq!(
            get_tool_path("postgres-bootstrap"),
            "/nix/store/abc/bin/postgres-bootstrap"
        );
        // The dash-preserving form is NOT what gets looked up — a value
        // exported there must not leak through.
        assert!(env::var("POSTGRES-BOOTSTRAP_BIN").is_err());
        env::remove_var("POSTGRES_BOOTSTRAP_BIN");
    }

    /// Pins the dash-to-underscore canonicalization for multi-dash names:
    /// every `-` collapses, not just the first. A tool name with N dashes
    /// derives the same `[A-Z0-9_]+_BIN` env var the shell that wrapped
    /// the binary set.
    #[test]
    fn test_get_tool_path_canonicalizes_multiple_dashes_to_underscores() {
        env::set_var("FOO_BAR_BAZ_BIN", "/nix/store/abc/bin/foo-bar-baz");
        assert_eq!(
            get_tool_path("foo-bar-baz"),
            "/nix/store/abc/bin/foo-bar-baz"
        );
        env::remove_var("FOO_BAR_BAZ_BIN");
    }
}

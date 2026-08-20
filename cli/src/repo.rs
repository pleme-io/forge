//! Repository utilities for forge
//!
//! Provides common repository-related functions like finding the repo root,
//! detecting environment, and working with paths.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Find repository root by looking for flake.nix
///
/// Search order:
/// 1. Current directory
/// 2. Parent directories (up to 10 levels)
/// 3. REPO_ROOT environment variable
///
/// # Errors
///
/// Returns an error if no flake.nix is found in any searched location.
///
/// # Examples
///
/// ```rust,ignore
/// let repo_root = find_repo_root()?;
/// println!("Repository root: {}", repo_root.display());
/// ```
pub fn find_repo_root() -> Result<PathBuf> {
    let current = std::env::current_dir().context("Failed to get current directory")?;

    debug!("Searching for repo root from: {}", current.display());

    // Check current directory
    if current.join("flake.nix").exists() {
        debug!("Found flake.nix in current directory");
        return Ok(current);
    }

    // Check parent directories (up to 10 levels)
    let mut dir = current.as_path();
    for level in 1..=10 {
        if let Some(parent) = dir.parent() {
            if parent.join("flake.nix").exists() {
                debug!(
                    "Found flake.nix {} level(s) up at: {}",
                    level,
                    parent.display()
                );
                return Ok(parent.to_path_buf());
            }
            dir = parent;
        } else {
            break;
        }
    }

    // Check REPO_ROOT env var
    if let Ok(repo_root) = std::env::var("REPO_ROOT") {
        let path = PathBuf::from(&repo_root);
        if path.join("flake.nix").exists() {
            debug!("Found flake.nix via REPO_ROOT env var: {}", path.display());
            return Ok(path);
        }
        debug!(
            "REPO_ROOT set to {} but no flake.nix found there",
            repo_root
        );
    }

    anyhow::bail!(
        "Cannot find repository root (flake.nix not found).\n\n  \
         Searched:\n  \
         - Current directory: {}\n  \
         - Parent directories (up to 10 levels)\n  \
         - REPO_ROOT environment variable\n\n  \
         Solutions:\n  \
         - Run this command from the repository root directory\n  \
         - Set REPO_ROOT environment variable to the repository root",
        current.display()
    )
}

/// Get a tool binary path from environment or fallback to PATH
///
/// # Arguments
///
/// * `env_var` - Environment variable name to check first
/// * `fallback` - Command name to use if env var not set
///
/// # Examples
///
/// ```rust,ignore
/// let cargo = get_tool_path("CARGO", "cargo");
/// let crate2nix = get_tool_path("CRATE2NIX", "crate2nix");
/// ```
pub fn get_tool_path(env_var: &str, fallback: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| fallback.to_string())
}

/// Verify a directory exists and contains expected files
///
/// # Arguments
///
/// * `dir` - Directory path to check
/// * `required_files` - List of files that must exist in the directory
///
/// # Errors
///
/// Returns an error if the directory doesn't exist or is missing required files.
pub fn verify_directory(dir: &Path, required_files: &[&str]) -> Result<()> {
    if !dir.exists() {
        anyhow::bail!(
            "Directory not found: {}\n\n  \
             If this is a new setup, you may need to create the directory.\n  \
             If on a different machine, try: git pull origin main",
            dir.display()
        );
    }

    if !dir.is_dir() {
        anyhow::bail!("Path exists but is not a directory: {}", dir.display());
    }

    for file in required_files {
        let file_path = dir.join(file);
        if !file_path.exists() {
            anyhow::bail!(
                "Required file not found: {}\n  \
                 Expected in: {}",
                file,
                dir.display()
            );
        }
    }

    Ok(())
}

/// Get the current environment (staging, production, etc.)
///
/// Reads from FORGE_ENV environment variable, defaults to "staging".
#[allow(dead_code)]
pub fn get_environment() -> String {
    std::env::var("FORGE_ENV").unwrap_or_else(|_| "staging".to_string())
}

/// Which product-directory layouts [`find_product_dir`] accepts as terminal.
///
/// The monorepo layout is universal — every consumer honors it. The
/// standalone layout is additive and consumed only by the rust-service
/// entry point, where a product may live as its own repository rather
/// than a `pkgs/products/{product}` subtree of a larger monorepo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductDirLayout {
    /// Monorepo pattern only: an ancestor whose parent is named `products`
    /// and whose grandparent is named `pkgs` — i.e. `.../pkgs/products/{product}`.
    Monorepo,
    /// Monorepo pattern OR standalone: additionally accept any ancestor
    /// directory that carries both `deploy.yaml` and `.git`, i.e. a
    /// product repository whose root IS the product directory.
    MonorepoOrStandalone,
}

/// Walk up from `start` toward the filesystem root, returning the first
/// ancestor (including `start` itself) that satisfies `layout`.
///
/// Fuses four sibling walkers that spelled the same parent-climb loop
/// verbatim across the crate:
///
/// - `commands/integration_tests.rs::find_product_dir_from_service`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/status.rs::find_product_dir_from_service`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/test.rs::find_product_dir_from_path`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/rust_service.rs::find_product_dir_from_path`
///   ([`ProductDirLayout::MonorepoOrStandalone`])
///
/// Three-of-four sites carried a byte-identical monorepo-only walker;
/// the fourth extended it with a per-iteration standalone check. Post-
/// lift the walk lives at ONE place with the layout choice encoded in
/// the closed enum — a future refinement (a third layout, a per-layer
/// audit hook, a symlink-cycle guard) lands atomically across every
/// consumer rather than at whichever copy the author notices.
///
/// Walker mechanics — matches the pre-lift shape at every consumer
/// site:
///
/// 1. The monorepo terminal is checked at every iteration against the
///    CURRENT node: `current.parent()` must be named `products` and
///    `current.parent().parent()` must be named `pkgs`. The `current`
///    node itself (the `{product}` component) is what is returned.
/// 2. The standalone terminal (only under
///    [`ProductDirLayout::MonorepoOrStandalone`]) is checked at every
///    iteration against the CURRENT node: `current/deploy.yaml` and
///    `current/.git` must both exist. Order matches the pre-lift
///    `commands/rust_service.rs::find_product_dir_from_path` layout —
///    monorepo terminal first, standalone terminal second — so a path
///    that satisfies both (a `pkgs/products/{product}` node that
///    additionally carries a nested `.git`) returns via the monorepo
///    branch, preserving the pre-lift precedence.
/// 3. On no match, climb by `current.parent()` and repeat. Terminate
///    with `None` when there is no parent (i.e. the filesystem root
///    was reached without hitting either terminal).
pub fn find_product_dir(start: &Path, layout: ProductDirLayout) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if let Some(parent) = current.parent() {
            if let Some(grandparent) = parent.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some("products")
                    && grandparent.file_name().and_then(|n| n.to_str()) == Some("pkgs")
                {
                    return Some(current);
                }
            }
        }
        if matches!(layout, ProductDirLayout::MonorepoOrStandalone)
            && current.join("deploy.yaml").exists()
            && current.join(".git").exists()
        {
            return Some(current);
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

/// Run a command in a specific directory, restoring the original directory afterward
///
/// # Arguments
///
/// * `dir` - Directory to run the command in
/// * `f` - Async function to execute
///
/// # Errors
///
/// Returns an error if changing directories fails or if the function returns an error.
pub async fn in_directory<F, Fut, T>(dir: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let original_dir = std::env::current_dir().context("Failed to get current directory")?;

    std::env::set_current_dir(dir)
        .with_context(|| format!("Failed to change to directory: {}", dir.display()))?;

    // Use scopeguard to ensure we restore the directory even on panic
    let _guard = scopeguard::guard((), |_| {
        let _ = std::env::set_current_dir(&original_dir);
    });

    f().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tool_path_with_env() {
        std::env::set_var("TEST_TOOL_PATH", "/custom/path/to/tool");
        assert_eq!(
            get_tool_path("TEST_TOOL_PATH", "default"),
            "/custom/path/to/tool"
        );
        std::env::remove_var("TEST_TOOL_PATH");
    }

    #[test]
    fn test_get_tool_path_fallback() {
        std::env::remove_var("NONEXISTENT_TOOL");
        assert_eq!(
            get_tool_path("NONEXISTENT_TOOL", "fallback-tool"),
            "fallback-tool"
        );
    }

    #[test]
    fn test_get_environment_default() {
        std::env::remove_var("FORGE_ENV");
        assert_eq!(get_environment(), "staging");
    }

    #[test]
    fn test_get_environment_custom() {
        std::env::set_var("FORGE_ENV", "production");
        assert_eq!(get_environment(), "production");
        std::env::remove_var("FORGE_ENV");
    }

    /// The monorepo terminal fires at the `{product}` node when its parent
    /// is `products` and its grandparent is `pkgs`. Pins the returned path
    /// to the `{product}` component itself — i.e. `.../pkgs/products/foo`
    /// walked up from a nested `services/bar` child, NOT the `services`
    /// sub-node or the `pkgs` root. Same shape every pre-lift consumer
    /// spelled: the walk-up returns the FIRST ancestor whose parent is
    /// `products` and grandparent is `pkgs`, so a deep service subtree
    /// resolves to its owning product directory.
    #[test]
    fn find_product_dir_monorepo_returns_product_dir_from_nested_service() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        let service = product.join("services").join("bar");
        std::fs::create_dir_all(&service).expect("create nested service dir");

        assert_eq!(
            find_product_dir(&service, ProductDirLayout::Monorepo),
            Some(product)
        );
    }

    /// A path with no `pkgs/products/{product}` ancestor and no
    /// `deploy.yaml`+`.git` marker under [`ProductDirLayout::Monorepo`]
    /// returns `None` at the filesystem-root terminal. Guards the walker's
    /// termination shape — the pre-lift `loop {}` returned `None` only
    /// when `current.parent()` was `None` at the outermost climb, and this
    /// post-lift shape must match. A silent `Some(root)` return here
    /// (e.g. a mis-refactored "any path counts" acceptance rule) would
    /// silently reroute every consumer's `deploy.yaml` lookup to the
    /// filesystem root.
    #[test]
    fn find_product_dir_monorepo_returns_none_when_no_pkgs_products_ancestor() {
        let root = tempfile::tempdir().expect("root tempdir");
        let unrelated = root.path().join("some").join("other").join("place");
        std::fs::create_dir_all(&unrelated).expect("create unrelated dir");

        assert!(find_product_dir(&unrelated, ProductDirLayout::Monorepo).is_none());
    }

    /// Under [`ProductDirLayout::MonorepoOrStandalone`], a directory
    /// carrying BOTH `deploy.yaml` and `.git` at the current node terminates
    /// the walk at that node — the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` shape. The
    /// walk starts from a nested subdirectory to prove the standalone
    /// terminal is checked at every level of the parent climb, not only at
    /// `start`.
    #[test]
    fn find_product_dir_standalone_terminal_matches_deploy_yaml_and_git() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("standalone-product");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let nested = repo_root.join("crates").join("worker");
        std::fs::create_dir_all(&nested).expect("create nested crate dir");

        assert_eq!(
            find_product_dir(&nested, ProductDirLayout::MonorepoOrStandalone),
            Some(repo_root)
        );
    }

    /// Under [`ProductDirLayout::Monorepo`], the standalone terminal is
    /// NOT checked — a `deploy.yaml`+`.git` directory outside a
    /// `pkgs/products/{product}` layout returns `None`. Pins the layout
    /// enum's semantics at the terminal boundary: a caller passing
    /// [`ProductDirLayout::Monorepo`] gets exactly the pre-lift
    /// monorepo-only shape, not a superset. Without this a future
    /// refactor could silently widen the `Monorepo` variant to also fire
    /// the standalone check and misroute `commands/status.rs` /
    /// `commands/integration_tests.rs` / `commands/test.rs`.
    #[test]
    fn find_product_dir_monorepo_ignores_standalone_marker() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("standalone-product");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(find_product_dir(&repo_root, ProductDirLayout::Monorepo).is_none());
    }

    /// A `deploy.yaml` alone (no `.git`) does NOT satisfy the standalone
    /// terminal — the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` shape
    /// required BOTH markers via `&&`. Prevents a bare-`deploy.yaml`
    /// intermediary directory in the walk (e.g. a `deploy/` folder holding
    /// per-service YAMLs) from being misidentified as a product root.
    #[test]
    fn find_product_dir_standalone_requires_both_deploy_yaml_and_git() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("half-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");

        assert!(find_product_dir(&repo_root, ProductDirLayout::MonorepoOrStandalone).is_none());
    }

    /// Monorepo terminal wins over standalone terminal when both fire at
    /// the same node. A `pkgs/products/{product}` directory that also
    /// carries `deploy.yaml`+`.git` returns via the monorepo branch, not
    /// the standalone one — preserves the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` precedence
    /// (monorepo check first, standalone check second, per iteration).
    /// Load-bearing because the return value shape is identical either way
    /// (`Some(current)`), so the branch that fires isn't observable at
    /// the return, only at the walker's internal ordering — and a
    /// reordering that silently checked standalone first would still
    /// return `Some(current)` at this test's node but would diverge at a
    /// hypothetical layout that terminated on a lower-precedence rule
    /// first.
    #[test]
    fn find_product_dir_monorepo_terminal_wins_when_both_fire() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        std::fs::create_dir_all(&product).expect("create product dir");
        std::fs::write(product.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(product.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&product, ProductDirLayout::MonorepoOrStandalone),
            Some(product)
        );
    }
}

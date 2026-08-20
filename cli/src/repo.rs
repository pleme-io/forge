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
/// than a `pkgs/products/{product}` subtree of a larger monorepo. The
/// named-standalone variant is additive on top of that: it also parses
/// the standalone `deploy.yaml` and requires a top-level string `name:`
/// field to be present, matching the `config::DeployConfig` loader's
/// pre-lift acceptance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductDirLayout {
    /// Monorepo pattern only: an ancestor whose parent is named `products`
    /// and whose grandparent is named `pkgs` — i.e. `.../pkgs/products/{product}`.
    Monorepo,
    /// Monorepo pattern OR standalone: additionally accept any ancestor
    /// directory that carries both `deploy.yaml` and `.git`, i.e. a
    /// product repository whose root IS the product directory.
    MonorepoOrStandalone,
    /// Monorepo pattern OR named standalone: additionally accept any
    /// ancestor directory that carries `deploy.yaml` and `.git` AND whose
    /// `deploy.yaml` parses as YAML with a top-level string `name:` field.
    /// The parse-and-verify step distinguishes a genuine product-repo root
    /// from any other `.git` directory that happens to carry an unrelated
    /// `deploy.yaml` (a deploy-manifest fragment for something else, a
    /// stray file). Matches the pre-lift
    /// `config::DeployConfig::find_product_directory` acceptance rule; a
    /// `.git`+`deploy.yaml` node without a valid `name:` string CONTINUES
    /// the climb rather than terminating, so an inner match at a deeper
    /// ancestor still resolves.
    MonorepoOrNamedStandalone,
}

/// Does `dir/deploy.yaml` parse as YAML and expose a top-level string
/// `name:` field? Extracted verbatim from the pre-lift
/// `config::DeployConfig::find_product_directory` inline check so the
/// named-standalone layout terminal preserves the same
/// tolerate-parse-failures shape: an unreadable file, an unparseable
/// YAML document, a document without a top-level `name`, or a `name`
/// whose value is not a string all return `false` (i.e. the walker
/// CONTINUES the climb) rather than propagating a parse error.
fn standalone_deploy_yaml_has_name(dir: &Path) -> bool {
    let deploy_yaml = dir.join("deploy.yaml");
    let Ok(content) = std::fs::read_to_string(&deploy_yaml) else {
        return false;
    };
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
        return false;
    };
    yaml.get("name").and_then(|n| n.as_str()).is_some()
}

/// Walk up from `start` toward the filesystem root, returning the first
/// ancestor (including `start` itself) that satisfies `layout`.
///
/// Fuses five sibling walkers that spelled the same parent-climb loop
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
/// - `config::DeployConfig::find_product_directory`
///   ([`ProductDirLayout::MonorepoOrNamedStandalone`])
///
/// Three of the five sites carried a byte-identical monorepo-only
/// walker; the fourth extended it with a per-iteration standalone
/// check; the fifth extended THAT with a `deploy.yaml`-parse-plus-`name:`
/// verification. Post-lift the walk lives at ONE place with the layout
/// choice encoded in the closed enum — a future refinement (a fourth
/// layout, a per-layer audit hook, a symlink-cycle guard) lands
/// atomically across every consumer rather than at whichever copy the
/// author notices.
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
/// 3. The named-standalone terminal (only under
///    [`ProductDirLayout::MonorepoOrNamedStandalone`]) is checked at
///    every iteration against the CURRENT node: `current/.git` and
///    `current/deploy.yaml` must both exist AND `current/deploy.yaml`
///    must parse as YAML exposing a top-level string `name:` field —
///    see [`standalone_deploy_yaml_has_name`]. A parse failure or a
///    missing / non-string `name:` field CONTINUES the climb rather
///    than terminating, so a deeper ancestor whose `deploy.yaml` DOES
///    carry a valid `name:` still resolves.
/// 4. On no match, climb by `current.parent()` and repeat. Terminate
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
        match layout {
            ProductDirLayout::Monorepo => {}
            ProductDirLayout::MonorepoOrStandalone => {
                if current.join("deploy.yaml").exists() && current.join(".git").exists() {
                    return Some(current);
                }
            }
            ProductDirLayout::MonorepoOrNamedStandalone => {
                if current.join(".git").exists()
                    && current.join("deploy.yaml").exists()
                    && standalone_deploy_yaml_has_name(&current)
                {
                    return Some(current);
                }
            }
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

/// Activate the root-flake pattern: publish `REPO_ROOT` + `SERVICE_DIR`
/// to the process environment and change the working directory to
/// `repo_root`.
///
/// Fuses three sibling call sites that each hand-spelled the same
/// three-line stanza verbatim:
///
/// - `main.rs::setup_service_directory` (the top-level CLI entry point;
///   pre-lift `set_var("REPO_ROOT", &root); set_var("SERVICE_DIR",
///   &dir); set_current_dir(&root)?`)
/// - `commands/status.rs::execute` (pre-lift `set_var("REPO_ROOT",
///   repo_root); set_var("SERVICE_DIR", service_dir);
///   set_current_dir(repo_root)?`)
/// - `commands/integration_tests.rs::execute_manual` (pre-lift
///   `set_var("REPO_ROOT", repo_root); set_var("SERVICE_DIR",
///   service_dir); set_current_dir(repo_root)?`)
///
/// The invariant every consumer honors — and that a fresh consumer
/// would forget by omission — is composed at ONE surface here:
///
/// 1. `REPO_ROOT` is set FIRST, so every downstream reader
///    (`repo::find_repo_root`, `git::get_repo_root`,
///    `PathBuilder::new`, `DeployConfig::load_for_service`) sees the
///    caller-supplied root regardless of whether the chdir succeeds.
/// 2. `SERVICE_DIR` is set SECOND, so `DeployConfig::load_for_service`
///    and every `commands/*::execute` that reads `SERVICE_DIR` sees the
///    caller-supplied service directory. Omitting this line at any of
///    the three pre-lift sites would have silently misrouted service
///    discovery to whatever `SERVICE_DIR` the calling shell inherited
///    from — a class of bug that structurally cannot occur post-lift.
/// 3. The chdir targets `repo_root`, NOT `service_dir` — the root
///    flake pattern (documented at `main.rs::setup_service_directory`)
///    is "run `nix build` from the repo root; the SERVICE_DIR env var
///    identifies the service to operate on." A caller that chdir'd to
///    `service_dir` instead would break every `nix flake` invocation
///    that follows.
///
/// The env vars are set BEFORE the chdir so a chdir failure still
/// leaves them populated — every pre-lift site had this property by
/// accident of source-order (the two `set_var` lines preceded the `?`
/// on `set_current_dir`); the primitive preserves it by construction.
///
/// # Errors
///
/// Returns an error if `set_current_dir(repo_root)` fails (e.g. the
/// path does not exist, the process lacks permission to enter it, or
/// the path is not a directory).
pub fn activate_root_flake<R, S>(repo_root: R, service_dir: S) -> Result<()>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    let repo_root = repo_root.as_ref();
    let service_dir = service_dir.as_ref();
    std::env::set_var("REPO_ROOT", repo_root);
    std::env::set_var("SERVICE_DIR", service_dir);
    std::env::set_current_dir(repo_root).with_context(|| {
        format!(
            "Failed to change working directory to repo root: {}",
            repo_root.display()
        )
    })
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

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a directory
    /// carrying `.git` + `deploy.yaml` whose YAML exposes a top-level
    /// string `name:` field terminates the walk at that node. Mirrors the
    /// pre-lift `config::DeployConfig::find_product_directory` shape: the
    /// walk starts from a nested subdirectory to prove the named-standalone
    /// terminal is checked at every level of the parent climb, not only at
    /// `start`.
    #[test]
    fn find_product_dir_named_standalone_terminal_matches_name_field() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("named-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "name: my-product\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let nested = repo_root.join("crates").join("worker");
        std::fs::create_dir_all(&nested).expect("create nested crate dir");

        assert_eq!(
            find_product_dir(&nested, ProductDirLayout::MonorepoOrNamedStandalone),
            Some(repo_root)
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a
    /// `.git`+`deploy.yaml` node whose YAML lacks a top-level `name:`
    /// field CONTINUES the climb rather than terminating. Load-bearing:
    /// the pre-lift `config::DeployConfig::find_product_directory` used
    /// this to distinguish a genuine product-repo root (carries a
    /// product `name:`) from any other repo whose `deploy.yaml` fragment
    /// happens to describe something else (e.g. only environment
    /// settings, or a top-level manifest for a non-product artifact).
    /// Without this rule the loader would silently mis-terminate at the
    /// wrong `.git` and resolve a wrong product name.
    #[test]
    fn find_product_dir_named_standalone_ignores_yaml_without_name_field() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("nameless");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n")
            .expect("write deploy.yaml without name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a
    /// `.git`+`deploy.yaml` whose CONTENT is unparseable YAML CONTINUES
    /// the climb, matching the pre-lift
    /// `config::DeployConfig::find_product_directory` tolerate-parse-
    /// failures shape (`if let Ok(yaml) = serde_yaml::from_str::<...>(...)`).
    /// A parse error propagating out of the walker would be a hard
    /// regression: today a stray malformed `deploy.yaml` at a wrong
    /// ancestor still lets the walker reach a valid deeper product root;
    /// after the port that must remain true.
    #[test]
    fn find_product_dir_named_standalone_tolerates_unparseable_yaml() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("broken");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        // Intentionally malformed YAML: unbalanced braces + tab where a
        // key is expected.
        std::fs::write(repo_root.join("deploy.yaml"), "\t{{\n")
            .expect("write malformed deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], the
    /// monorepo terminal STILL fires (and takes precedence) at a
    /// `pkgs/products/{product}` node even when that node ALSO carries a
    /// named standalone `.git`+`deploy.yaml`. Pins the precedence rule
    /// per (4) of `find_product_dir`'s doc: the closed enum adds only an
    /// alternative terminal, never redirects the monorepo one. Without
    /// this a well-formed monorepo product that additionally happens to
    /// carry a nested `.git` (e.g. a submodule root, a dev-only
    /// scratch git init) would silently return via the named-standalone
    /// branch instead of the monorepo branch — the pre-lift consumers'
    /// documented shape.
    #[test]
    fn find_product_dir_named_standalone_monorepo_terminal_still_wins() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        std::fs::create_dir_all(&product).expect("create product dir");
        std::fs::write(product.join("deploy.yaml"), "name: foo\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(product.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&product, ProductDirLayout::MonorepoOrNamedStandalone),
            Some(product)
        );
    }

    /// The `Monorepo` variant IGNORES the named-standalone marker (a
    /// `.git`+`deploy.yaml` whose YAML carries `name:`) — sibling of the
    /// existing `find_product_dir_monorepo_ignores_standalone_marker`
    /// test for the plain standalone marker. Guards the closed enum
    /// against a future refactor that silently widens `Monorepo` to also
    /// fire either standalone check.
    #[test]
    fn find_product_dir_monorepo_ignores_named_standalone_marker() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("named-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "name: my-product\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(find_product_dir(&repo_root, ProductDirLayout::Monorepo).is_none());
    }

    /// [`activate_root_flake`] publishes `REPO_ROOT` to the process
    /// environment as its FIRST side-effect, matching the pre-lift
    /// ordering at all three consumers (`main::setup_service_directory`,
    /// `commands/status::execute`, `commands/integration_tests::execute_manual`).
    /// A downstream `repo::find_repo_root` / `git::get_repo_root` /
    /// `PathBuilder::new` reading `REPO_ROOT` after the call sees the
    /// caller-supplied path, regardless of the chdir outcome.
    #[test]
    fn activate_root_flake_publishes_repo_root_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = dir.path().join("repo").join("services").join("api");
        std::fs::create_dir_all(&service_dir).expect("create service dir");
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        let prior_cwd = std::env::current_dir().expect("cwd");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        assert_eq!(
            std::env::var("REPO_ROOT")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(repo_root.as_path())
        );

        // Restore process-global state so unrelated tests see a clean
        // baseline (the lock guards the observation window; restoring
        // here narrows it further).
        let _ = std::env::set_current_dir(&prior_cwd);
        match prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// [`activate_root_flake`] publishes `SERVICE_DIR` to the process
    /// environment. Load-bearing: `DeployConfig::load_for_service`,
    /// `commands/developer_tools`, `commands/schema_validation`,
    /// `commands/bootstrap`, and `commands/rust_service` all read
    /// `SERVICE_DIR` — a caller that set `REPO_ROOT` but forgot
    /// `SERVICE_DIR` would silently misroute service discovery to
    /// whatever `SERVICE_DIR` the calling shell inherited. Pins the
    /// invariant that the primitive's contract makes the omission
    /// structurally impossible.
    #[test]
    fn activate_root_flake_publishes_service_dir_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = dir.path().join("repo").join("services").join("worker");
        std::fs::create_dir_all(&service_dir).expect("create service dir");
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        let prior_cwd = std::env::current_dir().expect("cwd");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        assert_eq!(
            std::env::var("SERVICE_DIR")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(service_dir.as_path())
        );

        let _ = std::env::set_current_dir(&prior_cwd);
        match prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// [`activate_root_flake`] changes the process working directory to
    /// `repo_root` — NOT `service_dir`. Load-bearing: the root-flake
    /// pattern (documented at `main::setup_service_directory`) runs
    /// `nix build` from the repo root, and every subsequent
    /// path-relative read in the CLI presupposes that root is the cwd.
    /// A migration that silently reversed the chdir target to
    /// `service_dir` would break every `nix flake` invocation
    /// downstream, so the test asserts the equality against `repo_root`
    /// canonicalized to match `set_current_dir`'s canonicalization.
    #[test]
    fn activate_root_flake_chdirs_to_repo_root_not_service_dir() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = repo_root.join("services").join("api");
        std::fs::create_dir_all(&service_dir).expect("create service dir");
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        let prior_cwd = std::env::current_dir().expect("cwd");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        let observed = std::env::current_dir().expect("cwd after activate");
        // Both sides go through canonicalize so a `/private/var/...` vs
        // `/var/...` symlink prefix at the tempdir root does not flake
        // the equality reading.
        let expected = repo_root.canonicalize().expect("canonicalize repo_root");
        let observed = observed.canonicalize().expect("canonicalize observed");
        assert_eq!(observed, expected);

        let _ = std::env::set_current_dir(&prior_cwd);
        match prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// [`activate_root_flake`] sets both env vars BEFORE attempting the
    /// chdir. Load-bearing: if the chdir fails (a caller passing a
    /// nonexistent path, a permission drop mid-pipeline), the env vars
    /// remain populated so a downstream `?`-propagated error handler
    /// can still read `REPO_ROOT` for its own diagnostics. Every
    /// pre-lift consumer had this property by accident of source-order
    /// (the two `set_var` lines preceded the `?` on `set_current_dir`);
    /// the primitive preserves it by construction, and this test pins
    /// it so a future rewrite that reordered the primitive's body
    /// cannot silently regress the invariant.
    #[test]
    fn activate_root_flake_publishes_env_vars_even_when_chdir_fails() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        // Point repo_root at a path that DOES NOT exist so
        // set_current_dir fails; service_dir can still be any path.
        let nonexistent_repo_root = dir.path().join("does-not-exist");
        let service_dir = dir.path().join("service");
        assert!(!nonexistent_repo_root.exists());
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        let prior_cwd = std::env::current_dir().expect("cwd");

        let result = activate_root_flake(&nonexistent_repo_root, &service_dir);
        assert!(result.is_err(), "chdir to nonexistent path should fail");
        // Env vars remain published despite the chdir failure.
        assert_eq!(
            std::env::var("REPO_ROOT")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(nonexistent_repo_root.as_path())
        );
        assert_eq!(
            std::env::var("SERVICE_DIR")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(service_dir.as_path())
        );

        let _ = std::env::set_current_dir(&prior_cwd);
        match prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// The chdir-failure error surfaces `repo_root`'s path in its
    /// context, so a `?`-propagated error the CLI prints to the
    /// operator names the exact directory that could not be entered.
    /// Pre-lift each consumer got a bare `std::io::Error` from
    /// `set_current_dir` with no path context; post-lift the primitive
    /// attaches `with_context` naming the offending path — a small
    /// diagnostic upgrade at every consumer by construction.
    #[test]
    fn activate_root_flake_error_context_names_the_repo_root_path() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent_repo_root = dir.path().join("nope");
        let service_dir = dir.path().join("service");
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        let prior_cwd = std::env::current_dir().expect("cwd");

        let err = activate_root_flake(&nonexistent_repo_root, &service_dir).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&nonexistent_repo_root.display().to_string()),
            "error should name the repo_root path; got: {msg}"
        );

        let _ = std::env::set_current_dir(&prior_cwd);
        match prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// The primitive accepts the caller's argument shape verbatim
    /// (`&str`, `String`, `&Path`, `PathBuf`) via `AsRef<Path>` bounds
    /// on both parameters. Load-bearing: the three pre-lift consumers
    /// each spelled the arguments differently (`main` passed
    /// `&String` from an `Option<String>` binding, `status` and
    /// `integration_tests` passed `&str` from their `&str`
    /// parameters). A single-type signature (e.g. `&str`-only) would
    /// have forced boilerplate at the `main` site; the `AsRef<Path>`
    /// bound makes every caller-shape pass by construction.
    #[test]
    fn activate_root_flake_accepts_str_and_string_and_path_args() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = repo_root.join("s");
        std::fs::create_dir_all(&service_dir).expect("mkdir");
        let repo_root_str: &str = repo_root.to_str().unwrap();
        let service_dir_string: String = service_dir.display().to_string();
        let prior_repo = std::env::var("REPO_ROOT");
        let prior_svc = std::env::var("SERVICE_DIR");
        let prior_cwd = std::env::current_dir().expect("cwd");

        // &str for repo_root, String for service_dir.
        activate_root_flake(repo_root_str, service_dir_string).expect("&str + String");
        // &Path for repo_root, PathBuf for service_dir.
        activate_root_flake(repo_root.as_path(), repo_root.join("s")).expect("&Path + PathBuf");
        // &String for repo_root (matches the pre-lift main.rs shape),
        // &str for service_dir (matches the pre-lift status.rs shape).
        let repo_root_owned: String = repo_root.display().to_string();
        activate_root_flake(&repo_root_owned, "").ok();

        let _ = std::env::set_current_dir(&prior_cwd);
        match prior_repo {
            Ok(v) => std::env::set_var("REPO_ROOT", v),
            Err(_) => std::env::remove_var("REPO_ROOT"),
        }
        match prior_svc {
            Ok(v) => std::env::set_var("SERVICE_DIR", v),
            Err(_) => std::env::remove_var("SERVICE_DIR"),
        }
    }

    /// The `MonorepoOrStandalone` variant does NOT verify the `name:`
    /// field — a `.git`+`deploy.yaml` node without `name:` terminates
    /// there under `MonorepoOrStandalone` (per the existing
    /// `find_product_dir_standalone_terminal_matches_deploy_yaml_and_git`
    /// test) but CONTINUES under `MonorepoOrNamedStandalone`. Pins the
    /// two standalone variants as independent branches: a shift of one
    /// variant's terminal condition must not silently reroute the other.
    #[test]
    fn find_product_dir_standalone_and_named_standalone_diverge_at_missing_name() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("nameless");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n")
            .expect("write deploy.yaml without name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrStandalone),
            Some(repo_root.clone())
        );
        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }
}

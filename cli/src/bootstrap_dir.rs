//! `<repo_root>/pkgs/platform/bootstrap` directory-path primitive — the
//! canonical filesystem location of the shared Bootstrap platform
//! component every product's bootstrap binary flake lives under.
//!
//! # Pre-lift census — two sibling composition sites
//!
//! Two pre-lift `commands/bootstrap.rs` sites each restated
//! `repo_root.join("pkgs/platform/bootstrap")` verbatim, differing only
//! in the surrounding env-var-first probe scaffolding:
//!
//! 1. `commands/bootstrap.rs::get_bootstrap_dir` (~L184) — the
//!    `build`-command private accessor's `Ok(repo_root
//!    .join("pkgs/platform/bootstrap"))` fallback, taken when the
//!    `SERVICE_DIR` env-var probe misses.
//! 2. `commands/bootstrap.rs::regenerate` (~L613) — the `regenerate`
//!    command's inline `.unwrap_or_else(|| repo_root
//!    .join("pkgs/platform/bootstrap"))` fallback on the same
//!    env-var-first probe pattern.
//!
//! Both sites compose the same three-segment `pkgs/platform/bootstrap`
//! path under a caller-provided `repo_root: &Path`. Post-lift the two
//! stanzas route through [`bootstrap_dir`]; a drift in the platform
//! layout (a rename of `pkgs/platform` to `platform/`, a swap of the
//! `bootstrap` segment to `boot` or `platform-bootstrap`, a promotion
//! of the component to a top-level `bootstrap/` crate) lands at ONE
//! typed body and reaches both consumers by construction.
//!
//! # Sibling of `crate::hanabi_dir::hanabi_dir`
//!
//! This primitive is the Bootstrap-half of the same
//! `<repo_root>/pkgs/platform/<component>` grammar the Hanabi half
//! ([`crate::hanabi_dir::hanabi_dir`]) resolves. A future lift that
//! grows a closed `PlatformComponent { Hanabi, Bootstrap }` enum plus
//! one `platform_component_dir(repo_root, component)` accessor can
//! land at ONE place and both this primitive and the Hanabi sibling
//! forward through it; the two half-primitives exist so the census
//! stays local and each consumer surface reaches for a name that
//! matches its component rather than a generic slot.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the Bootstrap platform-directory
//! composition lives at ONE construction surface so a future refinement
//! (a `SERVICE_DIR`-env-var-first probe promotion into this module, a
//! rename of the platform layout, a swap onto `PathBuf::from(env!(
//! "BOOTSTRAP_DIR"))` for hermetic Nix-derivation-pinned paths) lands
//! in one place rather than at every consumer.

use std::path::{Path, PathBuf};

/// Compose the Bootstrap platform directory path under a caller-provided
/// repository root: `<repo_root>/pkgs/platform/bootstrap`.
///
/// The two consumer sites in
/// `commands/bootstrap.rs::{get_bootstrap_dir, regenerate}` each spelled
/// `repo_root.join("pkgs/platform/bootstrap")` pre-lift; post-lift they
/// both forward through this function.
///
/// # Byte shape
///
/// Returns `repo_root.join("pkgs/platform/bootstrap")` byte-for-byte.
/// The three-segment composition is preserved via a single
/// `.join("pkgs/platform/bootstrap")` call — [`Path::join`] treats an
/// embedded `/` as a path separator, so the resulting [`PathBuf`]
/// components sequence is `[<repo_root components…>, "pkgs", "platform",
/// "bootstrap"]` identically to the pre-lift chained-`.join` shape.
///
/// # Ownership discipline
///
/// The returned [`PathBuf`] is heap-allocated and independent of the
/// input `repo_root` lifetime — a caller can drop `repo_root`
/// immediately after the call. Matches the pre-lift behavior at both
/// consumers, which both bind the result into a local `let` and hand
/// `&bootstrap_dir` to downstream calls that must outlive the arg.
pub fn bootstrap_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("pkgs/platform/bootstrap")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`bootstrap_dir`] returns the pre-lift chained-`.join`
    /// composition. A future refactor that (a) swapped the `bootstrap`
    /// segment to `boot` or `platform-bootstrap`, (b) dropped the
    /// `platform` middle segment, (c) reordered the three segments, or
    /// (d) added a trailing slash would flip this assertion.
    #[test]
    fn test_bootstrap_dir_matches_pre_lift_chained_joins() {
        let repo_root = Path::new("/home/user/forge");
        let expected = repo_root.join("pkgs").join("platform").join("bootstrap");
        assert_eq!(bootstrap_dir(repo_root), expected);
        assert_eq!(
            bootstrap_dir(repo_root),
            PathBuf::from("/home/user/forge/pkgs/platform/bootstrap")
        );
    }

    /// Component-sequence pin: the returned [`PathBuf`] appends exactly
    /// three named segments (`pkgs`, `platform`, `bootstrap`) after the
    /// caller's `<repo_root>` prefix — no fusion into a single
    /// `platform-bootstrap` segment, no fourth segment under
    /// `bootstrap/`.
    #[test]
    fn test_bootstrap_dir_appends_exactly_three_named_segments() {
        let repo_root = Path::new("/repo");
        let full = bootstrap_dir(repo_root);
        let full_components: Vec<_> = full
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let root_components: Vec<_> = repo_root
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let appended: Vec<_> = full_components[root_components.len()..].to_vec();
        assert_eq!(
            appended,
            vec![
                "pkgs".to_string(),
                "platform".to_string(),
                "bootstrap".to_string()
            ],
            "bootstrap_dir must append exactly the three-segment \
             `pkgs/platform/bootstrap` tail — got {appended:?}"
        );
    }

    /// Ownership pin: the primitive returns an OWNED [`PathBuf`], not a
    /// borrowed `&Path` bound to the caller's `repo_root` lifetime. A
    /// future signature change that returned `&Path` would refuse the
    /// two pre-lift consumer sites, both of which bind `bootstrap_dir`
    /// into a local `let` and hand `&bootstrap_dir` to downstream
    /// `verify_directory` / `in_directory` calls that must outlive
    /// the arg.
    #[test]
    fn test_bootstrap_dir_returns_owned_pathbuf() {
        let owned: PathBuf = bootstrap_dir(Path::new("/x"));
        assert_eq!(owned, PathBuf::from("/x/pkgs/platform/bootstrap"));
    }

    /// Relative-root pin: a caller-provided relative `repo_root`
    /// composes a relative Bootstrap path — the primitive does NOT
    /// silently absolutize. Pre-lift neither consumer spelled a
    /// `.canonicalize()` step, so the primitive stays as literal as the
    /// pre-lift chained `.join`.
    #[test]
    fn test_bootstrap_dir_preserves_relative_root() {
        assert_eq!(
            bootstrap_dir(Path::new("workspace")),
            PathBuf::from("workspace/pkgs/platform/bootstrap")
        );
        assert_eq!(
            bootstrap_dir(Path::new(".")),
            PathBuf::from("./pkgs/platform/bootstrap")
        );
    }

    /// Byte-oracle distinctness pin: the Bootstrap composition MUST
    /// differ from the sibling Hanabi composition on the same
    /// `<repo_root>`. A regression that pointed both platform-component
    /// primitives at the same directory (or swapped their trailing
    /// segments) would silently route the Bootstrap build's cargo
    /// commands into the Hanabi tree; this pin flips first.
    #[test]
    fn test_bootstrap_dir_differs_from_hanabi_dir_on_same_root() {
        let repo_root = Path::new("/x");
        assert_ne!(
            bootstrap_dir(repo_root),
            crate::hanabi_dir::hanabi_dir(repo_root),
            "bootstrap_dir and hanabi_dir must resolve to distinct \
             `pkgs/platform/<component>` paths under the same repo root"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `.join("pkgs/platform/bootstrap")` composition inline any more.
    /// The two pre-lift sites in `commands/bootstrap.rs` migrated; any
    /// future consumer that wants the same Bootstrap path reaches for
    /// [`bootstrap_dir`] on first grep, not by copy-pasting the literal
    /// from an existing site. Doc-comment mentions of the literal
    /// (`//! …pkgs/platform/bootstrap…`) are exempt via the leading-`//`
    /// filter — they cite the shape, they do not compose it.
    #[test]
    fn no_command_module_still_spells_raw_bootstrap_platform_join() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(StdPathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains("\"pkgs/platform/bootstrap\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `.join(\"pkgs/platform/bootstrap\")` composition(s) \
             survive under `commands/` — route each through \
             `crate::bootstrap_dir::bootstrap_dir(<repo_root>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift module that housed
    /// the two sites MUST forward through [`bootstrap_dir`] at least
    /// the pre-lift count of times, so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_hanabi_dir` shield in
    /// [`crate::hanabi_dir`].
    #[test]
    fn every_prelift_module_forwards_through_bootstrap_dir() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("bootstrap.rs", 2)];
        let needle = "bootstrap_dir(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `pkgs/platform/bootstrap` composition site(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}

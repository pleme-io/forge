//! `<repo_root>/pkgs/platform/hanabi` directory-path primitive — the
//! canonical filesystem location of the shared Hanabi BFF (Backend-
//! for-Frontend) platform component every product's web service links
//! against.
//!
//! # Pre-lift census — two sibling composition sites
//!
//! Two pre-lift `commands/web_service.rs` sites each restated
//! `repo_root_path.join("pkgs").join("platform").join("hanabi")`
//! verbatim, differing only in which caller function bound the
//! resulting `hanabi_dir` local:
//!
//! 1. `commands/web_service.rs::web_regenerate` (~L122) — the
//!    `regenerate` command's Hanabi Cargo.nix regeneration path bind,
//!    fed to [`crate::ui::print_path_label`] on the `"Hanabi"` label
//!    row and to [`crate::nix::run_crate2nix_in`] as the scoped
//!    working directory for the crate2nix generate spawn.
//! 2. `commands/web_service.rs::web_cargo_update` (~L229) — the
//!    `cargo-update` command's Hanabi path bind, fed to the same
//!    `print_path_label` row, to `Command::new(&cargo).arg("update")
//!    .current_dir(&hanabi_dir)` on the cargo-update step, and to
//!    the same `run_crate2nix_in` call on the Cargo.nix regenerate
//!    step.
//!
//! Both sites compose the same three-segment `pkgs/platform/hanabi`
//! path under a caller-provided `repo_root: &Path`. Post-lift the two
//! stanzas route through [`hanabi_dir`]; a drift in the platform layout
//! (a rename of `pkgs/platform` to `platform/`, a swap of the `hanabi`
//! segment to `bff` or `platform-hanabi`, a promotion of the component
//! to a top-level `hanabi/` crate) lands at ONE typed body and reaches
//! both consumers by construction.
//!
//! # Distinct from the sibling `pkgs/platform/bootstrap` composition
//!
//! `commands/bootstrap.rs` carries the analogous two-site pattern for
//! the `pkgs/platform/bootstrap` component — one binding at
//! `get_bootstrap_dir()` (~L184) and one binding at the
//! `regenerate_bootstrap` fallback (~L613). Those two are OUT OF SCOPE
//! for this primitive: `bootstrap` is a distinct platform component
//! with its own separate consumer surface (`fn get_bootstrap_dir()` is
//! an `Option`-lifting accessor that first probes `SERVICE_DIR`), and
//! collapsing the two platform components onto one generic
//! `resolve_platform_component_dir(repo_root, name)` would either lose
//! the two-argument-typing invariant (Hanabi callers never spell the
//! component name inline) or force an open `&str` slot the two sibling
//! components' consumer sites have no reason to accept. Post-lift the
//! shared prefix lives at the closed-enum accessor
//! [`crate::platform_component::platform_component_dir`] — this
//! primitive stays as the Hanabi-only forwarder so the caller-side
//! census stays local.
//!
//! # Distinct from the sibling product-directory composition
//!
//! [`crate::config::resolve_product_dir`] composes
//! `<repo_root>/pkgs/products/<product>` for the per-product source
//! tree — a run-time `&str` product name in the third segment. This
//! primitive composes `<repo_root>/pkgs/platform/hanabi` with the
//! `hanabi` segment fixed at compile time. The two shapes share the
//! `<repo_root>/pkgs/<class>/<name>` grammar but are distinct by
//! `<class>` (`products` vs `platform`), distinct in whether the
//! `<name>` is a run-time argument, and distinct in semantics
//! (per-product source tree vs shared BFF component).
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the Hanabi platform-directory
//! composition lives at ONE construction surface so a future refinement
//! (a `SERVICE_DIR`-env-var-first probe like `get_bootstrap_dir()`
//! carries, a promotion to `PathBuf::from(env!("HANABI_DIR"))` for
//! hermetic Nix-derivation-pinned paths, a rename of the platform
//! layout) lands in one place rather than at every consumer.

use std::path::{Path, PathBuf};

/// Compose the Hanabi platform directory path under a caller-provided
/// repository root: `<repo_root>/pkgs/platform/hanabi`.
///
/// The two consumer sites in
/// `commands/web_service.rs::{web_regenerate, web_cargo_update}` each
/// spelled `repo_root_path.join("pkgs").join("platform").join("hanabi")`
/// pre-lift; post-lift they both forward through this function.
///
/// # Byte shape
///
/// Returns
/// `repo_root.join("pkgs").join("platform").join("hanabi")` byte-for-
/// byte. The three-segment composition is preserved via a single
/// `.join("pkgs/platform/hanabi")` call — `Path::join` treats an
/// embedded `/` as a path separator, so the resulting `PathBuf`
/// components sequence is `[<repo_root components…>, "pkgs", "platform",
/// "hanabi"]` identically to the pre-lift chained-`.join` shape.
/// The [`tests::test_hanabi_dir_matches_pre_lift_chained_joins`]
/// byte-oracle pins this equivalence.
///
/// # Ownership discipline
///
/// The returned [`PathBuf`] is heap-allocated and independent of the
/// input `repo_root` lifetime — a caller can drop `repo_root`
/// immediately after the call. Matches the pre-lift chained-`.join`
/// behavior at both consumers.
pub fn hanabi_dir(repo_root: &Path) -> PathBuf {
    crate::platform_component::platform_component_dir(
        repo_root,
        crate::platform_component::PlatformComponent::Hanabi,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`hanabi_dir`] returns the pre-lift chained-`.join`
    /// composition. A future refactor that (a) swapped the `hanabi`
    /// segment to `bff` or `platform-hanabi`, (b) dropped the
    /// `platform` middle segment, (c) reordered the three segments,
    /// or (d) added a trailing slash would flip this assertion.
    #[test]
    fn test_hanabi_dir_matches_pre_lift_chained_joins() {
        let repo_root = Path::new("/home/user/forge");
        let expected = repo_root.join("pkgs").join("platform").join("hanabi");
        assert_eq!(hanabi_dir(repo_root), expected);
        assert_eq!(
            hanabi_dir(repo_root),
            PathBuf::from("/home/user/forge/pkgs/platform/hanabi")
        );
    }

    /// Component-sequence pin: the returned [`PathBuf`] has exactly
    /// four components after the `<repo_root>` prefix's components —
    /// none of the three appended segments (`pkgs`, `platform`,
    /// `hanabi`) may collapse into another. A drift that fused
    /// `platform/hanabi` into a single `platform-hanabi` segment would
    /// fail here, as would a drift that added a fourth `bff` segment
    /// under `hanabi/`.
    #[test]
    fn test_hanabi_dir_appends_exactly_three_named_segments() {
        let repo_root = Path::new("/repo");
        let full = hanabi_dir(repo_root);
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
                "hanabi".to_string()
            ],
            "hanabi_dir must append exactly the three-segment \
             `pkgs/platform/hanabi` tail — got {appended:?}"
        );
    }

    /// Ownership pin: the primitive returns an OWNED [`PathBuf`], not
    /// a borrowed `&Path` bound to the caller's `repo_root` lifetime.
    /// A future signature change that returned `&Path` would refuse
    /// the two pre-lift consumer sites, both of which bind
    /// `hanabi_dir` into a local `let` and hand `&hanabi_dir` to
    /// downstream calls that must outlive the arg.
    #[test]
    fn test_hanabi_dir_returns_owned_pathbuf() {
        let owned: PathBuf = hanabi_dir(Path::new("/x"));
        assert_eq!(owned, PathBuf::from("/x/pkgs/platform/hanabi"));
    }

    /// Relative-root pin: a caller-provided relative `repo_root`
    /// composes a relative Hanabi path — the primitive does NOT
    /// silently absolutize. Two pre-lift sites accept a relative or
    /// absolute `repo_root` alike (both threaded through from
    /// `web_regenerate` / `web_cargo_update` callers), and neither
    /// spelled a `.canonicalize()` step, so the primitive stays as
    /// literal as the pre-lift chained `.join`.
    #[test]
    fn test_hanabi_dir_preserves_relative_root() {
        assert_eq!(
            hanabi_dir(Path::new("workspace")),
            PathBuf::from("workspace/pkgs/platform/hanabi")
        );
        assert_eq!(
            hanabi_dir(Path::new(".")),
            PathBuf::from("./pkgs/platform/hanabi")
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `.join("pkgs").join("platform").join("hanabi")` chained
    /// composition inline any more. The two pre-lift sites in
    /// `commands/web_service.rs` migrated; any future consumer that
    /// wants the same Hanabi path reaches for [`hanabi_dir`] on first
    /// grep, not by copy-pasting the chained-`.join` literal.
    #[test]
    fn no_command_module_still_spells_raw_hanabi_platform_join_chain() {
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
                let mentions_hanabi = line.contains("\"hanabi\"");
                let mentions_platform = line.contains("\"platform\"");
                let forwards_through_primitive = line.contains("hanabi_dir(");
                if mentions_hanabi && mentions_platform && !forwards_through_primitive {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `.join(\"pkgs\").join(\"platform\").join(\"hanabi\")` chained \
             composition(s) survive under `commands/` — route each through \
             `crate::hanabi_dir::hanabi_dir(<repo_root>)` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift module that housed
    /// the two sites MUST forward through [`hanabi_dir`] at least the
    /// pre-lift count of times, so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_hanabi_dir() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 2)];
        let needle = "hanabi_dir(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `pkgs/platform/hanabi` composition site(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}

//! `<repo_root>/pkgs/platform/<component>` closed-enum accessor —
//! the ONE construction surface for every path in the shared platform-
//! component directory family forge orchestrates. Both
//! [`crate::hanabi_dir::hanabi_dir`] and
//! [`crate::bootstrap_dir::bootstrap_dir`] forward through
//! [`platform_component_dir`] post-lift.
//!
//! # Pre-lift census — two typed half-primitives on the same grammar
//!
//! The two prior lifts (422a2df, a607f63) each closed one half of the
//! `<repo_root>/pkgs/platform/<component>` grammar at a component-named
//! typed accessor:
//!
//! 1. [`crate::hanabi_dir::hanabi_dir`] — spells the two-caller
//!    Hanabi-only `<repo_root>/pkgs/platform/hanabi` shape, consumed
//!    by `commands/web_service.rs::{web_regenerate, web_cargo_update}`.
//! 2. [`crate::bootstrap_dir::bootstrap_dir`] — spells the two-caller
//!    Bootstrap-only `<repo_root>/pkgs/platform/bootstrap` shape,
//!    consumed by `commands/bootstrap.rs::{get_bootstrap_dir,
//!    regenerate}`.
//!
//! Both half-primitives compose the same three-segment path shape
//! against a caller-provided `repo_root: &Path`, differing ONLY in
//! the trailing `<component>` byte-string (`"hanabi"` vs
//! `"bootstrap"`). Two independently-drifting `.join("pkgs/platform/...")`
//! bodies past the PRIME DIRECTIVE's zero-duplication threshold: a
//! rename of `pkgs/platform` to `platform/`, a promotion to
//! `PathBuf::from(env!("PLATFORM_DIR"))`, or a swap of `Path::join`
//! for a hermetic Nix-derivation-pinned resolver would today land at
//! TWO code sites and drift.
//!
//! Post-lift the `pkgs/platform` prefix lives at ONE spot
//! ([`platform_component_dir`]'s body) and the two half-primitives
//! stay as component-named forwarders — a fresh caller reaches for the
//! component-named alias on first grep, while a platform-layout
//! refinement lands at the shared accessor and reaches BOTH consumer
//! surfaces (four call sites in total) by construction.
//!
//! # Closed enum, not an open string
//!
//! [`PlatformComponent`] is a closed [`Copy`] enum, not an open
//! `&'static str`. A caller cannot pass `"hanbai"` (typo), `"boot"`
//! (out-of-fleet name), or the empty string; the two variants pin the
//! two components the fleet composes today. Growing a third (say, a
//! future `Kensa` policy-engine platform component) is a variant
//! addition and a `segment` arm, not an open-string discipline
//! across every consumer site.
//!
//! # THEORY grounding
//!
//! §V.1 solve-once-at-the-primitive: the `pkgs/platform` prefix and
//! the closed-enum `<component>` projection each live at ONE code
//! point. §VI.1 duplication-is-a-bug (PRIME DIRECTIVE): two identical
//! `.join("pkgs/platform/...")` bodies past the zero-duplication
//! threshold, closed at the shared accessor. §II.1 typed-entry: the
//! open-`&str` component-name slot the sibling `hanabi_dir` doc
//! warned against ("`resolve_platform_component_dir(repo_root, name)`
//! would force an open `&str` slot") stays closed — the accessor
//! takes a [`PlatformComponent`], not an `&str`, so a component-name
//! typo becomes a compile error.

use std::path::{Path, PathBuf};

use anyhow::Result;

/// Closed enumeration of the shared platform components forge composes
/// `<repo_root>/pkgs/platform/<component>` directories for.
///
/// The two variants pin the fleet's current platform-component roster;
/// growing a third is a variant addition here plus a [`segment`]
/// arm, NOT an open-string discipline at every consumer.
///
/// [`segment`]: PlatformComponent::segment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformComponent {
    /// The Hanabi BFF (Backend-for-Frontend) Rust crate every product's
    /// web service links against. Lives at
    /// `<repo_root>/pkgs/platform/hanabi`.
    Hanabi,
    /// The Bootstrap binary flake every product's bootstrap unit builds
    /// against. Lives at `<repo_root>/pkgs/platform/bootstrap`.
    Bootstrap,
}

impl PlatformComponent {
    /// The trailing `<component>` byte-string segment in
    /// `<repo_root>/pkgs/platform/<component>`.
    ///
    /// A `const fn` because the projection is a compile-time constant;
    /// callers can bind the result into a `const CTX: &str = ...` or
    /// use it in `match` arms without a runtime dispatch.
    pub const fn segment(self) -> &'static str {
        match self {
            Self::Hanabi => "hanabi",
            Self::Bootstrap => "bootstrap",
        }
    }

    /// The Title-Case operator-facing display name every
    /// [`require_platform_component_dir_exists`] miss-arm bail message
    /// interpolates as `"{display_name} directory not found: {path}"`.
    ///
    /// Distinct from [`Self::segment`] because the disk segment is
    /// lower-cased (`"hanabi"`, `"bootstrap"`) but the operator-facing
    /// wording carries the component's Title-Case marketing name
    /// (`"Hanabi"`, `"Bootstrap"`). A single-axis projection would fuse
    /// the two and either force `.to_lowercase()` on the segment lookup
    /// or `.to_uppercase_first_letter()` on the wording; splitting the
    /// two projections keeps each arm literal.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Hanabi => "Hanabi",
            Self::Bootstrap => "Bootstrap",
        }
    }
}

/// Assert a caller-owned platform-component directory exists on disk,
/// bailing with the canonical two-line envelope
///
/// ```text
/// {component.display_name()} directory not found: {dir.display()}
///   Expected at: pkgs/platform/{component.segment()}/
/// ```
///
/// on the miss arm. The line-2 hint pins the expected in-repo location
/// under the shared `pkgs/platform/` prefix so an operator whose command
/// bailed can `cd <repo>/pkgs/platform/<component>/` without decoding
/// the display-projected absolute path on line 1.
///
/// # Pre-lift census — two sibling stanzas on the Hanabi variant
///
/// Two pre-lift `commands/web_service.rs` sites each spelled the 5-line
///
/// ```text
/// if !hanabi_dir.exists() {
///     bail!(
///         "Hanabi directory not found: {}\n  \
///          Expected at: pkgs/platform/hanabi/",
///         hanabi_dir.display()
///     );
/// }
/// ```
///
/// stanza verbatim, differing only in the surrounding caller function:
///
/// 1. `commands/web_service.rs::web_regenerate` (~L134) — Hanabi
///    Cargo.nix regeneration path, `hanabi_dir` pre-bound from
///    [`crate::hanabi_dir::hanabi_dir`].
/// 2. `commands/web_service.rs::web_cargo_update` (~L225) — Hanabi
///    cargo-update path, same `hanabi_dir` binding via the same
///    half-primitive.
///
/// Post-lift both stanzas route through this body; a future refinement
/// (a swap to `.exists()` on a canonical form, an added ENOENT probe
/// that surfaces `permission denied` distinctly, a re-wording of the
/// hint line, a variant-conditional segment resolution) lands at ONE
/// typed body and reaches both consumers by construction. Growing a
/// third caller — say, a future [`PlatformComponent::Bootstrap`]-side
/// existence assertion — reaches for the same body on first grep,
/// spelled `require_platform_component_dir_exists(&bootstrap_dir,
/// PlatformComponent::Bootstrap)?`.
///
/// # Errors
///
/// Returns `Err` with the exact wording above if `dir` does not exist
/// on disk. On the hit arm returns `Ok(())` without touching `dir`
/// further — the primitive does NOT probe the directory's contents,
/// permissions, or Nix hash, only its presence. A caller that also
/// wants the presence of `Cargo.nix` or `flake.nix` under `dir` gates
/// that separately.
///
/// # Byte shape
///
/// The bail message is composed via a single `anyhow::bail!` with an
/// interpolated `{}\n  Expected at: pkgs/platform/{}/` format string —
/// the pre-lift two-line envelope verbatim, byte-for-byte. The
/// [`tests::test_require_platform_component_dir_exists_hanabi_bail_shape`]
/// byte-oracle pins the exact miss-arm wording so a future edit that
/// dropped the two-space indent, respelled `"Expected at:"` to
/// `"expected:"`, or dropped the trailing `/` would flip the assertion.
pub fn require_platform_component_dir_exists(
    dir: &Path,
    component: PlatformComponent,
) -> Result<()> {
    if !dir.exists() {
        anyhow::bail!(
            "{} directory not found: {}\n  \
             Expected at: pkgs/platform/{}/",
            component.display_name(),
            dir.display(),
            component.segment(),
        );
    }
    Ok(())
}

/// Compose the platform-component directory path under a caller-
/// provided repository root: `<repo_root>/pkgs/platform/<component>`.
///
/// The two component-named half-primitives
/// ([`crate::hanabi_dir::hanabi_dir`] and
/// [`crate::bootstrap_dir::bootstrap_dir`]) both forward through this
/// function post-lift; the `pkgs/platform` prefix lives at exactly one
/// code point (this function's body).
///
/// # Byte shape
///
/// Returns `repo_root.join("pkgs/platform").join(component.segment())`
/// byte-for-byte. The resulting [`PathBuf`] components sequence is
/// `[<repo_root components…>, "pkgs", "platform",
/// <component.segment()>]` — identical to the pre-lift shapes the two
/// half-primitives spelled inline.
///
/// # Ownership discipline
///
/// The returned [`PathBuf`] is heap-allocated and independent of the
/// input `repo_root` lifetime — a caller can drop `repo_root`
/// immediately after the call. Matches both half-primitives'
/// pre-lift ownership shape.
pub fn platform_component_dir(repo_root: &Path, component: PlatformComponent) -> PathBuf {
    repo_root.join("pkgs/platform").join(component.segment())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`platform_component_dir`] on
    /// [`PlatformComponent::Hanabi`] resolves to the same [`PathBuf`]
    /// the pre-lift Hanabi half-primitive
    /// ([`crate::hanabi_dir::hanabi_dir`]) spells.
    #[test]
    fn test_platform_component_dir_hanabi_matches_prelift_shape() {
        let repo_root = Path::new("/home/user/forge");
        assert_eq!(
            platform_component_dir(repo_root, PlatformComponent::Hanabi),
            repo_root.join("pkgs").join("platform").join("hanabi"),
        );
        assert_eq!(
            platform_component_dir(repo_root, PlatformComponent::Hanabi),
            PathBuf::from("/home/user/forge/pkgs/platform/hanabi"),
        );
    }

    /// Byte-oracle: [`platform_component_dir`] on
    /// [`PlatformComponent::Bootstrap`] resolves to the same [`PathBuf`]
    /// the pre-lift Bootstrap half-primitive
    /// ([`crate::bootstrap_dir::bootstrap_dir`]) spells.
    #[test]
    fn test_platform_component_dir_bootstrap_matches_prelift_shape() {
        let repo_root = Path::new("/home/user/forge");
        assert_eq!(
            platform_component_dir(repo_root, PlatformComponent::Bootstrap),
            repo_root.join("pkgs").join("platform").join("bootstrap"),
        );
        assert_eq!(
            platform_component_dir(repo_root, PlatformComponent::Bootstrap),
            PathBuf::from("/home/user/forge/pkgs/platform/bootstrap"),
        );
    }

    /// Delegation pin: the two component-named half-primitives
    /// (`hanabi_dir`, `bootstrap_dir`) MUST resolve identically to
    /// their [`platform_component_dir`] counterpart on the same
    /// `repo_root`. A future refactor that (a) changed the shared
    /// accessor's `pkgs/platform` prefix without updating a
    /// half-primitive's forward, or (b) swapped a half-primitive back
    /// to an inline `.join(...)` chain would flip this pin.
    #[test]
    fn test_half_primitives_agree_with_shared_accessor() {
        let repo_root = Path::new("/x");
        assert_eq!(
            crate::hanabi_dir::hanabi_dir(repo_root),
            platform_component_dir(repo_root, PlatformComponent::Hanabi),
        );
        assert_eq!(
            crate::bootstrap_dir::bootstrap_dir(repo_root),
            platform_component_dir(repo_root, PlatformComponent::Bootstrap),
        );
    }

    /// Component-sequence pin: [`platform_component_dir`] appends
    /// exactly three named segments (`pkgs`, `platform`,
    /// `<component.segment()>`) — no fusion into
    /// `platform-<component>`, no fourth segment.
    #[test]
    fn test_platform_component_dir_appends_exactly_three_named_segments() {
        for (component, expected_tail) in [
            (PlatformComponent::Hanabi, "hanabi"),
            (PlatformComponent::Bootstrap, "bootstrap"),
        ] {
            let repo_root = Path::new("/repo");
            let full = platform_component_dir(repo_root, component);
            let appended: Vec<_> = full
                .components()
                .skip(repo_root.components().count())
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                appended,
                vec![
                    "pkgs".to_string(),
                    "platform".to_string(),
                    expected_tail.to_string(),
                ],
                "platform_component_dir({component:?}) must append exactly \
                 the three-segment `pkgs/platform/{expected_tail}` tail — \
                 got {appended:?}",
            );
        }
    }

    /// Ownership pin: the accessor returns an OWNED [`PathBuf`], not a
    /// borrowed `&Path` bound to the caller's `repo_root` lifetime. A
    /// future signature change that returned `&Path` would refuse both
    /// half-primitives' forwards (each returns an owned [`PathBuf`]
    /// its callers bind into a local `let`).
    #[test]
    fn test_platform_component_dir_returns_owned_pathbuf() {
        let owned: PathBuf = platform_component_dir(Path::new("/x"), PlatformComponent::Hanabi);
        assert_eq!(owned, PathBuf::from("/x/pkgs/platform/hanabi"));
    }

    /// Relative-root pin: a caller-provided relative `repo_root`
    /// composes a relative platform-component path — the accessor
    /// does NOT silently absolutize. Matches both half-primitives'
    /// pre-lift discipline (neither spelled a `.canonicalize()` step).
    #[test]
    fn test_platform_component_dir_preserves_relative_root() {
        assert_eq!(
            platform_component_dir(Path::new("workspace"), PlatformComponent::Hanabi),
            PathBuf::from("workspace/pkgs/platform/hanabi"),
        );
        assert_eq!(
            platform_component_dir(Path::new("."), PlatformComponent::Bootstrap),
            PathBuf::from("./pkgs/platform/bootstrap"),
        );
    }

    /// Cross-component distinctness pin: the two variants MUST resolve
    /// to distinct paths under the same `repo_root`. A regression that
    /// gave both variants the same `segment()` (or dropped the enum
    /// entirely) would silently route the Bootstrap build's cargo
    /// commands into the Hanabi tree; this pin flips first.
    #[test]
    fn test_platform_components_are_distinct_on_same_root() {
        let repo_root = Path::new("/x");
        assert_ne!(
            platform_component_dir(repo_root, PlatformComponent::Hanabi),
            platform_component_dir(repo_root, PlatformComponent::Bootstrap),
            "the two platform components must resolve to distinct paths",
        );
    }

    /// Segment pin: [`PlatformComponent::segment`] returns exactly the
    /// literal component name each half-primitive's doc-comments
    /// contract for. A silent variant reordering that swapped the
    /// return strings would surface here before it silently
    /// mis-routed either half-primitive's callers.
    #[test]
    fn test_platform_component_segment_arms() {
        assert_eq!(PlatformComponent::Hanabi.segment(), "hanabi");
        assert_eq!(PlatformComponent::Bootstrap.segment(), "bootstrap");
    }

    /// Display-name pin: [`PlatformComponent::display_name`] returns the
    /// Title-Case operator-facing name every
    /// [`require_platform_component_dir_exists`] miss-arm bail message
    /// interpolates as `"{display_name} directory not found: {path}"`.
    ///
    /// The two axes ([`PlatformComponent::segment`] and
    /// [`PlatformComponent::display_name`]) are DISTINCT projections of
    /// the same enum — a regression that fused them (say, by projecting
    /// `.display_name()` through `.to_lowercase()` and dropping the
    /// segment arm) would silently swap the operator-facing wording to
    /// `"hanabi directory not found: ..."` (lower-case) or the disk
    /// segment to `"Hanabi/"` (Title-Case). This pin flips first.
    #[test]
    fn test_platform_component_display_name_arms() {
        assert_eq!(PlatformComponent::Hanabi.display_name(), "Hanabi");
        assert_eq!(PlatformComponent::Bootstrap.display_name(), "Bootstrap");
        assert_ne!(
            PlatformComponent::Hanabi.display_name(),
            PlatformComponent::Hanabi.segment(),
            "display_name and segment must project distinct byte-strings — \
             a regression that fused them would silently lower-case the \
             operator-facing bail message or Title-Case the disk segment",
        );
    }

    /// Byte-oracle (Hanabi miss arm): the pre-lift
    /// `commands/web_service.rs` bail wording — the exact two-line
    /// envelope with the `Hanabi directory not found: <path>` prefix,
    /// the `\n  Expected at: pkgs/platform/hanabi/` hint (two-space
    /// indent, trailing `/`), and no `context`-added suffix — MUST
    /// survive the migration to [`require_platform_component_dir_exists`]
    /// byte-for-byte. A future refactor that (a) dropped the two-space
    /// indent, (b) respelled `"Expected at:"` to `"expected:"` /
    /// `"try:"`, (c) dropped the trailing `/` on the hint path, or
    /// (d) swapped the display projection from `<path>.display()` to
    /// `<path>.to_string_lossy()` would flip this assertion before it
    /// silently rewrote the operator-facing error surface.
    #[test]
    fn test_require_platform_component_dir_exists_hanabi_bail_shape() {
        let missing = Path::new("/nonexistent/pkgs/platform/hanabi");
        let err = require_platform_component_dir_exists(missing, PlatformComponent::Hanabi)
            .expect_err("missing directory must produce Err");
        let msg = format!("{err}");
        assert_eq!(
            msg,
            "Hanabi directory not found: /nonexistent/pkgs/platform/hanabi\n  \
             Expected at: pkgs/platform/hanabi/",
            "require_platform_component_dir_exists must bail with the \
             EXACT pre-lift two-line envelope for the Hanabi variant — \
             any drift silently rewrites the operator-facing surface \
             (got: {msg:?})",
        );
    }

    /// Byte-oracle (Bootstrap miss arm): the same two-line envelope
    /// shape MUST project correctly for the sibling
    /// [`PlatformComponent::Bootstrap`] variant, using its own
    /// [`Self::display_name`] and [`Self::segment`] arms. Prevents a
    /// silent variant-crossed drift where a hypothetical future
    /// Bootstrap consumer would surface a `"Hanabi directory not
    /// found: <bootstrap-path>"` mixed-variant wording.
    #[test]
    fn test_require_platform_component_dir_exists_bootstrap_bail_shape() {
        let missing = Path::new("/nonexistent/pkgs/platform/bootstrap");
        let err = require_platform_component_dir_exists(missing, PlatformComponent::Bootstrap)
            .expect_err("missing directory must produce Err");
        let msg = format!("{err}");
        assert_eq!(
            msg,
            "Bootstrap directory not found: /nonexistent/pkgs/platform/bootstrap\n  \
             Expected at: pkgs/platform/bootstrap/",
            "require_platform_component_dir_exists must project the \
             Bootstrap variant's display_name and segment into the same \
             two-line envelope shape — got: {msg:?}",
        );
    }

    /// Hit-arm pin: an existing directory returns `Ok(())` without
    /// touching the directory's contents. Uses [`env!`] `CARGO_MANIFEST_DIR`
    /// (the `cli/` crate root) as a directory guaranteed to exist under
    /// the test-run's working tree.
    #[test]
    fn test_require_platform_component_dir_exists_ok_when_dir_exists() {
        let existing = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(
            require_platform_component_dir_exists(existing, PlatformComponent::Hanabi).is_ok(),
            "an existing directory must return Ok(()) — the primitive \
             gates only on `.exists()`, never on segment/name match",
        );
    }

    /// Positive-delegation shield: `commands/web_service.rs` MUST
    /// forward through [`require_platform_component_dir_exists`] at
    /// least twice — the two pre-lift `if !hanabi_dir.exists() {
    /// bail!(...); }` stanzas migrated. A dropped call would leave the
    /// negative-shield scan below trivially satisfied by absence.
    #[test]
    fn every_prelift_module_forwards_through_require_platform_component_dir_exists() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 2)];
        let needle = "require_platform_component_dir_exists(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| line.contains(needle))
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `if !<dir>.exists() {{ bail!(...); }}` site(s) through \
                 `{needle}`; found {forwards}. A reverted call would \
                 restore the two-body drift the primitive closed.",
            );
        }
    }

    /// Negative caller shield: no source line under `cli/src/commands/`
    /// may spell the pre-lift raw `<Component> directory not found`
    /// bail wording inline any more. Both pre-lift Hanabi sites in
    /// `commands/web_service.rs` migrated; the two-line envelope belongs
    /// at ONE code point (this module's [`require_platform_component_dir_exists`]).
    /// A future consumer that wants the same wording reaches for the
    /// primitive on first grep, not by copy-pasting the raw
    /// `bail!("Hanabi directory not found: {}\n  Expected at: ...")`
    /// literal.
    #[test]
    fn no_command_module_still_spells_raw_platform_component_not_found_bail() {
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
                if line.contains("\"Hanabi directory not found:")
                    || line.contains("\"Bootstrap directory not found:")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `<Component> directory not found:` bail wording \
             survives under `commands/` — route each through \
             `crate::platform_component::require_platform_component_dir_exists\
             (&<dir>, PlatformComponent::<Variant>)?`:\n{:#?}",
            offenders,
        );
    }

    /// Positive-delegation shield: BOTH component-named half-primitives
    /// MUST forward through [`platform_component_dir`] in their post-
    /// lift source bodies. A migration that (a) reverted a half-
    /// primitive to an inline `.join(...)` chain, or (b) dropped the
    /// forward outright would flip this pin even if the byte-oracles
    /// still pass (because the byte-oracles compare shapes, they do
    /// not enforce the delegation trail).
    #[test]
    fn every_half_primitive_forwards_through_platform_component_dir() {
        use std::path::PathBuf as StdPathBuf;
        let src_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&str, usize)] = &[("hanabi_dir.rs", 1), ("bootstrap_dir.rs", 1)];
        let needle = "platform_component_dir(";
        for (basename, min_count) in expectations {
            let path = src_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            // Ignore doc-comment mentions of the needle — only lines
            // that are not comment-prefixed contribute.
            let forwards = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| line.contains(needle))
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} `{needle}` \
                 call(s); found {forwards}. A reverted half-primitive \
                 would restore the two-body drift the shared accessor \
                 closed.",
            );
        }
    }

    /// Negative caller shield: no source line under `cli/src/commands/`
    /// may spell the pre-lift raw `.join("pkgs/platform")` composition
    /// (as a string literal) inline any more. All four pre-lift
    /// consumer sites (two in `commands/web_service.rs`, two in
    /// `commands/bootstrap.rs`) migrated to the component-named
    /// half-primitives; the shared `pkgs/platform` prefix belongs at
    /// exactly one code point, this module. Doc-comment mentions
    /// (leading `//`) are exempt.
    #[test]
    fn no_command_module_still_spells_raw_pkgs_platform_prefix() {
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
                if line.contains("\"pkgs/platform/hanabi\"")
                    || line.contains("\"pkgs/platform/bootstrap\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `pkgs/platform/<component>` literal(s) survive under \
             `commands/` — route each through \
             `crate::platform_component::platform_component_dir(<repo>, \
             PlatformComponent::<Variant>)` or its component-named \
             alias:\n{:#?}",
            offenders,
        );
    }
}

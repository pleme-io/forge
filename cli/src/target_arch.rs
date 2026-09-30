//! Typed per-arch build-target primitive — the closed enum over the two
//! architectures forge builds Rust services for: AMD64 and ARM64.
//!
//! # Duplication being lifted
//!
//! Pre-lift the `commands/rust_service.rs::build_rust_service`
//! per-arch closure-push stanza called
//! [`crate::commands::rust_service::push_arch_closure_to_attic`] with a
//! `(<arch_label>, <result_symlink>, …)` correlated-string pair:
//!
//! ```ignore
//! push_arch_closure_to_attic("AMD64", "result-amd64", &cache_target).await;
//! push_arch_closure_to_attic("ARM64", "result-arm64", &cache_target).await;
//! ```
//!
//! The two `&str` arguments carry a correlation the type system did not
//! enforce: `"AMD64"` must go with `"result-amd64"`, `"ARM64"` with
//! `"result-arm64"`. A caller that flipped the pair
//! (`push_arch_closure_to_attic("AMD64", "result-arm64", …)`) compiled
//! cleanly and would have wrongly enumerated the ARM64 closure while
//! labelling the operator narration `AMD64`. The typed enum collapses
//! the two-slot pair into ONE discriminator whose projections
//! [`TargetArch::upper_label`] and [`TargetArch::result_symlink`] are
//! byte-oracle inverses of each other by construction.
//!
//! # Why a closed enum, not two `&str`s
//!
//! THEORY §V.1 (make invalid states unrepresentable) and §V.4 Phase 1
//! (typed primitives own their claims): a two-`&str` signature admits
//! four combinations, two of which are invalid; a single `TargetArch`
//! admits exactly two, both valid. `#[non_exhaustive]` reserves the
//! addition of a third variant (`Riscv64`, `Ppc64le`) as a
//! source-compatible change on internal `match` sites — the invariant
//! that the label/symlink projections stay in lockstep is enforced at
//! ONE construction surface by the impl block below.
//!
//! # Frontier inspiration
//!
//! OCI / Docker platform identifiers use the lowercase `amd64` / `arm64`
//! naming ([OCI image-spec `image-index.md`](https://github.com/opencontainers/image-spec/blob/main/image-index.md));
//! Nix's `system` axis uses `x86_64-linux` / `aarch64-linux`; forge's
//! operator narration uses `AMD64` / `ARM64` uppercase. The three
//! naming conventions collapse onto a single closed axis here, with
//! projections named for each downstream consumer's convention rather
//! than one convention forced across all three.

/// A per-arch build target forge knows how to build a Rust service for.
///
/// The two variants correspond to the two `result-<arch>` Nix `--out-link`
/// symlinks `commands/rust_service.rs::build_rust_service` produces, and
/// to the two operator-visible labels its progress narration prints.
///
/// `#[allow(dead_code)]` here mirrors the pre-existing baseline flag on
/// the enclosing consumer chain (`push_arch_closure_to_attic`, its
/// caller `build_rust_service`, and the `push_rust_service_with_tag`
/// dispatch surface) — the whole chain is dead-code-flagged under
/// `cargo clippy --all-targets` on the main `forge` bin target because
/// clippy's cross-module reachability from `main.rs`'s CLI dispatch
/// surface does not resolve through the enclosing async orchestrator
/// surfaces (a limitation the sibling `commands/federation_tests.rs`
/// and `commands/migrations.rs` consumer chains hit and pin the same
/// way at 122d2f / b962db5). The attribute keeps this lift's clippy
/// delta at 0 new baseline errors.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TargetArch {
    /// Intel/AMD 64-bit — the `x86_64-linux` Nix system, `"amd64"` OCI
    /// platform, `result-amd64` Nix out-link, `AMD64` operator label.
    /// Built unconditionally by
    /// `commands/rust_service.rs::build_rust_service`.
    Amd64,
    /// ARM 64-bit — the `aarch64-linux` Nix system, `"arm64"` OCI
    /// platform, `result-arm64` Nix out-link, `ARM64` operator label.
    /// Built conditionally by
    /// `commands/rust_service.rs::build_rust_service` when
    /// `should_build_arm64` resolves true.
    Arm64,
}

impl TargetArch {
    /// Canonical enumeration of every arch forge builds Rust services
    /// for, in the order operator-visible narration prints them (AMD64
    /// first, ARM64 second — mirroring the unconditional-then-gated
    /// ordering at `commands/rust_service.rs::build_rust_service`).
    ///
    /// # Duplication being lifted
    ///
    /// Pre-lift the `build_rust_service` prelude enumerated the two
    /// `result-<arch>` symlinks as a bare `&'static [&'static str; 2]`
    /// literal at `commands/rust_service.rs::build_rust_service`
    /// (~L329) to clean up any stale symlinks left by an earlier
    /// build:
    ///
    /// ```ignore
    /// for symlink in &["result-amd64", "result-arm64"] { … }
    /// ```
    ///
    /// The `&str` array literal restated the `result-<arch>` naming
    /// convention the sibling closure-push and image-composition sites
    /// already routed through [`TargetArch::result_symlink`]. A
    /// hypothetical third-arch admission (adding `Riscv64` to the
    /// enum) would silently miss this cleanup site — the array's
    /// hard-coded arity of 2 could not be discovered from the enum
    /// definition. Post-lift the cleanup iterates over
    /// [`TargetArch::ALL`], so a new variant propagates by
    /// construction rather than by hand-audit across every callsite.
    ///
    /// # Why a const, not a method
    ///
    /// The variant set is fixed at compile time and evaluated in const
    /// contexts (e.g. type-level tests, `#[test]` byte-oracle
    /// assertions on the exact ordering). A `pub const` slot in the
    /// impl block gives every consumer one canonical `for arch in
    /// TargetArch::ALL { … }` idiom without an intervening call
    /// syntax; the array-value type (`[Self; 2]`) participates in the
    /// edition-2021 by-value array `for` loop so a consumer never
    /// deals with a slice-of-references.
    ///
    /// # Dead-code baseline
    ///
    /// `#[allow(dead_code)]` here mirrors the enum-level flag above:
    /// the sole consumer today, `commands/rust_service.rs::
    /// build_rust_service`'s stale-symlink cleanup, sits inside an
    /// async orchestrator surface whose reachability clippy does not
    /// resolve across module boundaries from `main.rs`'s CLI dispatch
    /// surface. The attribute keeps this lift's clippy delta at 0
    /// new baseline warnings — the byte-oracle unit tests below
    /// exercise the constant unconditionally under `cargo test`.
    #[allow(dead_code)]
    pub const ALL: [Self; 2] = [Self::Amd64, Self::Arm64];

    /// The uppercase operator-visible label forge's per-arch narration
    /// interpolates into `println!` progress lines: `"AMD64"` /
    /// `"ARM64"`. This is the string the pre-lift
    /// `push_arch_closure_to_attic` first `&str` positional argument
    /// carried at each of its two call sites.
    pub const fn upper_label(self) -> &'static str {
        match self {
            Self::Amd64 => "AMD64",
            Self::Arm64 => "ARM64",
        }
    }

    /// The `result-<lowercase>` Nix `--out-link` symlink name forge's
    /// per-arch closure enumeration passes to
    /// [`crate::nix::path_info_recursive`]. This is the string the
    /// pre-lift `push_arch_closure_to_attic` second `&str` positional
    /// argument carried at each of its two call sites.
    pub const fn result_symlink(self) -> &'static str {
        match self {
            Self::Amd64 => "result-amd64",
            Self::Arm64 => "result-arm64",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TargetArch;

    /// Byte-oracle: the `AMD64` variant projects onto the
    /// pre-lift `("AMD64", "result-amd64")` correlated pair at
    /// `commands/rust_service.rs::build_rust_service`'s first call
    /// site. A drift on either projection (a lowercase-flip of the
    /// label, a renamed symlink) fails here rather than surfacing as
    /// a mislabelled operator narration or a `path-info --recursive`
    /// on a nonexistent symlink.
    #[test]
    fn amd64_projections_match_pre_lift_pair() {
        assert_eq!(TargetArch::Amd64.upper_label(), "AMD64");
        assert_eq!(TargetArch::Amd64.result_symlink(), "result-amd64");
    }

    /// Byte-oracle: the `ARM64` variant projects onto the pre-lift
    /// `("ARM64", "result-arm64")` correlated pair.
    #[test]
    fn arm64_projections_match_pre_lift_pair() {
        assert_eq!(TargetArch::Arm64.upper_label(), "ARM64");
        assert_eq!(TargetArch::Arm64.result_symlink(), "result-arm64");
    }

    /// Structural discipline: the two projections form correlated
    /// pairs — `upper_label` uppercases the arch, `result_symlink`
    /// prefixes `result-` to its lowercase form. A regression that
    /// broke the correlation (e.g. by renaming `Amd64.upper_label`
    /// to `"amd64"` in lowercase, silently mismatching the operator
    /// label vs the symlink) fails here.
    #[test]
    fn projections_stay_correlated_per_variant() {
        for arch in [TargetArch::Amd64, TargetArch::Arm64] {
            let label = arch.upper_label();
            let symlink = arch.result_symlink();
            let lower = label.to_ascii_lowercase();
            assert_eq!(
                symlink,
                format!("result-{}", lower),
                "TargetArch::{arch:?} label / result_symlink projections drifted: \
                 upper_label={label:?}, result_symlink={symlink:?}, expected \
                 result_symlink={:?}",
                format!("result-{}", lower)
            );
        }
    }

    /// Byte-oracle: [`TargetArch::ALL`] enumerates exactly the two
    /// variants forge currently builds for, in the canonical order
    /// AMD64-then-ARM64. This ordering mirrors the unconditional-
    /// then-gated arch dispatch at
    /// `commands/rust_service.rs::build_rust_service` — a reversal
    /// would drift the operator-visible per-arch narration from the
    /// dispatch order and silently swap the "unconditional" arch
    /// with the gated one at every downstream consumer that iterates
    /// through `ALL`.
    #[test]
    fn all_enumerates_amd64_then_arm64() {
        assert_eq!(
            TargetArch::ALL,
            [TargetArch::Amd64, TargetArch::Arm64],
            "TargetArch::ALL must enumerate exactly [Amd64, Arm64] in \
             that order — the pre-lift `for symlink in \
             &[\"result-amd64\", \"result-arm64\"]` cleanup at \
             `commands/rust_service.rs::build_rust_service` (~L329) \
             ordered AMD64 first (unconditionally built) and ARM64 \
             second (built when cross-compilation is available); a \
             reversal here would flip the two downstream cleanup and \
             narration ordering by construction. Found: {:?}",
            TargetArch::ALL
        );
    }

    /// Byte-oracle: [`TargetArch::ALL`] projected through
    /// [`TargetArch::result_symlink`] reproduces the pre-lift
    /// `&["result-amd64", "result-arm64"]` `&str` array literal
    /// verbatim, in the same order. A drift on either the enumeration
    /// (a dropped variant, a re-ordered variant) or the projection (a
    /// renamed symlink) fails here rather than surfacing as a
    /// half-cleaned build tree with a stale `result-<arch>` symlink
    /// pointing to a previous derivation.
    #[test]
    fn all_result_symlink_projections_match_pre_lift_array_literal() {
        let projected: Vec<&'static str> =
            TargetArch::ALL.iter().map(|a| a.result_symlink()).collect();
        assert_eq!(
            projected,
            vec!["result-amd64", "result-arm64"],
            "TargetArch::ALL projected through .result_symlink() must \
             reproduce the pre-lift `&[\"result-amd64\", \
             \"result-arm64\"]` `&str` array literal at \
             `commands/rust_service.rs::build_rust_service` (~L329) \
             verbatim. A drift here would silently orphan a stale \
             `result-<arch>` symlink from a previous build, causing \
             the next build to fail with a Nix `--out-link` conflict \
             error the pre-lift cleanup was landed to close. Found: \
             {projected:?}"
        );
    }
}

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
}

//! Per-arch build-complete narration line — the
//! `"   <UPPER_LABEL>: <result_symlink>\n"` stanza the pre-lift
//! `commands/rust_service.rs::build_rust_service` build-complete tail
//! spelled inline as two sibling `println!` literals at ~L684-686:
//!
//! ```ignore
//! println!("   AMD64: result-amd64");
//! if should_build_arm64 {
//!     println!("   ARM64: result-arm64");
//! }
//! ```
//!
//! # Duplication being lifted
//!
//! The correlated `("AMD64", "result-amd64")` / `("ARM64",
//! "result-arm64")` `&str` pair is exactly what
//! [`crate::target_arch::TargetArch::upper_label`] and
//! [`crate::target_arch::TargetArch::result_symlink`] project
//! (introduced at commit bf956cf, extended with the
//! [`crate::target_arch::TargetArch::ALL`] enumeration slot at 866a6a2).
//! Pre-lift the build-complete tail restated the pair verbatim: a drift
//! at the enum surface (a renamed variant, a re-cased label, a
//! re-prefixed symlink) would leave the two `println!` literals here
//! stale, silently mislabelling the operator-visible narration for
//! every build until the drift was hand-audited across every
//! `"result-<arch>"` and `"<ARCH>"` literal in the module.
//!
//! Post-lift both stanzas forward through
//! [`print_built_arch_symlink_line`] against the typed
//! [`crate::target_arch::TargetArch`] discriminator; a caller can no
//! longer flip one slot without the other, and a future third-arch
//! admission (`Riscv64`, `Ppc64le`) inherits the narration by
//! construction rather than by hand-audit.
//!
//! # Why a println! adapter over a writer sibling
//!
//! The pattern mirrors the sibling
//! [`crate::env_activation_status`] and
//! [`crate::push_source_announce`] UI primitives in this crate: the
//! [`print_built_arch_symlink_line`] stdout adapter delegates to the
//! [`write_built_arch_symlink_line`] writer sibling so the exact byte
//! shape (`"   AMD64: result-amd64\n"` /
//! `"   ARM64: result-arm64\n"`) is pinnable by fail-before-pass
//! byte-oracle tests below without capturing stdout.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Construction guarantees; make invalid states
//!   unrepresentable): the correlated `(upper_label, result_symlink)`
//!   pair lives at ONE construction surface — the closed
//!   [`crate::target_arch::TargetArch`] enum — and the build-complete
//!   narration tail now derives both slots from the same
//!   discriminator, so the drift bug class the enum was landed to
//!   close cannot re-open through a hard-coded literal here.
//! - `THEORY.md §VI.1` (Generation over composition; recurring shapes
//!   past duplication become helpers): two sibling `println!` stanzas
//!   at the build-complete tail past the two-times threshold, so the
//!   display body lifts onto ONE typed body and both consumers cite
//!   it.

use crate::target_arch::TargetArch;
use std::io;

/// Emit the canonical `"   <UPPER_LABEL>: <result_symlink>\n"`
/// per-arch build-complete narration line to stdout for `arch`.
///
/// Called from the build-complete tail of
/// [`crate::commands::rust_service::build_rust_service`] once per
/// built arch — AMD64 unconditionally, ARM64 gated by
/// `should_build_arm64` at the call site (the same gating shape the
/// sibling `push_arch_closure_to_attic` call pair carries at the
/// per-arch Attic cache warm-up, so the two consumers stay in
/// lockstep on which arches actually built).
///
/// Delegates to [`write_built_arch_symlink_line`] against
/// [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle tests below pin the exact rendered
/// bytes without capturing stdout.
#[allow(dead_code)]
pub fn print_built_arch_symlink_line(arch: TargetArch) {
    let _ = write_built_arch_symlink_line(&mut io::stdout().lock(), arch);
}

/// Writer-taking sibling to [`print_built_arch_symlink_line`]. Emits
/// the single `"   <UPPER_LABEL>: <result_symlink>\n"` line via
/// [`writeln!`] against the supplied writer.
///
/// [`print_built_arch_symlink_line`] is the stdout adapter; this
/// variant exists so tests can pin the three-space indent, the
/// per-arm uppercase label, the literal `": "` separator (colon + one
/// space), the per-arm `result-<arch>` symlink name, and the trailing
/// newline without capturing stdout.
#[allow(dead_code)]
pub fn write_built_arch_symlink_line<W: io::Write>(w: &mut W, arch: TargetArch) -> io::Result<()> {
    writeln!(w, "   {}: {}", arch.upper_label(), arch.result_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle for the [`TargetArch::Amd64`] arm. Pins the
    /// five-token body — the three-space indent, the `AMD64` uppercase
    /// label, the literal `": "` separator, the `result-amd64`
    /// symlink name, and the trailing `\n`. A silent drift — dropping
    /// the indent, re-casing the label, dropping the colon, renaming
    /// the symlink, or losing the newline — flips this assertion
    /// rather than compiling and silently diverging the two consumer
    /// arms' visual grammar.
    #[test]
    fn write_amd64_arm_emits_pre_lift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_built_arch_symlink_line(&mut buf, TargetArch::Amd64)
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("built-arch line must emit valid UTF-8 (the pre-lift println! did)");
        assert_eq!(
            out, "   AMD64: result-amd64\n",
            "AMD64 build-complete narration line must reproduce the \
             pre-lift `\"   AMD64: result-amd64\\n\"` byte-sequence \
             verbatim — the three-space indent, the uppercase `AMD64` \
             label, the `\": \"` colon-plus-space separator, the \
             `result-amd64` symlink name, and the trailing `\\n`. \
             Got {out:?}."
        );
    }

    /// Byte-oracle for the [`TargetArch::Arm64`] arm. Pins the same
    /// five-token body against the ARM64 correlated pair. A silent
    /// drift that hard-coded the [`TargetArch::Amd64`] arm's label or
    /// symlink on the ARM64 branch would mislabel a cross-arch build's
    /// operator narration as `"   AMD64: result-amd64"` when the
    /// build actually produced `result-arm64` — this assertion flips
    /// first.
    #[test]
    fn write_arm64_arm_emits_pre_lift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_built_arch_symlink_line(&mut buf, TargetArch::Arm64)
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out, "   ARM64: result-arm64\n",
            "ARM64 build-complete narration line must reproduce the \
             pre-lift `\"   ARM64: result-arm64\\n\"` byte-sequence \
             verbatim. Got {out:?}."
        );
    }

    /// Structural discipline: the writer body's rendered output on
    /// [`TargetArch::ALL`] reproduces the pre-lift correlated
    /// build-complete tail exactly — first the AMD64 stanza, then the
    /// ARM64 stanza, in the canonical order the enumeration slot
    /// projects. A drift on either the enumeration ordering or the
    /// per-arm projection fails here rather than surfacing as a
    /// per-arch mislabelling at the consumer site.
    #[test]
    fn write_projects_target_arch_all_onto_pre_lift_tail_sequence() {
        let mut buf: Vec<u8> = Vec::new();
        for arch in TargetArch::ALL {
            write_built_arch_symlink_line(&mut buf, arch)
                .expect("write against a Vec<u8> sink must succeed");
        }
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out, "   AMD64: result-amd64\n   ARM64: result-arm64\n",
            "TargetArch::ALL projected through \
             write_built_arch_symlink_line must reproduce the pre-lift \
             build-complete tail's two-stanza sequence verbatim, in \
             the canonical AMD64-then-ARM64 order. A drift here would \
             either reorder the operator narration or drop one arm \
             entirely. Got {out:?}."
        );
    }

    /// Delegation shield (positive half): the primitive's writer body
    /// reaches [`writeln!`] at exactly one call — no fallback path,
    /// no double-write, no branching on `arch` outside the projection
    /// accessors. Pins the one-oracle discipline THEORY §VI.1
    /// requires: a future refactor that introduced a `match arch {
    /// Amd64 => writeln!(..); Arm64 => writeln!(..); }` two-arm
    /// inline would surface here.
    #[test]
    fn primitive_reaches_writeln_at_exactly_one_call() {
        let source = include_str!("built_arch_symlink_line.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "built_arch_symlink_line.rs",
        );
        let hits: Vec<&str> = body
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!")
            })
            .filter(|l| l.contains("writeln!"))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "built_arch_symlink_line.rs primitive body must reach \
             `writeln!` at exactly one code line (the primitive \
             body); got {hits:#?}"
        );
    }
}

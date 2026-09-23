//! Announce-run fusion primitive for the four
//! `pub async fn rust_<verb>(service: String) -> Result<()>` command
//! bodies at [`super::developer_tools`] whose bodies each reduce to the
//! same two-step envelope:
//!
//! ```ignore
//! crate::commands::developer_tool_phase_open::print_developer_tool_phase_open(
//!     crate::commands::developer_tool_phase_open::DeveloperToolPhase::<Variant>,
//!     &service,
//! );
//! crate::retry::run_bin_args_inherited_status(
//!     &cargo_bin(),
//!     &[<argv…>],
//!     "<op_label>",
//! )
//! .await
//! ```
//!
//! # Pre-lift census — four sibling stanzas
//!
//! 1. [`super::developer_tools::rust_test`] (:174-185) —
//!    [`DeveloperToolPhase::UnitTest`] paired with
//!    `["test", "--lib", "--bins"]` / `"cargo test"`.
//! 2. [`super::developer_tools::rust_lint`] (:188-206) —
//!    [`DeveloperToolPhase::Clippy`] paired with
//!    `["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]`
//!    / `"cargo clippy"`.
//! 3. [`super::developer_tools::rust_fmt`] (:209-215) —
//!    [`DeveloperToolPhase::Format`] paired with `["fmt", "--all"]` /
//!    `"cargo fmt"`.
//! 4. [`super::developer_tools::rust_fmt_check`] (:218-229) —
//!    [`DeveloperToolPhase::FormatCheck`] paired with
//!    `["fmt", "--all", "--", "--check"]` / `"cargo fmt --check"`.
//!
//! Each site opened with the closed [`DeveloperToolPhase`] variant on
//! the announce line, then handed a fixed
//! `(cargo_argv, op_label)` pair to
//! [`crate::retry::run_bin_args_inherited_status`]. The
//! `(phase, argv, op_label)` triple lived at each caller site verbatim,
//! so a change on the visual grammar (announce line palette,
//! trailing ellipsis), on the spawn contract (retry policy, exit-code
//! bail phrasing), or on the argv for a given phase (adding
//! `--all-features` to `cargo test`, dropping `--` from `cargo fmt`) had
//! to be applied at four sites in lockstep or the developer-tool
//! grammar drifts against itself. Post-lift the triple lives inside the
//! closed [`DeveloperToolCargoPhase`] enum and the announce-run
//! envelope lives at ONE body in
//! [`announce_and_run_developer_tool_cargo_phase`].
//!
//! # Distinct from [`DeveloperToolPhase`]
//!
//! [`DeveloperToolPhase`] carries six variants because two additional
//! developer-tool commands ([`super::developer_tools::rust_extract_schema`],
//! [`super::developer_tools::rust_update_cargo_nix`]) also open with a
//! phase-open banner but do MORE than announce-plus-cargo-spawn —
//! [`super::developer_tools::rust_extract_schema`] searches for a
//! per-service extraction binary and only spawns cargo if one exists,
//! and [`super::developer_tools::rust_update_cargo_nix`] chains a
//! `cargo update` + `crate2nix generate` pair with intermediate prose.
//! Neither reduces to the fused two-step envelope this primitive owns,
//! so [`DeveloperToolCargoPhase`] closes on only the four
//! reducible-to-`cargo <argv>` phases and carries a total function
//! [`DeveloperToolCargoPhase::as_developer_tool_phase`] into the
//! six-variant parent enum.
//!
//! # Ordering invariant
//!
//! The announce line MUST fire BEFORE the cargo spawn, so the operator
//! sees the intent before the cargo output starts scrolling. The
//! primitive body pins this ordering by construction —
//! [`print_developer_tool_phase_open`] runs synchronously before the
//! `.await` on [`crate::retry::run_bin_args_inherited_status`]. On a
//! spawn failure the announce line is still emitted, matching the four
//! pre-lift sites' behavior verbatim.

use anyhow::Result;

use crate::commands::developer_tool_phase_open::{
    print_developer_tool_phase_open, DeveloperToolPhase,
};

/// The four [`DeveloperToolPhase`] variants whose command bodies at
/// [`super::developer_tools`] reduce to the fused
/// `announce → run_bin_args_inherited_status(cargo, argv, op_label)`
/// envelope.
///
/// Distinct from [`DeveloperToolPhase`] which has six variants —
/// [`DeveloperToolPhase::ExtractSchema`] and
/// [`DeveloperToolPhase::UpdateCargoNix`] do MORE than announce +
/// cargo-spawn, so they cannot pass through
/// [`announce_and_run_developer_tool_cargo_phase`] without losing that
/// behavior. Total function
/// [`DeveloperToolCargoPhase::as_developer_tool_phase`] projects each
/// variant onto its parent [`DeveloperToolPhase`] so the announce line
/// still routes through the canonical print primitive that owns the
/// visual grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperToolCargoPhase {
    /// [`super::developer_tools::rust_test`] — `cargo test --lib --bins`.
    UnitTest,
    /// [`super::developer_tools::rust_lint`] —
    /// `cargo clippy --all-targets --all-features -- -D warnings`.
    Clippy,
    /// [`super::developer_tools::rust_fmt`] — `cargo fmt --all`.
    Format,
    /// [`super::developer_tools::rust_fmt_check`] —
    /// `cargo fmt --all -- --check`.
    FormatCheck,
}

impl DeveloperToolCargoPhase {
    /// Project the [`DeveloperToolCargoPhase`] onto its parent
    /// [`DeveloperToolPhase`] so the announce line goes through the
    /// canonical [`print_developer_tool_phase_open`] primitive that
    /// owns the six-variant visual grammar.
    pub const fn as_developer_tool_phase(self) -> DeveloperToolPhase {
        match self {
            Self::UnitTest => DeveloperToolPhase::UnitTest,
            Self::Clippy => DeveloperToolPhase::Clippy,
            Self::Format => DeveloperToolPhase::Format,
            Self::FormatCheck => DeveloperToolPhase::FormatCheck,
        }
    }

    /// The canonical cargo argv for each variant. Each slice is the
    /// exact pre-lift argv the four caller sites spelled inline; a
    /// future change (adding `--all-features` to `cargo test`, swapping
    /// the clippy lint set, dropping `--` from `cargo fmt`) lands at
    /// ONE arm rather than at the caller.
    pub const fn cargo_argv(self) -> &'static [&'static str] {
        match self {
            Self::UnitTest => &["test", "--lib", "--bins"],
            Self::Clippy => &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            Self::Format => &["fmt", "--all"],
            Self::FormatCheck => &["fmt", "--all", "--", "--check"],
        }
    }

    /// The operator-facing `op_label` handed to
    /// [`crate::retry::run_bin_args_inherited_status`] on the spawn
    /// (routed through [`crate::retry::run_inherited_status`], which
    /// stamps the label on the exit-code `bail!` narrative on failure).
    /// Pinned per-variant so a stylistic pass on any one label cannot
    /// drift a sibling's spelling.
    pub const fn cargo_op_label(self) -> &'static str {
        match self {
            Self::UnitTest => "cargo test",
            Self::Clippy => "cargo clippy",
            Self::Format => "cargo fmt",
            Self::FormatCheck => "cargo fmt --check",
        }
    }
}

/// Fuse the [`print_developer_tool_phase_open`] announce line and the
/// [`crate::retry::run_bin_args_inherited_status`] spawn into ONE
/// typed body.
///
/// `phase` selects one of the four cargo-reducible variants of
/// [`DeveloperToolPhase`]; `service` is the display body threaded into
/// the `for <service.cyan()>...` announce grammar; `cargo_path` is the
/// resolved `cargo` binary path (typically read through the caller's
/// module-local `cargo_bin()` sigil so the `CARGO`-env-var override
/// contract is honored at ONE point across the caller module).
///
/// # Ordering invariant
///
/// The announce line fires BEFORE the cargo spawn. On a spawn failure
/// the announce line is still emitted — matching the four pre-lift
/// sites' behavior verbatim.
///
/// # Errors
///
/// Returns an error if the cargo spawn exits non-zero (surfaced through
/// [`crate::retry::run_inherited_status`] with the per-variant
/// [`DeveloperToolCargoPhase::cargo_op_label`] stamped on the exit-code
/// `bail!` narrative) or if the spawn itself fails.
pub async fn announce_and_run_developer_tool_cargo_phase(
    phase: DeveloperToolCargoPhase,
    service: &str,
    cargo_path: &str,
) -> Result<()> {
    print_developer_tool_phase_open(phase.as_developer_tool_phase(), service);
    crate::retry::run_bin_args_inherited_status(
        cargo_path,
        phase.cargo_argv(),
        phase.cargo_op_label(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Projection pin: each of the four cargo-reducible variants maps
    /// to the corresponding parent [`DeveloperToolPhase`] variant so
    /// the announce line routes through the same six-variant visual
    /// grammar the pre-lift sites carried.
    #[test]
    fn as_developer_tool_phase_projects_each_variant_onto_parent() {
        assert_eq!(
            DeveloperToolCargoPhase::UnitTest.as_developer_tool_phase(),
            DeveloperToolPhase::UnitTest
        );
        assert_eq!(
            DeveloperToolCargoPhase::Clippy.as_developer_tool_phase(),
            DeveloperToolPhase::Clippy
        );
        assert_eq!(
            DeveloperToolCargoPhase::Format.as_developer_tool_phase(),
            DeveloperToolPhase::Format
        );
        assert_eq!(
            DeveloperToolCargoPhase::FormatCheck.as_developer_tool_phase(),
            DeveloperToolPhase::FormatCheck
        );
    }

    /// Byte-oracle: the [`DeveloperToolCargoPhase::UnitTest`] argv pins
    /// the exact three-element pre-lift slice `["test", "--lib",
    /// "--bins"]`. Every element is a distinct string, and a rewrite
    /// that reordered them, merged them, or added `--all-features`
    /// regresses this assertion.
    #[test]
    fn cargo_argv_unit_test_carries_test_lib_bins() {
        assert_eq!(
            DeveloperToolCargoPhase::UnitTest.cargo_argv(),
            &["test", "--lib", "--bins"]
        );
    }

    /// Byte-oracle: the [`DeveloperToolCargoPhase::Clippy`] argv pins
    /// the exact six-element pre-lift slice — the `--all-targets` and
    /// `--all-features` scope selectors, then the `--` cargo/clippy
    /// separator, then `-D warnings` to deny warnings. Diverges from
    /// the pre-lift `rust_lint` site would regress this test.
    #[test]
    fn cargo_argv_clippy_carries_deny_warnings_lint_shape() {
        assert_eq!(
            DeveloperToolCargoPhase::Clippy.cargo_argv(),
            &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings"
            ]
        );
    }

    /// Byte-oracle: the [`DeveloperToolCargoPhase::Format`] argv pins
    /// the exact two-element pre-lift slice `["fmt", "--all"]`. The
    /// `--all` flag covers every workspace crate; dropping it silently
    /// narrows the scope to the current package.
    #[test]
    fn cargo_argv_format_carries_fmt_all() {
        assert_eq!(
            DeveloperToolCargoPhase::Format.cargo_argv(),
            &["fmt", "--all"]
        );
    }

    /// Byte-oracle: the [`DeveloperToolCargoPhase::FormatCheck`] argv
    /// pins the exact four-element pre-lift slice `["fmt", "--all",
    /// "--", "--check"]`. Diverges from [`DeveloperToolCargoPhase::Format`]
    /// on the trailing `["--", "--check"]` pair only — the axis that
    /// splits "reformat in place" from "verify formatting". A refactor
    /// that collapsed the two arms and passed `--check` as a boolean
    /// parameter loses this pin.
    #[test]
    fn cargo_argv_format_check_carries_fmt_all_dash_dash_check() {
        assert_eq!(
            DeveloperToolCargoPhase::FormatCheck.cargo_argv(),
            &["fmt", "--all", "--", "--check"]
        );
    }

    /// Projection pin: each of the four cargo-reducible variants maps
    /// to its pre-lift `op_label` verbatim. The label is stamped on
    /// [`crate::retry::run_inherited_status`]'s exit-code `bail!`
    /// narrative on failure, so drift in either direction (dropping
    /// the trailing `--check` on [`DeveloperToolCargoPhase::FormatCheck`],
    /// spelling `cargo test --lib --bins` on
    /// [`DeveloperToolCargoPhase::UnitTest`]) rewrites the operator's
    /// error-message needle.
    #[test]
    fn cargo_op_label_pins_pre_lift_narrative_for_each_variant() {
        assert_eq!(
            DeveloperToolCargoPhase::UnitTest.cargo_op_label(),
            "cargo test"
        );
        assert_eq!(
            DeveloperToolCargoPhase::Clippy.cargo_op_label(),
            "cargo clippy"
        );
        assert_eq!(
            DeveloperToolCargoPhase::Format.cargo_op_label(),
            "cargo fmt"
        );
        assert_eq!(
            DeveloperToolCargoPhase::FormatCheck.cargo_op_label(),
            "cargo fmt --check"
        );
    }

    /// Const-fn discipline: each accessor MUST be callable in a
    /// `const` context so a caller can materialize the projections at
    /// compile time (a future consumer that wants to statically pin
    /// the argv slice into another `const` array cannot rely on a
    /// runtime call). Uses associated `const` items rather than
    /// `const fn` locals inside `#[test]` because Rust does not permit
    /// `const fn` items inside a function body prior to stabilization
    /// of const-in-fn.
    #[test]
    fn accessors_callable_in_const_context() {
        const P: DeveloperToolPhase = DeveloperToolCargoPhase::UnitTest.as_developer_tool_phase();
        const A: &[&str] = DeveloperToolCargoPhase::Clippy.cargo_argv();
        const L: &str = DeveloperToolCargoPhase::Format.cargo_op_label();
        assert_eq!(P, DeveloperToolPhase::UnitTest);
        assert_eq!(A[0], "clippy");
        assert_eq!(L, "cargo fmt");
    }

    /// Ordering invariant shield: the primitive body must call
    /// [`print_developer_tool_phase_open`] BEFORE
    /// [`crate::retry::run_bin_args_inherited_status`]. A rewrite that
    /// reordered them (spawn cargo first, then announce) would let the
    /// cargo output start scrolling before the operator sees the
    /// intent. The needle scan is bounded to the module body before the
    /// first `#[cfg(test)]` block so this shield's own diagnostic prose
    /// does not false-match itself.
    #[test]
    fn primitive_body_prints_announce_before_run_bin_args() {
        let source = include_str!("developer_tool_cargo_phase.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "commands/developer_tool_cargo_phase.rs",
        );
        let announce_idx = body
            .find("print_developer_tool_phase_open(")
            .expect("primitive body must invoke `print_developer_tool_phase_open(`");
        let spawn_idx = body.find("run_bin_args_inherited_status(").expect(
            "primitive body must invoke `crate::retry::run_bin_args_inherited_status(` on \
                 the spawn line",
        );
        assert!(
            announce_idx < spawn_idx,
            "primitive body must call `print_developer_tool_phase_open(` BEFORE \
             `run_bin_args_inherited_status(` — the announce line MUST fire before the \
             cargo spawn so the operator sees the intent before cargo output starts \
             scrolling. Found announce at byte {announce_idx}, spawn at byte {spawn_idx}."
        );
    }

    /// Positive-delegation shield: `commands/developer_tools.rs` MUST
    /// carry EXACTLY four calls to
    /// [`announce_and_run_developer_tool_cargo_phase`] — one per
    /// pre-lift cargo-reducible site (`rust_test`, `rust_lint`,
    /// `rust_fmt`, `rust_fmt_check`). A dropped call would leave the
    /// caller open to re-copying the pre-lift stanza; an added call
    /// past four means a new consumer landed without expanding this
    /// shield in the same commit.
    #[test]
    fn developer_tools_module_forwards_through_cargo_phase_primitive_exactly_four_times() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("developer_tools.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = crate::test_support::code_line_hits(
            &source,
            "announce_and_run_developer_tool_cargo_phase(",
        );
        assert_eq!(
            forwards.len(),
            4,
            "developer_tools.rs must forward EXACTLY the four pre-lift \
             cargo-reducible sites (rust_test, rust_lint, rust_fmt, \
             rust_fmt_check) through \
             `crate::commands::developer_tool_cargo_phase::announce_and_run_developer_tool_cargo_phase(`; \
             found {} code-line hit(s): {forwards:#?}. A dropped call would \
             leave the negative shield below satisfied by absence; an added \
             call means a new consumer landed without expanding this shield.",
            forwards.len(),
        );
    }

    /// Caller shield (negative half): no `rust_<verb>` body in
    /// `commands/developer_tools.rs` may still spell the pre-lift
    /// announce-plus-spawn pair inline — every consumer must route
    /// through [`announce_and_run_developer_tool_cargo_phase`] so the
    /// (phase, argv, op_label) triple lives at ONE typed body.
    ///
    /// The needle scan is bounded to the module body before the first
    /// `#[cfg(test)]` block so any shield-diagnostic prose does not
    /// false-match itself.
    #[test]
    fn no_developer_tools_site_still_spells_raw_announce_and_cargo_spawn_pair() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("developer_tools.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let body = crate::test_support::module_body_before_first_cfg_test(
            &source,
            "commands/developer_tools.rs",
        );
        // Any site that pairs `DeveloperToolPhase::<UnitTest|Clippy|Format|FormatCheck>`
        // with an inline `run_bin_args_inherited_status(` spawn to
        // `cargo_bin()` is the pre-lift stanza — every such site must
        // now delegate through the fused primitive above.
        for variant in [
            "DeveloperToolPhase::UnitTest",
            "DeveloperToolPhase::Clippy",
            "DeveloperToolPhase::Format,",
            "DeveloperToolPhase::FormatCheck",
        ] {
            let variant_hits = crate::test_support::code_line_hits(body, variant);
            assert!(
                variant_hits.is_empty(),
                "commands/developer_tools.rs body must NOT spell \
                 `{variant}` at a code line any more — the announce-plus-cargo-spawn \
                 pair now delegates through \
                 `crate::commands::developer_tool_cargo_phase::announce_and_run_developer_tool_cargo_phase(\
                 DeveloperToolCargoPhase::<Variant>, &service, &cargo_bin())`. \
                 Found: {variant_hits:#?}"
            );
        }
    }

    /// Argv-shape shield (scoped to `commands/developer_tools.rs`): the
    /// caller module MUST NOT spell the exact pre-lift
    /// `["test", "--lib", "--bins"]` / `["fmt", "--all"]` argv literals
    /// inline any more. Every cargo-reducible site in the caller module
    /// now routes through [`DeveloperToolCargoPhase::cargo_argv`], so a
    /// future consumer that wants the pre-lift argv reaches for the
    /// closed enum on first grep rather than copy-pasting the literal.
    ///
    /// The shield is scoped to `commands/developer_tools.rs` only. Two
    /// independent lifts elsewhere in `commands/`
    /// (`commands/rust_test_phase.rs::RustTestPhase::Unit`,
    /// `commands/comprehensive_release.rs`, `commands/prerelease.rs`)
    /// each own their own cargo-test argv contract (some carrying
    /// extra flags like `--show-output`) and are not in scope for this
    /// primitive.
    #[test]
    fn developer_tools_body_no_longer_spells_pre_lift_cargo_argv_literals() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("developer_tools.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let body = crate::test_support::module_body_before_first_cfg_test(
            &source,
            "commands/developer_tools.rs",
        );
        for needle in [
            "\"test\", \"--lib\", \"--bins\"",
            "\"fmt\", \"--all\", \"--\", \"--check\"",
            "\"clippy\", \"--all-targets\", \"--all-features\", \"--\", \"-D\", \"warnings\"",
        ] {
            let hits = crate::test_support::code_line_hits(body, needle);
            assert!(
                hits.is_empty(),
                "commands/developer_tools.rs must NOT spell the pre-lift argv \
                 literal `{needle}` at any code line any more — route through \
                 `crate::commands::developer_tool_cargo_phase::DeveloperToolCargoPhase::<Variant>.cargo_argv()` \
                 via `announce_and_run_developer_tool_cargo_phase(...)`. \
                 Found: {hits:#?}",
            );
        }
    }
}

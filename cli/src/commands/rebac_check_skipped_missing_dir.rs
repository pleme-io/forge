//! Typed primitive for the sibling `if !config.quiet { println!("   \
//! (skipped — <dir-label> not configured)"); }` skip-branch stanzas
//! that guard every per-check `let Some(<dir>) = &config.<dir_opt> else
//! { …; return Ok(()); };` early-out across
//! `commands/rebac_validation.rs`.
//!
//! # Compounding
//!
//! Pre-lift 6 sibling call sites in `commands/rebac_validation.rs`
//! each restated the same three-line skip stanza:
//!
//! - `check_rebac_documentation`   / `docs_dir` absent branch (~:181)
//! - `check_permission_engine`     / `backend_dir` absent branch (~:219)
//! - `check_object_type_mapping`   / `(docs_dir, backend_dir)` absent
//!   branch (~:255)
//! - `check_relation_hierarchy`    / `backend_dir` absent branch (~:339)
//! - `check_redis_key_patterns`    / `docs_dir` absent branch (~:430)
//! - `check_graphql_permissions`   / `web_dir` absent branch (~:560)
//!
//! Each restated the required-directory phrase at ONE literal position
//! per site — the operator-facing
//! `"   (skipped — <dir-label> not configured)"` line the check emits
//! just after its numbered heading prints. A single-site typo would
//! silently drift the phrase off the 3-space indent the sibling
//! `crate::ui::print_step_check` / `print_step_uncheck` lines carry,
//! or would rename a directory phrase (`docs_arch dir` ↔ `docs dir`)
//! away from the [`RebacValidationConfig`] field the operator has
//! been trained to grep for when reconciling a `(skipped — …)` line
//! against the config field to populate.
//!
//! Post-lift the reason phrase closes over ONE `match` arm in
//! [`RebacValidationSkippedReason::label`]. Callers pass a variant,
//! not a string; the compiler refuses a reason that is not part of
//! the closed set; the printed line's indent, sigilless `(…)` shape,
//! and `not configured` suffix are byte-identical by construction.
//!
//! Sibling of `commands/chart_release_phase_failure.rs` — same
//! enum-owned per-variant-label + shared printed-line grammar pattern,
//! applied to the config-driven skip side of a validation check
//! rather than the failure-record side of a chart-batch step.
//!
//! A future refinement — a dimmed palette on the `(skipped — …)`
//! line, promotion to [`crate::ui::print_step_uncheck`] for a
//! sigil-bearing sibling, an OTLP `rebac_validation.check_skipped`
//! observability event carrying the check name + reason variant as
//! SEPARATE structured attributes, tightening the parenthesized
//! phrase to a `SKIPPED:` prefix for grep-anchoring — lands at ONE
//! typed body and reaches every consumer by construction.
//!
//! THEORY.md §VI.1 (three-times-is-a-law — "two occurrences is a
//! coincidence; three is a law"; 6 verbatim sibling sites redeemed
//! by extraction), §V.1 (Construction guarantees — an invalid
//! reason phrase is refused at compile time by [`Self::label`]'s
//! exhaustive arms).
//!
//! [`RebacValidationConfig`]: super::rebac_validation::RebacValidationConfig

use std::io;

/// Reason a per-check `let Some(<dir>) = &config.<dir_opt> else { … }`
/// branch fires and the check emits its
/// `"   (skipped — <label> not configured)"` line. Every variant
/// closes over the exact directory phrase the pre-lift site spelled
/// verbatim in its skip `println!`.
///
/// The variant set exhausts the four distinct directory phrases the
/// 6 skip sites in `commands/rebac_validation.rs` collectively
/// carried (`docs_arch dir` ×2, `backend dir` ×2,
/// `docs_arch and/or backend dir` ×1, `web dir` ×1). A future check
/// that skips on a fifth directory-config field (e.g. `contracts_dir`,
/// `iac_dir`) is one new variant plus one arm in [`Self::label`] —
/// the printed-line grammar stays fixed.
// The `Dir` postfix on every variant is intentional: each variant names a
// `RebacValidationConfig` field-suffixed-with-`_dir` whose absence trips the
// skip branch, so the postfix carries semantic parity with the config field
// the operator greps for. Renaming the variants to drop `Dir` would break
// that parity.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RebacValidationSkippedReason {
    /// `config.docs_dir` is `None` — the check requires the
    /// docs-architecture directory. Emitted at
    /// `check_rebac_documentation` and `check_redis_key_patterns`.
    DocsArchDir,
    /// `config.backend_dir` is `None` — the check requires the
    /// backend-service directory. Emitted at
    /// `check_permission_engine` and `check_relation_hierarchy`.
    BackendDir,
    /// EITHER of `config.docs_dir` / `config.backend_dir` is `None` —
    /// the check requires BOTH. Emitted at
    /// `check_object_type_mapping`, whose `let (Some(docs), Some(
    /// backend)) = (…, …) else { … };` conjoined destructure fires
    /// on either half being absent.
    DocsArchAndOrBackendDir,
    /// `config.web_dir` is `None` — the check requires the
    /// web-frontend directory. Emitted at
    /// `check_graphql_permissions`.
    WebDir,
}

impl RebacValidationSkippedReason {
    /// The directory phrase used verbatim between the `(skipped — `
    /// prefix and the ` not configured)` suffix on the skip line.
    /// One source of truth for the phrase — a caller-side typo can
    /// no longer drift `docs_arch dir` to `docs dir` at ONE site
    /// while the other five stay on the operator-trained spelling.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DocsArchDir => "docs_arch dir",
            Self::BackendDir => "backend dir",
            Self::DocsArchAndOrBackendDir => "docs_arch and/or backend dir",
            Self::WebDir => "web dir",
        }
    }
}

/// Emit the standard 3-space-indented
/// `"   (skipped — <reason.label()> not configured)"` line every
/// pre-lift rebac-validation check spelled inline in its
/// `let Some(<dir>) = &config.<dir_opt> else { … }` skip branch.
///
/// `quiet` mirrors `RebacValidationConfig::quiet`; when `true` the
/// line is suppressed, matching the pre-lift `if !config.quiet { … }`
/// gate every site carried. Delegates the line emission to
/// [`write_rebac_check_skipped_missing_dir_line`] against a locked
/// [`std::io::stdout`] handle; the writer split exists so the
/// fail-before-pass byte-oracle tests can pin the exact rendered
/// bytes against a `Vec<u8>` sink without capturing stdout.
pub fn print_rebac_check_skipped_missing_dir(quiet: bool, reason: RebacValidationSkippedReason) {
    if quiet {
        return;
    }
    let _ = write_rebac_check_skipped_missing_dir_line(&mut io::stdout().lock(), reason);
}

/// Writer-taking sibling to
/// [`print_rebac_check_skipped_missing_dir`]. Emits the single
/// `"   (skipped — <label> not configured)"` line via [`writeln!`]
/// against the supplied writer.
///
/// [`print_rebac_check_skipped_missing_dir`] is the stdout adapter;
/// this variant exists so tests can pin the 3-space indent, the
/// parenthesized `(skipped — …)` grammar, the em-dash separator,
/// the reason phrase, the ` not configured)` suffix, and the
/// trailing `\n` by inspecting emitted bytes rather than shelling
/// out and grepping stdout.
pub fn write_rebac_check_skipped_missing_dir_line<W: io::Write>(
    w: &mut W,
    reason: RebacValidationSkippedReason,
) -> io::Result<()> {
    writeln!(w, "   (skipped — {} not configured)", reason.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Label-axis pin: each [`RebacValidationSkippedReason`] variant
    /// returns the verbatim directory phrase the pre-lift 6 skip
    /// sites in `commands/rebac_validation.rs` each spelled inline
    /// as a `println!` string literal. A future refactor that
    /// swapped `docs_arch dir` for `docs dir`, or dropped the
    /// `dir` suffix, regresses one arm here without touching the
    /// others.
    #[test]
    fn reason_label_maps_to_pre_lift_directory_phrase_for_every_variant() {
        assert_eq!(
            RebacValidationSkippedReason::DocsArchDir.label(),
            "docs_arch dir"
        );
        assert_eq!(
            RebacValidationSkippedReason::BackendDir.label(),
            "backend dir"
        );
        assert_eq!(
            RebacValidationSkippedReason::DocsArchAndOrBackendDir.label(),
            "docs_arch and/or backend dir",
        );
        assert_eq!(RebacValidationSkippedReason::WebDir.label(), "web dir");
    }

    /// Pin the [`RebacValidationSkippedReason::DocsArchDir`] byte-form:
    /// one line exactly — three spaces of indent, then
    /// `(skipped — docs_arch dir not configured)`, terminated by
    /// `\n`. A future refactor that dropped the 3-space indent,
    /// swapped the em-dash for `-`, dropped the ` not configured)`
    /// suffix, or dropped the trailing newline regresses this.
    #[test]
    fn write_docs_arch_dir_line_pins_bytes() {
        let mut buf = Vec::new();
        write_rebac_check_skipped_missing_dir_line(
            &mut buf,
            RebacValidationSkippedReason::DocsArchDir,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   (skipped — docs_arch dir not configured)\n",
        );
    }

    /// Pin the [`RebacValidationSkippedReason::BackendDir`] byte-form
    /// under the same one-line grammar, differing only in the
    /// directory phrase — the invariant the enum owns.
    #[test]
    fn write_backend_dir_line_pins_bytes() {
        let mut buf = Vec::new();
        write_rebac_check_skipped_missing_dir_line(
            &mut buf,
            RebacValidationSkippedReason::BackendDir,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   (skipped — backend dir not configured)\n",
        );
    }

    /// Pin the [`RebacValidationSkippedReason::DocsArchAndOrBackendDir`]
    /// byte-form. This variant carries the longer conjoined phrase
    /// `docs_arch and/or backend dir` for the ONE
    /// `check_object_type_mapping` site whose `let (Some(_), Some(_)) =
    /// (…, …) else { … };` destructure fires on either half being
    /// absent. A future refactor that dropped the `and/or` conjunction
    /// or reordered the two directory phrases regresses this.
    #[test]
    fn write_docs_arch_and_or_backend_dir_line_pins_bytes() {
        let mut buf = Vec::new();
        write_rebac_check_skipped_missing_dir_line(
            &mut buf,
            RebacValidationSkippedReason::DocsArchAndOrBackendDir,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   (skipped — docs_arch and/or backend dir not configured)\n",
        );
    }

    /// Pin the [`RebacValidationSkippedReason::WebDir`] byte-form.
    #[test]
    fn write_web_dir_line_pins_bytes() {
        let mut buf = Vec::new();
        write_rebac_check_skipped_missing_dir_line(&mut buf, RebacValidationSkippedReason::WebDir)
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   (skipped — web dir not configured)\n",
        );
    }

    /// Quiet-gate contract: [`print_rebac_check_skipped_missing_dir`]
    /// must suppress the line when `quiet == true`, matching the
    /// pre-lift `if !config.quiet { println!(…); }` gate every
    /// pre-lift site carried. The negative caller shield in the
    /// consumer module forbids a bare `println!("   (skipped — …")`
    /// literal, but only this contract prevents a "silently drop
    /// the quiet gate" cleanup from surfacing skip lines under
    /// `--quiet` where the operator has explicitly asked for
    /// silence.
    ///
    /// The behavioural pin is a structural scan of the primitive
    /// body for the `if quiet { return; }` early-out and the
    /// gate-inverting `!config.quiet` legacy spelling MUST NOT
    /// return — a naked `writeln!` at the top of the body would
    /// print unconditionally.
    #[test]
    fn primitive_body_carries_quiet_early_return_gate() {
        let source = include_str!("rebac_check_skipped_missing_dir.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "rebac_check_skipped_missing_dir.rs",
        );
        assert!(
            body.contains("if quiet {"),
            "primitive body must carry a `if quiet {{ return; }}` early-out — a \
             cleanup that dropped the gate would print the skip line under \
             `--quiet` where the operator explicitly asked for silence.",
        );
        assert!(
            body.contains("return;"),
            "primitive body must return early when `quiet` — the gate cannot be \
             a no-op `if quiet {{ }}` that falls through to the unconditional \
             writeln.",
        );
    }
}

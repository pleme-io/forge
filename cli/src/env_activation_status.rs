//! Per-env `● / ○` activation-status line — the closed
//! [`EnvActivationStatus`] dichotomy that owns the four correlated
//! projections the pre-lift Environment Status block spelled inline
//! at two sibling call sites: the glyph (`●` / `○`), the glyph's
//! ANSI color (`.green()` / `.dimmed()`), the env name's ANSI color
//! (`.cyan()` / `.dimmed()`), and the parenthesized label
//! (`(active)` / `(inactive)`).
//!
//! # Pre-lift census — two sibling `println!` stanzas
//!
//! Both consumer sites live in
//! `commands/rust_service.rs::execute` inside the Environment Status
//! block that fires when `all_envs.len() != active_envs.len()`
//! (~L1240-1244). The two branches of the `if active_envs.contains(env)`
//! test each spelled the same five-token `println!` template
//! verbatim, differing only on the four correlated projections above:
//!
//! ```ignore
//! for env in all_envs {
//!     if active_envs.contains(env) {
//!         println!("   {} {} (active)", "●".green(), env.cyan());
//!     } else {
//!         println!("   {} {} (inactive)", "○".dimmed(), env.dimmed());
//!     }
//! }
//! ```
//!
//! Two identically-shaped bodies past the point THEORY.md §VI.1
//! calls duplication a bug. A drift to the three-space indent, the
//! glyph selection, the glyph-color, the env-color, the parenthesized
//! label wording, or the trailing-newline had to hit both branches in
//! lockstep pre-lift; post-lift the drift hits ONE typed body and
//! both branches inherit the change from the primitive.
//!
//! # Why a closed enum instead of a `bool`
//!
//! The pre-lift branch condition is `active_envs.contains(env)` —
//! a `bool` — but the four coordinated projections it drives are not
//! independent. A third state (a hypothetical `Retired` or
//! `Suspended` environment) that a future
//! [`crate::config::release::ReleaseConfig`] surface introduced would
//! need its own glyph / color pair / label; a `bool` cannot carry
//! that state. The closed enum makes the "someone adds a third env
//! activation state and forgets to name its display projection"
//! failure mode structurally impossible: the enum forces the caller
//! to name the new variant, and every consumer inherits the
//! correlated glyph / color / label triple from the typed accessors
//! rather than through a third inline `println!` a future edit could
//! omit.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Construction guarantees; Types → Invariants
//!   → Proofs → Render Anywhere): the correlated
//!   glyph / glyph-color / env-color / label quartet lives at ONE
//!   construction surface — [`EnvActivationStatus`]'s per-arm
//!   projections — and its byte-oracle tests below pin the four
//!   projections as `cargo test`-verifiable invariants rather than as
//!   two-site display conventions.
//! - `THEORY.md §VI.1` (Generation over composition; recurring shapes
//!   past duplication become helpers): two sibling occurrences of the
//!   five-token `println!` template past the two-sibling threshold,
//!   so the display body lifts onto ONE typed body and both consumers
//!   cite it.

use colored::{ColoredString, Colorize};
use std::io;

/// The closed dichotomy of per-env activation states surfaced in the
/// Environment Status block of `forge release`. The
/// [`Active`](Self::Active) arm carries the `●` bullet, the
/// [`.green()`](Colorize::green) glyph color, the
/// [`.cyan()`](Colorize::cyan) env-name color, and the `(active)`
/// parenthesized label; the [`Inactive`](Self::Inactive) arm carries
/// the `○` hollow bullet, the [`.dimmed()`](Colorize::dimmed) glyph
/// color, the [`.dimmed()`](Colorize::dimmed) env-name color, and the
/// `(inactive)` label.
///
/// Modelling the two states as a closed enum rather than a `bool`
/// forces a future third state (a hypothetical `Retired`,
/// `Suspended`, or `Draining` environment) to name a distinct
/// glyph / color / label triple at ONE construction surface rather
/// than through a third inline `println!` a future edit could
/// silently omit at the caller side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvActivationStatus {
    /// The env appears in the deploy-config's `active_environments`
    /// slice — will receive a release. Pre-lift glyph `●`, glyph
    /// color `.green()`, env color `.cyan()`, label `active`.
    Active,
    /// The env is declared in `environment_order` but omitted from
    /// `active_environments` — inert for this release. Pre-lift
    /// glyph `○`, glyph color `.dimmed()`, env color `.dimmed()`,
    /// label `inactive`.
    Inactive,
}

impl EnvActivationStatus {
    /// Classify `env` against the effective-active slice `active_envs`
    /// returned by
    /// [`crate::config::release::ReleaseConfig::effective_environments`].
    /// Membership is by equality against the caller-supplied slice; a
    /// case-insensitive match is deliberately NOT performed, matching
    /// the pre-lift `active_envs.contains(env)` semantic that this
    /// classify method replaces.
    pub fn classify(env: &str, active_envs: &[String]) -> Self {
        if active_envs.iter().any(|e| e == env) {
            Self::Active
        } else {
            Self::Inactive
        }
    }

    /// The uncolored glyph byte-sequence — `●` for
    /// [`Active`](Self::Active), `○` for [`Inactive`](Self::Inactive).
    /// Const so the two byte-sequences are pinnable by a projection
    /// test without touching any styling frontier.
    pub const fn glyph(self) -> &'static str {
        match self {
            Self::Active => "●",
            Self::Inactive => "○",
        }
    }

    /// The uncolored parenthesized label word — `active` for
    /// [`Active`](Self::Active), `inactive` for
    /// [`Inactive`](Self::Inactive). The surrounding parentheses live
    /// at the `writeln!` template, not here — pre-lift they were part
    /// of the template literal at both call sites.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }

    /// The pre-lift glyph coloring: `.green()` for
    /// [`Active`](Self::Active), `.dimmed()` for
    /// [`Inactive`](Self::Inactive). Returns a fresh
    /// [`ColoredString`] carrying the exact ANSI envelope the
    /// pre-lift `println!` embedded at slot 1.
    pub fn glyph_colored(self) -> ColoredString {
        match self {
            Self::Active => self.glyph().green(),
            Self::Inactive => self.glyph().dimmed(),
        }
    }

    /// The pre-lift env-name coloring: `.cyan()` for
    /// [`Active`](Self::Active), `.dimmed()` for
    /// [`Inactive`](Self::Inactive). Takes the caller's `env` verbatim
    /// (no upcase, no trim) and returns a fresh [`ColoredString`]
    /// carrying the ANSI envelope the pre-lift `println!` embedded at
    /// slot 2.
    pub fn env_colored(self, env: &str) -> ColoredString {
        match self {
            Self::Active => env.cyan(),
            Self::Inactive => env.dimmed(),
        }
    }
}

/// Emit the canonical `   <glyph_colored> <env_colored> (<label>)\n`
/// per-env activation-status line to stdout for `env` under `status`.
/// Called from the Environment Status block of
/// [`crate::commands::rust_service::execute`] once per env in
/// `environment_order` when the block fires (i.e. when the
/// effective-active slice is a strict subset of the environment
/// order).
///
/// Delegates to [`write_env_activation_status_line`] against
/// [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle tests below pin the exact rendered
/// bytes without capturing stdout.
pub fn print_env_activation_status_line(env: &str, status: EnvActivationStatus) {
    let _ = write_env_activation_status_line(&mut io::stdout().lock(), env, status);
}

/// Writer-taking sibling to [`print_env_activation_status_line`].
/// Emits the single `   <glyph_colored> <env_colored> (<label>)\n`
/// line via [`writeln!`] against the supplied writer.
///
/// [`print_env_activation_status_line`] is the stdout adapter; this
/// variant exists so tests can pin the three-space indent, the
/// per-arm glyph selection, the per-arm glyph coloring, the
/// caller's `<env>` verbatim under the per-arm env coloring, the
/// literal parentheses, the per-arm label word, and the trailing
/// newline without capturing stdout.
pub fn write_env_activation_status_line<W: io::Write>(
    w: &mut W,
    env: &str,
    status: EnvActivationStatus,
) -> io::Result<()> {
    writeln!(
        w,
        "   {} {} ({})",
        status.glyph_colored(),
        status.env_colored(env),
        status.label()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize every test in this module that touches the
    /// process-global [`colored::control::set_override`] toggle a
    /// peer test in `crate::ui` also acquires — a fair copy of the
    /// `AnsiOverrideForTest` guard shape in
    /// `cli/src/push_source_announce.rs`. Cargo runs tests in
    /// parallel by default, so without a mutex two tests racing the
    /// override toggle would flap between the "ANSI on" and "ANSI
    /// off" arms.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that force-enables [`colored`] ANSI emission for
    /// the duration of a writer-level byte-oracle test.
    struct AnsiOverrideForTest {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl AnsiOverrideForTest {
        fn acquire() -> Self {
            let lock = ANSI_OVERRIDE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            colored::control::set_override(true);
            Self { _lock: lock }
        }
    }

    impl Drop for AnsiOverrideForTest {
        fn drop(&mut self) {
            colored::control::unset_override();
        }
    }

    /// Byte-oracle for the [`EnvActivationStatus::Active`] arm. Pins
    /// the five-token body — the three-space indent, the `●` glyph,
    /// the caller's `<env>` verbatim, the literal `(active)` label
    /// (parens included, no space between env and paren), and the
    /// trailing `\n`. A silent drift — dropping the indent, swapping
    /// the glyph, changing the label wording, or losing the newline
    /// — flips this assertion rather than compiling and silently
    /// diverging the two consumer branches' visual grammar.
    #[test]
    fn write_active_variant_emits_pre_lift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_env_activation_status_line(&mut buf, "staging", EnvActivationStatus::Active)
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("status line must emit valid UTF-8 (the pre-lift println! did)");
        assert!(
            out.starts_with("   "),
            "active line must open with three-space indent. Got {out:?}"
        );
        assert!(
            out.contains('●'),
            "active line must carry the `●` glyph. Got {out:?}"
        );
        assert!(
            !out.contains('○'),
            "active line must NOT carry the `○` glyph (that's the \
             inactive arm). Got {out:?}"
        );
        assert!(
            out.contains("staging"),
            "active line must carry the caller's `<env>` verbatim. \
             Got {out:?}"
        );
        assert!(
            out.contains("(active)"),
            "active line must carry the parenthesized `(active)` \
             label (parens included). Got {out:?}"
        );
        assert!(
            !out.contains("(inactive)"),
            "active line must NOT carry the `(inactive)` label \
             (that's the inactive arm). Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "status line must terminate with a single `\\n` \
             (pre-lift `println!` did). Got {out:?}"
        );
    }

    /// Byte-oracle for the [`EnvActivationStatus::Inactive`] arm.
    /// Pins the five-token body — the three-space indent, the `○`
    /// hollow glyph, the caller's `<env>` verbatim, the literal
    /// `(inactive)` label, and the trailing `\n`. A silent drift
    /// that hard-coded the [`Active`](EnvActivationStatus::Active)
    /// arm's `●` on the inactive branch would mislabel a
    /// deploy-config's `staging`-only environment_order as
    /// `● production (inactive)` — this assertion flips first.
    #[test]
    fn write_inactive_variant_emits_pre_lift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_env_activation_status_line(&mut buf, "production", EnvActivationStatus::Inactive)
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.starts_with("   "),
            "inactive line must open with three-space indent. \
             Got {out:?}"
        );
        assert!(
            out.contains('○'),
            "inactive line must carry the `○` hollow glyph. Got {out:?}"
        );
        assert!(
            !out.contains('●'),
            "inactive line must NOT carry the `●` glyph (that's the \
             active arm). Got {out:?}"
        );
        assert!(
            out.contains("production"),
            "inactive line must carry the caller's `<env>` verbatim. \
             Got {out:?}"
        );
        assert!(
            out.contains("(inactive)"),
            "inactive line must carry the parenthesized `(inactive)` \
             label. Got {out:?}"
        );
        assert!(
            !out.contains("(active)"),
            "inactive line must NOT carry the `(active)` label \
             (that's the active arm). Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "status line must terminate with a single `\\n`. \
             Got {out:?}"
        );
    }

    /// Pin the [`EnvActivationStatus::glyph`] and
    /// [`EnvActivationStatus::label`] `const fn` projections against
    /// the pre-lift byte-sequences at both sibling call sites. A
    /// silent drift (swapping the two arms, re-casing the label to
    /// `"Active"`, spelling the glyph as the ASCII `*` fallback) trips
    /// here at the projection surface before it diverges the two
    /// consumer branches downstream.
    #[test]
    fn glyph_and_label_projections_match_pre_lift_literals() {
        assert_eq!(
            EnvActivationStatus::Active.glyph(),
            "●",
            "Active::glyph() must project the pre-lift `●` filled \
             bullet"
        );
        assert_eq!(
            EnvActivationStatus::Inactive.glyph(),
            "○",
            "Inactive::glyph() must project the pre-lift `○` hollow \
             bullet"
        );
        assert_eq!(
            EnvActivationStatus::Active.label(),
            "active",
            "Active::label() must project the pre-lift `active` \
             lowercase noun"
        );
        assert_eq!(
            EnvActivationStatus::Inactive.label(),
            "inactive",
            "Inactive::label() must project the pre-lift `inactive` \
             lowercase noun"
        );
    }

    /// Pin the [`EnvActivationStatus::glyph_colored`] projection
    /// against the pre-lift ANSI envelopes. The
    /// [`Active`](EnvActivationStatus::Active) glyph carries a green
    /// SGR envelope (ANSI `\x1b[32m` prefix); the
    /// [`Inactive`](EnvActivationStatus::Inactive) glyph carries a
    /// dim SGR envelope (ANSI `\x1b[2m` prefix). A silent drift that
    /// swapped the two arms' colorings would land the wrong
    /// visual-severity encoding at both consumer branches; this
    /// assertion catches the swap before it diverges the render.
    ///
    /// The test forces ANSI output on by calling
    /// [`colored::control::set_override`] so it does not depend on
    /// whether the test runner's stdout is a TTY.
    #[test]
    fn glyph_colored_projection_carries_pre_lift_ansi_envelopes() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let active_rendered = format!("{}", EnvActivationStatus::Active.glyph_colored());
        let inactive_rendered = format!("{}", EnvActivationStatus::Inactive.glyph_colored());
        assert!(
            active_rendered.contains("\x1b[32m"),
            "Active::glyph_colored() must carry the green SGR \
             envelope (`\\x1b[32m`). Got {active_rendered:?}"
        );
        assert!(
            inactive_rendered.contains("\x1b[2m"),
            "Inactive::glyph_colored() must carry the dim SGR \
             envelope (`\\x1b[2m`). Got {inactive_rendered:?}"
        );
    }

    /// Pin the [`EnvActivationStatus::env_colored`] projection
    /// against the pre-lift ANSI envelopes. The
    /// [`Active`](EnvActivationStatus::Active) env-name carries a
    /// cyan SGR envelope (ANSI `\x1b[36m` prefix); the
    /// [`Inactive`](EnvActivationStatus::Inactive) env-name carries a
    /// dim SGR envelope. This is the second half of the color-pair
    /// invariant: pre-lift the two branches encoded a coordinated
    /// (glyph-color, env-color) pair, and a drift that changed only
    /// one of the two would produce a mismatched line
    /// (e.g. `● staging` with a dim `staging`) — this assertion
    /// flips first.
    #[test]
    fn env_colored_projection_carries_pre_lift_ansi_envelopes() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let active_rendered = format!("{}", EnvActivationStatus::Active.env_colored("staging"));
        let inactive_rendered = format!(
            "{}",
            EnvActivationStatus::Inactive.env_colored("production")
        );
        assert!(
            active_rendered.contains("\x1b[36m"),
            "Active::env_colored() must carry the cyan SGR envelope \
             (`\\x1b[36m`). Got {active_rendered:?}"
        );
        assert!(
            active_rendered.contains("staging"),
            "Active::env_colored() must carry the caller's `<env>` \
             verbatim inside the ANSI envelope. Got {active_rendered:?}"
        );
        assert!(
            inactive_rendered.contains("\x1b[2m"),
            "Inactive::env_colored() must carry the dim SGR envelope \
             (`\\x1b[2m`). Got {inactive_rendered:?}"
        );
        assert!(
            inactive_rendered.contains("production"),
            "Inactive::env_colored() must carry the caller's `<env>` \
             verbatim inside the ANSI envelope. Got {inactive_rendered:?}"
        );
    }

    /// Pin the [`EnvActivationStatus::classify`] projection against
    /// the pre-lift `active_envs.contains(env)` semantic. Membership
    /// is by equality against a `&[String]` slice — the return type
    /// of [`crate::config::release::ReleaseConfig::effective_environments`].
    /// A drift that added a case-insensitive fold, a whitespace
    /// trim, or a substring match would silently mis-classify
    /// `staging ` (trailing space) as
    /// [`Active`](EnvActivationStatus::Active) when the pre-lift
    /// `Vec::contains` would report [`Inactive`](EnvActivationStatus::Inactive).
    #[test]
    fn classify_matches_pre_lift_contains_semantics() {
        let active = vec!["staging".to_string(), "production".to_string()];
        assert_eq!(
            EnvActivationStatus::classify("staging", &active),
            EnvActivationStatus::Active,
            "`staging` in the active slice must classify Active"
        );
        assert_eq!(
            EnvActivationStatus::classify("production", &active),
            EnvActivationStatus::Active,
            "`production` in the active slice must classify Active"
        );
        assert_eq!(
            EnvActivationStatus::classify("dev", &active),
            EnvActivationStatus::Inactive,
            "an env NOT in the active slice must classify Inactive"
        );
        assert_eq!(
            EnvActivationStatus::classify("Staging", &active),
            EnvActivationStatus::Inactive,
            "case-mismatched `Staging` must classify Inactive — the \
             pre-lift `Vec::contains` is case-sensitive by equality"
        );
        assert_eq!(
            EnvActivationStatus::classify("staging ", &active),
            EnvActivationStatus::Inactive,
            "trailing-whitespace `staging ` must classify Inactive — \
             the pre-lift `Vec::contains` does not trim"
        );
        let empty: Vec<String> = vec![];
        assert_eq!(
            EnvActivationStatus::classify("anything", &empty),
            EnvActivationStatus::Inactive,
            "an empty active slice must classify every env Inactive"
        );
    }

    /// Delegation shield (positive half): the primitive's writer body
    /// reaches [`writeln!`] at exactly one call — no fallback path,
    /// no double-write, no branching on `status` outside the
    /// projection accessors. Pins the one-oracle discipline
    /// THEORY §VI.1 requires: a future refactor that introduced a
    /// `match status { Active => writeln!(..); Inactive => writeln!(..); }`
    /// two-arm inline would surface here.
    #[test]
    fn primitive_reaches_writeln_at_exactly_one_call() {
        let source = include_str!("env_activation_status.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "env_activation_status.rs",
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
            "env_activation_status.rs primitive body must reach \
             `writeln!` at exactly one code line (the primitive \
             body); got {hits:#?}"
        );
    }

    /// Delegation shield (positive half): the sole pre-lift consumer
    /// site now reaches [`print_env_activation_status_line`] at
    /// exactly one call. Anchored on the fully qualified path so a
    /// future refactor that renamed the module or dropped the
    /// `crate::env_activation_status::` prefix would regress the
    /// count.
    #[test]
    fn rust_service_reaches_print_env_activation_status_line_at_expected_forwards() {
        const SOURCE: &str = include_str!("commands/rust_service.rs");
        let hits = crate::test_support::code_line_hits(
            SOURCE,
            "crate::env_activation_status::print_env_activation_status_line(",
        );
        assert_eq!(
            hits.len(),
            1,
            "commands/rust_service.rs must reach \
             `crate::env_activation_status::print_env_activation_status_line(` \
             at exactly 1 code line (the Environment Status per-env \
             loop body); got {hits:#?}"
        );
    }

    /// Whole-module negative caller shield: no raw
    /// `"(active)"` or `"(inactive)"` string literal may live in
    /// `commands/rust_service.rs` outside of a delegation to
    /// [`print_env_activation_status_line`]. Post-lift both branches
    /// of the Environment Status block forward through the primitive;
    /// a future re-inline silently reopens the two-branch duplication
    /// class this lift closed.
    ///
    /// Enforced against the module body BEFORE its first
    /// `#[cfg(test)]` region so a test-support mention of the raw
    /// shape does not defeat the shield.
    #[test]
    fn no_raw_active_or_inactive_label_survives_in_rust_service() {
        const SOURCE: &str = include_str!("commands/rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        let raw_active = format!("\"({}{})\"", "active", "");
        let raw_inactive = format!("\"({}{})\"", "inactive", "");
        for (i, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !line.contains(&raw_active),
                "commands/rust_service.rs:{lineno} spells the \
                 pre-lift raw `\"(active)\"` label literal — that \
                 shape was lifted onto \
                 `crate::env_activation_status::EnvActivationStatus::Active` \
                 and reached through \
                 `print_env_activation_status_line`. Line: {line:?}",
                lineno = i + 1
            );
            assert!(
                !line.contains(&raw_inactive),
                "commands/rust_service.rs:{lineno} spells the \
                 pre-lift raw `\"(inactive)\"` label literal — that \
                 shape was lifted onto \
                 `crate::env_activation_status::EnvActivationStatus::Inactive` \
                 and reached through \
                 `print_env_activation_status_line`. Line: {line:?}",
                lineno = i + 1
            );
        }
    }
}

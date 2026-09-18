//! Per-env indexed step prefix — the `[{}/{}] {} <infix?> → {}`
//! six-line stanza fused with the ANSI-styled env / namespace
//! projections on both consumer sites.
//!
//! # Pre-lift census — two sibling stanzas, one six-line body
//!
//! Two consumer sites in `commands/rust_service.rs::
//! deploy_service_across_environments` each spelled the same
//! six-line `println!("   [{}/{}] {} <infix?> → {}", i + 1,
//! environments.len(), env.cyan().bold(), namespace.dimmed())`
//! body verbatim, diverging only on the presence of a middle
//! `" migrations"` infix between `env.cyan().bold()` and the arrow:
//!
//! 1. Step 2 migrations loop (line 1462) — the migrations-phase
//!    per-env header spells the `" migrations"` infix between the
//!    styled env name and the ` → ` separator.
//! 2. Step 3 deploy loop (line 1502) — the deploy-phase per-env
//!    header omits the infix, leaving `env.cyan().bold()` flush
//!    against ` → `.
//!
//! Two identically-shaped bodies past THEORY.md §VI.1's
//! duplication-is-a-bug threshold. A drift to the indent
//! (`   ` → `  `), the `[{}/{}]` bracket-index prefix, the arrow
//! glyph (` → ` → ` >> `), the env-styling (`env.cyan().bold()` →
//! `env.magenta().bold()`), or the namespace-styling
//! (`namespace.dimmed()` → `namespace.bold()`) had to hit both
//! sites in lockstep pre-lift; post-lift the drift hits ONE typed
//! body and both consumers inherit the change from the primitive.
//!
//! # Byte-oracle
//!
//! [`write_env_indexed_step_prefix`] is the writer-taking sibling —
//! a `Vec<u8>` sink lets tests pin the exact rendered bytes (the
//! `   [<i>/<total>] ` bracket-index prefix, the `.cyan().bold()`
//! env envelope, the optional ` migrations` infix, the ` → `
//! arrow separator, the `.dimmed()` namespace envelope, and the
//! trailing `\n`) at one site rather than as two lockstep
//! literals across `rust_service.rs`.

use colored::Colorize;
use std::io;

/// Which phase of the multi-environment deploy pipeline the per-env
/// header line belongs to. A closed enum whose `env_infix`
/// projection is the inverse of the pre-lift `println!` template
/// variance: [`Migrations`](Self::Migrations) inserts the
/// `" migrations"` word between the styled env name and the ` → `
/// separator; [`Deploy`](Self::Deploy) omits it entirely. Named as
/// a closed enum so a future third phase (a hypothetical
/// `Rollback`) surfaces as an unhandled arm rather than a silent
/// string-parameter drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvIndexedStepPhase {
    /// The Step-2 migrations-loop per-env header — spells the
    /// `" migrations"` infix between the styled env name and the
    /// ` → ` separator.
    Migrations,
    /// The Step-3 deploy-loop per-env header — omits the infix.
    Deploy,
}

impl EnvIndexedStepPhase {
    /// Project the phase-variance onto the exact byte-slice the
    /// pre-lift `println!` template embedded between
    /// `env.cyan().bold()` and the ` → ` arrow separator. The
    /// [`Migrations`](Self::Migrations) arm returns the pre-lift
    /// `" migrations"` (leading space included so the env-name
    /// styling is not adjacent to a word boundary); the
    /// [`Deploy`](Self::Deploy) arm returns the empty string,
    /// leaving the styled env name flush against ` → `.
    pub const fn env_infix(self) -> &'static str {
        match self {
            Self::Migrations => " migrations",
            Self::Deploy => "",
        }
    }
}

/// Emit the canonical `   [<index>/<total>] <env.cyan().bold()>
/// <phase.env_infix()> → <namespace.dimmed()>` per-env header line
/// to stdout. Called from each per-env loop iteration inside
/// [`crate::commands::rust_service::deploy_service_across_environments`]
/// (Step 2 migrations loop with
/// [`EnvIndexedStepPhase::Migrations`] and Step 3 deploy loop with
/// [`EnvIndexedStepPhase::Deploy`]).
///
/// Delegates to [`write_env_indexed_step_prefix`] against
/// [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle test pins the exact rendered bytes
/// without capturing stdout.
pub fn print_env_indexed_step_prefix(
    index_1_based: usize,
    total: usize,
    env: &str,
    namespace: &str,
    phase: EnvIndexedStepPhase,
) {
    let _ = write_env_indexed_step_prefix(
        &mut io::stdout().lock(),
        index_1_based,
        total,
        env,
        namespace,
        phase,
    );
}

/// Writer-taking sibling to [`print_env_indexed_step_prefix`].
/// Emits the single `   [<index>/<total>] <env.cyan().bold()>
/// <infix> → <namespace.dimmed()>\n` line via [`writeln!`] against
/// the supplied writer.
///
/// [`print_env_indexed_step_prefix`] is the stdout adapter; this
/// variant exists so tests can pin the three-space indent, the
/// `[<index>/<total>]` bracket-index prefix, the caller's `<env>`
/// verbatim under `.cyan().bold()`, the phase-conditional
/// `" migrations"` infix or its absence, the ` → ` arrow
/// separator, and the caller's `<namespace>` verbatim under
/// `.dimmed()` without capturing stdout.
pub fn write_env_indexed_step_prefix<W: io::Write>(
    w: &mut W,
    index_1_based: usize,
    total: usize,
    env: &str,
    namespace: &str,
    phase: EnvIndexedStepPhase,
) -> io::Result<()> {
    writeln!(
        w,
        "   [{}/{}] {}{} → {}",
        index_1_based,
        total,
        env.cyan().bold(),
        phase.env_infix(),
        namespace.dimmed()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for the
    /// [`EnvIndexedStepPhase::Migrations`] variant. Pins the
    /// six-token body — the three-space indent, the `[1/3]`
    /// bracket-index prefix, the env name `staging`, the
    /// `" migrations"` infix (leading space included so the env
    /// styling is not adjacent to a word boundary), the ` → `
    /// arrow separator, and the namespace `pleme-staging`. A
    /// silent drift a future rewrite might introduce — dropping
    /// the infix, swapping ` → ` for a plain `->`, changing the
    /// indent, dropping the styling — flips this assertion rather
    /// than compiling and silently diverging the two consumer
    /// sites' visual grammar.
    #[test]
    fn write_migrations_variant_emits_pre_lift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_env_indexed_step_prefix(
            &mut buf,
            1,
            3,
            "staging",
            "pleme-staging",
            EnvIndexedStepPhase::Migrations,
        )
        .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("prefix line must emit valid UTF-8 (the pre-lift println! did)");
        assert!(
            out.contains("   [1/3] "),
            "migrations prefix must open with three-space indent + \
             `[1/3] ` bracket-index prefix. Got {out:?}"
        );
        assert!(
            out.contains("staging"),
            "migrations prefix must carry the caller's `<env>` \
             verbatim. Got {out:?}"
        );
        assert!(
            out.contains(" migrations → "),
            "migrations prefix must spell the ` migrations → ` \
             infix + arrow between env and namespace (pre-lift \
             literal from Step 2 loop). Got {out:?}"
        );
        assert!(
            out.contains("pleme-staging"),
            "migrations prefix must carry the caller's \
             `<namespace>` verbatim. Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "prefix line must terminate with a single `\\n` \
             (pre-lift `println!` did). Got {out:?}"
        );
    }

    /// Fail-before-pass envelope for the
    /// [`EnvIndexedStepPhase::Deploy`] variant. Pins the
    /// no-infix shape — the env name flush against ` → ` with no
    /// intervening `" migrations"` word. A silent drift that
    /// hard-coded the [`env_infix`](EnvIndexedStepPhase::env_infix)
    /// projection on the [`Migrations`](EnvIndexedStepPhase::Migrations)
    /// arm's return would mislabel the Step-3 deploy loop's
    /// per-env header as `production migrations → pleme-prod` —
    /// this assertion flips first.
    #[test]
    fn write_deploy_variant_emits_pre_lift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        write_env_indexed_step_prefix(
            &mut buf,
            2,
            3,
            "production",
            "pleme-prod",
            EnvIndexedStepPhase::Deploy,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("   [2/3] "),
            "deploy prefix must open with three-space indent + \
             `[2/3] ` bracket-index prefix. Got {out:?}"
        );
        assert!(
            out.contains("production"),
            "deploy prefix must carry the caller's `<env>` \
             verbatim. Got {out:?}"
        );
        assert!(
            !out.contains(" migrations "),
            "deploy prefix must NOT carry the ` migrations ` \
             infix (pre-lift Step-3 loop omitted it — the arrow \
             stood flush against the styled env name). Got {out:?}"
        );
        assert!(
            out.contains(" → pleme-prod")
                || out.contains(" → \x1b[2mpleme-prod")
                || out.contains("pleme-prod"),
            "deploy prefix must carry ` → <namespace>` with the \
             namespace flush against the arrow separator. Got {out:?}"
        );
    }

    /// Pin the [`EnvIndexedStepPhase::env_infix`] projection —
    /// [`Migrations`](EnvIndexedStepPhase::Migrations) must
    /// return the exact pre-lift `" migrations"` byte sequence
    /// (a single leading space, then the noun), and
    /// [`Deploy`](EnvIndexedStepPhase::Deploy) must return the
    /// empty string. A silent drift (dropping the leading space,
    /// re-casing to `" Migrations"`, or accidentally returning a
    /// non-empty string on the deploy arm) trips here before it
    /// diverges the two consumer sites.
    #[test]
    fn env_infix_projection_matches_pre_lift_literals() {
        assert_eq!(
            EnvIndexedStepPhase::Migrations.env_infix(),
            " migrations",
            "Migrations::env_infix() must project the pre-lift \
             ` migrations` byte sequence (leading space + lowercase \
             noun). Got {:?}",
            EnvIndexedStepPhase::Migrations.env_infix()
        );
        assert_eq!(
            EnvIndexedStepPhase::Deploy.env_infix(),
            "",
            "Deploy::env_infix() must project the empty string — \
             pre-lift Step-3 loop's env name stood flush against \
             ` → `. Got {:?}",
            EnvIndexedStepPhase::Deploy.env_infix()
        );
    }

    /// Whole-module negative caller shield: no raw
    /// `"   [{}/{}] {} migrations → {}"` template literal may
    /// live in `commands/rust_service.rs` outside of a delegation
    /// to [`print_env_indexed_step_prefix`]. Post-lift the
    /// Step-2 migrations-loop site forwards through the primitive
    /// with [`EnvIndexedStepPhase::Migrations`]; a future
    /// re-inline silently reopens the two-site duplication class
    /// this lift closed.
    ///
    /// Enforced against the module body BEFORE its first
    /// `#[cfg(test)]` region so a test-support mention of the
    /// raw shape does not defeat the shield.
    #[test]
    fn no_raw_migrations_prefix_template_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"   [{}/{}] {} migrations → {}\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the \
                 pre-lift raw `\"   [{{}}/{{}}] {{}} migrations → \
                 {{}}\"` template literal — that shape was lifted \
                 onto `crate::commands::env_indexed_step_prefix::\
                 print_env_indexed_step_prefix` with \
                 `EnvIndexedStepPhase::Migrations`. A re-inline \
                 silently reopens the two-site duplication class \
                 this shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Sibling negative shield for the Step-3 deploy-loop
    /// no-infix template. Post-lift the Step-3 site forwards
    /// through the primitive with
    /// [`EnvIndexedStepPhase::Deploy`]; a re-inline that copied
    /// only the deploy-arm template (dropping the migrations arm,
    /// or vice versa) still trips a shield.
    #[test]
    fn no_raw_deploy_prefix_template_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"   [{}/{}] {} → {}\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the \
                 pre-lift raw `\"   [{{}}/{{}}] {{}} → {{}}\"` \
                 template literal — that shape was lifted onto \
                 `crate::commands::env_indexed_step_prefix::\
                 print_env_indexed_step_prefix` with \
                 `EnvIndexedStepPhase::Deploy`. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/rust_service.rs`
    /// must forward through [`print_env_indexed_step_prefix`] at
    /// exactly two sites (one per pre-lift consumer: the Step-2
    /// migrations loop and the Step-3 deploy loop). A fusion
    /// that folded the two sites into one call or dropped one of
    /// the loops silently fails here — the negative halves above
    /// would still pass, but the positive count would fall below
    /// the pre-lift census.
    #[test]
    fn rust_service_forwards_through_prefix_primitive_twice() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const FORWARD_NEEDLE: &str = "env_indexed_step_prefix::print_env_indexed_step_prefix(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/rust_service.rs body must forward to \
             `crate::commands::env_indexed_step_prefix::\
             print_env_indexed_step_prefix(...)` at exactly 2 \
             sites — one per pre-lift consumer (Step-2 migrations \
             loop with `EnvIndexedStepPhase::Migrations` and \
             Step-3 deploy loop with `EnvIndexedStepPhase::Deploy`). \
             Found {forward_hits} forwarding hits."
        );
    }
}

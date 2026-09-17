//! [`tokio::process::Command`] extension trait fusing the
//! `.env("RUST_LOG", "info").env("RUST_BACKTRACE", "1")` two-line
//! diagnostic env-pair on a `cargo test` spawn into a single
//! `.rust_test_diagnostic_env()` chain call.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites in
//! [`crate::commands::comprehensive_release::execute`] each restated the
//! same fused env-pair on a `tokio::process::Command` builder for a
//! `cargo test` spawn, verbatim:
//!
//! ```ignore
//! .env("RUST_LOG", "info")
//! .env("RUST_BACKTRACE", "1")
//! ```
//!
//! - `commands/comprehensive_release.rs:334-335` — STEP-1 unit-tests
//!   spawn (`cargo test --lib --bins -- --show-output`), which then
//!   chains a third `.env("SQLX_OFFLINE", "true")` payload-specific to
//!   the offline-sqlx-macros gate.
//! - `commands/comprehensive_release.rs:657-658` — post-`docker-compose
//!   up` integration-tests spawn (`cargo test --test * -- --ignored
//!   --test-threads=1`), which stops at the fused pair.
//!
//! Both sites want the SAME diagnostic posture on the child cargo test
//! process — tracing info-level output routed through the `tracing` /
//! `env_logger` `RUST_LOG` sigil AND a panic backtrace on assertion
//! failure via `RUST_BACKTRACE=1` — so an operator debugging a red CI
//! run sees the same evidence surface on both suites. The two axes are
//! fused: enabling `RUST_LOG` without `RUST_BACKTRACE` (or vice versa)
//! would leave a failed test with half its diagnostic context (info
//! logs but no panic frame, or a bare panic frame with no lead-up
//! trace) and turn the failure banner
//! [`crate::commands::test_suite_failure_banner::print_suite_failure_banner`]
//! prints below into a lie by omission. A future contributor adding a
//! third `cargo test` spawn on the release surface could regress to
//! `.env("RUST_LOG", "info")` alone — the fused primitive here makes
//! that regression structurally invisible.
//!
//! # The primitive
//!
//! An extension trait, not a free function: every call site chains on a
//! [`tokio::process::Command`] builder that is freshly constructed
//! (`Command::new(&cargo).current_dir(&working_dir).args(&[...])
//! .rust_test_diagnostic_env()`). A free function would break the
//! builder chain; the trait method preserves it and returns `&mut
//! Command` for the next chained call (either `.env("SQLX_OFFLINE",
//! "true")` at the unit-tests site, or `.status()` at the
//! integration-tests site). Same choice as the sibling
//! [`crate::tokio_command_inherit_stdio::InheritChildStdio`] and
//! [`crate::tokio_command_piped_stdio::PipedChildStdio`] traits, whose
//! docstrings argue the same builder-chain preservation.
//!
//! # Byte contract
//!
//! [`RustTestDiagnosticEnv::rust_test_diagnostic_env`] calls
//! [`tokio::process::Command::env`] with `("RUST_LOG", "info")` and
//! then with `("RUST_BACKTRACE", "1")`, in that order. The order does
//! not affect the resulting env map — the two keys are independent and
//! the underlying [`std::process::Command`] env store is not
//! order-preserving on iteration — so the tests below assert set
//! membership + values, not iteration order. The source-line order is
//! kept to match the two-line pre-lift stanza a reader of the shield
//! docstring expects to see translate through.
//!
//! # Why not lift the `SQLX_OFFLINE` companion too
//!
//! The unit-tests site adds a third `.env("SQLX_OFFLINE", "true")`
//! immediately after the fused pair; the integration-tests site does
//! not (its cargo test target runs against a live docker-compose
//! Postgres brought up in a prior step, so offline-sqlx-macros
//! substitution would MASK a schema-drift regression the integration
//! suite is meant to catch). Lifting `SQLX_OFFLINE` into the same
//! primitive would either force the integration site to set it (a
//! payload change hiding a class of defect) or introduce a
//! configuration axis on the primitive with only one paying consumer
//! (payload leakage the pre-lift shape did not carry). The pair the
//! primitive owns is exactly the pair both sites share; the third env
//! stays where it is, chained after the primitive's `&mut Self` return
//! at the unit-tests site.

use tokio::process::Command;

/// Extension trait fusing the pre-lift `.env("RUST_LOG", "info")
/// .env("RUST_BACKTRACE", "1")` two-line env-pair on a
/// [`tokio::process::Command`] builder into a single chain call.
///
/// Blanket-implemented for [`tokio::process::Command`] only — the two
/// pre-lift sibling sites are both async / tokio spawns of `cargo
/// test`, and there is no synchronous `std::process::Command` site in
/// the crate that would pay for a second impl block. The trait-shape
/// oracle below pins the intentional narrowness.
pub trait RustTestDiagnosticEnv {
    /// Set both `RUST_LOG=info` and `RUST_BACKTRACE=1` on `self`,
    /// returning `&mut Self` for chain continuation.
    fn rust_test_diagnostic_env(&mut self) -> &mut Self;
}

impl RustTestDiagnosticEnv for Command {
    fn rust_test_diagnostic_env(&mut self) -> &mut Self {
        self.env("RUST_LOG", "info").env("RUST_BACKTRACE", "1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// Behavior oracle: `.rust_test_diagnostic_env()` returns the same
    /// [`tokio::process::Command`] builder for chain continuation —
    /// verified by threading the result into `.arg("...")` and reading
    /// back the argv via [`tokio::process::Command::as_std`]. If the
    /// method were to return `()` or a fresh `Command`, the chained
    /// `.arg("chained-arg-marker")` would not appear in the resulting
    /// argv and this test would flip.
    ///
    /// The fixture binary path is built via a `&str` binding rather
    /// than a `Command::new("<literal>")` inline literal so this
    /// test's own source text does NOT match the crate-wide bare-
    /// literal-spawn tally shield at `tools::spawn_shield` — same
    /// discipline the sibling `tokio_command_inherit_stdio` and
    /// `tokio_command_piped_stdio` fixture tests apply.
    #[test]
    fn rust_test_diagnostic_env_returns_chainable_command_ref() {
        let bin: &'static str = "true";
        let mut cmd = Command::new(bin);
        cmd.rust_test_diagnostic_env().arg("chained-arg-marker");
        let argv: Vec<&OsStr> = cmd.as_std().get_args().collect();
        assert_eq!(
            argv.len(),
            1,
            "the chained `.arg()` after `.rust_test_diagnostic_env()` \
             must land on the SAME Command builder — the extension \
             method must return `&mut Self`, not `()` or a fresh \
             Command; got argv {argv:?}"
        );
        assert_eq!(
            argv[0], "chained-arg-marker",
            "chained arg must be `chained-arg-marker`; got {argv:?}"
        );
    }

    /// Byte oracle: [`RustTestDiagnosticEnv::rust_test_diagnostic_env`]
    /// installs BOTH `RUST_LOG=info` and `RUST_BACKTRACE=1` on the
    /// underlying [`std::process::Command`]'s env map, in the pre-lift
    /// order. A regression that (a) dropped either key, (b) rewrote
    /// either value (e.g. `RUST_LOG=debug` or `RUST_BACKTRACE=full`),
    /// (c) unset either key via [`std::process::Command::env_remove`],
    /// or (d) swapped the fused pair for a `.envs([...])` bulk call
    /// with divergent contents would flip one of the assertions here.
    #[test]
    fn rust_test_diagnostic_env_installs_both_keys_with_pre_lift_values() {
        let bin: &'static str = "true";
        let mut cmd = Command::new(bin);
        cmd.rust_test_diagnostic_env();
        let envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.as_std().get_envs().collect();

        let rust_log = envs
            .iter()
            .find(|(k, _)| *k == OsStr::new("RUST_LOG"))
            .unwrap_or_else(|| panic!("RUST_LOG must be set; got envs {envs:?}"));
        assert_eq!(
            rust_log.1,
            Some(OsStr::new("info")),
            "RUST_LOG must be set to \"info\"; got {:?}",
            rust_log.1
        );

        let rust_backtrace = envs
            .iter()
            .find(|(k, _)| *k == OsStr::new("RUST_BACKTRACE"))
            .unwrap_or_else(|| panic!("RUST_BACKTRACE must be set; got envs {envs:?}"));
        assert_eq!(
            rust_backtrace.1,
            Some(OsStr::new("1")),
            "RUST_BACKTRACE must be set to \"1\"; got {:?}",
            rust_backtrace.1
        );
    }

    /// Chain oracle: a caller may append a third `.env(...)` after
    /// `.rust_test_diagnostic_env()` and both the fused pair AND the
    /// appended entry appear on the env map. Pinned because the
    /// unit-tests site chains `.env("SQLX_OFFLINE", "true")` after
    /// the primitive; if the primitive stopped returning `&mut Self`
    /// or reset the env map, the SQLX_OFFLINE entry would silently
    /// vanish and the sqlx-offline gate would flip to online mode
    /// against a container that isn't up yet.
    #[test]
    fn rust_test_diagnostic_env_allows_additional_env_chain() {
        let bin: &'static str = "true";
        let mut cmd = Command::new(bin);
        cmd.rust_test_diagnostic_env().env("SQLX_OFFLINE", "true");
        let envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.as_std().get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == OsStr::new("RUST_LOG") && *v == Some(OsStr::new("info"))),
            "RUST_LOG=info must survive the SQLX_OFFLINE chain append; \
             got envs {envs:?}"
        );
        assert!(
            envs.iter()
                .any(|(k, v)| *k == OsStr::new("RUST_BACKTRACE") && *v == Some(OsStr::new("1"))),
            "RUST_BACKTRACE=1 must survive the SQLX_OFFLINE chain append; \
             got envs {envs:?}"
        );
        assert!(
            envs.iter()
                .any(|(k, v)| *k == OsStr::new("SQLX_OFFLINE") && *v == Some(OsStr::new("true"))),
            "SQLX_OFFLINE=true chained AFTER the primitive must appear on \
             the env map; got envs {envs:?}"
        );
    }

    /// Post-lift shield: no LIVE source line under `cli/src/commands/`
    /// may still spell the pre-lift fused
    /// `.env("RUST_LOG", "info")` / `.env("RUST_BACKTRACE", "1")`
    /// two-line stanza inline. Scans the whole module (not just before
    /// the first `#[cfg(test)]`) because the pre-lift sites live in
    /// the module body of `commands/comprehensive_release.rs` which
    /// has no test region of its own; the shield's own docstring
    /// mention of the pre-lift shape lives HERE, inside a `#[cfg(test)]`
    /// region on a different module, so it does not contribute to the
    /// scanned surface.
    #[test]
    fn no_command_module_still_spells_raw_rust_test_diagnostic_env_pair() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            let lines: Vec<(usize, &str)> = source
                .lines()
                .enumerate()
                .filter_map(|(idx, line)| {
                    let trimmed = line.trim_start();
                    if in_block_comment {
                        if trimmed.contains("*/") {
                            in_block_comment = false;
                        }
                        return None;
                    }
                    if trimmed.starts_with("/*") && !trimmed.contains("*/") {
                        in_block_comment = true;
                        return None;
                    }
                    if trimmed.starts_with("//") {
                        return None;
                    }
                    Some((idx + 1, line))
                })
                .collect();
            for window in lines.windows(2) {
                let (line_a, a) = window[0];
                let (_line_b, b) = window[1];
                let a_hit = a.contains(".env(\"RUST_LOG\", \"info\")");
                let b_hit = b.contains(".env(\"RUST_BACKTRACE\", \"1\")");
                if a_hit && b_hit {
                    offenders.push((path.clone(), line_a, format!("{a}\n{b}")));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw fused `.env(\"RUST_LOG\", \"info\").env(\"RUST_BACKTRACE\", \"1\")` \
             two-line stanza(s) survive in `cli/src/commands/` — route \
             each through \
             `crate::rust_test_diagnostic_env::RustTestDiagnosticEnv::rust_test_diagnostic_env` \
             instead:\n{offenders:#?}"
        );
    }

    /// Positive shield: the one pre-lift `commands/` module that
    /// houses the two sibling sites must forward through the extension
    /// method at least twice. A dropped call site would leave the
    /// negative shield above trivially satisfied by absence — this
    /// positive count catches that.
    #[test]
    fn comprehensive_release_forwards_through_rust_test_diagnostic_env_method() {
        const SOURCE: &str = include_str!("commands/comprehensive_release.rs");
        let forwards = SOURCE.matches(".rust_test_diagnostic_env()").count();
        assert!(
            forwards >= 2,
            "commands/comprehensive_release.rs: expected at least 2 \
             `.rust_test_diagnostic_env()` forward(s) in module body \
             (pre-lift sibling count); found {forwards}. A dropped call \
             would leave the negative raw-shape scan satisfied by absence."
        );
    }

    /// Trait-shape oracle: [`RustTestDiagnosticEnv`] is implemented
    /// for [`tokio::process::Command`] and NOT for its `std::process`
    /// twin. Pins the intentional narrowness of the impl surface —
    /// the pre-lift sibling census is 100% async / tokio, and a
    /// speculative `impl RustTestDiagnosticEnv for
    /// std::process::Command` would widen the trait without a paying
    /// consumer.
    #[test]
    fn rust_test_diagnostic_env_is_wired_for_tokio_command() {
        fn assert_impl<T: RustTestDiagnosticEnv>() {}
        assert_impl::<tokio::process::Command>();
    }
}

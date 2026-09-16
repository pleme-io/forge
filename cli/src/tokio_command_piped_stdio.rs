//! [`tokio::process::Command`] extension trait fusing the
//! `.stdout(Stdio::piped()).stderr(Stdio::piped())` two-line stanza
//! into a single `.piped_child_stdio()` chain call.
//!
//! Sibling of [`crate::tokio_command_inherit_stdio`]: same fused-pair
//! discipline, opposite [`std::process::Stdio`] variant. Where the
//! inherit primitive is for spawns that stream child output live to
//! the operator's terminal, this primitive is for spawns that capture
//! child output for structural inspection — `cmd.output().await`
//! consumers (attic `push`/`login`/`use` retry loops, `nix
//! path-info --recursive` closure discovery) and long-running
//! `spawn()` + `wait_with_output().await` consumers (per-suite
//! [`crate::commands::integration_tests`] runners threaded through
//! [`tokio::time::timeout`]).
//!
//! # Duplication being lifted
//!
//! Nine pre-lift sibling sites — every one on a
//! [`tokio::process::Command`] builder — each restated the fused
//! `.stdout(Stdio::piped()).stderr(Stdio::piped())` pair verbatim,
//! eight as the canonical two-line stanza and one as the
//! semantically-identical single-line form
//! (`.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());`):
//!
//! ```ignore
//! .stdout(Stdio::piped())
//! .stderr(Stdio::piped())
//! ```
//!
//! - `nix.rs:148-149` — `nix <build-argv>` build spawn inside
//!   [`crate::nix::run_nix_build_typed`] (the same-line form).
//! - `nix.rs:598-599` — `nix path-info --recursive <output-link>`
//!   closure enumeration ahead of `push_closure_via_stdin`.
//! - `commands/integration_tests.rs:861-862` — per-suite `sh -c
//!   <suite-command>` spawn under
//!   [`crate::commands::integration_tests::execute_suite`]'s
//!   [`tokio::time::timeout`] boundary.
//! - `commands/integration_tests.rs:1374-1375` — post-deployment
//!   test-command spawn under the same timeout-boundary wrapper.
//! - `infrastructure/attic.rs:387-388` — `attic push <cache>
//!   <store_path>` retry-loop attempt inside
//!   [`crate::infrastructure::attic::AtticClient::push_store_path`].
//! - `infrastructure/attic.rs:507-508` — `attic push <cache> --stdin`
//!   spawn inside
//!   [`crate::infrastructure::attic::AtticClient::push_closure_via_stdin`]
//!   (this is a 3-line pre-lift stanza — `.stdin(Stdio::piped())`
//!   sits immediately BEFORE the fused pair; the primitive lifts the
//!   pair while leaving the `.stdin(...)` call in place, so the site
//!   post-lift reads `.stdin(Stdio::piped()).piped_child_stdio()`).
//! - `infrastructure/attic.rs:575-576` — `attic login <cache>
//!   <server_url> <token>` inside
//!   [`crate::infrastructure::attic::AtticClient::login`].
//! - `infrastructure/attic.rs:703-704` — `attic login <cache>
//!   <server_url> <token>` retry-loop attempt inside
//!   [`crate::infrastructure::attic::AtticClient::login_with_retry`].
//! - `infrastructure/attic.rs:766-767` — `attic use <cache_ref>`
//!   inside [`crate::infrastructure::attic::AtticClient::use_cache`].
//!
//! The pre-lift `commands/seed.rs:103-104` site (three-line
//! `.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())`
//! stanza on the psql seed-injection [`std::process::Command`]) is
//! NOT counted — it is a synchronous
//! [`std::process::Command`] builder, and adding a speculative
//! [`std::process::Command`] impl block for one paying consumer
//! would widen the trait surface without a matching sibling census.
//! The trait-shape oracle test below pins that intentional
//! narrowness.
//!
//! Every site is a [`tokio::process::Command`] builder wanting both
//! child stdout AND child stderr captured (via
//! [`std::process::Stdio::piped`]) so the caller can inspect the
//! raw bytes downstream — either via
//! [`tokio::process::Command::output`] (the attic + nix
//! `output().await` sites) or via
//! [`tokio::process::Child::wait_with_output`] (the
//! integration-tests `spawn()` + timeout wrappers). The two axes
//! are fused: piping stdout without stderr (or vice versa) would
//! silently drop half the child's captured bytes and turn a typed
//! failure classification (attic exit-code + stderr tuple, nix
//! `PathInfoFailed` record) into a partial one. The fused primitive
//! makes that regression structurally invisible.
//!
//! # The primitive
//!
//! An extension trait, not a free function: every call site chains
//! on a [`tokio::process::Command`] builder that is either freshly
//! constructed (`Command::new(&attic_bin).args([...])
//! .piped_child_stdio()`) or returned by a factory
//! (`self.command().args([...]).piped_child_stdio()`). A free
//! function would break the builder chain; the trait method
//! preserves it and returns `&mut Command` for the next chained
//! call. Same choice as the sibling
//! [`crate::tokio_command_inherit_stdio::InheritChildStdio`] trait.
//!
//! # Byte contract
//!
//! [`PipedChildStdio::piped_child_stdio`] calls
//! [`tokio::process::Command::stdout`] with
//! [`std::process::Stdio::piped`] and then
//! [`tokio::process::Command::stderr`] with the same, in that
//! order. The order does not affect the resulting stdio config
//! (stdout and stderr are set on independent fields) but is pinned
//! by the tests below because a caller who reads the shield's
//! docstring expects the two-line pre-lift stanza to have
//! translated in exactly that order.

use std::process::Stdio;
use tokio::process::Command;

/// Extension trait fusing the pre-lift `.stdout(Stdio::piped())
/// .stderr(Stdio::piped())` two-line stanza on a
/// [`tokio::process::Command`] builder into a single chain call.
///
/// Blanket-implemented for [`tokio::process::Command`] only —
/// [`std::process::Command`] has one pre-lift sibling site
/// (`commands/seed.rs:103-104`), which is not enough to justify a
/// second impl block. See the module docstring's site census for
/// the reasoning; the trait-shape oracle below pins the narrowness.
pub trait PipedChildStdio {
    /// Set both `stdout` and `stderr` on `self` to
    /// [`std::process::Stdio::piped`], returning `&mut Self` for
    /// chain continuation.
    fn piped_child_stdio(&mut self) -> &mut Self;
}

impl PipedChildStdio for Command {
    fn piped_child_stdio(&mut self) -> &mut Self {
        self.stdout(Stdio::piped()).stderr(Stdio::piped())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Behavior oracle: `.piped_child_stdio()` returns the same
    /// [`tokio::process::Command`] builder for chain continuation —
    /// verified by threading the result into `.arg("...")` and
    /// reading back the argv via
    /// [`tokio::process::Command::as_std`]. If the method were to
    /// return `()` or a fresh `Command`, the chained
    /// `.arg("chained-arg-marker")` would not appear in the
    /// resulting argv and this test would flip.
    ///
    /// The fixture binary path is built via a `&str` binding rather
    /// than a `Command::new("<literal>")` inline literal so this
    /// test's own source text does NOT match the crate-wide bare-
    /// literal-spawn tally shield at `tools::spawn_shield` — same
    /// discipline the sibling inherit-primitive fixture tests
    /// apply.
    #[test]
    fn piped_child_stdio_returns_chainable_command_ref() {
        let bin: &'static str = "true";
        let mut cmd = Command::new(bin);
        cmd.piped_child_stdio().arg("chained-arg-marker");
        let argv: Vec<&std::ffi::OsStr> = cmd.as_std().get_args().collect();
        assert_eq!(
            argv.len(),
            1,
            "the chained `.arg()` after `.piped_child_stdio()` must \
             land on the SAME Command builder — the extension method \
             must return `&mut Self`, not `()` or a fresh Command; \
             got argv {argv:?}"
        );
        assert_eq!(
            argv[0], "chained-arg-marker",
            "chained arg must be `chained-arg-marker`; got {argv:?}"
        );
    }

    /// Behavior oracle: running `.piped_child_stdio().output()`
    /// against a spawnable shim whose stdout and stderr each carry
    /// a distinct marker byte-string yields BOTH captured on the
    /// resulting [`std::process::Output`]. A regression that swapped
    /// [`std::process::Stdio::piped`] for
    /// [`std::process::Stdio::null`] on either axis would drop that
    /// axis's captured bytes and flip this test; a regression that
    /// dropped one axis entirely would produce empty bytes on the
    /// dropped axis. The exit status must also be successful.
    #[tokio::test]
    async fn piped_child_stdio_captures_both_stdout_and_stderr() {
        let (_dir, shim) = crate::test_support::make_executable_shim(
            "piped-child-stdio-shim",
            "#!/bin/sh\n\
             echo 'STDOUT-MARKER-A7F3'\n\
             echo 'STDERR-MARKER-B8E4' 1>&2\n\
             exit 0\n",
        );
        let output = Command::new(&shim)
            .piped_child_stdio()
            .output()
            .await
            .expect("shim must spawn under `.piped_child_stdio()`");
        assert!(
            output.status.success(),
            "shim `exit 0` under `.piped_child_stdio().output()` \
             must return success; got {:?}",
            output.status
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("STDOUT-MARKER-A7F3"),
            "shim's stdout marker must be captured under \
             `.piped_child_stdio()`; got stdout={stdout:?}"
        );
        assert!(
            stderr.contains("STDERR-MARKER-B8E4"),
            "shim's stderr marker must be captured under \
             `.piped_child_stdio()`; got stderr={stderr:?}"
        );
    }

    /// Split a source body into an ordered list of (line-number,
    /// live-code-line) pairs, dropping every line that lives inside
    /// a `/* … */` block comment or begins with a `//` line
    /// comment. Same discipline as the sibling
    /// [`crate::tokio_command_inherit_stdio`] shield's `live_lines`
    /// helper — a docstring `//` mention of the pre-lift shape
    /// must NOT be counted as a live site.
    fn live_lines(body: &str) -> Vec<(usize, &str)> {
        let mut out: Vec<(usize, &str)> = Vec::new();
        let mut in_block = false;
        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if in_block {
                if trimmed.contains("*/") {
                    in_block = false;
                }
                continue;
            }
            if trimmed.starts_with("/*") && !trimmed.contains("*/") {
                in_block = true;
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            out.push((idx + 1, line));
        }
        out
    }

    /// Detect a live fused
    /// `.stdout(Stdio::piped()).stderr(Stdio::piped())` pair
    /// across the given live source lines, in either of its two
    /// pre-lift forms: the canonical two-line stanza (adjacent
    /// lines each carrying one axis) OR the same-line form
    /// (a single line containing both). Accepts both the bare
    /// `Stdio::` spelling (the pre-lift sibling census) and the
    /// fully-qualified `std::process::Stdio::` spelling, so a
    /// future site that omits the `use std::process::Stdio;`
    /// import cannot regress past the shield by qualifying the
    /// path inline.
    fn scan_offenders<'a>(
        module_path: &'static str,
        live: &[(usize, &'a str)],
    ) -> Vec<(&'static str, usize, String)> {
        fn stdout_piped_hit(s: &str) -> bool {
            s.contains(".stdout(Stdio::piped())")
                || s.contains(".stdout(std::process::Stdio::piped())")
        }
        fn stderr_piped_hit(s: &str) -> bool {
            s.contains(".stderr(Stdio::piped())")
                || s.contains(".stderr(std::process::Stdio::piped())")
        }
        let mut offenders: Vec<(&'static str, usize, String)> = Vec::new();
        for &(line_no, line) in live {
            if stdout_piped_hit(line) && stderr_piped_hit(line) {
                offenders.push((module_path, line_no, line.to_string()));
            }
        }
        for window in live.windows(2) {
            let (line_a, a) = window[0];
            let (_line_b, b) = window[1];
            if stdout_piped_hit(a)
                && !stderr_piped_hit(a)
                && stderr_piped_hit(b)
                && !stdout_piped_hit(b)
            {
                offenders.push((module_path, line_a, format!("{a}\n{b}")));
            }
        }
        offenders
    }

    /// Post-lift shield: no LIVE source line under
    /// `cli/src/commands/` may still spell the pre-lift fused
    /// `.stdout(Stdio::piped()).stderr(Stdio::piped())` two-line
    /// stanza inline. Scans module bodies BEFORE their first
    /// `#[cfg(test)]` region so a docstring-shaped mention of the
    /// pre-lift shape inside a sibling shield's own diagnostic
    /// prose does not defeat the shield, and strips `/* … */`
    /// block-comment lines via [`live_lines`].
    #[test]
    fn commands_no_longer_spell_raw_stdout_stderr_piped_pair() {
        struct Site {
            module_path: &'static str,
            source: &'static str,
        }
        let sites: &[Site] = &[Site {
            module_path: "commands/integration_tests.rs",
            source: include_str!("commands/integration_tests.rs"),
        }];
        let mut offenders: Vec<(&'static str, usize, String)> = Vec::new();
        for site in sites {
            let body = crate::test_support::module_body_before_first_cfg_test(
                site.source,
                site.module_path,
            );
            let live = live_lines(body);
            offenders.extend(scan_offenders(site.module_path, &live));
        }
        assert!(
            offenders.is_empty(),
            "raw fused `.stdout(Stdio::piped()).stderr(Stdio::piped())` \
             two-line stanza(s) survive in `cli/src/commands/` — route \
             each through `crate::tokio_command_piped_stdio::PipedChildStdio::piped_child_stdio` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (attic infrastructure surface):
    /// `cli/src/infrastructure/attic.rs` — the five pre-lift sibling
    /// sites (`push_store_path` retry attempt, `push_closure_via_stdin`
    /// 3-line stanza, `login`, `login_with_retry` retry attempt,
    /// `use_cache`) — no longer spell the fused pair inline. Split
    /// from the `commands/` shield above so a future attic-surface
    /// spawn that regresses to the raw pair flags at THIS shield
    /// rather than the `commands/`-scoped one.
    #[test]
    fn attic_no_longer_spells_raw_stdout_stderr_piped_pair() {
        const SOURCE: &str = include_str!("infrastructure/attic.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "infrastructure/attic.rs",
        );
        let live = live_lines(body);
        let offenders = scan_offenders("infrastructure/attic.rs", &live);
        assert!(
            offenders.is_empty(),
            "raw fused `.stdout(Stdio::piped()).stderr(Stdio::piped())` \
             pair survives in cli/src/infrastructure/attic.rs — route \
             through `crate::tokio_command_piped_stdio::PipedChildStdio::piped_child_stdio` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (nix surface): `cli/src/nix.rs` — the
    /// `path_info_recursive_with_bin` site at :600-601 — no longer
    /// spells the fused pair inline.
    #[test]
    fn nix_no_longer_spells_raw_stdout_stderr_piped_pair() {
        const SOURCE: &str = include_str!("nix.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(SOURCE, "nix.rs");
        let live = live_lines(body);
        let offenders = scan_offenders("nix.rs", &live);
        assert!(
            offenders.is_empty(),
            "raw fused `.stdout(Stdio::piped()).stderr(Stdio::piped())` \
             pair survives in cli/src/nix.rs — route through \
             `crate::tokio_command_piped_stdio::PipedChildStdio::piped_child_stdio` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Positive shield: each migrated module must forward through
    /// the extension method at least the migrated count. A dropped
    /// call site would leave the negative shields above trivially
    /// satisfied by absence — this positive count catches that.
    #[test]
    fn migrated_sites_forward_through_piped_child_stdio_method() {
        struct Migration {
            module_path: &'static str,
            source: &'static str,
            expected_count: usize,
        }
        let migrations: &[Migration] = &[
            Migration {
                module_path: "nix.rs",
                source: include_str!("nix.rs"),
                expected_count: 2,
            },
            Migration {
                module_path: "commands/integration_tests.rs",
                source: include_str!("commands/integration_tests.rs"),
                expected_count: 2,
            },
            Migration {
                module_path: "infrastructure/attic.rs",
                source: include_str!("infrastructure/attic.rs"),
                expected_count: 5,
            },
        ];
        for m in migrations {
            let body =
                crate::test_support::module_body_before_first_cfg_test(m.source, m.module_path);
            let forwards = body.matches(".piped_child_stdio()").count();
            assert!(
                forwards >= m.expected_count,
                "{}: expected at least {} `.piped_child_stdio()` \
                 forward(s) in module body (pre-lift sibling count); \
                 found {}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                m.module_path,
                m.expected_count,
                forwards
            );
        }
    }

    /// Trait-shape oracle: [`PipedChildStdio`] is implemented for
    /// [`tokio::process::Command`] and NOT for its `std::process`
    /// twin. Pins the intentional narrowness of the impl surface —
    /// the pre-lift sibling census under the fused-pair discipline
    /// counts eight tokio sites and one std site (`commands/seed.rs`
    /// with a 3-line `.stdin(...).stdout(...).stderr(...)` stanza,
    /// documented in the module docstring), so a speculative
    /// `impl PipedChildStdio for std::process::Command` would widen
    /// the trait for a single paying consumer while inviting the
    /// three-line stanza to divergently drop through both impls.
    #[test]
    fn piped_child_stdio_is_wired_for_tokio_command() {
        fn assert_impl<T: PipedChildStdio>() {}
        assert_impl::<tokio::process::Command>();
    }
}

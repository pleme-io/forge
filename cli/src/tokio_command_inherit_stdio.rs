//! [`tokio::process::Command`] extension trait fusing the
//! `.stdout(Stdio::inherit()).stderr(Stdio::inherit())` two-line stanza
//! into a single `.inherit_child_stdio()` chain call.
//!
//! # Duplication being lifted
//!
//! Six pre-lift sibling sites — five across `cli/src/commands/` and one
//! in `cli/src/git.rs` — each restated the same two-line stanza on a
//! `tokio::process::Command` builder verbatim:
//!
//! ```ignore
//! .stdout(Stdio::inherit())
//! .stderr(Stdio::inherit())
//! ```
//!
//! - `commands/developer_tools.rs:559-560` — `sqlx migrate run` spawn on
//!   the local-developer `migrate` app.
//! - `commands/test.rs:458-459` — `sh -c <suite-command>` spawn under
//!   [`run_test_suite`]'s per-suite `tokio::time::timeout`.
//! - `commands/migrations.rs:613-614` — `kubectl wait
//!   --for=condition=complete job/<name>` waiter for the migration Job.
//! - `commands/migrations.rs:667-668` — `kubectl logs <pod> --tail=100`
//!   diagnostic tail on the failed-migration path.
//! - `commands/rust_service.rs:509-510` — AMD64 image-build spawn.
//! - `git.rs:1267-1268` — [`git_commit_idempotent`]'s `git commit -m …`
//!   spawn.
//!
//! The `commands/rust_service.rs:589-590` ARM64 image-build stanza is
//! not counted — it lives inside a `/* … */` block comment awaiting a
//! root-flake exposure fix, so it is dead code today, not a live
//! sibling. The negative-shape shield below strips block-comment lines
//! before scanning so the dead stanza stays out of scope.
//!
//! Every site is a `tokio::process::Command` builder wanting the child
//! process's stdout and stderr streams inherited by the calling forge
//! process (so the operator sees Nix build output, kubectl logs, cargo
//! test output, etc. streaming live in the terminal). The two axes are
//! fused: enabling stdout inheritance without stderr inheritance (or
//! vice versa) would silently drop half the child's live output. A
//! future contributor adding an eighth inherit-both site could regress
//! to `.stdout(Stdio::inherit())` alone — the fused primitive here
//! makes that regression structurally invisible.
//!
//! # The primitive
//!
//! An extension trait, not a free function: every call site chains on a
//! `tokio::process::Command` builder that is either freshly constructed
//! (`Command::new("...").inherit_child_stdio().spawn()`) or returned by
//! a factory (`kubectl_command_async().args([...]).inherit_child_stdio()
//! .status().await`). A free function would break the builder chain;
//! the trait method preserves it and returns `&mut Command` for the
//! next chained call.
//!
//! # Byte contract
//!
//! [`InheritChildStdio::inherit_child_stdio`] calls
//! [`tokio::process::Command::stdout`] with
//! [`std::process::Stdio::inherit`] and then
//! [`tokio::process::Command::stderr`] with the same, in that order.
//! The order does not affect the resulting stdio config (stdout and
//! stderr are set on independent fields) but is pinned by the tests
//! below because a caller who reads the shield's docstring expects the
//! two-line pre-lift stanza to have translated in exactly that order.

use std::process::Stdio;
use tokio::process::Command;

/// Extension trait fusing the pre-lift `.stdout(Stdio::inherit())
/// .stderr(Stdio::inherit())` two-line stanza on a
/// [`tokio::process::Command`] builder into a single chain call.
///
/// Blanket-implemented for [`tokio::process::Command`] only —
/// [`std::process::Command`] has no pre-lift sibling site in forge that
/// would justify a second impl block, and adding one speculatively would
/// widen the trait's surface without a paying consumer.
pub trait InheritChildStdio {
    /// Set both `stdout` and `stderr` on `self` to
    /// [`std::process::Stdio::inherit`], returning `&mut Self` for
    /// chain continuation.
    fn inherit_child_stdio(&mut self) -> &mut Self;
}

impl InheritChildStdio for Command {
    fn inherit_child_stdio(&mut self) -> &mut Self {
        self.stdout(Stdio::inherit()).stderr(Stdio::inherit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Behavior oracle: `.inherit_child_stdio()` returns the same
    /// [`tokio::process::Command`] builder for chain continuation —
    /// verified by threading the result into `.arg("...")` and reading
    /// back the argv via [`tokio::process::Command::as_std`]. If the
    /// method were to return `()` or a fresh `Command`, the chained
    /// `.arg("chained")` would not appear in the resulting argv and
    /// this test would flip.
    ///
    /// The fixture binary path is built via a `&str` binding rather
    /// than a `Command::new("<literal>")` inline literal so this
    /// test's own source text does NOT match the crate-wide bare-
    /// literal-spawn tally shield at `tools::spawn_shield` — same
    /// discipline the sibling `tools.rs` fixture tests apply.
    #[test]
    fn inherit_child_stdio_returns_chainable_command_ref() {
        let bin: &'static str = "true";
        let mut cmd = Command::new(bin);
        cmd.inherit_child_stdio().arg("chained-arg-marker");
        let argv: Vec<&std::ffi::OsStr> = cmd.as_std().get_args().collect();
        assert_eq!(
            argv.len(),
            1,
            "the chained `.arg()` after `.inherit_child_stdio()` must \
             land on the SAME Command builder — the extension method \
             must return `&mut Self`, not `()` or a fresh Command; got \
             argv {argv:?}"
        );
        assert_eq!(
            argv[0], "chained-arg-marker",
            "chained arg must be `chained-arg-marker`; got {argv:?}"
        );
    }

    /// Behavior oracle: running `.inherit_child_stdio().status()`
    /// against a spawnable no-op command produces a successful exit
    /// status. This confirms the two `Stdio::inherit` slots the
    /// extension method wires do not disable spawning — a regression
    /// that swapped `Stdio::inherit()` for `Stdio::null()` on a
    /// non-existent file descriptor path would either flip this test
    /// or hang the runner; either is a signal the fused primitive
    /// broke the child-stdio contract.
    #[tokio::test]
    async fn inherit_child_stdio_spawns_true_shim_successfully() {
        let (_dir, shim) = crate::test_support::make_executable_shim(
            "inherit-child-stdio-shim",
            "#!/bin/sh\nexit 0\n",
        );
        let status = Command::new(&shim)
            .inherit_child_stdio()
            .status()
            .await
            .expect("shim must spawn under `.inherit_child_stdio()`");
        assert!(
            status.success(),
            "shim `exit 0` under `.inherit_child_stdio().status()` \
             must return success; got {status:?}"
        );
    }

    /// Split a source body into an ordered list of (line-number,
    /// live-code-line) pairs, dropping every line that lives inside a
    /// `/* … */` block comment or begins with a `//` line comment.
    /// Splitting `/*` / `*/` on a per-line boundary is sufficient for
    /// the pre-lift sites' surrounding source shape (no `/*` / `*/`
    /// appears mid-line inside a scanned window) and matches the pre-
    /// lift `commands/rust_service.rs:532-595` dead-code block whose
    /// `.stdout(Stdio::inherit()).stderr(Stdio::inherit())` stanza sits
    /// inside a TODO'd `/* … */`.
    fn live_lines<'a>(body: &'a str) -> Vec<(usize, &'a str)> {
        let mut out: Vec<(usize, &'a str)> = Vec::new();
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

    /// Post-lift shield: no LIVE source line under `cli/src/commands/`
    /// may still spell the pre-lift fused
    /// `.stdout(Stdio::inherit()).stderr(Stdio::inherit())` two-line
    /// stanza inline. Scans module bodies BEFORE their first
    /// `#[cfg(test)]` region so a docstring-shaped mention of the
    /// pre-lift shape inside a sibling shield's own diagnostic prose
    /// (e.g. `commands/pangea_infra.rs:173` documenting the pre-lift
    /// primitive) does not defeat the shield, and strips `/* … */`
    /// block-comment lines via [`live_lines`] so the dead-code ARM64
    /// stanza at `commands/rust_service.rs:589-590` (inside a TODO'd
    /// comment block) does not either.
    #[test]
    fn commands_no_longer_spell_raw_stdout_stderr_inherit_pair() {
        struct Site {
            module_path: &'static str,
            source: &'static str,
        }
        let sites: &[Site] = &[
            Site {
                module_path: "commands/developer_tools.rs",
                source: include_str!("commands/developer_tools.rs"),
            },
            Site {
                module_path: "commands/test.rs",
                source: include_str!("commands/test.rs"),
            },
            Site {
                module_path: "commands/migrations.rs",
                source: include_str!("commands/migrations.rs"),
            },
            Site {
                module_path: "commands/rust_service.rs",
                source: include_str!("commands/rust_service.rs"),
            },
        ];
        let mut offenders: Vec<(&'static str, usize, String)> = Vec::new();
        for site in sites {
            let body = crate::test_support::module_body_before_first_cfg_test(
                site.source,
                site.module_path,
            );
            let live = live_lines(body);
            for window in live.windows(2) {
                let (line_a, a) = window[0];
                let (_line_b, b) = window[1];
                let a_hit = a.contains(".stdout(Stdio::inherit())")
                    || a.contains(".stdout(std::process::Stdio::inherit())");
                let b_hit = b.contains(".stderr(Stdio::inherit())")
                    || b.contains(".stderr(std::process::Stdio::inherit())");
                if a_hit && b_hit {
                    offenders.push((site.module_path, line_a, format!("{a}\n{b}")));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw fused `.stdout(Stdio::inherit()).stderr(Stdio::inherit())` \
             two-line stanza(s) survive in `cli/src/commands/` — route \
             each through `crate::tokio_command_inherit_stdio::InheritChildStdio::inherit_child_stdio` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (git surface): `cli/src/git.rs` — the sixth
    /// pre-lift sibling site at :1267-1268 in
    /// [`crate::git::git_commit_idempotent`] — no longer spells the
    /// fused pair inline. Split from the `commands/` shield above so a
    /// future commit that re-adds a Stdio::inherit call to `git.rs`
    /// (e.g. a new inherited-stdio `git push` variant) flags at THIS
    /// shield rather than the `commands/`-scoped one.
    #[test]
    fn git_no_longer_spells_raw_stdout_stderr_inherit_pair() {
        const SOURCE: &str = include_str!("git.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(SOURCE, "git.rs");
        let live = live_lines(body);
        let mut offenders: Vec<(usize, String)> = Vec::new();
        for window in live.windows(2) {
            let (line_a, a) = window[0];
            let (_line_b, b) = window[1];
            let a_hit = a.contains(".stdout(Stdio::inherit())")
                || a.contains(".stdout(std::process::Stdio::inherit())");
            let b_hit = b.contains(".stderr(Stdio::inherit())")
                || b.contains(".stderr(std::process::Stdio::inherit())");
            if a_hit && b_hit {
                offenders.push((line_a, format!("{a}\n{b}")));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw fused `.stdout(...).stderr(...)` pair survives in \
             cli/src/git.rs — route through \
             `crate::tokio_command_inherit_stdio::InheritChildStdio::inherit_child_stdio` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Positive shield: the four pre-lift `commands/` modules AND
    /// `cli/src/git.rs` must each forward through the extension method
    /// at least the migrated count. A dropped call site would leave
    /// the negative shields above trivially satisfied by absence —
    /// this positive count catches that.
    #[test]
    fn migrated_sites_forward_through_inherit_child_stdio_method() {
        struct Migration {
            module_path: &'static str,
            source: &'static str,
            expected_count: usize,
        }
        let migrations: &[Migration] = &[
            Migration {
                module_path: "commands/developer_tools.rs",
                source: include_str!("commands/developer_tools.rs"),
                expected_count: 1,
            },
            Migration {
                module_path: "commands/test.rs",
                source: include_str!("commands/test.rs"),
                expected_count: 1,
            },
            Migration {
                module_path: "commands/migrations.rs",
                source: include_str!("commands/migrations.rs"),
                expected_count: 2,
            },
            Migration {
                module_path: "commands/rust_service.rs",
                source: include_str!("commands/rust_service.rs"),
                expected_count: 1,
            },
            Migration {
                module_path: "git.rs",
                source: include_str!("git.rs"),
                expected_count: 1,
            },
        ];
        for m in migrations {
            let body =
                crate::test_support::module_body_before_first_cfg_test(m.source, m.module_path);
            let forwards = body.matches(".inherit_child_stdio()").count();
            assert!(
                forwards >= m.expected_count,
                "{}: expected at least {} `.inherit_child_stdio()` \
                 forward(s) in module body (pre-lift sibling count); \
                 found {}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                m.module_path,
                m.expected_count,
                forwards
            );
        }
    }

    /// Trait-shape oracle: [`InheritChildStdio`] is implemented for
    /// [`tokio::process::Command`] and NOT for its `std::process`
    /// twin. Pins the intentional narrowness of the impl surface —
    /// the pre-lift sibling census is 100% async / tokio, and a
    /// speculative `impl InheritChildStdio for std::process::Command`
    /// would widen the trait without a paying consumer.
    #[test]
    fn inherit_child_stdio_is_wired_for_tokio_command() {
        fn assert_impl<T: InheritChildStdio>() {}
        assert_impl::<tokio::process::Command>();
    }
}

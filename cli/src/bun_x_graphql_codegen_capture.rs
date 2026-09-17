//! Captured-output `bun x graphql-codegen --config codegen.ts` spawn
//! primitive — the composition every schema/codegen-driven consumer
//! spelled inline immediately after its `let bun = bun_bin();` sigil
//! resolve.
//!
//! # Pre-lift census — three sibling stanzas, one splayed only on error envelope
//!
//! Three consumer sites each spelled the same six-line captured-output
//! spawn composition — `Command::new(&bun)` + `.args(crate::bun_argv::
//! bun_x_graphql_codegen_argv())` + `.current_dir(<web_dir>)` +
//! `.output().await` — verbatim, and each wrapped the resulting
//! [`std::io::Result`] with its own [`anyhow::Context`] envelope
//! (differing only in the message string, which stays with the caller):
//!
//! 1. `commands/codegen.rs::execute` (Step 3 codegen run, `web_dir:
//!    &Path`, `.with_context(|| format!("Failed to run graphql-codegen
//!    in {}", web_dir.display()))?`).
//! 2. `commands/codegen_validation.rs::validate_schema_and_codegen`
//!    (drift-check codegen run, `web_dir: &Path`, same
//!    `.with_context(|| format!("Failed to run graphql-codegen in {}",
//!    web_dir.display()))?` envelope byte-for-byte).
//! 3. `commands/sync.rs::execute_drift_check` (schema-vs-codegen drift
//!    check, `&config.web_dir`, one-arg
//!    `.context("Failed to run graphql-codegen")?` envelope).
//!
//! A drift in the spawn composition — a swap of `.output()` for
//! `.status()` (loses stderr), a dropped `.current_dir(web_dir)`
//! (spawns codegen in forge's own cwd, whose `codegen.ts` won't
//! match), an argv-order swap between subcommand and flag, a
//! `.envs(...)` addition that leaked forge's `RUST_LOG` into bun's
//! process env — pre-lift had to hit three sites in lockstep or
//! diverge; post-lift it hits ONE typed body and every consumer
//! inherits the change from
//! [`run_bun_x_graphql_codegen_capture_at`].
//!
//! # Why the `.context(...)` envelope stays with the caller
//!
//! Each of the three sites processes the returned
//! [`std::io::Result<std::process::Output>`] differently on the failure
//! arm:
//!
//! - `commands/codegen.rs::execute` bubbles via `anyhow::bail!` with
//!   a formatted `stderr` and `stdout` join.
//! - `commands/codegen_validation.rs::validate_schema_and_codegen`
//!   walks a `drift_indicators` array over the joined `stderr` and
//!   `stdout` to decide whether the failure is drift-shaped or a
//!   raw codegen crash, and lands each in the
//!   [`crate::commands::codegen_validation::CodegenValidationResult`]
//!   struct as an `error: Some(String)` with distinct message
//!   phrasing.
//! - `commands/sync.rs::execute_drift_check` returns a
//!   [`crate::commands::sync::DriftCheckResult`] with `error:
//!   Some("codegen failed".to_string())` on the failure arm.
//!
//! A fused primitive that bail-on-non-zero would collapse every
//! per-site processing shape into one envelope and lose the
//! per-site error phrasing the drift-vs-crash discriminator and the
//! result-struct callers depend on. So the primitive owns ONLY the
//! spawn composition through `.output().await`, and each caller wraps
//! the returned `Result` with its own
//! `.context(...)` / `.with_context(...)` shape.
//!
//! # Sibling of the `bun_argv` primitive family
//!
//! [`crate::bun_argv::bun_x_graphql_codegen_argv`] owns the 4-element
//! argv slice (`["x", "graphql-codegen", "--config", "codegen.ts"]`);
//! this primitive owns the surrounding tokio-`Command` builder chain
//! that consumes it. The two compose:
//! `Command::new(bun_bin()).args(bun_x_graphql_codegen_argv())
//! .current_dir(web_dir).output().await`. A future refinement of
//! the argv shape (a `--overwrite` toggle, a `codegen.ts` -> `codegen.mjs`
//! rename by graphql-codegen) lands in `bun_argv`; a future refinement
//! of the spawn composition (a `.kill_on_drop(true)` addition, a
//! per-site `.env(...)` pass-through) lands here. Both refinements
//! reach every consumer through the same
//! [`run_bun_x_graphql_codegen_capture_at`] fan-in point.
//!
//! # `bun` binary resolution stays with the caller's sigil
//!
//! Each pre-lift module carries a module-scoped `fn bun_bin() ->
//! String { get_tool_path("BUN_BIN", "bun") }` sigil pinned by a
//! module-local `bun_env_routing_tests` shield ("the two-argument
//! resolve appears in EXACTLY one place"). Threading the `bun` path
//! through this primitive as a `bun: &str` argument — rather than
//! calling [`crate::repo::get_tool_path`] internally — keeps every
//! caller's shield still passing after the lift: the primitive
//! introduces no additional `get_tool_path("BUN_BIN", "bun")` call
//! site inside any caller's module scope, and the caller's `let
//! bun = bun_bin();` binding (shared with the sibling `bun install`
//! spawn in the same function) continues to feed both spawn sites
//! from the same one resolution.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `bun x graphql-codegen`
//! captured-output spawn composition lives at ONE construction
//! surface so a future refinement lands in one place rather than at
//! every consumer.
//!
//! §VI.1 one-oracle typed contract: the tokio-`Command` builder
//! chain is a construction surface with one owner; every consumer
//! reaches for [`run_bun_x_graphql_codegen_capture_at`] on first
//! grep, not by copy-pasting the raw six-line chain from an existing
//! command module.

use std::path::Path;

use tokio::process::Command;

/// Build the tokio [`Command`] for a `bun x graphql-codegen --config
/// codegen.ts` captured-output spawn scoped to `web_dir`, resolving the
/// `bun` binary from `bun` (caller's module-scoped `bun_bin()` sigil
/// result).
///
/// Splitting the `Command` factory out from the spawn-and-await
/// [`run_bun_x_graphql_codegen_capture_at`] lets the byte-oracle tests
/// pin the exact argv shape and `current_dir` via
/// [`Command::get_program`] and [`Command::get_args`] without ever
/// spawning `bun` under `cargo test` (the primitive stays pure
/// construction).
pub fn build_bun_x_graphql_codegen_capture_command(bun: &str, web_dir: &Path) -> Command {
    let mut cmd = Command::new(bun);
    cmd.args(crate::bun_argv::bun_x_graphql_codegen_argv())
        .current_dir(web_dir);
    cmd
}

/// Spawn `bun x graphql-codegen --config codegen.ts` at `web_dir`,
/// capturing stdout/stderr, and return the raw
/// [`std::process::Output`] regardless of exit status — the
/// captured-output spawn composition three pre-lift consumers
/// (`commands/codegen.rs::execute`,
/// `commands/codegen_validation.rs::validate_schema_and_codegen`,
/// `commands/sync.rs::execute_drift_check`) each spelled inline.
///
/// # Ok arm
///
/// Returns the raw [`std::process::Output`] on spawn success,
/// regardless of `output.status.success()` — each caller inspects the
/// exit status itself to distinguish drift-shaped codegen failure from
/// a raw crash, and reaches for `output.stderr` / `output.stdout`
/// verbatim.
///
/// # Err arm
///
/// Returns [`std::io::Error`] on spawn failure (e.g., the `bun`
/// binary path does not exist, `web_dir` is not accessible). Each
/// caller wraps the error with its own [`anyhow::Context`] shape (see
/// module docs for the three call-site envelopes).
pub async fn run_bun_x_graphql_codegen_capture_at(
    bun: &str,
    web_dir: &Path,
) -> std::io::Result<std::process::Output> {
    build_bun_x_graphql_codegen_capture_command(bun, web_dir)
        .output()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Byte-oracle: the `Command` built by
    /// [`build_bun_x_graphql_codegen_capture_command`] spawns `bun` as
    /// its program — the exact bin string threaded through by the
    /// caller — with no wrapping shell (`/bin/sh -c`), no `env`
    /// prefix, and no `nix run --` shim. A refactor that shelled out
    /// through `sh -c` would defeat the `.current_dir(web_dir)`
    /// scoping (the shell would inherit the parent's cwd on some
    /// hosts) and reopen a shell-quoting attack surface for any future
    /// caller-supplied argv element.
    #[test]
    fn build_bun_x_graphql_codegen_capture_command_uses_supplied_bun_as_program() {
        let cmd = build_bun_x_graphql_codegen_capture_command(
            "/nix/store/xyz-bun/bin/bun",
            Path::new("/repo/web"),
        );
        let std_cmd: &std::process::Command = cmd.as_std();
        assert_eq!(
            std_cmd.get_program(),
            std::ffi::OsStr::new("/nix/store/xyz-bun/bin/bun"),
            "the built Command must spawn the supplied `bun` binary \
             directly — no `sh -c` wrapper, no `env` prefix, no `nix \
             run` shim"
        );
    }

    /// Byte-oracle: the built `Command`'s argv is exactly the
    /// pre-lift 4-element slice
    /// `["x", "graphql-codegen", "--config", "codegen.ts"]`, in that
    /// order, with no extra element and no rewritten value. Same
    /// four elements the sibling
    /// [`crate::bun_argv::bun_x_graphql_codegen_argv`] byte-oracle
    /// pins, projected here from the composed builder chain via
    /// [`Command::get_args`] to prove the argv slice reaches the
    /// spawn boundary verbatim (no `.arg("--verbose")` addition, no
    /// argv-order rewrite, no dropped element).
    #[test]
    fn build_bun_x_graphql_codegen_capture_command_carries_pre_lift_argv_verbatim() {
        let cmd = build_bun_x_graphql_codegen_capture_command("bun", Path::new("/w"));
        let std_cmd: &std::process::Command = cmd.as_std();
        let args: Vec<&std::ffi::OsStr> = std_cmd.get_args().collect();
        assert_eq!(
            args,
            vec![
                std::ffi::OsStr::new("x"),
                std::ffi::OsStr::new("graphql-codegen"),
                std::ffi::OsStr::new("--config"),
                std::ffi::OsStr::new("codegen.ts"),
            ],
            "the built Command's argv must be exactly the pre-lift \
             4-element `bun_x_graphql_codegen_argv` slice, in order"
        );
    }

    /// Byte-oracle: the caller-supplied `web_dir` reaches the built
    /// `Command`'s [`Command::get_current_dir`] verbatim — a dropped
    /// `.current_dir(web_dir)` (which would spawn codegen in forge's
    /// own cwd, missing the caller's `codegen.ts` config) or a swap
    /// to `.env("PWD", web_dir)` (which does not scope the spawn) is
    /// caught here.
    #[test]
    fn build_bun_x_graphql_codegen_capture_command_scopes_current_dir_to_web_dir() {
        let web = PathBuf::from("/repo/apps/web");
        let cmd = build_bun_x_graphql_codegen_capture_command("bun", &web);
        let std_cmd: &std::process::Command = cmd.as_std();
        assert_eq!(
            std_cmd.get_current_dir(),
            Some(web.as_path()),
            "the built Command's current_dir must be the supplied \
             `web_dir` verbatim — a dropped `.current_dir(web_dir)` \
             or a swap to an env-var-only shape would leave this None"
        );
    }

    /// Byte-oracle: the built `Command` inherits no ambient env
    /// entries beyond the caller's process environment — no
    /// `.env(...)` calls appear in the builder chain. A future
    /// `.env("BUN_INSTALL_CACHE", ...)` pass-through would appear as
    /// a non-empty [`Command::get_envs`] override list.
    #[test]
    fn build_bun_x_graphql_codegen_capture_command_carries_no_env_overrides() {
        let cmd = build_bun_x_graphql_codegen_capture_command("bun", Path::new("/w"));
        let std_cmd: &std::process::Command = cmd.as_std();
        assert_eq!(
            std_cmd.get_envs().count(),
            0,
            "the built Command must carry no `.env(...)` overrides — \
             the pre-lift three consumers each spelled the six-line \
             chain with no env pass-through"
        );
    }

    /// Post-lift shield (negative): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw
    /// `Command::new(&bun).args(crate::bun_argv::bun_x_graphql_codegen_argv())`
    /// composition inline. Every consumer reaches for
    /// [`run_bun_x_graphql_codegen_capture_at`] on first grep, not by
    /// copy-pasting the raw six-line chain from an existing command
    /// module. Scoped to non-comment lines so a docstring mention of
    /// the raw shape does not defeat the shield.
    #[test]
    fn no_command_module_still_spells_raw_bun_x_graphql_codegen_capture_chain() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle_head = "Command::new(&bun)";
        // Reconstruct the `.args(...)` head via format! so this
        // shield's own source never contains the literal
        // `bun_x_graphql_codegen_argv` string on a code line and
        // cannot false-match itself.
        let argv_fn = format!("{}bun_x_graphql_codegen_argv", "crate::bun_argv::");
        let mut offenders: Vec<(StdPathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if !line.contains(needle_head) {
                    continue;
                }
                // Look ahead up to 3 lines for the argv-fn hit — the
                // raw stanza spans `Command::new(&bun)` on line N and
                // `.args(crate::bun_argv::bun_x_graphql_codegen_argv())`
                // on line N+1 in the pre-lift shape.
                let window_end = (idx + 4).min(lines.len());
                let has_argv_fn = lines[idx..window_end].iter().any(|l| l.contains(&argv_fn));
                if has_argv_fn {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `Command::new(&bun).args({}())` composition(s) \
             survive under `commands/` — route each through \
             `crate::bun_x_graphql_codegen_capture::\
             run_bun_x_graphql_codegen_capture_at(&bun, web_dir)` \
             instead:\n{:#?}",
            argv_fn,
            offenders
        );
    }

    /// Post-lift shield (positive): the three pre-lift modules MUST
    /// forward through [`run_bun_x_graphql_codegen_capture_at`] at
    /// least once each. A migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_bun_x_graphql_codegen_capture() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[
            ("codegen.rs", 1),
            ("codegen_validation.rs", 1),
            ("sync.rs", 1),
        ];
        let needle = "run_bun_x_graphql_codegen_capture_at(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `bun x graphql-codegen` captured-output spawn site(s) \
                 through `{needle}`; found {forwards}. A dropped call \
                 would leave the negative raw-shape scan satisfied by \
                 absence.",
            );
        }
    }
}

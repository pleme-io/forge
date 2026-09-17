//! Captured-output `bun install --frozen-lockfile` spawn primitive —
//! the composition every schema/codegen-adjacent consumer spelled
//! inline immediately after its `let bun = bun_bin();` sigil resolve,
//! sibling to
//! [`crate::bun_x_graphql_codegen_capture`] on the same bun-frontier.
//!
//! # Pre-lift census — three sibling stanzas over one construction shape
//!
//! Three consumer sites each spelled the same tokio-`Command` builder
//! chain — `Command::new(&bun)` + `.args(crate::bun_argv::
//! bun_install_frozen_lockfile_argv())` + `.current_dir(<web_dir>)`
//! — verbatim, differing only in the downstream consumption of the
//! resulting future and the per-site error envelope:
//!
//! 1. `commands/codegen.rs::execute` (Step 3 preamble, `web_dir:
//!    &Path`): handed the constructed [`Command`] to
//!    [`crate::retry::run_capture_anyhow`] with the op label
//!    `"bun install"`, wrapping the anyhow error with
//!    `.with_context(|| format!("bun install in {}",
//!    web_dir.display()))?`.
//! 2. `commands/codegen_validation.rs::validate_schema_and_codegen`
//!    (drift-detection gate, `web_dir: &Path`): drove the constructed
//!    [`Command`] through a bare `.output().await` and wrapped the
//!    [`std::io::Result`] with `.with_context(|| format!("Failed to
//!    run bun install in {}", web_dir.display()))?`.
//! 3. `commands/sync.rs::execute_drift_check` (drift-check gate,
//!    `&config.web_dir`): drove the constructed [`Command`] through a
//!    bare `.output().await` and wrapped the [`std::io::Result`] with
//!    one-arg `.context("Failed to run bun install")?`.
//!
//! A drift in the construction shape — a dropped
//! `.current_dir(web_dir)` (spawns bun in forge's own cwd, whose
//! `package.json` won't match), an argv-order swap between
//! `install` and `--frozen-lockfile`, a `.envs(...)` addition that
//! leaked forge's `RUST_LOG` into bun's process env, a swap of
//! `bun` for a hard-coded `Command::new("bun")` bypassing the
//! caller's `BUN_BIN` sigil — pre-lift had to hit three sites in
//! lockstep or diverge; post-lift it lands at ONE typed body and
//! every consumer inherits the change from
//! [`build_bun_install_frozen_lockfile_capture_command`].
//!
//! # Two entry points partition the async / anyhow-shape axes
//!
//! Two consumers ([`crate::commands::codegen_validation`],
//! [`crate::commands::sync`]) drive the constructed [`Command`]
//! through a bare `.output().await` and wrap the raw
//! [`std::io::Result<std::process::Output>`] with their own
//! [`anyhow::Context`] envelope — each returns the raw
//! [`std::process::Output`] on spawn success and inspects
//! `output.status.success()` itself to distinguish `bun install`
//! failure from a downstream codegen failure, landing the result
//! bytes in a caller-shaped `Result` struct
//! ([`crate::commands::codegen_validation::CodegenValidationResult`] /
//! [`crate::commands::sync::DriftCheckResult`]) with per-caller
//! `error: Some(String)` phrasing. The third consumer
//! ([`crate::commands::codegen`]) reaches for
//! [`crate::retry::run_capture_anyhow`] which bail-on-non-zeros into
//! the canonical `"<op> failed: {stderr}"` anyhow envelope — a
//! different shape.
//!
//! [`run_bun_install_frozen_lockfile_capture_at`] owns the bare
//! `.output().await` variant that consumers 2 and 3 reach for;
//! [`build_bun_install_frozen_lockfile_capture_command`] is the
//! `Command` factory consumer 1 hands off to
//! [`crate::retry::run_capture_anyhow`]. Both entry points route the
//! same construction body — the `Command` factory — so a future
//! refinement of the construction (a `.kill_on_drop(true)`
//! addition, a per-site `.env(...)` pass-through) lands in one
//! place rather than being restated at every consumer.
//!
//! A fused primitive that bail-on-non-zeroed would collapse the
//! per-site processing shape consumers 2 and 3 depend on (a
//! `DriftCheckResult { error: Some("bun install failed") }` return
//! vs. a bubbled `anyhow::bail!`) and lose the per-site error
//! phrasing the result-struct callers narrate — so the primitive
//! owns ONLY the construction (and the bare `.output().await`
//! runner), and each caller wraps the return with its own
//! `.context(...)` / `.with_context(...)` shape.
//!
//! # Sibling of the `bun_argv` primitive family
//!
//! [`crate::bun_argv::bun_install_frozen_lockfile_argv`] owns the
//! 2-element argv slice (`["install", "--frozen-lockfile"]`); this
//! primitive owns the surrounding tokio-`Command` builder chain that
//! consumes it. The two compose:
//! `Command::new(bun_bin()).args(bun_install_frozen_lockfile_argv())
//! .current_dir(web_dir)`. A future refinement of the argv shape (a
//! `--production` toggle, a `--no-scripts` addition) lands in
//! `bun_argv`; a future refinement of the spawn composition (a
//! `.kill_on_drop(true)` addition, an `.env("BUN_INSTALL_CACHE",
//! ...)` pass-through for a hermetic bun-cache-dir contract) lands
//! here. Both refinements reach every consumer through the same
//! [`build_bun_install_frozen_lockfile_capture_command`] fan-in
//! point. Mirrors the sibling
//! [`crate::bun_x_graphql_codegen_capture`] partition exactly.
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
//! bun = bun_bin();` binding (shared with the sibling
//! [`crate::bun_x_graphql_codegen_capture::run_bun_x_graphql_codegen_capture_at`]
//! spawn in the same function) continues to feed both spawn sites
//! from the same one resolution.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `bun install --frozen-lockfile`
//! captured-output spawn composition lives at ONE construction
//! surface so a future refinement lands in one place rather than at
//! every consumer.
//!
//! §VI.1 one-oracle typed contract: the tokio-`Command` builder
//! chain is a construction surface with one owner; every consumer
//! reaches for [`build_bun_install_frozen_lockfile_capture_command`]
//! (or its `.output().await` runner sibling) on first grep, not by
//! copy-pasting the raw builder chain from an existing command
//! module.

use std::path::Path;

use tokio::process::Command;

/// Build the tokio [`Command`] for a `bun install --frozen-lockfile`
/// captured-output spawn scoped to `web_dir`, resolving the `bun`
/// binary from `bun` (caller's module-scoped `bun_bin()` sigil
/// result).
///
/// Splitting the `Command` factory out from the spawn-and-await
/// [`run_bun_install_frozen_lockfile_capture_at`] lets the
/// [`crate::commands::codegen`] caller hand the constructed
/// [`Command`] off to [`crate::retry::run_capture_anyhow`]
/// (bail-on-non-zero anyhow envelope) while the two bare-`.output()`
/// consumers reach for the runner sibling. It also lets the
/// byte-oracle tests pin the exact argv shape, `current_dir`, and
/// env-override count via [`Command::get_program`],
/// [`Command::get_args`], [`Command::get_current_dir`], and
/// [`Command::get_envs`] without ever spawning `bun` under
/// `cargo test` (the primitive stays pure construction).
pub fn build_bun_install_frozen_lockfile_capture_command(bun: &str, web_dir: &Path) -> Command {
    let mut cmd = Command::new(bun);
    cmd.args(crate::bun_argv::bun_install_frozen_lockfile_argv())
        .current_dir(web_dir);
    cmd
}

/// Spawn `bun install --frozen-lockfile` at `web_dir`, capturing
/// stdout/stderr, and return the raw [`std::process::Output`]
/// regardless of exit status — the bare `.output().await` spawn
/// composition two pre-lift consumers
/// (`commands/codegen_validation.rs::validate_schema_and_codegen`,
/// `commands/sync.rs::execute_drift_check`) each spelled inline.
///
/// # Ok arm
///
/// Returns the raw [`std::process::Output`] on spawn success,
/// regardless of `output.status.success()` — each caller inspects the
/// exit status itself and lands the failure in a caller-shaped
/// `Result` struct with per-caller error phrasing (see module docs).
///
/// # Err arm
///
/// Returns [`std::io::Error`] on spawn failure (e.g., the `bun`
/// binary path does not exist, `web_dir` is not accessible). Each
/// caller wraps the error with its own [`anyhow::Context`] shape.
pub async fn run_bun_install_frozen_lockfile_capture_at(
    bun: &str,
    web_dir: &Path,
) -> std::io::Result<std::process::Output> {
    build_bun_install_frozen_lockfile_capture_command(bun, web_dir)
        .output()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Byte-oracle: the `Command` built by
    /// [`build_bun_install_frozen_lockfile_capture_command`] spawns
    /// `bun` as its program — the exact bin string threaded through
    /// by the caller — with no wrapping shell (`/bin/sh -c`), no
    /// `env` prefix, and no `nix run --` shim. A refactor that
    /// shelled out through `sh -c` would defeat the
    /// `.current_dir(web_dir)` scoping (the shell would inherit the
    /// parent's cwd on some hosts) and reopen a shell-quoting attack
    /// surface for any future caller-supplied argv element.
    #[test]
    fn build_bun_install_frozen_lockfile_capture_command_uses_supplied_bun_as_program() {
        let cmd = build_bun_install_frozen_lockfile_capture_command(
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
    /// pre-lift 2-element slice `["install", "--frozen-lockfile"]`,
    /// in that order, with no extra element and no rewritten value.
    /// Same two elements the sibling
    /// [`crate::bun_argv::bun_install_frozen_lockfile_argv`]
    /// byte-oracle pins, projected here from the composed builder
    /// chain via [`Command::get_args`] to prove the argv slice
    /// reaches the spawn boundary verbatim (no `.arg("--production")`
    /// addition, no argv-order rewrite, no dropped element).
    #[test]
    fn build_bun_install_frozen_lockfile_capture_command_carries_pre_lift_argv_verbatim() {
        let cmd = build_bun_install_frozen_lockfile_capture_command("bun", Path::new("/w"));
        let std_cmd: &std::process::Command = cmd.as_std();
        let args: Vec<&std::ffi::OsStr> = std_cmd.get_args().collect();
        assert_eq!(
            args,
            vec![
                std::ffi::OsStr::new("install"),
                std::ffi::OsStr::new("--frozen-lockfile"),
            ],
            "the built Command's argv must be exactly the pre-lift \
             2-element `bun_install_frozen_lockfile_argv` slice, in \
             order"
        );
    }

    /// Byte-oracle: the caller-supplied `web_dir` reaches the built
    /// `Command`'s [`Command::get_current_dir`] verbatim — a dropped
    /// `.current_dir(web_dir)` (which would spawn bun in forge's own
    /// cwd, missing the caller's `package.json` and `bun.lockb`) or a
    /// swap to `.env("PWD", web_dir)` (which does not scope the
    /// spawn) is caught here.
    #[test]
    fn build_bun_install_frozen_lockfile_capture_command_scopes_current_dir_to_web_dir() {
        let web = PathBuf::from("/repo/apps/web");
        let cmd = build_bun_install_frozen_lockfile_capture_command("bun", &web);
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
    /// a non-empty [`Command::get_envs`] override list. Pre-lift the
    /// three consumers each spelled the chain with no env
    /// pass-through, and the drift-detection gates
    /// (`codegen_validation`, `sync`) depend on that: an
    /// `.env("RUST_LOG", "info")` leaked from forge's own process
    /// env into bun would echo forge's stderr into the classifier's
    /// `drift_indicators` walk and produce a spurious drift
    /// verdict.
    #[test]
    fn build_bun_install_frozen_lockfile_capture_command_carries_no_env_overrides() {
        let cmd = build_bun_install_frozen_lockfile_capture_command("bun", Path::new("/w"));
        let std_cmd: &std::process::Command = cmd.as_std();
        assert_eq!(
            std_cmd.get_envs().count(),
            0,
            "the built Command must carry no `.env(...)` overrides — \
             the pre-lift three consumers each spelled the builder \
             chain with no env pass-through"
        );
    }

    /// Post-lift shield (negative): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw
    /// `Command::new(&bun).args(crate::bun_argv::bun_install_frozen_lockfile_argv())`
    /// composition inline. Every consumer reaches for
    /// [`build_bun_install_frozen_lockfile_capture_command`] (or the
    /// runner sibling) on first grep, not by copy-pasting the raw
    /// builder chain from an existing command module. Scoped to
    /// non-comment lines so a docstring mention of the raw shape
    /// does not defeat the shield.
    #[test]
    fn no_command_module_still_spells_raw_bun_install_frozen_lockfile_capture_chain() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle_head = "Command::new(&bun)";
        // Reconstruct the `.args(...)` head via format! so this
        // shield's own source never contains the literal
        // `bun_install_frozen_lockfile_argv` string on a code line
        // and cannot false-match itself.
        let argv_fn = format!("{}bun_install_frozen_lockfile_argv", "crate::bun_argv::");
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
                // raw stanza spans `Command::new(&bun)` on line N
                // and `.args(crate::bun_argv::bun_install_frozen_lockfile_argv())`
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
             `crate::bun_install_frozen_lockfile_capture::\
             build_bun_install_frozen_lockfile_capture_command(&bun, web_dir)` \
             (for the `run_capture_anyhow` hand-off) or \
             `run_bun_install_frozen_lockfile_capture_at(&bun, web_dir)` \
             (for the bare `.output().await` shape) instead:\n{:#?}",
            argv_fn,
            offenders
        );
    }

    /// Post-lift shield (positive): the three pre-lift modules MUST
    /// forward through [`build_bun_install_frozen_lockfile_capture_command`]
    /// (or its `.output().await` runner sibling
    /// [`run_bun_install_frozen_lockfile_capture_at`]) at least once
    /// each. A migration that dropped a call site outright leaves
    /// the negative "no raw inline shape" scan trivially satisfied
    /// by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_bun_install_frozen_lockfile_capture() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[
            ("codegen.rs", 1),
            ("codegen_validation.rs", 1),
            ("sync.rs", 1),
        ];
        // Match either the factory (used by `codegen.rs` — the
        // `run_capture_anyhow` hand-off) or the bare-`.output().await`
        // runner (used by `codegen_validation.rs` and `sync.rs`).
        let factory_needle = "build_bun_install_frozen_lockfile_capture_command(";
        let runner_needle = "run_bun_install_frozen_lockfile_capture_at(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards =
                source.matches(factory_needle).count() + source.matches(runner_needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `bun install --frozen-lockfile` captured-output \
                 spawn site(s) through either `{factory_needle}` \
                 or `{runner_needle}`; found {forwards}. A dropped \
                 call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}

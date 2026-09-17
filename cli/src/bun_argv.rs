//! Fixed-arity `bun` argv slices used at every bun spawn site across the
//! crate. Two primitives: `bun_install_frozen_lockfile_argv` for the
//! dep-install preamble, and `bun_x_graphql_codegen_argv` for the
//! `bun x graphql-codegen --config codegen.ts` run.
//!
//! # Pre-lift census — four sibling stanzas, byte-identical
//!
//! Four consumer sites each spelled the same 2-element
//! `["install", "--frozen-lockfile"]` literal verbatim on their `bun`
//! builder:
//!
//! 1. `commands/codegen.rs::run_codegen_at` (Step 2 dep-install preamble,
//!    routed through [`crate::retry::run_capture_anyhow`])
//! 2. `commands/codegen_validation.rs::validate_codegen` (`bun install`
//!    dep-install preamble ahead of the drift check)
//! 3. `commands/sync.rs::check_drift` (`bun install` dep-install preamble
//!    ahead of the codegen drift check)
//! 4. `commands/frontend_validation.rs::validate_frontend_with_config`
//!    (dep-install preamble via the `bun_output_at` helper)
//!
//! A bun-install argv drift — a `--production` toggle, a `--no-scripts`
//! opt-out, an argv-order swap, a `--frozen-lockfile` rename by the bun
//! project — pre-lift had to hit four sites in lockstep or diverge;
//! post-lift it hits ONE typed body and every consumer inherits the
//! change from `Command::args(bun_install_frozen_lockfile_argv())` (or
//! `&bun_install_frozen_lockfile_argv()` for `&[&str]`-taking helpers).
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The four consumers differ AFTER the argv slice on three axes:
//!
//! - **Spawn adapter.** Sites 1 uses [`crate::retry::run_capture_anyhow`]
//!   for the captured-output + classify chain; sites 2–3 build their own
//!   `Command::new(&bun).output().await` and hand-classify the exit; site
//!   4 routes through the module-local `bun_output_at` helper which owns
//!   a shared `classify_spawn_anyhow` wrapping.
//! - **Working directory shape.** Sites 1–2 take `&Path`; site 3 takes
//!   `&config.web_dir` (owned inside a config struct); site 4 receives
//!   the `web_dir: &Path` argument through the helper.
//! - **Error-envelope shape.** Sites 1 bubbles via `anyhow::Context`,
//!   sites 2–3 wrap into a typed result struct with `error: Option<String>`,
//!   and site 4 pushes into a `Vec<String>` error accumulator.
//!
//! A `Command`-builder primitive would have to expose all three axes as
//! parameters; the argv slice owns only the shape both `tokio::process`
//! and `std::process` `Command`s' `.args()` (and any `&[&str]`-taking
//! helper) consume identically. Modeled on
//! [`crate::infrastructure::registry::doca_push_argv`] (d9b5dd8), the
//! same shape lifted for the 9-element `doca push` argv across four
//! sites of the push family.
//!
//! # Distinct from the sibling `bun_bin()` sigil family
//!
//! Every consumer already resolves the `bun` binary via a module-scoped
//! `bun_bin()` sigil (see the whole-module shields on
//! `codegen{,_validation}.rs`, `sync.rs`, `frontend_validation.rs`,
//! `e2e.rs`), which reads the `BUN_BIN` env-var forward from the Nix
//! derivation. That sigil owns *which* binary spawns; this primitive
//! owns *which arguments* it receives on the frozen-lockfile install
//! phase. The two concerns compose: `Command::new(bun_bin()).args(
//! crate::bun_argv::bun_install_frozen_lockfile_argv())`.

/// The pre-lift 2-element `install --frozen-lockfile` argv slice used at
/// every bun-install spawn site.
///
/// Callers assemble the surrounding builder chain (`Command::new(&bun)`,
/// `.current_dir(web_dir)`, `.output()` vs
/// [`crate::retry::run_capture_anyhow`], etc.) themselves — those axes
/// vary across the four consumers. This primitive owns ONLY the
/// 2-element argv shape.
///
/// # `&'static str` lifetimes, not borrows from inputs
///
/// Unlike [`crate::infrastructure::registry::doca_push_argv`], which
/// interpolates caller-supplied `image_path` / `host` / `image` / `tag`
/// strings into a 9-element slice and therefore borrows from its
/// arguments, every element here is a compile-time string literal
/// (`"install"`, `"--frozen-lockfile"`). Returning `[&'static str; 2]`
/// pins that at the type level: no caller can accidentally shorten the
/// slice's lifetime, and the returned array outlives every use.
pub fn bun_install_frozen_lockfile_argv() -> [&'static str; 2] {
    ["install", "--frozen-lockfile"]
}

/// The pre-lift 4-element `x graphql-codegen --config codegen.ts` argv
/// slice used at every `bun x graphql-codegen`-driven schema-codegen
/// spawn site across the crate.
///
/// # Pre-lift census — three sibling stanzas, one splayed
///
/// Three consumer sites each spelled the same 4-argument invocation on
/// their `bun` builder, two byte-identical and one splayed across a
/// `.arg("x")` + 3-element `.args([...])` pair:
///
/// 1. `commands/codegen.rs::run_codegen_at` (Step 4 codegen run,
///    splayed as `.arg("x").args(["graphql-codegen", "--config",
///    "codegen.ts"])`).
/// 2. `commands/codegen_validation.rs::validate_codegen` (drift-check
///    codegen run, 4-element inline literal).
/// 3. `commands/sync.rs::check_drift` (schema-vs-codegen drift check,
///    4-element inline literal).
///
/// A drift in the codegen argv — a `--config` rename by graphql-codegen,
/// a `--overwrite` toggle, a config-file path change from `codegen.ts`
/// to `codegen.mjs`, an argv-order swap between subcommand and flag —
/// pre-lift had to hit three sites in lockstep (with the splayed site
/// separately) or diverge; post-lift it hits ONE typed body and every
/// consumer inherits the change from `Command::args(
/// bun_x_graphql_codegen_argv())`. The splayed site is normalized in
/// the same lift so the `.arg` / `.args` split no longer hides half the
/// argv from a future grep.
///
/// Sibling of [`bun_install_frozen_lockfile_argv`] in the same module:
/// same shape (compile-time literal elements, `[&'static str; N]`
/// return type, no borrows from inputs), same consumer boundary
/// (`commands/`), same shield pair. The two primitives partition the
/// bun-argv duplication budget: install-phase (`bun install
/// --frozen-lockfile`) and codegen-phase (`bun x graphql-codegen
/// --config codegen.ts`), which are the only two argv shapes forge
/// spawns `bun` with at runtime.
///
/// # `&'static str` lifetimes, not borrows from inputs
///
/// Every element is a compile-time string literal — no caller-supplied
/// path is interpolated into the argv. Returning `[&'static str; 4]`
/// pins that at the type level: no caller can accidentally shorten the
/// slice's lifetime, and the returned array outlives every use.
pub fn bun_x_graphql_codegen_argv() -> [&'static str; 4] {
    ["x", "graphql-codegen", "--config", "codegen.ts"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`bun_install_frozen_lockfile_argv`] returns the
    /// pre-lift 2-element slice element-for-element (`"install"`,
    /// `"--frozen-lockfile"`), in the pre-lift order, with no extra
    /// element and no rewritten value. A future refactor that (a)
    /// reordered the slice, (b) added a `--production` / `--no-scripts`
    /// flag, (c) renamed `--frozen-lockfile` to bun's newer
    /// `--frozen-lockfile` alias, or (d) collapsed the two elements
    /// regresses this assertion.
    #[test]
    fn test_bun_install_frozen_lockfile_argv_emits_pre_lift_two_element_slice() {
        let argv = bun_install_frozen_lockfile_argv();
        assert_eq!(argv[0], "install");
        assert_eq!(argv[1], "--frozen-lockfile");
        assert_eq!(argv.len(), 2);
    }

    /// The return type is a fixed-arity `[&str; 2]`, NOT a `Vec<&str>`
    /// or a `&'static [&'static str]`. A type change to a `Vec<String>`
    /// would allow a caller to `.push` a stray argument without touching
    /// this module; a change to a slice reference would allow an
    /// unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 2]` shape, this line fails to type-check.
    #[test]
    fn test_bun_install_frozen_lockfile_argv_returns_fixed_arity_two() {
        let argv: [&str; 2] = bun_install_frozen_lockfile_argv();
        let [first, second] = argv;
        assert_eq!(first, "install");
        assert_eq!(second, "--frozen-lockfile");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `["install", "--frozen-lockfile"]` argv literal inline any more.
    /// The four pre-lift sites migrated; any future consumer that wants
    /// the same frozen-lockfile install shape reaches for
    /// [`bun_install_frozen_lockfile_argv`] on first grep, not by
    /// copy-pasting the raw literal from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_bun_install_frozen_lockfile_argv() {
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
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("\"install\", \"--frozen-lockfile\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"install\", \"--frozen-lockfile\"]` argv literal(s) \
             survive under `commands/` — route each through \
             `crate::bun_argv::bun_install_frozen_lockfile_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two remaining post-lift
    /// direct consumers of [`bun_install_frozen_lockfile_argv`] MUST
    /// each forward through it at least once, so a migration that
    /// dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails.
    ///
    /// Pre-lift four consumer modules
    /// (`commands/{codegen,codegen_validation,sync,frontend_validation}.rs`)
    /// each spelled the
    /// `.args(crate::bun_argv::bun_install_frozen_lockfile_argv())`
    /// call inline on their own `Command::new(&bun)` chain
    /// (`codegen_validation`, `sync`) or handed the slice through a
    /// helper (`codegen`'s `run_capture_anyhow` prep, `frontend_validation`'s
    /// generic `bun_output_at` wrapper). Post-lift the three
    /// captured-output spawn consumers
    /// (`commands/{codegen,codegen_validation,sync}.rs`) delegate to
    /// [`crate::bun_install_frozen_lockfile_capture`], which owns
    /// the argv-carrying builder body; the argv routing for those
    /// three sites is tracked by the sibling
    /// `bun_install_frozen_lockfile_capture::tests::every_prelift_module_forwards_through_bun_install_frozen_lockfile_capture`
    /// shield.
    ///
    /// The two remaining direct consumers of the argv slice are:
    ///
    /// 1. [`crate::bun_install_frozen_lockfile_capture`] — the
    ///    captured-output spawn primitive's
    ///    `build_bun_install_frozen_lockfile_capture_command` body,
    ///    which is the sole post-lift caller for the three
    ///    `Command::new(&bun).args(...).current_dir(<web_dir>).output().await`
    ///    consumers.
    /// 2. `commands/frontend_validation.rs::validate_frontend` — hands
    ///    the argv slice to a module-local `bun_output_at(args:
    ///    &[&str], cwd: &Path, op: &str)` helper that also serves
    ///    `bun run typecheck`, `bun test`, and `bunx biome check`
    ///    spawns; the generic helper is a different lift axis
    ///    (multi-argv wrapper, not a `bun install`-specialized
    ///    Command factory), so its argv routing stays direct.
    #[test]
    fn every_prelift_module_forwards_through_bun_install_frozen_lockfile_argv() {
        use std::path::PathBuf;
        let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, &str, usize)] = &[
            (
                manifest_root.join("bun_install_frozen_lockfile_capture.rs"),
                "bun_install_frozen_lockfile_capture.rs",
                1,
            ),
            (
                manifest_root
                    .join("commands")
                    .join("frontend_validation.rs"),
                "commands/frontend_validation.rs",
                1,
            ),
        ];
        let needle = "bun_install_frozen_lockfile_argv(";
        for (path, label, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{label} must forward at least {min_count} bun-install \
                 spawn site(s) through `{needle}`; found {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }

    /// Byte-oracle: [`bun_x_graphql_codegen_argv`] returns the pre-lift
    /// 4-element slice element-for-element (`"x"`, `"graphql-codegen"`,
    /// `"--config"`, `"codegen.ts"`), in the pre-lift order, with no
    /// extra element and no rewritten value. A future refactor that (a)
    /// reordered the slice, (b) added a `--overwrite` / `--errors-only`
    /// flag, (c) renamed `--config` to graphql-codegen's alternative
    /// short form, (d) switched the config extension from `.ts` to
    /// `.mjs`, or (e) collapsed the four elements regresses this
    /// assertion.
    #[test]
    fn test_bun_x_graphql_codegen_argv_emits_pre_lift_four_element_slice() {
        let argv = bun_x_graphql_codegen_argv();
        assert_eq!(argv[0], "x");
        assert_eq!(argv[1], "graphql-codegen");
        assert_eq!(argv[2], "--config");
        assert_eq!(argv[3], "codegen.ts");
        assert_eq!(argv.len(), 4);
    }

    /// The return type is a fixed-arity `[&str; 4]`, NOT a `Vec<&str>`
    /// or a `&'static [&'static str]`. Pin the fixed arity at compile
    /// time via a destructured binding — if the returned type ever
    /// loses its `[_; 4]` shape, this line fails to type-check. Mirrors
    /// the sibling
    /// [`test_bun_install_frozen_lockfile_argv_returns_fixed_arity_two`]
    /// shape.
    #[test]
    fn test_bun_x_graphql_codegen_argv_returns_fixed_arity_four() {
        let argv: [&str; 4] = bun_x_graphql_codegen_argv();
        let [first, second, third, fourth] = argv;
        assert_eq!(first, "x");
        assert_eq!(second, "graphql-codegen");
        assert_eq!(third, "--config");
        assert_eq!(fourth, "codegen.ts");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `["x", "graphql-codegen", "--config", "codegen.ts"]` argv literal
    /// (nor the pre-lift splayed form
    /// `.arg("x").args(["graphql-codegen", "--config", "codegen.ts"])`)
    /// inline any more. The three pre-lift sites migrated; any future
    /// consumer that wants the same codegen run shape reaches for
    /// [`bun_x_graphql_codegen_argv`] on first grep, not by
    /// copy-pasting the raw literal from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_bun_x_graphql_codegen_argv() {
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
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                let hits_full_4tuple =
                    line.contains("\"x\", \"graphql-codegen\", \"--config\", \"codegen.ts\"");
                let hits_splayed_3tuple =
                    line.contains("\"graphql-codegen\", \"--config\", \"codegen.ts\"");
                if hits_full_4tuple || hits_splayed_3tuple {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"x\", \"graphql-codegen\", \"--config\", \"codegen.ts\"]` \
             argv literal(s) (full or splayed) survive under `commands/` — \
             route each through \
             `crate::bun_argv::bun_x_graphql_codegen_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the sole post-lift consumer of
    /// [`bun_x_graphql_codegen_argv`] — the
    /// [`crate::bun_x_graphql_codegen_capture`] captured-output spawn
    /// primitive's `build_bun_x_graphql_codegen_capture_command` body
    /// — MUST forward through it at least once. Pre-lift the three
    /// consumer modules (`commands/{codegen,codegen_validation,sync}.rs`)
    /// each spelled the `.args(crate::bun_argv::bun_x_graphql_codegen_argv())`
    /// call inline on their `Command::new(&bun)` chain; post-lift the
    /// same three modules delegate to
    /// `crate::bun_x_graphql_codegen_capture::run_bun_x_graphql_codegen_capture_at`,
    /// which owns the argv-carrying builder body. This shield tracks
    /// the routing to the new one-owner spawn primitive so a
    /// migration that dropped the argv routing outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. The per-caller
    /// forward-count for the three `commands/` modules is retained
    /// by the sibling
    /// `bun_x_graphql_codegen_capture::tests::every_prelift_module_forwards_through_bun_x_graphql_codegen_capture`
    /// shield.
    #[test]
    fn every_prelift_module_forwards_through_bun_x_graphql_codegen_argv() {
        use std::path::PathBuf;
        let capture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("bun_x_graphql_codegen_capture.rs");
        let needle = "bun_x_graphql_codegen_argv(";
        let source = std::fs::read_to_string(&capture_path).unwrap_or_else(|_| {
            panic!(
                "expected {} to exist — the sole post-lift consumer of \
                 the `bun_x_graphql_codegen_argv` primitive",
                capture_path.display()
            )
        });
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 1,
            "bun_x_graphql_codegen_capture.rs must forward through `{needle}` \
             at least once — the fusion primitive's `build_..._command` body \
             is the sole post-lift caller of `bun_x_graphql_codegen_argv`. \
             A dropped call would leave the negative raw-shape scan (under \
             `commands/`) trivially satisfied by absence.",
        );
    }
}

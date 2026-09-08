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

    /// Caller shield (positive half): the four pre-lift modules MUST
    /// each forward through
    /// [`bun_install_frozen_lockfile_argv`] at least once, so a
    /// migration that dropped a call site outright leaves the negative
    /// "no raw inline shape" scan trivially satisfied by absence but the
    /// positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_bun_install_frozen_lockfile_argv() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[
            ("codegen.rs", 1),
            ("codegen_validation.rs", 1),
            ("sync.rs", 1),
            ("frontend_validation.rs", 1),
        ];
        let needle = "bun_install_frozen_lockfile_argv(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} bun-install \
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

    /// Caller shield (positive half): the three pre-lift modules MUST
    /// each forward through [`bun_x_graphql_codegen_argv`] at least
    /// once, so a migration that dropped a call site outright leaves
    /// the negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_bun_x_graphql_codegen_argv() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[
            ("codegen.rs", 1),
            ("codegen_validation.rs", 1),
            ("sync.rs", 1),
        ];
        let needle = "bun_x_graphql_codegen_argv(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} bun-x-graphql-codegen \
                 spawn site(s) through `{needle}`; found {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}

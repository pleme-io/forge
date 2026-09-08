//! Fixed-arity `cargo test --test <NAME> --features integration-tests
//! [suffix]` argv slices used at every integration-test / E2E cargo
//! spawn site across the crate.
//!
//! # Pre-lift census — four sibling stanzas, two argv shapes
//!
//! Two argv shapes each covered a pair of byte-identical spawn sites:
//!
//! - **Shape A — 5-element integration-tests argv:**
//!   `["test", "--test", "integration_tests", "--features", "integration-tests"]`
//!   1. `commands/e2e.rs::run_backend_integration_tests`
//!      (`vec![...]`-then-optional-`--` / filter push)
//!   2. `commands/prerelease.rs::run_integration_tests` (G13 gate,
//!      `.args([...])` direct on `Command::new(&cargo)`)
//! - **Shape B — 7-element e2e-tests-include-ignored argv:**
//!   `["test", "--test", "e2e_tests", "--features", "integration-tests",
//!    "--", "--include-ignored"]`
//!   1. `commands/e2e.rs::run_e2e_tests` (`vec![...]`-then-optional-filter push)
//!   2. `commands/prerelease.rs::run_e2e_tests` (G14 gate, `.args([...])`
//!      direct on `Command::new(&cargo)`)
//!
//! A cargo-integration-test argv drift — a `--features` rename, an
//! `--all-features` toggle, a `--test` binary rename, a `--profile
//! release-lto` add, or a bake into the `[dev-dependencies]` cargo config
//! — pre-lift had to hit two sites in lockstep or diverge; post-lift it
//! hits ONE typed body per shape and every consumer inherits the change
//! from `Command::args(&cargo_test_argv::cargo_integration_tests_argv())`
//! (or the matching e2e-shape helper).
//!
//! # Why two argv slices, not one enum-projecting primitive
//!
//! The two shapes share the `--test <NAME> --features integration-tests`
//! head but diverge in argv length and trailing suffix (Shape A ends at
//! `integration-tests`; Shape B carries `-- --include-ignored`). A single
//! enum-projecting primitive would have to return a heterogeneously-sized
//! slice — either a `Vec<&'static str>` (loses the compile-time fixed-arity
//! guarantee that a caller cannot silently `.push` a stray argument) or a
//! `&'static [&'static str]` (same story on the unsized-length axis). Two
//! separate fixed-arity `[&'static str; N]` returns pin each shape's length
//! at the type level: a future refactor that changes either argv's element
//! count is a type-check failure at every consumer, not a silent behavior
//! drift. Modeled on [`crate::bun_argv::bun_install_frozen_lockfile_argv`]
//! (4928b5b) and [`crate::infrastructure::registry::doca_push_argv`]
//! (d9b5dd8), which each own one argv shape apiece for the same reason.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers per shape differ AFTER the argv slice on four axes:
//!
//! - **`Command` kind.** Both `prerelease.rs` sites spawn via
//!   `tokio::process::Command::new(&cargo).args(...).output()` under a
//!   `tokio::time::timeout` envelope. Both `e2e.rs` sites spawn via the
//!   sibling `run_inherited_status_sync` (a `std::process` wrapper) after
//!   an optional filter push.
//! - **Working directory shape.** `prerelease.rs` sites take
//!   `&config.backend_dir` (a `PathBuf` inside a config struct);
//!   `e2e.rs::run_backend_integration_tests` takes `&str`;
//!   `e2e.rs::run_e2e_tests` builds `format!("{}/services/rust/backend",
//!   repo_root)` and passes the owned `String`.
//! - **Optional filter suffix.** Both `e2e.rs` sites append an
//!   `Option<&str>` filter after the fixed argv (Shape A appends `["--",
//!   filter]`; Shape B appends `[filter]` because `--` already appears in
//!   the fixed slice). The `prerelease.rs` sites never take a filter.
//! - **Env envelope.** `prerelease.rs::run_e2e_tests` sets `E2E_HEADLESS=1`
//!   conditionally on `headless`; `e2e.rs::run_e2e_tests` also flips
//!   `env_remove("E2E_HEADLESS")` on the false branch. The
//!   integration-tests sites carry no such env.
//!
//! A `Command`-builder primitive would have to expose all four axes as
//! parameters; the argv slice owns only the shape both `tokio::process`
//! and `std::process` `Command`s' `.args()` consume identically, and
//! remains equally usable in the `let mut args = vec![...]; args.push(...)`
//! sites via `.to_vec()`.
//!
//! # Distinct from the sibling `cargo_bin()` sigil family
//!
//! Every consumer already resolves the `cargo` binary via a module-scoped
//! `cargo_bin()` sigil, which reads the `CARGO` env-var forward from the
//! Nix derivation (see the whole-module shields on `bootstrap.rs`,
//! `comprehensive_release.rs`, `developer_tools.rs`, `e2e.rs`,
//! `prerelease.rs`, `test.rs`). That sigil owns *which* binary spawns;
//! this module owns *which arguments* it receives on the
//! integration-test / E2E test phase. The two concerns compose:
//! `Command::new(cargo_bin()).args(
//! crate::cargo_test_argv::cargo_integration_tests_argv())`.

/// The pre-lift 5-element `test --test integration_tests --features
/// integration-tests` argv slice used at every integration-test cargo
/// spawn site.
///
/// Callers assemble the surrounding builder chain (`Command::new(&cargo)`,
/// `.current_dir(backend_dir)`, `.output()` under a
/// `tokio::time::timeout` envelope vs a synchronous
/// [`crate::retry::run_inherited_status_sync`], any trailing `["--",
/// filter]` suffix on the `e2e.rs` site) themselves — those axes vary
/// across the two consumers. This primitive owns ONLY the 5-element argv
/// shape.
///
/// # `&'static str` lifetimes, not borrows from inputs
///
/// Unlike [`crate::infrastructure::registry::doca_push_argv`], which
/// interpolates caller-supplied `image_path` / `host` / `image` / `tag`
/// strings into a 9-element slice and therefore borrows from its
/// arguments, every element here is a compile-time string literal
/// (`"test"`, `"--test"`, `"integration_tests"`, `"--features"`,
/// `"integration-tests"`). Returning `[&'static str; 5]` pins that at
/// the type level: no caller can accidentally shorten the slice's
/// lifetime, and the returned array outlives every use — matches
/// [`crate::bun_argv::bun_install_frozen_lockfile_argv`] on the same
/// static-lifetime axis.
pub fn cargo_integration_tests_argv() -> [&'static str; 5] {
    [
        "test",
        "--test",
        "integration_tests",
        "--features",
        "integration-tests",
    ]
}

/// The pre-lift 7-element `test --test e2e_tests --features
/// integration-tests -- --include-ignored` argv slice used at every E2E
/// test cargo spawn site.
///
/// The `--` separator plus `--include-ignored` sit INSIDE the returned
/// slice because both pre-lift consumers spelled the full 7-element
/// literal verbatim — the E2E suite's `#[ignore]`-annotated cases are
/// the ones that actually connect to Docker-backed backend services, so
/// pushing them below the `--` boundary is not a variant knob at either
/// consumer.
///
/// Callers assemble the surrounding builder chain (`Command::new(&cargo)`,
/// `.current_dir(backend_dir)`, `.output()` under a
/// `tokio::time::timeout` envelope vs a synchronous
/// [`crate::retry::run_inherited_status_sync`], any trailing `[filter]`
/// suffix on the `e2e.rs` site, the `E2E_HEADLESS=1` env conditional)
/// themselves — those axes vary across the two consumers. This primitive
/// owns ONLY the 7-element argv shape.
///
/// # `&'static str` lifetimes, not borrows from inputs
///
/// Every element is a compile-time string literal; returning
/// `[&'static str; 7]` pins the lifetime at the type level — same
/// discipline [`cargo_integration_tests_argv`] and
/// [`crate::bun_argv::bun_install_frozen_lockfile_argv`] carry.
pub fn cargo_e2e_tests_include_ignored_argv() -> [&'static str; 7] {
    [
        "test",
        "--test",
        "e2e_tests",
        "--features",
        "integration-tests",
        "--",
        "--include-ignored",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`cargo_integration_tests_argv`] returns the pre-lift
    /// 5-element slice element-for-element (`"test"`, `"--test"`,
    /// `"integration_tests"`, `"--features"`, `"integration-tests"`), in
    /// the pre-lift order, with no extra element and no rewritten value.
    /// A future refactor that (a) reordered the slice, (b) added a
    /// `--all-features` / `--profile release-lto` flag, (c) renamed
    /// `integration_tests` to a different `--test` binary, or (d)
    /// collapsed the two `--test <NAME>` elements regresses this
    /// assertion.
    #[test]
    fn test_cargo_integration_tests_argv_emits_pre_lift_five_element_slice() {
        let argv = cargo_integration_tests_argv();
        assert_eq!(argv[0], "test");
        assert_eq!(argv[1], "--test");
        assert_eq!(argv[2], "integration_tests");
        assert_eq!(argv[3], "--features");
        assert_eq!(argv[4], "integration-tests");
        assert_eq!(argv.len(), 5);
    }

    /// Byte-oracle: [`cargo_e2e_tests_include_ignored_argv`] returns the
    /// pre-lift 7-element slice element-for-element, in the pre-lift
    /// order. A refactor that dropped the `--include-ignored` boundary
    /// (or moved `--` past it) would silently skip every `#[ignore]`
    /// case at both consumer sites and pass the suite green with less
    /// real coverage; this assertion catches that regression at compile
    /// time.
    #[test]
    fn test_cargo_e2e_tests_include_ignored_argv_emits_pre_lift_seven_element_slice() {
        let argv = cargo_e2e_tests_include_ignored_argv();
        assert_eq!(argv[0], "test");
        assert_eq!(argv[1], "--test");
        assert_eq!(argv[2], "e2e_tests");
        assert_eq!(argv[3], "--features");
        assert_eq!(argv[4], "integration-tests");
        assert_eq!(argv[5], "--");
        assert_eq!(argv[6], "--include-ignored");
        assert_eq!(argv.len(), 7);
    }

    /// The return types are fixed-arity `[&str; 5]` / `[&str; 7]`, NOT
    /// `Vec<&str>` or `&'static [&'static str]`. A type change to a
    /// `Vec<String>` would allow a caller to `.push` a stray argument
    /// without touching this module; a change to a slice reference would
    /// allow an unsized-length pattern that a variadic future refactor
    /// might silently exploit. Pin the fixed arities at compile time via
    /// destructured bindings — if either returned type ever loses its
    /// `[_; N]` shape, this test fails to type-check.
    #[test]
    fn test_cargo_test_argvs_return_fixed_arity_five_and_seven() {
        let integration: [&str; 5] = cargo_integration_tests_argv();
        let [i0, i1, i2, i3, i4] = integration;
        assert_eq!(i0, "test");
        assert_eq!(i1, "--test");
        assert_eq!(i2, "integration_tests");
        assert_eq!(i3, "--features");
        assert_eq!(i4, "integration-tests");

        let e2e: [&str; 7] = cargo_e2e_tests_include_ignored_argv();
        let [e0, e1, e2, e3, e4, e5, e6] = e2e;
        assert_eq!(e0, "test");
        assert_eq!(e1, "--test");
        assert_eq!(e2, "e2e_tests");
        assert_eq!(e3, "--features");
        assert_eq!(e4, "integration-tests");
        assert_eq!(e5, "--");
        assert_eq!(e6, "--include-ignored");
    }

    /// The two argv shapes share the head `["test", "--test", <NAME>,
    /// "--features", "integration-tests"]` — a future primitive that
    /// unifies them via a `CargoIntegrationSuite` enum must preserve
    /// that head. This assertion pins the shared prefix so a drift that
    /// diverged the two shapes' heads (e.g. renamed `--features` on one
    /// but not the other) would be a compile-time regression on the
    /// zip-compare below.
    #[test]
    fn test_cargo_test_argvs_share_pre_lift_five_element_head() {
        let integration = cargo_integration_tests_argv();
        let e2e = cargo_e2e_tests_include_ignored_argv();
        assert_eq!(integration[0], e2e[0]);
        assert_eq!(integration[1], e2e[1]);
        // Element 2 diverges intentionally: `integration_tests` vs `e2e_tests`.
        assert_ne!(integration[2], e2e[2]);
        assert_eq!(integration[3], e2e[3]);
        assert_eq!(integration[4], e2e[4]);
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `["test", "--test", "integration_tests", "--features",
    /// "integration-tests"]` argv literal (or the 7-element E2E
    /// variant) inline any more. The four pre-lift sites migrated; any
    /// future consumer that wants the same integration-test or E2E
    /// argv shape reaches for one of the two typed primitives here on
    /// first grep, not by copy-pasting the raw literal from an existing
    /// command module. Mirrors the negative half of the sibling
    /// `no_command_module_still_spells_raw_bun_install_frozen_lockfile_argv`
    /// shield on [`crate::bun_argv`] (4928b5b).
    #[test]
    fn no_command_module_still_spells_raw_cargo_integration_or_e2e_argv() {
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
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own docstring
                // reference to the pre-lift shape in prose can't
                // self-hit through another module's copy.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                // Anchor on the joined pair `"--test", "integration_tests"`
                // or `"--test", "e2e_tests"` — a stanza that spelled the
                // pre-lift argv verbatim always carried this two-element
                // adjacency, and no post-lift consumer will (the typed
                // primitives own the joined pair inside their bodies).
                if line.contains("\"--test\", \"integration_tests\"")
                    || line.contains("\"--test\", \"e2e_tests\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"--test\", \"integration_tests\", ...]` or \
             `[\"--test\", \"e2e_tests\", ...]` argv literal(s) survive \
             under `commands/` — route each through \
             `crate::cargo_test_argv::cargo_integration_tests_argv()` or \
             `crate::cargo_test_argv::cargo_e2e_tests_include_ignored_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules MUST each
    /// forward through one of the two primitives at least twice (one per
    /// Shape A / Shape B call site), so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling `every_prelift_module_forwards_through_*`
    /// shields the crate carries against every other typed argv
    /// primitive.
    #[test]
    fn every_prelift_module_forwards_through_cargo_test_argv_primitives() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("e2e.rs", 2), ("prerelease.rs", 2)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let integration = source.matches("cargo_integration_tests_argv(").count();
            let e2e = source
                .matches("cargo_e2e_tests_include_ignored_argv(")
                .count();
            let total = integration + e2e;
            assert!(
                total >= *min_count,
                "{basename} must forward at least {min_count} cargo integration/E2E \
                 test spawn site(s) through one of \
                 `cargo_integration_tests_argv(` / \
                 `cargo_e2e_tests_include_ignored_argv(`; found {total} \
                 ({integration} integration + {e2e} e2e). A dropped call \
                 would leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
